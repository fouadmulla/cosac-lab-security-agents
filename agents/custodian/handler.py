"""Custodian, running for real.

Invoked by EventBridge when GuardDuty raises a finding. Reads the real
finding, describes the real instance, calls a real model, and really swaps
security groups when the escalation policy permits it.

Both twins run this identical file with identical IAM. The only difference is
CUSTODIAN_ESCALATION_PROFILE.
"""

from __future__ import annotations

import json
import os
from typing import Any

import boto3

from agents.common.executor import DynamoLedger, QuarantineExecutor
from agents.common.ingest import describe_instances, finding_from_event, findings_from_detector
from agents.common.llm import DEFAULT_MODEL_ID
from agents.common.policy.escalate import ApprovalGatedEscalation, NonBlockingEscalation
from agents.custodian.agent import Custodian

REGION = os.environ.get("AWS_REGION", "us-east-1")
AGENT_ID = os.environ.get("AGENT_ID", "custodian-a")
TWIN = os.environ.get("TWIN", "custodian-a")
ISOLATION_SG = os.environ["ISOLATION_SG_ID"]
LEDGER_TABLE = os.environ.get("LEDGER_TABLE", "cosac-decision-ledger")
MODEL_ID = os.environ.get("COSAC_MODEL_ID", DEFAULT_MODEL_ID)


def _policy():
    profile = os.environ.get("CUSTODIAN_ESCALATION_PROFILE", "non_blocking").lower()
    return ApprovalGatedEscalation() if profile == "approval_gated" else NonBlockingEscalation()


def carry_out_approval(event: dict[str, Any], ec2, dynamodb) -> dict[str, Any]:
    """Do the thing a human just approved.

    An approval that nothing executes is not an approval. The board wrote
    "approved" into the ledger and released a Step Functions token if one
    existed -- and none ever does, because these agents are not a state
    machine. So the request was answered, the strip said the agent may now
    act, and the machine stayed on the network, leaking.

    The agent performs it, not the board, so the ledger records the act under
    the identity that asked for it, with the before and after state. That is
    what Record is for.

    The payload is NOT trusted. It names a decision; this re-reads that
    decision from the ledger and acts only if the ledger says it belongs to
    this agent and that a human really approved it. Anything else is a caller
    asking an agent to quarantine a machine on its own say-so.
    """
    ask = event.get("approved_decision") or {}
    decision_id = str(ask.get("decision_id", ""))
    if not decision_id:
        return {"agent": AGENT_ID, "error": "no decision_id"}

    rows = dynamodb.query(
        TableName=LEDGER_TABLE,
        KeyConditionExpression="agent_id = :a AND decision_id = :d",
        ExpressionAttributeValues={":a": {"S": AGENT_ID}, ":d": {"S": decision_id}},
    ).get("Items", [])
    if not rows:
        # Either it is another twin's decision or it does not exist. Both are
        # a refusal, and neither is this agent's business to act on.
        return {"agent": AGENT_ID, "decision_id": decision_id, "error": "not mine"}

    row = rows[0]
    status = row.get("status", {}).get("S", "")
    if status != "approved":
        return {"agent": AGENT_ID, "decision_id": decision_id,
                "error": f"status is {status!r}, not approved"}

    instance_id = row.get("target", {}).get("S", "")
    described = describe_instances(ec2, [instance_id]) if instance_id else {}
    inst = described.get(instance_id)
    if not inst or inst.get("twin") != TWIN:
        return {"agent": AGENT_ID, "decision_id": decision_id,
                "error": "target is not this twin's instance"}

    prior = tuple(inst.get("security_groups", []))
    if not prior:
        # No prior state means the swap cannot be undone, and an approval does
        # not make an irreversible action acceptable.
        return {"agent": AGENT_ID, "decision_id": decision_id,
                "error": "no prior security groups; refusing an irreversible swap"}

    executor = QuarantineExecutor(
        agent_id=AGENT_ID,
        ledger=DynamoLedger(table=LEDGER_TABLE, client=dynamodb),
        isolation_group_id=ISOLATION_SG,
        client=ec2,
    )
    executor.quarantine(instance_id, prior_groups=prior)

    out = {
        "agent": AGENT_ID,
        "decision_id": decision_id,
        "contained": [instance_id],
        "approved_by": row.get("decided_by", {}).get("S", ""),
        "note": "carried out an approval a human granted on the board",
    }
    print(json.dumps(out, default=str))
    return out


def handler(event: dict[str, Any], _context: Any = None) -> dict[str, Any]:
    session = boto3.Session()
    ec2 = session.client("ec2", region_name=REGION)
    guardduty = session.client("guardduty", region_name=REGION)
    dynamodb = session.client("dynamodb", region_name=REGION)
    bedrock = session.client("bedrock-runtime", region_name=REGION)

    # A human answered a request this agent raised. That is not a new
    # investigation: the thinking was done when the request was made, and
    # re-running the model here would let it reach a different conclusion
    # from the one the human actually approved.
    if event and event.get("approved_decision"):
        return carry_out_approval(event, ec2, dynamodb)

    # EventBridge delivery is the real path; polling the detector is the
    # fallback for a manual invocation.
    finding = finding_from_event(event or {})
    findings = [finding] if finding else []
    if not findings:
        detectors = guardduty.list_detectors().get("DetectorIds", [])
        if detectors:
            findings = findings_from_detector(guardduty, detectors[0])

    # Each twin owns one instance. Both are told about every finding, but
    # neither may act on the other's machine -- otherwise one twin's decision
    # would show up on the other's side of the board.
    def mine_only(candidates):
        ids = [f["instance_id"] for f in candidates if f.get("instance_id")]
        described = describe_instances(ec2, ids) if ids else {}
        owned = {i: d for i, d in described.items() if d.get("twin") == TWIN}
        return owned, [f for f in candidates if f.get("instance_id") in owned]

    instances, findings = mine_only(findings)

    # EventBridge delivered the same finding to both twins, and it named the
    # other twin's instance. Observed live: each function was invoked once,
    # for the same event, so one twin would have sat idle while its own
    # machine leaked. If the delivered event is not ours, ask the detector
    # directly rather than returning empty-handed.
    if not findings:
        detectors = guardduty.list_detectors().get("DetectorIds", [])
        if detectors:
            instances, findings = mine_only(findings_from_detector(guardduty, detectors[0]))

    mine = instances

    if not findings:
        return {"agent": AGENT_ID, "findings": 0, "note": "nothing implicating this twin"}

    executor = QuarantineExecutor(
        agent_id=AGENT_ID,
        ledger=DynamoLedger(table=LEDGER_TABLE, client=dynamodb),
        isolation_group_id=ISOLATION_SG,
        client=ec2,
    )

    agent = Custodian(findings=findings, instances=mine, executor=executor, policy=_policy())
    run = agent.investigate(bedrock, model_id=MODEL_ID)

    summary = {
        "agent": AGENT_ID,
        "profile": os.environ.get("CUSTODIAN_ESCALATION_PROFILE", "non_blocking"),
        "model": MODEL_ID,
        "findings": len(findings),
        "tool_calls": [s.name for s in run.transcript.tool_calls] if run.transcript else [],
        "contained": run.contained,
        "escalated": run.escalated,
        "said": run.transcript.final_text if run.transcript else "",
    }
    print(json.dumps(summary, default=str))
    return summary
