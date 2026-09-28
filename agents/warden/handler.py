"""Warden, running for real.

Invoked by a CloudWatch Logs subscription filter as WAF lines arrive, or on a
schedule as a fallback. Reads real logs, calls a real model, and writes real
IPSet entries when the policy gate allows it.

Both twins run this identical file with identical IAM. The only difference is
WARDEN_POLICY_PROFILE, which decides what `load_policy()` returns.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3

from agents.common.executor import BlocklistExecutor, DynamoLedger
from agents.common.ingest import (
    observations_from_logs,
    observations_from_subscription,
)
from agents.common.llm import DEFAULT_MODEL_ID
from agents.common.policy.constrain import ENTRY_TTL, EnforcingPolicy, LegacyPolicy
from agents.warden.agent import Warden

REGION = os.environ.get("AWS_REGION", "us-east-1")
AGENT_ID = os.environ.get("AGENT_ID", "warden-a")
IPSET_NAME = os.environ["IPSET_NAME"]
IPSET_ID = os.environ["IPSET_ID"]

# A WAF IPSet holds one address family. The lab's topology is IPv6, but the
# load balancer is public and the open internet is overwhelmingly IPv4, so
# blocking what the agent actually sees takes a second set.
IPSET_V4_NAME = os.environ.get("IPSET_V4_NAME", "")
IPSET_V4_ID = os.environ.get("IPSET_V4_ID", "")
LOG_GROUP = os.environ["WAF_LOG_GROUP"]
LEDGER_TABLE = os.environ.get("LEDGER_TABLE", "cosac-decision-ledger")
MODEL_ID = os.environ.get("COSAC_MODEL_ID", DEFAULT_MODEL_ID)
LOOKBACK_MINUTES = int(os.environ.get("LOOKBACK_MINUTES", "5"))

# The responder's own monitoring. Excluded from what the agent is shown, the
# way a SOC allowlists its own probes. The subscription filter already keeps
# it from waking the agent; this keeps it out of the reasoning as well, for
# the polling path and for anything the filter lets through.
CANARY_PATH = os.environ.get("CANARY_PATH", "/__canary")


def _policy():
    """The one line that differs between the twins.

    Read here rather than passed in, so that the deployed difference is a
    single environment variable and nothing else.
    """
    profile = os.environ.get("WARDEN_POLICY_PROFILE", "enforcing").lower()
    if profile == "legacy":
        return LegacyPolicy()

    raw = os.environ.get("WARDEN_PROTECTED_PREFIXES", "")
    protected = [p.strip() for p in raw.split(",") if p.strip()]
    return EnforcingPolicy(protected)


def carry_out_approval(event: dict[str, Any], wafv2, dynamodb) -> dict[str, Any]:
    """Write the entry a human approved.

    Same shape as the custodian's. The board records the verdict; the agent
    performs the act, so the ledger carries it under the identity that asked.

    The payload is NOT trusted. It names a decision, and this re-reads that
    decision from the ledger before acting.
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
        return {"agent": AGENT_ID, "decision_id": decision_id, "error": "not mine"}

    row = rows[0]
    status = row.get("status", {}).get("S", "")
    if status != "approved":
        return {"agent": AGENT_ID, "decision_id": decision_id,
                "error": f"status is {status!r}, not approved"}

    entry = row.get("target", {}).get("S", "")
    if not entry:
        return {"agent": AGENT_ID, "decision_id": decision_id, "error": "no target"}

    # An approval releases something the policy ESCALATED. It does not release
    # something the policy DENIED, and the two must not be confused: no human
    # sign-off makes blocking your own responders correct. A denied range
    # never reaches a queue, so this should be unreachable -- which is exactly
    # why it is worth asserting rather than assuming.
    verdict = _policy().evaluate(entry, entries_last_hour=0)
    if verdict.rule_hit == "protected_prefix":
        return {"agent": AGENT_ID, "decision_id": decision_id,
                "error": "that range is protected; an approval cannot waive a deny"}

    executor = BlocklistExecutor(
        agent_id=AGENT_ID,
        ledger=DynamoLedger(table=LEDGER_TABLE, client=dynamodb),
        ipset_name=IPSET_NAME,
        ipset_id=IPSET_ID,
        ipset_v4_name=IPSET_V4_NAME,
        ipset_v4_id=IPSET_V4_ID,
        region=REGION,
        client=wafv2,
    )
    expires_at = datetime.now(UTC) + ENTRY_TTL
    executor.block(entry, expires_at=expires_at)

    out = {
        "agent": AGENT_ID,
        "decision_id": decision_id,
        "written": [entry],
        "expires_at": expires_at.isoformat(),
        "approved_by": row.get("decided_by", {}).get("S", ""),
        "note": "carried out an approval a human granted on the board",
    }
    print(json.dumps(out, default=str))
    return out


def _entries_written_recently(ledger_client) -> int:
    """How many entries this agent has written in the last hour.

    Feeds the rate budget. An agent that forgets what it has already done
    cannot be rate-limited.

    The window is the point, and it was missing: without it this counted every
    entry the agent had EVER written, so after twenty-five lifetime writes the
    budget was permanently exhausted. Observed live -- an agent with an empty
    block list and seventy pending requests, unable to act again ever.
    """
    since = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    try:
        result = ledger_client.query(
            TableName=LEDGER_TABLE,
            KeyConditionExpression="agent_id = :a",
            FilterExpression="#s = :executed AND #at > :since",
            ExpressionAttributeNames={"#s": "status", "#at": "at"},
            ExpressionAttributeValues={
                ":a": {"S": AGENT_ID},
                ":executed": {"S": "executed"},
                ":since": {"S": since},
            },
        )
        return len(result.get("Items", []))
    except Exception:
        # A ledger that cannot be read must not stop containment; the other
        # constraints still apply.
        return 0


def handler(event: dict[str, Any], _context: Any = None) -> dict[str, Any]:
    session = boto3.Session()
    logs = session.client("logs", region_name=REGION)
    wafv2 = session.client("wafv2", region_name=REGION)
    dynamodb = session.client("dynamodb", region_name=REGION)
    bedrock = session.client("bedrock-runtime", region_name=REGION)

    # A human answered a request this agent raised. That is not a new
    # investigation: the thinking was done when the request was made, and
    # re-running the model here would let it reach a different conclusion
    # from the one the human actually approved.
    if event and event.get("approved_decision"):
        return carry_out_approval(event, wafv2, dynamodb)

    # The subscription filter is a TRIGGER, not the data source.
    #
    # It delivers a handful of log lines per invocation -- often one -- and an
    # agent handed a single request cannot see a pattern. The first live run
    # showed exactly that: one observation per invocation, so the agent
    # blocked a lone /128 and never had the chance to consider whether
    # eighteen addresses were one actor.
    #
    # So: wake on delivery, then read the whole window. Prompt reaction,
    # reasoning over context.
    triggered_by = len(observations_from_subscription(event or {}))
    observations = [
        o for o in observations_from_logs(logs, LOG_GROUP, minutes=LOOKBACK_MINUTES)
        if o.get("path") != CANARY_PATH
    ]

    if not observations:
        return {"agent": AGENT_ID, "observations": 0, "note": "nothing to look at"}

    executor = BlocklistExecutor(
        agent_id=AGENT_ID,
        ledger=DynamoLedger(table=LEDGER_TABLE, client=dynamodb),
        ipset_name=IPSET_NAME,
        ipset_id=IPSET_ID,
        ipset_v4_name=IPSET_V4_NAME,
        ipset_v4_id=IPSET_V4_ID,
        region=REGION,
        client=wafv2,
    )

    agent = Warden(
        observations=observations,
        executor=executor,
        policy=_policy(),
        entries_last_hour=_entries_written_recently(dynamodb),
    )
    run = agent.investigate(bedrock, model_id=MODEL_ID)

    summary = {
        "agent": AGENT_ID,
        "profile": os.environ.get("WARDEN_POLICY_PROFILE", "enforcing"),
        "model": MODEL_ID,
        "observations": len(observations),
        "triggered_by": triggered_by,
        "tool_calls": [s.name for s in run.transcript.tool_calls] if run.transcript else [],
        "written": run.written,
        "escalated": [e["entry"] for e in run.escalated],
        "denied": [e["entry"] for e in run.denied],
        "said": run.transcript.final_text if run.transcript else "",
    }
    print(json.dumps(summary, default=str))
    return summary
