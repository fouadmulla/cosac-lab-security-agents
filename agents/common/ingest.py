"""Ingestion — real AWS input, wrapped and trust-tiered before the model sees it.

This is where the Trace pillar is actually enforced. Every record that reaches
an agent has been through here, and here is where it is decided which parts of
it AWS vouched for and which parts a stranger chose.

The distinction is not cosmetic. In a WAF log line, `clientIp` is the address
AWS observed the connection arrive from; `User-Agent`, the URI and every
header are strings the client wrote. An agent that treats the second kind as
identity can be told who it is talking to by the person it is investigating.
"""

from __future__ import annotations

import base64
import gzip
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from agents.common.provenance.envelope import TrustTier, wrap

# ---------------------------------------------------------------------------
# Scenario A: WAF logs
# ---------------------------------------------------------------------------

def parse_waf_record(raw: str) -> dict[str, Any] | None:
    """One WAF log line into an observation.

    Returns None for anything unparseable rather than raising: a malformed
    line is the attacker's prerogative and must not stop the agent working.
    """
    try:
        event = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None

    request = event.get("httpRequest") or {}
    source = request.get("clientIp")
    if not source:
        return None

    headers = {
        h.get("name", "").lower(): h.get("value", "")
        for h in request.get("headers", [])
    }

    return {
        # AWS observed this. It is the only field safe to act on.
        "source": source,
        "request_id": event.get("requestId", ""),
        "timestamp": event.get("timestamp"),
        "action": event.get("action", ""),
        # Everything below was chosen by whoever sent the request.
        "path": request.get("uri", ""),
        "method": request.get("httpMethod", ""),
        "user_agent": headers.get("user-agent", ""),
        "country": request.get("country", ""),
    }


def observations_from_logs(
    logs_client: Any,
    log_group: str,
    minutes: int = 15,
    limit: int = 1000,
) -> list[dict[str, Any]]:
    """Pull recent WAF records out of CloudWatch Logs.

    CloudWatch rather than Firehose-to-S3 because Firehose buffers for a minute
    or more, and an agent that reacts a minute late is not reacting.
    """
    start = int((datetime.now(UTC) - timedelta(minutes=minutes)).timestamp() * 1000)
    observations: list[dict[str, Any]] = []
    kwargs: dict[str, Any] = {
        "logGroupName": log_group,
        "startTime": start,
        "limit": min(limit, 10_000),
    }

    while True:
        page = logs_client.filter_log_events(**kwargs)
        for event in page.get("events", []):
            record = parse_waf_record(event.get("message", ""))
            if record:
                observations.append(record)
        token = page.get("nextToken")
        if not token or len(observations) >= limit:
            break
        kwargs["nextToken"] = token

    return observations[:limit]


def observations_from_subscription(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Records delivered by a CloudWatch Logs subscription filter.

    The payload is gzipped and base64-encoded in `awslogs.data`. This is the
    fast path: the agent is invoked as the lines arrive rather than polling.
    """
    blob = (event.get("awslogs") or {}).get("data")
    if not blob:
        return []
    payload = json.loads(gzip.decompress(base64.b64decode(blob)))
    out = []
    for entry in payload.get("logEvents", []):
        record = parse_waf_record(entry.get("message", ""))
        if record:
            out.append(record)
    return out


def envelope_observations(
    observations: list[dict[str, Any]], source_arn: str
) -> list[Any]:
    """Wrap each record so its provenance travels with it.

    The source address is tiered AWS_ATTESTED; everything the client chose is
    UNTRUSTED_REMOTE. Only the attested half is ever allowed to decide who an
    action targets.
    """
    wrapped = []
    for index, record in enumerate(observations):
        wrapped.append(wrap(
            source_arn=source_arn,
            trust_tier=TrustTier.AWS_ATTESTED,
            ingest_id=record.get("request_id") or f"waf-{index}",
            payload={"source": record["source"]},
        ))
        wrapped.append(wrap(
            source_arn=source_arn,
            trust_tier=TrustTier.UNTRUSTED_REMOTE,
            ingest_id=record.get("request_id") or f"waf-{index}",
            payload={
                "path": record.get("path", ""),
                "user_agent": record.get("user_agent", ""),
                "method": record.get("method", ""),
            },
        ))
    return wrapped


# ---------------------------------------------------------------------------
# Scenario B: GuardDuty
# ---------------------------------------------------------------------------

def finding_from_event(event: dict[str, Any]) -> dict[str, Any] | None:
    """A GuardDuty finding delivered by EventBridge."""
    detail = event.get("detail") or {}
    if not detail.get("type"):
        return None
    instance = ((detail.get("resource") or {}).get("instanceDetails") or {})
    return {
        "id": detail.get("id", ""),
        "type": detail.get("type", ""),
        "severity": float(detail.get("severity", 0) or 0),
        "instance_id": instance.get("instanceId", ""),
        "description": detail.get("description", ""),
        "region": detail.get("region", ""),
    }


def findings_from_detector(
    guardduty_client: Any, detector_id: str, limit: int = 20
) -> list[dict[str, Any]]:
    """Poll the detector, for a run that was not triggered by an event."""
    # `list_findings` returns ARCHIVED findings as well unless told otherwise,
    # which is the opposite of what anyone assumes. Archiving is how GuardDuty
    # is told an incident is dealt with, so without this filter a reset can
    # archive every finding and the count does not move -- and the agent
    # re-investigates intrusions that were over days ago.
    listed = guardduty_client.list_findings(
        DetectorId=detector_id,
        FindingCriteria={"Criterion": {
            "type": {"Eq": ["Backdoor:EC2/C&CActivity.B!DNS"]},
            "service.archived": {"Eq": ["false"]},
        }},
        MaxResults=limit,
    )
    ids = listed.get("FindingIds", [])
    if not ids:
        return []

    got = guardduty_client.get_findings(DetectorId=detector_id, FindingIds=ids)
    out = []
    for finding in got.get("Findings", []):
        instance = ((finding.get("Resource") or {}).get("InstanceDetails") or {})
        out.append({
            "id": finding.get("Id", ""),
            "type": finding.get("Type", ""),
            "severity": float(finding.get("Severity", 0) or 0),
            "instance_id": instance.get("InstanceId", ""),
            "description": finding.get("Description", ""),
        })
    return out


def describe_instances(ec2_client: Any, instance_ids: list[str]) -> dict[str, dict[str, Any]]:
    """Current state of the instances a finding implicates.

    The security groups read here become `original_security_groups` on the
    quarantine target, which is what makes the action reversible -- and
    reversibility is a precondition of being allowed to act at all.
    """
    if not instance_ids:
        return {}

    described = ec2_client.describe_instances(InstanceIds=instance_ids)
    out: dict[str, dict[str, Any]] = {}
    for reservation in described.get("Reservations", []):
        for instance in reservation.get("Instances", []):
            tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
            out[instance["InstanceId"]] = {
                "instance_type": instance.get("InstanceType", ""),
                "environment": tags.get("environment", ""),
                "criticality": tags.get("criticality", ""),
                "twin": tags.get("Twin", ""),
                # A terminated instance still appears here for a while, with
                # no security groups at all. Without the state that is
                # indistinguishable from "prior groups were never recorded",
                # which is a very different thing.
                "state": (instance.get("State") or {}).get("Name", ""),
                "security_groups": [g["GroupName"] for g in instance.get("SecurityGroups", [])],
                "security_group_ids": [g["GroupId"] for g in instance.get("SecurityGroups", [])],
            }
    return out
