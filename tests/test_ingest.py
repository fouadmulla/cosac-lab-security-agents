"""Ingestion, against the shapes AWS actually delivers.

The fixtures here are trimmed from real records captured during the live run
on 2026-09-18, not invented. Ingestion is where the Trace pillar is enforced,
so what matters is that it keeps the attested half of a record apart from the
half a stranger wrote.
"""

from __future__ import annotations

import base64
import gzip
import json

from agents.common.ingest import (
    describe_instances,
    envelope_observations,
    finding_from_event,
    findings_from_detector,
    observations_from_logs,
    observations_from_subscription,
    parse_waf_record,
)
from agents.common.provenance.envelope import TrustTier

WAF_LINE = json.dumps({
    "timestamp": 1758226000000,
    "requestId": "abc123",
    "action": "ALLOW",
    "httpRequest": {
        "clientIp": "2600:1f18:3800:6510:78dd:a8a8:f337:5ec5",
        "country": "US",
        "uri": "/admin",
        "httpMethod": "GET",
        "headers": [
            {"name": "User-Agent", "value": "Mozilla/5.0 (compatible; scanner)"},
            {"name": "Host", "value": "cosac-a-a.example"},
        ],
    },
})


# -- WAF --------------------------------------------------------------------

def test_parses_a_real_waf_line():
    record = parse_waf_record(WAF_LINE)
    assert record["source"] == "2600:1f18:3800:6510:78dd:a8a8:f337:5ec5"
    assert record["path"] == "/admin"
    assert record["user_agent"] == "Mozilla/5.0 (compatible; scanner)"
    assert record["action"] == "ALLOW"


def test_malformed_lines_are_skipped_not_raised():
    # A malformed line is the attacker's prerogative; it must not stop the
    # agent from working on the rest.
    assert parse_waf_record("not json") is None
    assert parse_waf_record("{}") is None
    assert parse_waf_record(json.dumps({"httpRequest": {}})) is None


def test_source_is_attested_and_client_strings_are_not():
    """The distinction the whole Trace pillar rests on."""
    envelopes = envelope_observations([parse_waf_record(WAF_LINE)], "arn:aws:logs:::x")
    attested = [e for e in envelopes if e.trust_tier is TrustTier.AWS_ATTESTED]
    untrusted = [e for e in envelopes if e.trust_tier is TrustTier.UNTRUSTED_REMOTE]

    assert attested[0].payload == {"source": "2600:1f18:3800:6510:78dd:a8a8:f337:5ec5"}
    assert "user_agent" in untrusted[0].payload
    assert attested[0].is_actionable_identity
    assert not untrusted[0].is_actionable_identity


def test_subscription_payload_is_unwrapped():
    payload = {"logEvents": [{"message": WAF_LINE}, {"message": "junk"}]}
    blob = base64.b64encode(gzip.compress(json.dumps(payload).encode())).decode()
    got = observations_from_subscription({"awslogs": {"data": blob}})
    assert len(got) == 1
    assert got[0]["source"].startswith("2600:")


def test_subscription_payload_absent_is_not_an_error():
    assert observations_from_subscription({}) == []


class FakeLogs:
    def __init__(self, pages):
        self.pages = list(pages)
        self.calls = []

    def filter_log_events(self, **kwargs):
        self.calls.append(kwargs)
        return self.pages.pop(0)


def test_polling_follows_pagination():
    logs = FakeLogs([
        {"events": [{"message": WAF_LINE}], "nextToken": "t"},
        {"events": [{"message": WAF_LINE}]},
    ])
    got = observations_from_logs(logs, "aws-waf-logs-x", minutes=15)
    assert len(got) == 2
    assert logs.calls[1]["nextToken"] == "t"


def test_polling_uses_a_time_window():
    logs = FakeLogs([{"events": []}])
    observations_from_logs(logs, "aws-waf-logs-x", minutes=5)
    assert logs.calls[0]["startTime"] > 0
    assert logs.calls[0]["logGroupName"] == "aws-waf-logs-x"


# -- GuardDuty --------------------------------------------------------------

FINDING_EVENT = {
    "detail-type": "GuardDuty Finding",
    "detail": {
        "id": "b4d05b402d5ef4cfa2fd00d7b53b9bf5",
        "type": "Backdoor:EC2/C&CActivity.B!DNS",
        "severity": 8,
        "description": "queried a domain associated with command and control",
        "resource": {"instanceDetails": {"instanceId": "i-0deb3fa9effcb8c41"}},
    },
}


def test_parses_a_real_guardduty_event():
    finding = finding_from_event(FINDING_EVENT)
    assert finding["type"] == "Backdoor:EC2/C&CActivity.B!DNS"
    assert finding["severity"] == 8.0
    assert finding["instance_id"] == "i-0deb3fa9effcb8c41"


def test_a_non_finding_event_yields_nothing():
    assert finding_from_event({"detail": {}}) is None
    assert finding_from_event({}) is None


class FakeEC2:
    def describe_instances(self, InstanceIds):  # noqa: N803 - boto3 casing
        return {"Reservations": [{"Instances": [{
            "InstanceId": InstanceIds[0],
            "InstanceType": "t3.micro",
            "State": {"Name": "running"},
            "Tags": [
                {"Key": "environment", "Value": "lab"},
                {"Key": "criticality", "Value": "low"},
                {"Key": "Twin", "Value": "custodian-b"},
            ],
            "SecurityGroups": [{"GroupName": "cosac-b-normal", "GroupId": "sg-1"}],
        }]}]}


def test_instance_state_carries_what_the_policy_needs():
    """Type, environment, criticality and prior groups all gate the decision."""
    got = describe_instances(FakeEC2(), ["i-0deb3fa9effcb8c41"])
    inst = got["i-0deb3fa9effcb8c41"]
    assert inst["instance_type"] == "t3.micro"
    assert inst["environment"] == "lab"
    assert inst["criticality"] == "low"
    assert inst["twin"] == "custodian-b"
    # Without this the action is not reversible, and so not permitted.
    assert inst["security_groups"] == ["cosac-b-normal"]


def test_state_is_carried_so_a_dead_instance_is_recognisable():
    """A terminated instance answers DescribeInstances with no groups at all."""
    class Terminated:
        def describe_instances(self, InstanceIds):  # noqa: N803
            return {"Reservations": [{"Instances": [{
                "InstanceId": InstanceIds[0],
                "InstanceType": "t3.micro",
                "State": {"Name": "terminated"},
                "SecurityGroups": [],
            }]}]}

    got = describe_instances(Terminated(), ["i-089eaa0cb0ce3cb9b"])
    assert got["i-089eaa0cb0ce3cb9b"]["state"] == "terminated"


def test_no_instances_means_no_api_call():
    class Explodes:
        def describe_instances(self, **_):
            raise AssertionError("should not be called")

    assert describe_instances(Explodes(), []) == {}


def test_the_detector_poll_skips_findings_already_dealt_with():
    """Archived findings are returned unless excluded, which nobody expects.

    Without the filter a reset archives every finding, the count does not
    move, and the agent re-investigates an intrusion that ended days ago --
    on stage, against a machine that may no longer exist.
    """
    class Recorder:
        def __init__(self):
            self.criteria = None

        def list_findings(self, **kwargs):
            self.criteria = kwargs["FindingCriteria"]["Criterion"]
            return {"FindingIds": []}

    gd = Recorder()
    findings_from_detector(gd, "det-1")
    assert gd.criteria["service.archived"] == {"Eq": ["false"]}
