"""Carrying out an approval a human granted on the board.

Observed live on 2026-09-20: the strip said "fmulla approved custodian-a's
request. It may now act", the ledger row went to `approved` -- and the machine
stayed on the network, still leaking. Nothing executed it. `decide()` released
a Step Functions token if one existed, and none ever does, because these
agents are not a state machine.

The tests below are mostly about what the agent REFUSES, because the payload
that triggers this arrives from outside and names a decision. Acting on the
payload's word would mean anything that can reach the agent can quarantine a
machine by asserting an approval that never happened.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("ISOLATION_SG_ID", "sg-isolation")
os.environ.setdefault("AGENT_ID", "custodian-a")
os.environ.setdefault("TWIN", "custodian-a")

from agents.custodian import handler as H  # noqa: E402

APPROVED = {
    "agent_id": {"S": "custodian-a"},
    "decision_id": {"S": "approval#1"},
    "status": {"S": "approved"},
    "target": {"S": "i-lab001"},
    "decided_by": {"S": "fmulla"},
}


class FakeDDB:
    def __init__(self, items):
        self.items = items
        self.put: list[dict] = []

    def query(self, **kwargs):
        return {"Items": self.items}

    def put_item(self, **kwargs):
        self.put.append(kwargs)
        return {}


class FakeEC2:
    def __init__(self, groups=("cosac-b-normal",), twin="custodian-a"):
        self.groups, self.twin = groups, twin
        self.modified: list[tuple] = []

    def describe_instances(self, InstanceIds):  # noqa: N803 - boto3 casing
        return {"Reservations": [{"Instances": [{
            "InstanceId": InstanceIds[0],
            "InstanceType": "t3.micro",
            "State": {"Name": "running"},
            "Tags": [{"Key": "Twin", "Value": self.twin},
                     {"Key": "environment", "Value": "lab"},
                     {"Key": "criticality", "Value": "low"}],
            "SecurityGroups": [{"GroupName": g, "GroupId": "sg-1"} for g in self.groups],
        }]}]}

    def modify_instance_attribute(self, **kwargs):
        self.modified.append((kwargs.get("InstanceId"), tuple(kwargs.get("Groups", []))))
        return {}


def call(ec2, ddb, decision_id="approval#1"):
    event = {"approved_decision": {"agent_id": "custodian-a", "decision_id": decision_id}}
    return H.carry_out_approval(event, ec2, ddb)


def test_an_approved_decision_is_actually_carried_out():
    ec2, ddb = FakeEC2(), FakeDDB([APPROVED])
    out = call(ec2, ddb)

    assert out["contained"] == ["i-lab001"]
    assert out["approved_by"] == "fmulla"
    # The machine really came off the network.
    assert ec2.modified == [("i-lab001", ("sg-isolation",))]


def test_the_prior_groups_are_recorded_so_it_can_be_undone():
    ec2, ddb = FakeEC2(), FakeDDB([APPROVED])
    call(ec2, ddb)
    assert ddb.put, "the act must reach the ledger"


@pytest.mark.parametrize("status", ["pending", "denied", "withdrawn", ""])
def test_only_an_approved_row_is_acted_on(status):
    """The payload says approved. The ledger is what decides."""
    row = dict(APPROVED, status={"S": status})
    ec2, ddb = FakeEC2(), FakeDDB([row])

    out = call(ec2, ddb)
    assert "error" in out
    assert ec2.modified == []


def test_a_decision_that_does_not_exist_is_refused():
    ec2, ddb = FakeEC2(), FakeDDB([])
    assert call(ec2, ddb)["error"] == "not mine"
    assert ec2.modified == []


def test_a_missing_decision_id_is_refused():
    ec2, ddb = FakeEC2(), FakeDDB([APPROVED])
    assert "error" in H.carry_out_approval({"approved_decision": {}}, ec2, ddb)
    assert ec2.modified == []


def test_one_twin_may_not_act_on_the_others_machine():
    """Otherwise an approval on one side of the board moves the other side."""
    ec2, ddb = FakeEC2(twin="custodian-b"), FakeDDB([APPROVED])
    assert "not this twin" in call(ec2, ddb)["error"]
    assert ec2.modified == []


def test_an_irreversible_swap_is_refused_even_when_approved():
    """Reversibility is a precondition, not something sign-off can waive."""
    ec2, ddb = FakeEC2(groups=()), FakeDDB([APPROVED])
    assert "irreversible" in call(ec2, ddb)["error"]
    assert ec2.modified == []


# -- the warden side of the same mechanism -----------------------------------

os.environ.setdefault("IPSET_NAME", "cosac-a-b-block")
os.environ.setdefault("IPSET_ID", "ipset-1")
os.environ.setdefault("WAF_LOG_GROUP", "aws-waf-logs-x")

from agents.warden import handler as W  # noqa: E402

RANGE_APPROVED = {
    "agent_id": {"S": "warden-a"},
    "decision_id": {"S": "approval#45.43.64.0/24"},
    "status": {"S": "approved"},
    "target": {"S": "45.43.64.0/24"},
    "decided_by": {"S": "fmulla"},
}


class FakeWAF:
    def __init__(self):
        self.written = None

    def get_ip_set(self, **kwargs):
        return {"IPSet": {"Addresses": []}, "LockToken": "tok"}

    def update_ip_set(self, **kwargs):
        self.written = list(kwargs["Addresses"])
        return {}


def warden_call(waf, ddb, decision_id="approval#45.43.64.0/24"):
    event = {"approved_decision": {"agent_id": "warden-a", "decision_id": decision_id}}
    return W.carry_out_approval(event, waf, ddb)


def test_an_approved_range_is_actually_written(monkeypatch):
    monkeypatch.setattr(W, "AGENT_ID", "warden-a")
    waf, ddb = FakeWAF(), FakeDDB([RANGE_APPROVED])

    out = warden_call(waf, ddb)
    assert out["written"] == ["45.43.64.0/24"]
    assert waf.written == ["45.43.64.0/24"]
    # Duration is a constraint, not a courtesy: the entry expires by itself.
    assert out["expires_at"]


def test_an_approval_cannot_waive_a_deny(monkeypatch):
    """Sign-off releases what was escalated. It never releases what was denied."""
    monkeypatch.setattr(W, "AGENT_ID", "warden-a")
    monkeypatch.setenv("WARDEN_POLICY_PROFILE", "enforcing")
    monkeypatch.setenv("WARDEN_PROTECTED_PREFIXES", "2600:1f18:3800:6512::/64")

    row = dict(RANGE_APPROVED, target={"S": "2600:1f18:3800:6512::/64"})
    waf, ddb = FakeWAF(), FakeDDB([row])

    assert "cannot waive a deny" in warden_call(waf, ddb)["error"]
    assert waf.written is None


def test_a_warden_may_not_act_on_a_decision_that_is_not_its_own(monkeypatch):
    monkeypatch.setattr(W, "AGENT_ID", "warden-b")
    waf, ddb = FakeWAF(), FakeDDB([])
    assert warden_call(waf, ddb)["error"] == "not mine"
    assert waf.written is None
