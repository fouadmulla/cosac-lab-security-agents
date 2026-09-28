"""Scenario B: the divergence between Custodian-A and Custodian-B.

The pillar clause under test is "without delaying permitted containment".
The tests that matter are the ones asserting that an escalated target does
not suppress containment of a permitted one.
"""

from __future__ import annotations

import pytest

from agents.common.policy.escalate import (
    MAX_UNILATERAL_CONTAINMENTS,
    ApprovalGatedEscalation,
    NonBlockingEscalation,
    QuarantineTarget,
)


def target(
    instance_id: str = "i-lab001",
    instance_type: str = "t3.micro",
    criticality: str = "low",
    environment: str = "lab",
    severity: float = 8.0,
    original_sgs: tuple[str, ...] = ("sg-original",),
) -> QuarantineTarget:
    return QuarantineTarget(
        instance_id=instance_id,
        instance_type=instance_type,
        criticality=criticality,
        environment=environment,
        finding_severity=severity,
        original_security_groups=original_sgs,
    )


LAB_MICRO = target()
PROD_INSTANCE = target("i-prod001", criticality="high", environment="production")
LARGE_INSTANCE = target("i-lab002", instance_type="m5.4xlarge")
UNRECORDED = target("i-lab003", original_sgs=())


@pytest.fixture
def non_blocking() -> NonBlockingEscalation:
    return NonBlockingEscalation()


@pytest.fixture
def approval_gated() -> ApprovalGatedEscalation:
    return ApprovalGatedEscalation()


# -- target classification -------------------------------------------------

def test_lab_micro_is_within_unilateral_authority():
    assert LAB_MICRO.within_unilateral_authority


@pytest.mark.parametrize("t", [PROD_INSTANCE, LARGE_INSTANCE, UNRECORDED])
def test_targets_outside_authority(t):
    assert not t.within_unilateral_authority


def test_containment_requires_recorded_prior_state():
    # Reversibility is a precondition, not an afterthought: you may not
    # quarantine an instance you cannot un-quarantine.
    assert not UNRECORDED.reversible
    assert not UNRECORDED.within_unilateral_authority


# -- Custodian-A -----------------------------------------------------------

def test_permitted_target_contained_immediately(non_blocking):
    d = non_blocking.route((LAB_MICRO,))
    assert d.contain_now == ("i-lab001",)
    assert d.escalate == ()


def test_beyond_limit_target_is_escalated_not_contained(non_blocking):
    d = non_blocking.route((PROD_INSTANCE,))
    assert d.contain_now == ()
    assert d.escalate == ("i-prod001",)


def test_escalation_does_not_delay_permitted_containment(non_blocking):
    """The clause. The whole pillar is this assertion."""
    d = non_blocking.route((LAB_MICRO, PROD_INSTANCE))
    assert "i-lab001" in d.contain_now, "permitted containment must not wait"
    assert "i-prod001" in d.escalate, "beyond-limit target must still be routed"


def test_rate_overflow_escalates_without_dropping_or_blocking(non_blocking):
    targets = tuple(
        target(f"i-lab{n:03d}") for n in range(MAX_UNILATERAL_CONTAINMENTS + 2)
    )
    d = non_blocking.route(targets)

    assert len(d.contain_now) == MAX_UNILATERAL_CONTAINMENTS
    assert len(d.escalate) == 2
    assert d.rule_hit == "max_unilateral_containments"
    # Nothing silently vanishes.
    assert set(d.contain_now) | set(d.escalate) == {t.instance_id for t in targets}


# -- Custodian-B -----------------------------------------------------------

@pytest.mark.parametrize(
    "targets",
    [(LAB_MICRO,), (PROD_INSTANCE,), (LAB_MICRO, PROD_INSTANCE)],
)
def test_approval_gated_never_contains_anything(approval_gated, targets):
    d = approval_gated.route(targets)
    assert d.contain_now == ()
    assert not d.contains_anything


def test_approval_gated_routes_everything(approval_gated):
    d = approval_gated.route((LAB_MICRO, PROD_INSTANCE))
    assert set(d.escalate) == {"i-lab001", "i-prod001"}


# -- the headline ----------------------------------------------------------

def test_the_demo_actually_diverges(non_blocking, approval_gated):
    """Identical finding, identical target, opposite outcome."""
    a = non_blocking.route((LAB_MICRO,))
    b = approval_gated.route((LAB_MICRO,))

    assert a.contains_anything, "Custodian-A must contain the foothold"
    assert not b.contains_anything, "Custodian-B must not, or there is no demo"
    assert set(a.contain_now) | set(a.escalate) == set(b.escalate), (
        "both twins must consider exactly the same target set"
    )
