"""Scenario A: the divergence between Warden-A and Warden-B, proven in CI.

If these tests pass, the demo's central claim is true before anyone walks on
stage: the same proposal produces containment on one side and a defence-
disabling block on the other, and the only difference is a config value.
"""

from __future__ import annotations

import pytest

from agents.common.policy.constrain import (
    MAX_BLAST_RADIUS,
    EnforcingPolicy,
    LegacyPolicy,
    Verdict,
    blast_radius,
    intersects_protected,
)

# The lab topology from docs/SCENARIO-A-WARDEN.md.
ATTACKER_HOST = "2600:1f18:aaaa:1::a/128"
ATTACKER_SUBNET = "2600:1f18:aaaa:1::/64"
RESPONDER_PREFIX = "2600:1f18:aaaa:2::/64"
SHARED_48 = "2600:1f18:aaaa::/48"

PROTECTED = [RESPONDER_PREFIX, "10.0.0.0/8"]


@pytest.fixture
def enforcing() -> EnforcingPolicy:
    return EnforcingPolicy(PROTECTED)


@pytest.fixture
def legacy() -> LegacyPolicy:
    return LegacyPolicy()


# -- pure functions --------------------------------------------------------

def test_blast_radius_counts_addresses():
    assert blast_radius(ATTACKER_HOST) == 1
    assert blast_radius(ATTACKER_SUBNET) == 2**64
    assert blast_radius(SHARED_48) == 2**80


def test_protected_overlap_is_detected_in_both_directions():
    # The /48 does not equal the responder /64; it contains it. Containment
    # must count, or Warden-B's exact failure slips through.
    assert intersects_protected(SHARED_48, PROTECTED) == RESPONDER_PREFIX
    assert intersects_protected(RESPONDER_PREFIX, [SHARED_48]) == SHARED_48


def test_protected_overlap_ignores_mismatched_address_family():
    assert intersects_protected(ATTACKER_HOST, ["10.0.0.0/8"]) is None


# -- Warden-A --------------------------------------------------------------

def test_single_host_is_contained_immediately(enforcing):
    d = enforcing.evaluate(ATTACKER_HOST, entries_last_hour=0)
    assert d.verdict is Verdict.ALLOW
    assert d.executable


def test_allowed_entries_always_carry_a_ttl(enforcing):
    # Duration is a required leg of Constrain: the default outcome of any
    # mistake must be that it heals itself.
    d = enforcing.evaluate(ATTACKER_HOST, entries_last_hour=0)
    assert d.ttl_expires_at is not None


def test_wide_but_permissible_range_escalates_rather_than_denying(enforcing):
    d = enforcing.evaluate(ATTACKER_SUBNET, entries_last_hour=0)
    assert d.verdict is Verdict.ESCALATE
    assert d.rule_hit == "max_blast_radius"
    assert not d.executable


def test_range_containing_responders_is_denied_not_escalated(enforcing):
    # No human approval makes blocking your own incident responders correct,
    # so this must never reach an approval queue.
    d = enforcing.evaluate(SHARED_48, entries_last_hour=0)
    assert d.verdict is Verdict.DENY
    assert d.rule_hit == "protected_prefix"


def test_protected_check_precedes_blast_radius_check(enforcing):
    # Both rules match the /48. Ordering decides whether it is deniable or
    # merely approvable, so pin it.
    d = enforcing.evaluate(SHARED_48, entries_last_hour=0)
    assert d.rule_hit == "protected_prefix"


def test_rate_budget_escalates_once_exhausted(enforcing):
    d = enforcing.evaluate(ATTACKER_HOST, entries_last_hour=999)
    assert d.verdict is Verdict.ESCALATE
    assert d.rule_hit == "rate_budget"


@pytest.mark.parametrize("prefix", [128, 127, 124])
def test_narrow_v6_entries_are_within_authority(enforcing, prefix):
    d = enforcing.evaluate(f"2600:1f18:aaaa:1::/{prefix}", entries_last_hour=0)
    assert d.blast_radius <= MAX_BLAST_RADIUS
    assert d.verdict is Verdict.ALLOW


# -- Warden-B --------------------------------------------------------------

@pytest.mark.parametrize("entry", [ATTACKER_HOST, ATTACKER_SUBNET, SHARED_48])
def test_legacy_allows_everything(legacy, entry):
    assert legacy.evaluate(entry, entries_last_hour=10**6).verdict is Verdict.ALLOW


def test_legacy_entries_never_expire(legacy):
    # The single null that turns a transient mistake into a standing outage.
    assert legacy.evaluate(SHARED_48, entries_last_hour=0).ttl_expires_at is None


# -- the headline ----------------------------------------------------------

def test_the_demo_actually_diverges(enforcing, legacy):
    """The claim the whole talk rests on."""
    a = enforcing.evaluate(SHARED_48, entries_last_hour=0)
    b = legacy.evaluate(SHARED_48, entries_last_hour=0)

    assert not a.executable, "Warden-A must refuse to blind its own SOC"
    assert b.executable, "Warden-B must proceed, or there is no demo"
    assert a.blast_radius == b.blast_radius, "same proposal, same radius"
