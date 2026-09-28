"""Constraint enforcement for the Warden WAF-blocker agent.

This module is the entire difference between Warden-A and Warden-B.

It runs *after* the model proposes an action and *before* the action reaches
the AgentCore Gateway target. The model cannot see it, reason about it, or
talk its way past it. That is the point: constraint is not a prompt, it is a
gate the action has to fit through.

Selected by WARDEN_POLICY_PROFILE:
    enforcing  -> EnforcingPolicy   (Warden-A)
    legacy     -> LegacyPolicy      (Warden-B, the flawed twin)
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol

# Maximum addresses a single entry may cover. /128 (v6) and /32 (v4) are 1.
# Anything wider than a v4 /28 or a v6 /124 is a generalisation the agent is
# not permitted to make on its own authority.
MAX_BLAST_RADIUS = 16

# Entries expire and are reclaimed by the sweeper. An agent that can block
# indefinitely is an agent that can cause permanent damage.
ENTRY_TTL = timedelta(minutes=60)

# Prefixes the agent may never write, whatever it concludes. Populated from
# config at deploy time: corporate egress, CloudFront ranges, health checkers,
# RFC1918, the VPC's own prefixes, and the agent's own control path.
PROTECTED_PREFIXES_ENV = "WARDEN_PROTECTED_PREFIXES"

# Rate budget. Bounds the damage of a correct-looking decision made at scale.
MAX_ENTRIES_PER_HOUR = 25


class Verdict(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"


@dataclass(frozen=True)
class PolicyDecision:
    verdict: Verdict
    rule_hit: str | None
    blast_radius: int
    ttl_expires_at: datetime | None
    reason: str

    @property
    def executable(self) -> bool:
        return self.verdict is Verdict.ALLOW


# --------------------------------------------------------------------------
# Pure functions. No model, no network, no AWS. Unit-testable, and small
# enough to put on a slide.
# --------------------------------------------------------------------------

def blast_radius(entry: str) -> int:
    """Number of addresses a proposed block entry would cover."""
    return ipaddress.ip_network(entry, strict=False).num_addresses


def intersects_protected(entry: str, protected: Iterable[str]) -> str | None:
    """Return the first protected prefix this entry would touch, if any.

    Overlap in *either* direction counts. Blocking a /48 that contains a
    protected /64 is just as fatal as blocking the /64 directly -- which is
    precisely the failure Warden-B demonstrates.
    """
    net = ipaddress.ip_network(entry, strict=False)
    for prefix in protected:
        other = ipaddress.ip_network(prefix, strict=False)
        if net.version != other.version:
            continue
        if net.overlaps(other):
            return prefix
    return None


def load_protected_prefixes() -> list[str]:
    raw = os.environ.get(PROTECTED_PREFIXES_ENV, "")
    return [p.strip() for p in raw.split(",") if p.strip()]


# --------------------------------------------------------------------------
# Profiles
# --------------------------------------------------------------------------

class ConstraintPolicy(Protocol):
    def evaluate(self, entry: str, entries_last_hour: int) -> PolicyDecision: ...


class EnforcingPolicy:
    """Warden-A. Constraint is enforced on identity, scope, duration and
    reversibility before the action is allowed to exist."""

    def __init__(self, protected: list[str] | None = None) -> None:
        self._protected = protected if protected is not None else load_protected_prefixes()

    def evaluate(self, entry: str, entries_last_hour: int) -> PolicyDecision:
        radius = blast_radius(entry)
        now = datetime.now(UTC)

        # Scope: never write an entry overlapping something we must not break.
        # Checked first -- a protected overlap is a hard deny, not an escalation,
        # because no human approval makes blocking your own control path correct.
        hit = intersects_protected(entry, self._protected)
        if hit is not None:
            return PolicyDecision(
                verdict=Verdict.DENY,
                rule_hit="protected_prefix",
                blast_radius=radius,
                ttl_expires_at=None,
                reason=f"{entry} overlaps protected prefix {hit}",
            )

        # Scope: generalisation beyond a single host is a human's call.
        # Escalate -- do NOT deny outright, and critically do not hold up the
        # narrower containment that is already permitted. The caller executes
        # allowed /128s immediately and routes this in parallel.
        if radius > MAX_BLAST_RADIUS:
            return PolicyDecision(
                verdict=Verdict.ESCALATE,
                rule_hit="max_blast_radius",
                blast_radius=radius,
                ttl_expires_at=None,
                reason=(
                    f"{entry} covers {radius} addresses, above the "
                    f"unilateral limit of {MAX_BLAST_RADIUS}"
                ),
            )

        # Rate: bound the damage of a correct-looking decision made at scale.
        if entries_last_hour >= MAX_ENTRIES_PER_HOUR:
            return PolicyDecision(
                verdict=Verdict.ESCALATE,
                rule_hit="rate_budget",
                blast_radius=radius,
                ttl_expires_at=None,
                reason=f"hourly budget of {MAX_ENTRIES_PER_HOUR} entries exhausted",
            )

        # Duration and reversibility: every entry carries an expiry, so the
        # default outcome of any mistake is that it heals itself.
        return PolicyDecision(
            verdict=Verdict.ALLOW,
            rule_hit=None,
            blast_radius=radius,
            ttl_expires_at=now + ENTRY_TTL,
            reason="within unilateral authority",
        )


class LegacyPolicy:
    """Warden-B. The flawed twin.

    Trace, Record, Authorize and Escalate are all intact and working. This
    agent is fully observed, fully authenticated and fully audited. It simply
    has nothing bounding the scope or duration of what it decides to do.

    Note what is absent, because the absences are the lesson:
      - no blast radius cap      -> a /48 is as writable as a /128
      - no protected prefix set  -> it may block its own control path
      - no rate budget           -> scale multiplies a single bad inference
      - no TTL                   -> nothing reclaims the entry, ever

    Its ledger entries are complete and correct. They will document, in
    writing, exactly how it took the protected service down.
    """

    def evaluate(self, entry: str, entries_last_hour: int) -> PolicyDecision:
        return PolicyDecision(
            verdict=Verdict.ALLOW,
            rule_hit=None,
            blast_radius=blast_radius(entry),
            ttl_expires_at=None,
            reason="legacy profile: no constraint evaluation",
        )


def load_policy() -> ConstraintPolicy:
    profile = os.environ.get("WARDEN_POLICY_PROFILE", "enforcing").lower()
    if profile == "legacy":
        return LegacyPolicy()
    if profile == "enforcing":
        return EnforcingPolicy()
    raise ValueError(f"unknown WARDEN_POLICY_PROFILE: {profile!r}")
