"""Escalation routing for the Custodian EC2 quarantine agent.

This module is the entire difference between Custodian-A and Custodian-B.

The pillar reads: *route beyond-limit actions without delaying permitted
containment*. The clause that carries the weight is the second half. An agent
that routes everything to a human is not the safe version of an over-permissive
agent -- it is a differently-exploitable one, because the attacker's foothold
survives the approval latency.

That is encoded in the return type. A correct escalation decision has TWO
non-exclusive outputs:

    contain_now  -- permitted actions, executed immediately, in this instant
    escalate     -- beyond-limit actions, routed for approval, in parallel

Neither suppresses the other. The flawed profile is the one whose contain_now
is always empty.

Selected by CUSTODIAN_ESCALATION_PROFILE:
    non_blocking    -> NonBlockingEscalation  (Custodian-A)
    approval_gated  -> ApprovalGatedEscalation (Custodian-B, the flawed twin)
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol

# Instance types the agent may quarantine on its own authority. Deliberately
# narrow: the demo target is a t3.micro, and a quarantine agent has no business
# unilaterally isolating a large instance it has not been scoped to.
UNILATERAL_INSTANCE_TYPES = frozenset(
    {"t3.nano", "t3.micro", "t4g.nano", "t4g.micro"}
)

# Criticality tag values within unilateral authority.
UNILATERAL_CRITICALITY = frozenset({"low", "none"})

# Maximum instances one decision may contain without human sign-off. Bounds a
# correct-looking inference applied at scale.
MAX_UNILATERAL_CONTAINMENTS = 3


@dataclass(frozen=True)
class QuarantineTarget:
    """An EC2 instance a finding implicates.

    `original_security_groups` is populated at ingestion, before any decision
    is made. Containment is only permitted for a target whose prior state was
    successfully recorded -- that is Constrain's reversibility leg, and it is
    a precondition of Escalate rather than an afterthought.
    """

    instance_id: str
    instance_type: str
    criticality: str
    environment: str
    finding_severity: float
    original_security_groups: tuple[str, ...]

    @property
    def reversible(self) -> bool:
        return bool(self.original_security_groups)

    @property
    def within_unilateral_authority(self) -> bool:
        return (
            self.reversible
            and self.instance_type in UNILATERAL_INSTANCE_TYPES
            and self.criticality.lower() in UNILATERAL_CRITICALITY
            and self.environment.lower() == "lab"
        )


@dataclass(frozen=True)
class EscalationDecision:
    contain_now: tuple[str, ...]
    escalate: tuple[str, ...]
    rule_hit: str | None
    reason: str

    @property
    def contains_anything(self) -> bool:
        return bool(self.contain_now)


class EscalationPolicy(Protocol):
    def route(self, targets: tuple[QuarantineTarget, ...]) -> EscalationDecision: ...


class NonBlockingEscalation:
    """Custodian-A. Contain what is permitted, now. Route the rest, in parallel.

    Note that the two branches are computed independently and both returned.
    A target that must be escalated never suppresses containment of a target
    that need not be.
    """

    def route(self, targets: tuple[QuarantineTarget, ...]) -> EscalationDecision:
        permitted = [t for t in targets if t.within_unilateral_authority]
        beyond = [t for t in targets if not t.within_unilateral_authority]

        rule_hit = None

        # Rate ceiling applies only to the permitted set. Overflow is routed
        # for approval rather than dropped -- and the first N still contain.
        if len(permitted) > MAX_UNILATERAL_CONTAINMENTS:
            overflow = permitted[MAX_UNILATERAL_CONTAINMENTS:]
            permitted = permitted[:MAX_UNILATERAL_CONTAINMENTS]
            beyond.extend(overflow)
            rule_hit = "max_unilateral_containments"

        reason = f"contained {len(permitted)}, escalated {len(beyond)}"
        if beyond and not rule_hit:
            rule_hit = "beyond_unilateral_authority"

        return EscalationDecision(
            contain_now=tuple(t.instance_id for t in permitted),
            escalate=tuple(t.instance_id for t in beyond),
            rule_hit=rule_hit,
            reason=reason,
        )


class ApprovalGatedEscalation:
    """Custodian-B. The flawed twin.

    Trace, Record, Authorize and Constrain are all intact and working. This
    agent has *more* human oversight than Custodian-A, not less. It is the
    configuration a nervous organisation ships on purpose, and no auditor
    flags it.

    The flaw is one field: contain_now is unconditionally empty. Every action,
    however small, reversible and clearly within scope, waits behind a human.
    The attacker's foothold survives the wait, and exfiltration integrates over
    the whole of it:

        bytes_exfiltrated = egress_rate * time_to_containment
    """

    def route(self, targets: tuple[QuarantineTarget, ...]) -> EscalationDecision:
        return EscalationDecision(
            contain_now=(),
            escalate=tuple(t.instance_id for t in targets),
            rule_hit="approval_required",
            reason="approval_gated profile: all containment awaits sign-off",
        )


def load_policy() -> EscalationPolicy:
    profile = os.environ.get("CUSTODIAN_ESCALATION_PROFILE", "non_blocking").lower()
    if profile == "approval_gated":
        return ApprovalGatedEscalation()
    if profile == "non_blocking":
        return NonBlockingEscalation()
    raise ValueError(f"unknown CUSTODIAN_ESCALATION_PROFILE: {profile!r}")
