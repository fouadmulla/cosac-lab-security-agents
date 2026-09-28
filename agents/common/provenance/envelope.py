"""Provenance envelopes -- the Trace pillar.

Applied at ingestion, before the model is invoked. The model cannot see this
module, cannot reason about it, and cannot talk its way past it.

Every scenario in this repository implements Trace *correctly in both twins*.
That is deliberate. It means no demonstration in this repository can be
dismissed as "you just prompt-injected it": the flawed agent's inputs are as
rigorously tiered as the correct agent's, and the failure happens anyway.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum
from typing import Any


class TrustTier(IntEnum):
    """Ordered, so policy can express "at least AWS_ATTESTED"."""

    UNTRUSTED_REMOTE = 0  # the client chose it: User-Agent, URI, headers, XFF, body
    AWS_ATTESTED = 1      # AWS derived it: source address, timestamps, finding ids
    OPERATOR = 2          # a human authored it: runbook, policy config


@dataclass(frozen=True)
class Envelope:
    """One input record, with everything needed to say where it came from."""

    source_arn: str
    trust_tier: TrustTier
    observed_at: datetime
    ingest_id: str
    payload: Mapping[str, Any]
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        canonical = json.dumps(self.payload, sort_keys=True, separators=(",", ":"))
        object.__setattr__(
            self, "digest", hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        )

    @property
    def is_actionable_identity(self) -> bool:
        """Whether this record may be used to decide *who* an action targets.

        An identity claim is only actionable if AWS attested it. This is what
        makes X-Forwarded-For spoofing a non-starter against these agents, and
        it is why Scenario A's attack has to work on genuinely attested IPv6
        addresses rather than forged headers.
        """
        return self.trust_tier >= TrustTier.AWS_ATTESTED


def wrap(
    source_arn: str,
    trust_tier: TrustTier,
    ingest_id: str,
    payload: Mapping[str, Any],
    observed_at: datetime | None = None,
) -> Envelope:
    return Envelope(
        source_arn=source_arn,
        trust_tier=trust_tier,
        observed_at=observed_at or datetime.now(UTC),
        ingest_id=ingest_id,
        payload=payload,
    )


def render_for_prompt(envelopes: tuple[Envelope, ...]) -> str:
    """Render records as labelled data operands.

    UNTRUSTED_REMOTE values are never concatenated into the instruction region.
    They appear only inside a delimited, explicitly-labelled data block, so the
    model is told -- structurally, not politely -- which bytes a stranger chose.
    """
    lines = []
    for env in envelopes:
        lines.append(
            f"<record tier={env.trust_tier.name} "
            f"ingest_id={env.ingest_id} digest={env.digest[:12]}>"
        )
        for key, value in sorted(env.payload.items()):
            lines.append(f"  {key}={value!r}")
        lines.append("</record>")
    return "\n".join(lines)
