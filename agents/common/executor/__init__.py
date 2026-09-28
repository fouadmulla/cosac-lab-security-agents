"""Executors — the only things here that touch AWS.

The agent never holds a credential. It proposes; the policy gate decides; an
executor performs. Keeping that as three separate objects is what makes the
claim "the model cannot talk its way past the gate" structurally true rather
than merely asserted.

Each executor also has an in-memory twin used by the tests, so the agents can
be exercised end to end without an AWS account.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol


class Ledger(Protocol):
    def record(self, entry: dict[str, Any]) -> None: ...


@dataclass
class InMemoryLedger:
    entries: list[dict[str, Any]] = field(default_factory=list)

    def record(self, entry: dict[str, Any]) -> None:
        self.entries.append({**entry, "at": datetime.now(UTC).isoformat()})

    def pending(self) -> list[dict[str, Any]]:
        return [e for e in self.entries if e.get("status") == "pending"]


# ---------------------------------------------------------------------------
# Scenario A
# ---------------------------------------------------------------------------

@dataclass
class BlocklistExecutor:
    """Writes to a WAF IPSet, or to memory when there is no AWS."""

    agent_id: str
    ledger: Ledger
    ipset_name: str = ""
    ipset_id: str = ""
    # A WAF IPSet holds one address family, so blocking what a public load
    # balancer actually sees takes two of them. Which one an entry goes to is
    # arithmetic, not a decision, and the agent is never troubled with it.
    ipset_v4_name: str = ""
    ipset_v4_id: str = ""
    region: str = "us-east-1"
    client: Any = None  # a wafv2 client, or None for the in-memory twin
    _entries: list[str] = field(default_factory=list)

    def _set_for(self, entry: str) -> tuple[str, str]:
        version = ipaddress.ip_network(entry, strict=False).version
        if version == 4 and self.ipset_v4_id:
            return self.ipset_v4_name, self.ipset_v4_id
        return self.ipset_name, self.ipset_id

    def _addresses(self, name: str, ipset_id: str) -> list[str]:
        got = self.client.get_ip_set(Name=name, Scope="REGIONAL", Id=ipset_id)
        return list(got["IPSet"]["Addresses"])

    def current_entries(self) -> list[str]:
        """Everything this agent has blocked, both families together.

        One blocklist as far as the agent, the ledger and the board are
        concerned. The split is an implementation detail of WAF.
        """
        if self.client is None:
            return list(self._entries)
        out = self._addresses(self.ipset_name, self.ipset_id)
        if self.ipset_v4_id:
            out += self._addresses(self.ipset_v4_name, self.ipset_v4_id)
        return out

    def block(self, entry: str, expires_at: datetime | None = None) -> None:
        before = self.current_entries()

        if self.client is not None:
            name, ipset_id = self._set_for(entry)
            got = self.client.get_ip_set(Name=name, Scope="REGIONAL", Id=ipset_id)
            # Only this set's own addresses, or writing an IPv6 entry would
            # carry the IPv4 ones into a set that cannot hold them.
            updated = sorted(set(got["IPSet"]["Addresses"]) | {entry})
            self.client.update_ip_set(
                Name=name, Scope="REGIONAL", Id=ipset_id,
                Addresses=updated, LockToken=got["LockToken"],
            )
            after = sorted(set(before) | {entry})
        else:
            after = sorted(set(before) | {entry})
            self._entries = after

        # Before and after, not just intent: the ledger has to be able to
        # prove what actually changed, which is the whole of the Record pillar.
        self.ledger.record({
            "agent_id": self.agent_id,
            "decision_id": f"block#{entry}",
            "status": "executed",
            "action": "block",
            "target": entry,
            "before": before,
            "after": after,
            "ttl_expires_at": expires_at.isoformat() if expires_at else None,
        })

    def escalate(self, entry: str, decision: Any) -> None:
        self.ledger.record({
            "agent_id": self.agent_id,
            "decision_id": f"approval#{entry}",
            "status": "pending",
            "action": "Ban a whole range",
            "target": entry,
            "blast_radius": float(getattr(decision, "blast_radius", 0)),
            "reason": getattr(decision, "reason", ""),
            "rule_hit": getattr(decision, "rule_hit", None),
            "requested_at": datetime.now(UTC).isoformat(timespec="seconds"),
        })


# ---------------------------------------------------------------------------
# Scenario B
# ---------------------------------------------------------------------------

@dataclass
class QuarantineExecutor:
    """Swaps an instance's security groups for the isolation group."""

    agent_id: str
    ledger: Ledger
    isolation_group_id: str = "sg-isolation"
    client: Any = None  # an ec2 client, or None for the in-memory twin
    quarantined: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def quarantine(self, instance_id: str, prior_groups: tuple[str, ...]) -> None:
        if self.client is not None:
            self.client.modify_instance_attribute(
                InstanceId=instance_id, Groups=[self.isolation_group_id]
            )
        self.quarantined[instance_id] = prior_groups

        # prior_groups is written before the swap is reported, so the record
        # of how to undo it exists even if everything after this fails.
        self.ledger.record({
            "agent_id": self.agent_id,
            "decision_id": f"quarantine#{instance_id}",
            "status": "executed",
            "action": "quarantine",
            "target": instance_id,
            "before": list(prior_groups),
            "after": [self.isolation_group_id],
        })

    def escalate(self, instance_id: str, decision: Any) -> None:
        self.ledger.record({
            "agent_id": self.agent_id,
            "decision_id": f"approval#{instance_id}",
            "status": "pending",
            "action": "Quarantine an instance",
            "target": instance_id,
            "blast_radius": 1.0,
            "reason": getattr(decision, "reason", ""),
            "rule_hit": getattr(decision, "rule_hit", None),
            "requested_at": datetime.now(UTC).isoformat(timespec="seconds"),
        })


# ---------------------------------------------------------------------------
# Ledger backed by DynamoDB
# ---------------------------------------------------------------------------

@dataclass
class DynamoLedger:
    table: str = "cosac-decision-ledger"
    client: Any = None

    def record(self, entry: dict[str, Any]) -> None:
        if self.client is None:
            return
        item = {}
        for key, value in entry.items():
            if value is None:
                continue
            if isinstance(value, bool):
                item[key] = {"BOOL": value}
            elif isinstance(value, (int, float)):
                item[key] = {"N": str(value)}
            elif isinstance(value, (list, tuple, dict)):
                item[key] = {"S": json.dumps(list(value) if isinstance(value, tuple) else value)}
            else:
                item[key] = {"S": str(value)}
        item.setdefault("at", {"S": datetime.now(UTC).isoformat()})
        self.client.put_item(TableName=self.table, Item=item)
