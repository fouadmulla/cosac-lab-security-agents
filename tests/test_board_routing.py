"""Which agent the board wakes when a human approves.

Observed on the board: two `warden-b` requests, approved, and nothing written.
The approval was sent to `cosac-custodian-b` — because the routing assumed
every request came from a custodian. The custodian then correctly refused a
decision that was not its own, so the failure was silent: the operator saw
"approved", the ledger said approved, and the range was never blocked.

A one-line rule with four cases is exactly the kind of thing that deserves a
test rather than a careful read.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

BOARD = Path(__file__).resolve().parents[1] / "demo" / "scoreboard.py"


@pytest.fixture
def board(monkeypatch):
    spec = importlib.util.spec_from_file_location("board", BOARD)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    calls: list[list[str]] = []

    def fake_aws(*args, **kwargs):
        calls.append(list(args))
        return {}

    def fake_ddb(*args, **kwargs):
        return {"Attributes": {}}

    monkeypatch.setattr(mod, "aws", fake_aws)
    monkeypatch.setattr(mod, "_ddb", fake_ddb)
    mod.calls = calls
    return mod


def invoked(mod):
    for call in mod.calls:
        if call[:2] == ["lambda", "invoke"]:
            return call[call.index("--function-name") + 1]
    return None


@pytest.mark.parametrize("agent_id,expected", [
    ("warden-a", "cosac-warden-a"),
    ("warden-b", "cosac-warden-b"),
    ("custodian-a", "cosac-custodian-a"),
    ("custodian-b", "cosac-custodian-b"),
])
def test_an_approval_wakes_the_agent_that_asked(board, agent_id, expected):
    board.decide(agent_id, "approval#x", "approved", who="tester")
    assert invoked(board) == expected


def test_a_denial_wakes_nobody():
    """Nothing was approved, so there is nothing for an agent to carry out."""
    spec = importlib.util.spec_from_file_location("board2", BOARD)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    calls: list[list[str]] = []
    mod.aws = lambda *a, **k: calls.append(list(a)) or {}
    mod._ddb = lambda *a, **k: {"Attributes": {}}

    mod.decide("warden-b", "approval#x", "denied", who="tester")
    assert not [c for c in calls if c[:2] == ["lambda", "invoke"]]
