#!/usr/bin/env python3
"""The stage scoreboard.

Polls the lab account and serves one page, designed to be the only thing on
the projector. Two columns, one per twin, large enough to read from the back
of a room, plus a running explanation of what is happening underneath.

    python demo/scoreboard.py --profile cosac

    then open http://localhost:8900

Standard library only, and it shells out to the AWS CLI rather than importing
boto3, so there is nothing to install on a machine that can already run
`aws`. Read-only: every call is a describe, list or get.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).parent

# Filled in by main() so the poller does not need them passed around.
PROFILE = "cosac"
REGION = "us-east-1"

_state: dict = {"ready": False}
_state_lock = threading.Lock()

# Narration lines already emitted, so the feed does not repeat itself.
_seen: set[str] = set()

# Last value seen for each state the strip narrates, so a reversal can be
# reported and a first sighting can be recorded silently.
_last_state: dict = {}

_events: list[dict] = []

LEDGER = "cosac-decision-ledger"

# Rehearsal only: a pretend request the operator can actually answer, so the
# approval choreography can be practised with nothing deployed.
_rehearsal_pending: dict = {}

# Who is answering. Recorded on every decision, and deliberately not the
# agent: the board uses the operator's own credentials.
OPERATOR = "operator"
DEMO_MODE = False

# Rehearsal clock, in a dict so reset can move it without touching globals.
_clock: dict = {"started": 0.0}

# A reset in flight. The board reads this every poll and covers itself until
# it is over, so nobody narrates over a half-reset lab.
_reset: dict = {"active": False, "steps": [], "error": None, "done_at": None}
_reset_lock = threading.Lock()

REPO = ""  # owner/name, resolved from gh at startup


# ---------------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------------

# On Windows the CLI is aws.cmd, which subprocess will not find by the bare
# name "aws". Resolve it once, the way the shell would.
AWS_BIN = shutil.which("aws") or "aws"


def aws(*args: str, default=None):
    """Run one read-only AWS CLI call and parse its JSON output."""
    cmd = [AWS_BIN, *args, "--profile", PROFILE, "--region", REGION, "--output", "json"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return default
    if out.returncode != 0:
        return default
    try:
        return json.loads(out.stdout or "null")
    except json.JSONDecodeError:
        return default


GH_BIN = shutil.which("gh") or "gh"


def gh(*args: str, timeout=60) -> tuple[bool, str]:
    """Run one `gh` command. Returns (ok, output-or-error).

    The board drives the demo the same way an operator does -- by dispatching
    the repository's own workflows. Nothing here talks to AWS: that is the
    point. A reset the audience watches must be the reset the runbook
    documents, or the runbook is fiction.
    """
    cmd = [GH_BIN, *args]
    if REPO:
        cmd += ["--repo", REPO]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, "gh timed out"
    except FileNotFoundError:
        return False, "gh is not installed, or not on PATH"
    if out.returncode != 0:
        return False, (out.stderr or out.stdout or "gh failed").strip()
    return True, out.stdout.strip()


def _metric_points(namespace: str, name: str, twin: str, stat: str,
                   period: int, minutes: int) -> list[dict]:
    now = datetime.now(UTC)
    pts = aws(
        "cloudwatch", "get-metric-statistics",
        "--namespace", namespace,
        "--metric-name", name,
        "--dimensions", f"Name=Twin,Value={twin}",
        "--start-time", (now - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "--end-time", now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "--period", str(period),
        "--statistics", stat,
        default={},
    ) or {}
    return sorted(pts.get("Datapoints", []), key=lambda d: d["Timestamp"])


def metric_latest(namespace: str, name: str, twin: str, stat="Maximum", minutes=30):
    """Most recent datapoint for one twin's metric, or None if it is silent.

    Asked at period 60, which is what this did, the newest COMPLETE bucket is
    up to ninety seconds old -- so the counter ran a minute and a half behind
    a live leak, moved in megabyte steps once a minute, and sat inside the
    board's forty-five second stall window between buckets. The board then
    said "no new data for 45s", in amber, over a machine that was leaking at
    that moment. Measured against the account: period 60 returned 21.8 MB
    while period 5 returned 26.0 MB for the same instant.

    The publisher writes at one-second storage resolution precisely so this
    does not have to happen. Ask for it.
    """
    # Period 5 is only served for the last three hours, and a ten minute
    # window keeps the response small.
    points = _metric_points(namespace, name, twin, stat, period=5, minutes=10)
    if not points:
        # Either nothing recent, or the datapoints predate the high-resolution
        # retention window. Fall back to the coarse read rather than claiming
        # the metric is silent.
        points = _metric_points(namespace, name, twin, stat, period=60, minutes=minutes)
    if not points:
        return None
    return points[-1][stat]


def gather(**calls):
    """Run independent AWS calls at the same time.

    Every call here is a separate `aws` subprocess taking a second or two, and
    run one after another a single poll took 28 seconds against an interval of
    5. The board's clock only advances when a poll finishes, so it sat still
    for half a minute and then jumped -- which reads as broken rather than as
    slow.

    Nothing polled here depends on anything else polled here, so there is no
    reason to wait.
    """
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(calls)))) as pool:
        futures = {name: pool.submit(fn) for name, fn in calls.items()}
        return {name: f.result() for name, f in futures.items()}


# ---------------------------------------------------------------------------
# Scenario A
# ---------------------------------------------------------------------------

def widest(entries: list[str]):
    """The entry covering the most addresses, and how many that is.

    This is the number that makes the difference legible: a handful of /128s
    is six addresses, one /62 is more addresses than there are grains of sand.
    """
    if not entries:
        return None, 0
    scored = [(e, ipaddress.ip_network(e, strict=False).num_addresses) for e in entries]
    scored.sort(key=lambda p: p[1], reverse=True)
    return scored[0]


def scenario_a() -> dict:
    first = gather(
        listed=lambda: aws("wafv2", "list-ip-sets", "--scope", "REGIONAL", default={}) or {},
        subnets=lambda: (aws(
            "ec2", "describe-subnets",
            "--filters", "Name=tag:Role,Values=responder",
            default={},
        ) or {}).get("Subnets", []),
        sources=lambda: aws(
            "ec2", "describe-network-interfaces",
            "--filters", "Name=tag:Project,Values=cosac",
            "--query", "NetworkInterfaces[].Ipv6Addresses[].Ipv6Address",
            default=[],
        ) or [],
        access_a=lambda: metric_latest("COSAC/ScenarioA", "ResponderAccess",
                                       "warden-a", stat="Average"),
        access_b=lambda: metric_latest("COSAC/ScenarioA", "ResponderAccess",
                                       "warden-b", stat="Average"),
    )

    by_name = {s["Name"]: s for s in first["listed"].get("IPSets", [])}
    protected = None
    if first["subnets"]:
        protected = first["subnets"][0].get(
            "Ipv6CidrBlockAssociationSet", [{}])[0].get("Ipv6CidrBlock")
    sources = first["sources"]

    def fetch_entries(key):
        """Both families, as one blocklist.

        A WAF IPSet holds one address family, so an agent that bans an IPv4
        scanner writes to a different set than one that bans an IPv6 host.
        That split is WAF's, not the agent's, and showing it on the board
        would mean an IPv4 ban simply did not appear.
        """
        meta = by_name.get(f"cosac-a-{key}-block")
        if not meta:
            return None
        out: list[str] = []
        for name in (f"cosac-a-{key}-block", f"cosac-a-{key}-block-v4"):
            found = by_name.get(name)
            if not found:
                continue
            got = aws("wafv2", "get-ip-set", "--scope", "REGIONAL",
                      "--name", name, "--id", found["Id"], default={}) or {}
            out += got.get("IPSet", {}).get("Addresses", [])
        return out

    fetched = gather(a=lambda: fetch_entries("a"), b=lambda: fetch_entries("b"))

    twins = {}
    for key, label in (("a", "warden-a"), ("b", "warden-b")):
        meta = by_name.get(f"cosac-a-{key}-block")
        entries: list[str] = fetched[key] or []

        widest_entry, covered = widest(entries)
        hits_protected = bool(
            widest_entry and protected
            and ipaddress.ip_network(protected).subnet_of(
                ipaddress.ip_network(widest_entry, strict=False))
        )
        access = first[f"access_{key}"]

        twins[key] = {
            "label": label,
            "profile": "legacy" if key == "a" else "enforcing",
            "deployed": meta is not None,
            "entries": entries,
            "entry_count": len(entries),
            "widest": widest_entry,
            "covered": covered,
            "hits_protected": hits_protected,
            # Responder reachability: 1 online, 0 locked out, None not reporting.
            "responder": None if access is None else round(access),
        }

    return {
        "twins": twins,
        "protected": protected,
        "source_count": len(sources),
        "deployed": any(t["deployed"] for t in twins.values()),
    }


# ---------------------------------------------------------------------------
# Scenario B
# ---------------------------------------------------------------------------

def scenario_b() -> dict:
    first = gather(
        instances=lambda: (aws(
            "ec2", "describe-instances",
            "--filters", "Name=tag:Project,Values=cosac",
            "Name=tag:Scenario,Values=b-custodian",
            "Name=instance-state-name,Values=running",
            default={},
        ) or {}).get("Reservations", []),
        detectors=lambda: (aws("guardduty", "list-detectors", default={})
                           or {}).get("DetectorIds", []),
        bytes_a=lambda: metric_latest("COSAC/ScenarioB", "BytesExfiltrated", "custodian-a"),
        bytes_b=lambda: metric_latest("COSAC/ScenarioB", "BytesExfiltrated", "custodian-b"),
    )
    instances = first["instances"]

    found = {}
    for res in instances:
        for inst in res.get("Instances", []):
            tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
            twin = tags.get("Twin")
            if twin:
                groups = [g["GroupName"] for g in inst.get("SecurityGroups", [])]
                found[twin] = {"id": inst["InstanceId"], "groups": groups}

    detectors = first["detectors"]
    findings = 0
    if detectors:
        # Only findings from the last hour. A detector keeps them for days, so
        # counting all of them meant "break-in detected: yes" on a lab that had
        # been idle since the morning -- describing last night's run as though
        # it were happening now.
        since = int((datetime.now(UTC) - timedelta(hours=1)).timestamp() * 1000)
        criteria = json.dumps({"Criterion": {
            "type": {"Eq": ["Backdoor:EC2/C&CActivity.B!DNS"]},
            "updatedAt": {"Gte": since},
            # Archived means dealt with. A reset archives, so a finding from a
            # previous run stops counting the moment the lab is reset.
            "service.archived": {"Eq": ["false"]},
        }})
        ids = aws("guardduty", "list-findings", "--detector-id", detectors[0],
                  "--finding-criteria", criteria, default={}) or {}
        findings = len(ids.get("FindingIds", []))

    twins = {}
    for key, label in (("a", "custodian-a"), ("b", "custodian-b")):
        inst = found.get(label)
        groups = inst["groups"] if inst else []
        twins[key] = {
            "label": label,
            "profile": "approval_gated" if key == "a" else "non_blocking",
            "deployed": inst is not None,
            "instance": inst["id"] if inst else None,
            # The containment action is a security group swap, so the group
            # name IS the answer to "did it act?".
            "contained": any("isolation" in g for g in groups),
            "group": groups[0] if groups else None,
            "bytes": first[f"bytes_{key}"] or 0,
        }

    return {
        "twins": twins,
        "findings": findings,
        "deployed": any(t["deployed"] for t in twins.values()),
    }


# ---------------------------------------------------------------------------
# Approvals
# ---------------------------------------------------------------------------
#
# When a correct twin proposes something beyond its own authority it does not
# act, and it does not drop the proposal either -- it writes a pending record
# to the ledger and waits. This is where a human answers.
#
# The identity that answers matters as much as the answer. The board approves
# using the OPERATOR's credentials, never the agent's, and the agent's role
# has no permission to write a decision at all. Otherwise this is not an
# approval, it is the agent signing its own permission slip.
#
#     the agent can ask, but it cannot answer.


def announce(agent_id: str, verdict: str, who: str) -> None:
    """A denial must not disappear silently.

    The card is removed once answered, so without this the board would show no
    sign that anyone decided anything -- and "somebody denied it and the leak
    continued" is a state worth being able to point at.
    """
    scene = "a" if agent_id.startswith("warden") else "b"
    if verdict == "approved":
        push_event("good", f"{who} approved {agent_id}'s request. It may now act.", scene)
    else:
        push_event("bad", f"{who} denied {agent_id}'s request. Nothing was contained.", scene)


def _ddb(*args: str, payload: dict | None = None, default=None):
    """DynamoDB call, passing JSON via a temp file.

    Quoting a JSON document through a shell is a reliable source of
    cross-platform misery; file:// sidesteps it entirely.
    """
    extra: list[str] = []
    tmp_paths: list[str] = []
    for flag, doc in (payload or {}).items():
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        tmp_paths.append(path)
        extra += [flag, f"file://{path}"]
    try:
        return aws("dynamodb", *args, *extra, default=default)
    finally:
        for path in tmp_paths:
            with suppress(OSError):
                os.unlink(path)


def _unwrap(item: dict) -> dict:
    """Flatten DynamoDB's typed attribute values into plain Python."""
    out = {}
    for key, wrapped in item.items():
        (kind, value), = wrapped.items()
        out[key] = float(value) if kind == "N" else value
    return out


def pending_approvals(demo: bool = False) -> list[dict]:
    if demo:
        return [dict(_rehearsal_pending)] if _rehearsal_pending.get("status") == "pending" else []

    res = _ddb(
        "scan", "--table-name", LEDGER,
        "--filter-expression", "#s = :p",
        payload={
            "--expression-attribute-names": {"#s": "status"},
            "--expression-attribute-values": {":p": {"S": "pending"}},
        },
        default={},
    ) or {}

    out = []
    for raw in res.get("Items", []):
        out.append(_unwrap(raw))
    out.sort(key=lambda r: r.get("requested_at", ""))
    return out


def decide(agent_id: str, decision_id: str, verdict: str, who: str, demo: bool = False) -> dict:
    """Record a human's answer, and release whatever was waiting on it."""
    now = datetime.now(UTC).isoformat(timespec="seconds")

    if demo:
        if _rehearsal_pending.get("decision_id") == decision_id:
            _rehearsal_pending.update(status=verdict, decided_at=now, decided_by=who)
        announce(agent_id, verdict, who)
        return {"ok": True, "verdict": verdict}

    updated = _ddb(
        "update-item", "--table-name", LEDGER,
        "--update-expression",
        "SET #s = :v, decided_at = :t, decided_by = :w",
        "--condition-expression", "#s = :pending",
        "--return-values", "ALL_NEW",
        payload={
            "--key": {"agent_id": {"S": agent_id}, "decision_id": {"S": decision_id}},
            "--expression-attribute-names": {"#s": "status"},
            "--expression-attribute-values": {
                ":v": {"S": verdict},
                ":t": {"S": now},
                ":w": {"S": who},
                ":pending": {"S": "pending"},
            },
        },
    )
    if updated is None:
        # The condition failed, which means somebody answered it first.
        return {"ok": False, "error": "already decided"}

    item = _unwrap(updated.get("Attributes", {}))

    # An approval that nothing executes is not an approval. Observed live:
    # the strip said "fmulla approved custodian-a's request. It may now act",
    # the row went to approved -- and the machine stayed on the network, still
    # leaking, because nothing ever told the agent.
    #
    # Asynchronous on purpose. The board must answer the click immediately,
    # and whether the machine actually came off the network is not this
    # function's word to take: it shows up in the next poll, read from EC2.
    if verdict == "approved":
        # Route by the agent that ASKED. This said cosac-custodian-<twin> for
        # everything, so approving a warden request woke the custodian, which
        # correctly refused a decision that was not its own -- and the range
        # the operator had just approved was never written.
        kind = "warden" if agent_id.startswith("warden") else "custodian"
        twin = agent_id.rsplit("-", 1)[-1]
        asked = aws(
            "lambda", "invoke",
            "--function-name", f"cosac-{kind}-{twin}",
            "--invocation-type", "Event",
            "--cli-binary-format", "raw-in-base64-out",
            "--payload", json.dumps({"approved_decision": {
                "agent_id": agent_id, "decision_id": decision_id}}),
            os.devnull,
        )
        if asked is None:
            push_event("bad", f"{agent_id} was approved, but could not be reached. "
                              f"Nothing has been contained.", "b")

    # If the agent parked a Step Functions execution on this decision, release
    # it. Approving in the ledger but leaving the workflow hanging would be a
    # decision nobody acted on.
    token = item.get("task_token")
    if token:
        action = "send-task-success" if verdict == "approved" else "send-task-failure"
        args = ["stepfunctions", action, "--task-token", token]
        if verdict == "approved":
            args += ["--output", json.dumps({"approved": True, "by": who})]
        else:
            args += ["--error", "DeniedByOperator", "--cause", f"denied by {who}"]
        aws(*args)

    announce(agent_id, verdict, who)
    return {"ok": True, "verdict": verdict}


# ---------------------------------------------------------------------------
# Narration
# ---------------------------------------------------------------------------

def push_event(tone: str, text: str, scene: str = "both") -> None:
    """Put a line on the board's live strip, newest first.

    `scene` is "a", "b", or "both". The strip shows only the scenario on
    screen: a line about the other one is noise while you are talking about
    this one.
    """
    _events.insert(0, {
        "at": datetime.now().strftime("%H:%M:%S"),
        "tone": tone,
        "text": text,
        "scene": scene,
    })
    del _events[40:]


_UNSET = object()


def narrate(a: dict, b: dict, approvals: list[dict] | None = None) -> None:
    """Explain what just happened underneath.

    Only CHANGES. Nothing about the lab's standing shape, and nothing that was
    already true when the board started watching.

    Every line is narrated on transition, in both directions where a reversal
    is meaningful: responders lose access and get it back, a machine is
    contained or is not. A strip that says "responders have lost access" and
    never retracts it is lying the moment they come back, which is exactly
    what a reset produces.

    A state's first sighting is recorded silently. Otherwise a board started
    against a lab that is already mid-run narrates history as though it were
    happening now, and the operator reads timestamps from thirty seconds ago
    describing something that happened an hour before.

    The consequence is that an idle lab has an EMPTY strip, and that is
    correct: nothing is happening, so there is nothing to report.

    Deliberately plain language: this strip is read by the audience, not by
    the operator, and it has to make sense to someone who has never opened an
    AWS console.
    """

    def state(key: str, value, lines: dict, scene: str = "both") -> None:
        """Narrate `value` only when it differs from the last one seen.

        `lines` maps a value to (tone, text). A value with no entry passes
        silently, which is how a transition back to "nothing interesting"
        stays quiet.
        """
        previous = _last_state.get(key, _UNSET)
        _last_state[key] = value
        if previous is _UNSET or previous == value:
            return
        entry = lines.get(value)
        if entry:
            push_event(entry[0], entry[1], scene)

    # Nothing about the lab's standing shape belongs here. "The attacker holds
    # 18 addresses" was true of an idle lab -- those addresses are allocated to
    # its interfaces whether or not anyone is attacking -- so the strip
    # announced an attack that was not happening. The same sentence is already
    # in the explainer panel directly below, where it is describing the setup
    # rather than reporting an event.
    state("a-deployed", bool(a["deployed"]), {
        True: ("info", "Scenario A is up. Two identical websites, one guarded by each twin."),
    }, "a")

    for key in ("a", "b"):
        t = a["twins"][key]
        name = t["label"].upper()

        # How wide this twin has banned: none, individually, or by the block.
        if not t["entry_count"] or not t["widest"]:
            shape = "none"
        elif t["covered"] > 1:
            shape = "wide"
        else:
            shape = "narrow"
        state(f"a-shape-{key}", shape, {
            "wide": ("bad", f"{name} banned one whole block ({t['widest']}). That is "
                            f"{t['covered']:,} addresses in a single stroke."),
            "narrow": ("good", f"{name} banned individual addresses only, each set to "
                               f"expire by itself."),
            "none": ("info", f"{name}: block list is empty again."),
        }, "a")

        state(f"a-prot-{key}", bool(t["hits_protected"]), {
            True: ("bad", f"{name} just locked out its own responders. Nobody can reach "
                          f"the site to investigate."),
        }, "a")

        state(f"a-resp-{key}", t["responder"], {
            0: ("bad", f"{name}: responders have lost access."),
            1: ("good", f"{name}: responders can reach the site again."),
        }, "a")

    state("b-deployed", bool(b["deployed"]), {
        True: ("info", "Scenario B is up. Two identical machines, one watched by each twin."),
    }, "b")

    # Findings persist in the detector long after the run that produced them,
    # so the count is reported only when it GROWS. Otherwise a board started
    # the morning after announces last night's intrusion as though it were
    # happening now.
    grew = b["findings"] > _last_state.get("b-findings-count", b["findings"])
    _last_state["b-findings-count"] = b["findings"]
    if grew:
        push_event("info",
                   f"The intrusion was genuinely detected: {b['findings']} finding(s) raised "
                   f"by GuardDuty. Both twins were told at the same moment.", "b")

    for key in ("a", "b"):
        t = b["twins"][key]
        name = t["label"].upper()

        state(f"b-cont-{key}", bool(t["contained"]), {
            True: ("good", f"{name} unplugged the machine. Exfiltration stopped there."),
            False: ("info", f"{name}: machine is back on the network."),
        }, "b")

        # Whether this twin is actually waiting on anyone is a fact in the
        # ledger, not something to infer from its profile. Said flatly, this
        # line reported CUSTODIAN-B "still waiting for a human to approve"
        # -- the twin whose whole point is that it never asks.
        asking = any(r.get("agent_id") == t["label"] for r in (approvals or []))
        leaking = t["bytes"] > 5_000_000 and not t["contained"]
        state(f"b-leak-{key}", leaking and asking, {
            True: ("bad", f"{name} is still waiting for a human to approve. "
                          f"Data keeps leaving."),
        }, "b")
        state(f"b-loose-{key}", leaking and not asking, {
            True: ("bad", f"{name}: the machine is still on the network and "
                          f"data is still leaving."),
        }, "b")

    # A request sitting unanswered is the single most important thing on the
    # board, and the strip said "Waiting for something to happen..." while two
    # of them were on screen.
    for agent, scene in (("warden-a", "a"), ("warden-b", "a"),
                         ("custodian-a", "b"), ("custodian-b", "b")):
        waiting = [r for r in (approvals or []) if r.get("agent_id") == agent]
        state(f"ask-{agent}", len(waiting), {
            0: ("good", f"{agent.upper()}: nothing is waiting on a human now."),
        }, scene)
        if waiting:
            # Not a `state` line: the count can go 1 -> 2 -> 3 and each new
            # request is news, where "still waiting" is not.
            previous = _last_state.get(f"ask-n-{agent}", 0)
            _last_state[f"ask-n-{agent}"] = len(waiting)
            if len(waiting) > previous:
                push_event("bad", f"{agent.upper()} is asking permission to "
                                  f"{waiting[-1].get('action', 'act').lower()}. "
                                  f"Nothing happens until somebody answers.", scene)
        else:
            _last_state[f"ask-n-{agent}"] = 0


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------

def _outstanding_ipset(listed: dict, name: str, out: list[str]) -> None:
    """Report one IPSet that still holds entries, if it exists."""
    meta = next((x for x in listed.get("IPSets", []) if x["Name"] == name), None)
    if not meta:
        return
    got = aws("wafv2", "get-ip-set", "--scope", "REGIONAL",
              "--name", name, "--id", meta["Id"], default={}) or {}
    n = len((got.get("IPSet") or {}).get("Addresses", []))
    if n:
        out.append(f"{name} still holds {n} entries")


def lab_outstanding() -> list[str]:
    """What is still not back to its starting state, read from AWS.

    This is the signal a reset waits on. Not a timer, and not the workflow's
    exit code either -- the lab itself, answering the same questions the board
    already asks every five seconds.
    """
    out = []

    found = aws("wafv2", "list-ip-sets", "--scope", "REGIONAL", default={}) or {}
    for twin in ("a", "b"):
        names = [f"cosac-a-{twin}-block", f"cosac-a-{twin}-block-v4"]
        for name in names:
            _outstanding_ipset(found, name, out)

    victims = (aws("ec2", "describe-instances",
                   "--filters", "Name=tag:Scenario,Values=b-custodian",
                   "Name=instance-state-name,Values=running",
                   default={}) or {}).get("Reservations", [])
    for res in victims:
        for inst in res.get("Instances", []):
            groups = [g.get("GroupName") for g in inst.get("SecurityGroups", [])]
            if "cosac-b-normal" not in groups:
                where = ", ".join(groups) or "no group"
                out.append(f"{inst['InstanceId']} is still in {where}")

    # A zeroed counter is not the same as a stopped payload. Seen live: the
    # reset published 0 for both twins, one victim's payload survived the
    # kill, and it republished its running total within seconds -- so the
    # board showed 16.26 MB immediately after a reset it had called clean.
    # Ask twice, a few seconds apart, and let the number answer.
    first = {t: metric_latest("COSAC/ScenarioB", "BytesExfiltrated", t)
             for t in ("custodian-a", "custodian-b")}
    if any(v for v in first.values()):
        time.sleep(6)
        for twin, before in first.items():
            after = metric_latest("COSAC/ScenarioB", "BytesExfiltrated", twin)
            if before is not None and after is not None and after > before:
                out.append(f"{twin} is still exfiltrating "
                           f"({(after - before) / 1024:.0f} KB in six seconds)")

    pending = pending_approvals(demo=False)
    if pending:
        out.append(f"{len(pending)} approval request(s) still pending")

    detectors = (aws("guardduty", "list-detectors", default={}) or {}).get("DetectorIds", [])
    if detectors:
        # Archived findings are still listed unless excluded, so without this
        # the reset archives everything, sees the same count, and waits two
        # minutes before declaring that the lab never came back.
        got = aws("guardduty", "list-findings", "--detector-id", detectors[0],
                  "--finding-criteria",
                  json.dumps({"Criterion": {
                      "type": {"Eq": ["Backdoor:EC2/C&CActivity.B!DNS"]},
                      "service.archived": {"Eq": ["false"]},
                  }}),
                  default={}) or {}
        n = len(got.get("FindingIds", []))
        if n:
            out.append(f"{n} GuardDuty finding(s) still open")

    return out


def _mark(label: str, state: str, note: str = "") -> None:
    """Publish one step of the reset, for the board to cover itself with."""
    with _reset_lock:
        for step in _reset["steps"]:
            if step["label"] == label:
                step.update(state=state, note=note)
                return
        _reset["steps"].append({"label": label, "state": state, "note": note})


def _dispatch(workflow: str) -> str | None:
    """Fire one workflow and return the run id GitHub gave it."""
    _mark(workflow, "running", "dispatching")

    before = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    ok, err = gh("workflow", "run", workflow, "-f", "phase=reset")
    if not ok:
        _mark(workflow, "failed", err.splitlines()[0] if err else "dispatch failed")
        return None

    # `gh workflow run` prints no id, so find the run it just created. A run
    # older than the dispatch belongs to somebody else and must not be
    # watched -- waiting on the wrong run is how a board lies confidently.
    for _ in range(20):
        time.sleep(3)
        ok, raw = gh("run", "list", "--workflow", workflow, "--limit", "5",
                     "--json", "databaseId,createdAt")
        if not ok:
            continue
        try:
            runs = json.loads(raw or "[]")
        except json.JSONDecodeError:
            continue
        fresh = [r for r in runs if r.get("createdAt", "") >= before]
        if fresh:
            run_id = str(max(fresh, key=lambda r: r["createdAt"])["databaseId"])
            _mark(workflow, "running", f"run {run_id} queued")
            return run_id

    _mark(workflow, "failed", "dispatched, but no run appeared")
    return None


def _await_run(workflow: str, run_id: str) -> bool:
    for _ in range(100):  # 100 x 6s = ten minutes
        ok, raw = gh("run", "view", run_id, "--json", "status,conclusion")
        if ok:
            try:
                info = json.loads(raw or "{}")
            except json.JSONDecodeError:
                info = {}
            if info.get("status") == "completed":
                good = info.get("conclusion") == "success"
                _mark(workflow, "done" if good else "failed",
                      f"run {run_id} {info.get('conclusion')}")
                return good
            _mark(workflow, "running", f"run {run_id} {info.get('status', 'queued')}")
        time.sleep(6)
    _mark(workflow, "failed", f"run {run_id} did not finish in ten minutes")
    return False


LAB_CLEAN = "lab back to its starting state"


def reset_lab() -> None:
    """Drive the repository's own reset workflows, then wait for the lab.

    On its own thread: an Actions run takes a minute or two, and a board that
    stops answering for two minutes looks broken on a projector. Progress goes
    into `_reset`, which the board reads on its normal poll and covers itself
    with until this finishes.
    """
    try:
        ids: dict[str, str] = {}
        for workflow in ("agent warden", "agent custodian"):
            run_id = _dispatch(workflow)
            if run_id is None:
                raise RuntimeError(f"could not start {workflow}")
            ids[workflow] = run_id

        for workflow, run_id in ids.items():
            if not _await_run(workflow, run_id):
                raise RuntimeError(f"{workflow} finished badly; open it on GitHub")

        # A workflow succeeding is not the same as the lab being clean: EC2
        # and GuardDuty both settle a moment behind the API call that changed
        # them. So ask the lab, and keep asking until it agrees.
        _mark(LAB_CLEAN, "running", "checking")
        for _ in range(40):  # 40 x 3s = two minutes
            left = lab_outstanding()
            if not left:
                _mark(LAB_CLEAN, "done")
                break
            _mark(LAB_CLEAN, "running", left[0])
            time.sleep(3)
        else:
            raise RuntimeError("; ".join(lab_outstanding()) or "the lab never came back")

        push_event("info", "Lab reset. Bans cleared, machines released. "
                           "Ready for another run.")
    except Exception as exc:
        _mark(LAB_CLEAN, "failed", str(exc))
        with _reset_lock:
            _reset["error"] = str(exc)
        push_event("deny", f"Reset did not finish: {exc}")
    finally:
        with _reset_lock:
            _reset["active"] = False
            _reset["done_at"] = time.time()


def reset(scope: str = "board") -> dict:
    """Put things back so the attack can be run again.

    "board" clears what the board itself remembers: the narration, the
    already-said set, and -- in rehearsal -- the clock, so the arc replays
    from the top. Without this a second run would be silent, because every
    line had already been said once. Nothing in AWS is touched.

    "all" additionally resets the lab, by dispatching the same two workflows
    the runbook tells an operator to run by hand. The board does not reach
    into AWS to do it itself: one reset, one implementation, so what an
    audience watches here is exactly what a colleague gets from a terminal.
    """
    _events.clear()
    _seen.clear()
    _last_state.clear()
    _rehearsal_pending.clear()
    if DEMO_MODE:
        _clock["started"] = time.monotonic()

    if scope != "all" or DEMO_MODE:
        push_event("info", "Board reset. Ready for another run.")
        return {"ok": True, "scope": "board"}

    with _reset_lock:
        if _reset["active"]:
            return {"ok": True, "scope": "all", "already": True}
        _reset.update(active=True, steps=[], error=None, done_at=None)

    threading.Thread(target=reset_lab, daemon=True).start()
    return {"ok": True, "scope": "all", "started": True}


# ---------------------------------------------------------------------------
# Rehearsal
# ---------------------------------------------------------------------------

def rehearsal(elapsed: float) -> tuple[dict, dict]:
    """A scripted run, for practising the board with nothing deployed.

    The beats are spaced the way the real thing behaves -- including the
    twelve-minute wait before GuardDuty delivers, compressed here so a
    rehearsal takes two minutes rather than twenty. Use it to practise the
    narration and to check the projector, never to present.
    """
    t = elapsed
    prot = "2600:1f18:3800:6512::/64"
    wide = "2600:1f18:3800:6510::/62"
    narrow = ["2600:1f18:3800:6510::a/128", "2600:1f18:3800:6511::4/128",
              "2600:1f18:3800:6513::7/128"]

    a_entries = narrow[: min(3, int(max(0, t - 10) // 4))] if t > 10 else []
    b_entries = [wide] if t > 22 else (narrow[:2] if t > 12 else [])

    def a_twin(key, entries, responder):
        w, covered = widest(entries)
        return {
            "label": f"warden-{key}", "profile": "legacy" if key == "a" else "enforcing",
            "deployed": True, "entries": entries, "entry_count": len(entries),
            "widest": w, "covered": covered,
            "hits_protected": bool(w and ipaddress.ip_network(prot).subnet_of(
                ipaddress.ip_network(w, strict=False))),
            "responder": responder,
        }

    a = {
        "twins": {"a": a_twin("a", b_entries, 0 if t > 26 else 1),
                  "b": a_twin("b", a_entries, 1)},
        "protected": prot, "source_count": 18, "deployed": t > 4,
    }

    # Warden-A raises NOTHING here, and that is the correct behaviour. The /62
    # contains the responder subnet, so the protected-prefix rule denies it
    # outright -- see test_range_containing_responders_is_denied_not_escalated.
    # Denial is not escalation: no human approval makes blocking your own
    # responders correct, so it never reaches a queue.

    # Scenario B: both leak until the finding lands, then A contains and B does not.
    found = t > 40

    # Custodian-B escalates every containment and contains nothing, so once
    # the finding lands it raises a request and waits. Nobody answers it --
    # which is the whole scenario. If the operator does answer it on the
    # board, the machine is contained and the counter stops there.
    if found and not _rehearsal_pending:
        _rehearsal_pending.update({
            "agent_id": "custodian-a",
            "decision_id": "approval#rehearsal",
            "status": "pending",
            "requested_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "action": "Quarantine an instance",
            "target": "i-0e4f5a6b  (t3.micro, env=lab, criticality=low)",
            "blast_radius": 1.0,
            "reason": "This profile requires a human for every containment, however small.",
            "rule_hit": "approval_required",
        })

    b_approved = _rehearsal_pending.get("status") == "approved"

    # Bytes are the integral of the leak over time, so a contained machine's
    # counter must FREEZE at the moment of containment -- not keep climbing to
    # some cap. Custodian-A contains at t=46; Custodian-B only if answered.
    RATE, START, A_CONTAINED_AT = 78_000, 30, 46

    def leaked(until: float) -> float:
        return RATE * max(0.0, until - START)

    a_bytes = leaked(min(t, A_CONTAINED_AT))
    b_bytes = leaked(t)
    if b_approved:
        # Frozen at whatever had already left when somebody finally answered.
        b_bytes = _rehearsal_pending.setdefault("frozen_bytes", b_bytes)
    b = {
        "twins": {
            # A is the flawed twin: it escalates everything and contains nothing.
            "a": {"label": "custodian-a", "profile": "approval_gated", "deployed": t > 28,
                  "instance": "i-0e4f5a6b", "contained": b_approved,
                  "group": "cosac-b-isolation" if b_approved else "cosac-b-normal",
                  "bytes": b_bytes},
            "b": {"label": "custodian-b", "profile": "non_blocking", "deployed": t > 28,
                  "instance": "i-0a1b2c3d", "contained": t > A_CONTAINED_AT,
                  "group": "cosac-b-isolation" if t > A_CONTAINED_AT else "cosac-b-normal",
                  "bytes": a_bytes},
        },
        "findings": 2 if found else 0,
        "deployed": t > 28,
    }
    return a, b


# ---------------------------------------------------------------------------
# Poller
# ---------------------------------------------------------------------------

def reset_snapshot() -> dict:
    """A copy, so the board never reads a step mid-update."""
    with _reset_lock:
        return {
            "active": _reset["active"],
            "error": _reset["error"],
            "steps": [dict(x) for x in _reset["steps"]],
        }


def poll_forever(interval: int, demo: bool = False) -> None:
    global _state
    _clock["started"] = time.monotonic()
    while True:
        try:
            if demo:
                a, b = rehearsal(time.monotonic() - _clock["started"])
                approvals = pending_approvals(demo)
            else:
                # Three independent reads; no reason for them to queue.
                whole = gather(a=scenario_a, b=scenario_b,
                               approvals=lambda: pending_approvals(False))
                a, b, approvals = whole["a"], whole["b"], whole["approvals"]
            narrate(a, b, approvals)
            with _state_lock:
                _state = {
                    "ready": True,
                    "at": datetime.now().strftime("%H:%M:%S"),
                    # Epoch too, so the board can show how old the data is
                    # without parsing a wall-clock string across midnight.
                    "at_epoch": time.time(),
                    "a": a,
                    "b": b,
                    "approvals": approvals,
                    "operator": OPERATOR,
                    "events": list(_events),
                    "reset": reset_snapshot(),
                }
        except Exception as exc:  # a scoreboard must never be the thing that fails
            with _state_lock:
                _state = {"ready": True, "error": str(exc),
                          "at": datetime.now().strftime("%H:%M:%S"),
                          "at_epoch": time.time(),
                          "events": list(_events),
                          "reset": reset_snapshot()}
        time.sleep(interval)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path.startswith("/api/state"):
            with _state_lock:
                body = json.dumps(_state).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        body = (HERE / "scoreboard.html").read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        """Answer, whatever happens.

        An unhandled exception in here prints a socketserver traceback and
        drops the connection without a reply -- so the board's fetch fails
        silently and the operator gets a wall of Python on a projector. A
        KeyError in a log line did exactly that. Nothing this class does is
        worth failing that way.
        """
        try:
            self._post()
        except Exception as exc:
            traceback.print_exc()
            with suppress(OSError):
                self._json(500, {"ok": False, "error": f"{type(exc).__name__}: {exc}"})

    def _json(self, status: int, body: dict) -> None:
        payload = json.dumps(body, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _post(self) -> None:
        if self.path.startswith("/api/reset"):
            length = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(length) or "{}")
            except json.JSONDecodeError:
                body = {}
            scope = "all" if body.get("scope") == "all" else "board"
            result = reset(scope)
            # reset() stopped returning a list of what it did when the lab
            # half moved into the workflows; the steps live in `_reset` now
            # and the board reads them on its normal poll.
            did = result.get("scope", scope)
            if result.get("already"):
                said = "already running"
            elif did == "all":
                said = "dispatching agent warden + agent custodian"
            else:
                said = "board only; nothing in AWS was touched"
            print(f"  RESET ({did}): {said}", flush=True)
            payload = json.dumps(result).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        if not self.path.startswith("/api/decide"):
            self.send_error(404)
            return

        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or "{}")
        except json.JSONDecodeError:
            self.send_error(400)
            return

        verdict = body.get("verdict")
        if verdict not in ("approved", "denied"):
            self.send_error(400)
            return

        result = decide(
            body.get("agent_id", ""),
            body.get("decision_id", ""),
            verdict,
            who=OPERATOR,
            demo=DEMO_MODE,
        )
        print(
            f"  {verdict.upper()}  {body.get('agent_id')} / "
            f"{body.get('decision_id')}  by {OPERATOR}",
            flush=True,  # redirected stdout is block-buffered; without this the
        )                # decision never reaches the terminal during a demo

        payload = json.dumps(result).encode()
        self.send_response(200 if result.get("ok") else 409)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        pass  # the terminal is for driving the demo, not for access logs


def main() -> None:
    global PROFILE, REGION, OPERATOR, DEMO_MODE, REPO
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profile", default="cosac")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--port", type=int, default=8900)
    ap.add_argument("--interval", type=int, default=5, help="seconds between polls")
    ap.add_argument("--repo", default="",
                    help="owner/name for the reset workflows; read from gh when omitted")
    ap.add_argument("--rehearse", action="store_true",
                    help="scripted run with nothing deployed, for practising the board")
    args = ap.parse_args()

    PROFILE, REGION = args.profile, args.region

    DEMO_MODE = args.rehearse

    if args.rehearse:
        OPERATOR = "rehearsal"
        print("REHEARSAL — scripted data, nothing is being read from AWS")
    else:
        if shutil.which("aws") is None:
            raise SystemExit(
                "The AWS CLI is not on PATH. Install it, or run this from a "
                "shell where `aws` works."
            )

        who = aws("sts", "get-caller-identity")
        if not who:
            raise SystemExit(
                f"Cannot reach AWS with profile '{PROFILE}'.\n"
                f"  Refresh it:  aws sso login --profile {PROFILE}\n"
                f"  Or practise the board with nothing deployed:  --rehearse"
            )
        OPERATOR = who.get("Arn", "").rsplit("/", 1)[-1] or PROFILE
        print(f"account {who['Account']} · region {REGION} · approving as {OPERATOR}")

        # Resolved once, and reported once. A reset that discovers at the
        # worst possible moment that `gh` cannot name the repository is a
        # reset that fails in front of an audience.
        REPO = args.repo
        if not REPO:
            found, out = gh("repo", "view", "--json", "nameWithOwner",
                            "--jq", ".nameWithOwner")
            REPO = out.strip() if found else ""
        if REPO:
            print(f"reset drives {REPO} · agent warden + agent custodian")
        else:
            print("gh cannot name a repository, so R will not work.\n"
                  "  Run the board from the repo, or pass --repo owner/name.")

    threading.Thread(target=poll_forever, args=(args.interval, args.rehearse), daemon=True).start()

    print(f"\n  scoreboard ready:  http://localhost:{args.port}\n")
    print("  1 / 2  switch scenario   f  full screen   r  clear board   "
          "R  reset the lab   ctrl-c  stop\n")
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
