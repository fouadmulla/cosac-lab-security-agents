"""The agent loop.

An agent is not one inference call with pre-chewed input. It is given tools,
decides which to call and in what order, sees each result, and decides again
until it is finished. This module is that loop, and nothing in it knows what
the tools do.

The loop matters to the demonstration as much as to the code. The claim the
whole exercise rests on is *the model reasoned perfectly well and it did not
help*. That claim only survives if the model actually reasons -- investigates,
weighs, chooses a granularity -- rather than filling in a field of a JSON
object somebody else designed for it.

Note what the agent never gets: a credential. Every effectful tool is
intercepted by the policy gate before it reaches AWS, and the gate's verdict
comes back to the model *as a tool result*. So a refusal is something the
agent observes and can respond to, inside its own loop -- which is exactly
what the correct twin does and the flawed twin never has to.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

# Anthropic models on Bedrock, via a cross-region inference profile. Override
# with COSAC_MODEL_ID; the agent does not care which model it is.
DEFAULT_MODEL_ID = os.environ.get(
    "COSAC_MODEL_ID", "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
)

# A bound on how many times the agent may act before we stop it. Not a
# safety control -- the policy gate is the safety control -- just a guard
# against a loop that will not terminate on its own.
MAX_TURNS = 8


@dataclass(frozen=True)
class Tool:
    """One capability the agent may choose to use."""

    name: str
    description: str
    schema: dict[str, Any]
    handler: Callable[..., Any]

    # Effectful tools are the ones the policy gate intercepts. Read-only
    # tools are free: an agent that cannot look before it acts is not
    # reasoning, it is guessing.
    effectful: bool = False

    def spec(self) -> dict[str, Any]:
        return {
            "toolSpec": {
                "name": self.name,
                "description": self.description,
                "inputSchema": {"json": self.schema},
            }
        }


@dataclass
class Step:
    """One thing the agent did, kept for the ledger and for the transcript."""

    kind: str  # "tool" | "text"
    name: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    result: Any = None
    text: str = ""


class Converser(Protocol):
    """The slice of a Bedrock runtime client this module needs.

    Narrow on purpose, so tests can supply a scripted one without mocking
    half of boto3.
    """

    def converse(self, **kwargs: Any) -> dict[str, Any]: ...


@dataclass
class Transcript:
    steps: list[Step] = field(default_factory=list)
    stopped_because: str = ""

    @property
    def tool_calls(self) -> list[Step]:
        return [s for s in self.steps if s.kind == "tool"]

    def calls_to(self, name: str) -> list[Step]:
        return [s for s in self.tool_calls if s.name == name]

    @property
    def final_text(self) -> str:
        texts = [s.text for s in self.steps if s.kind == "text" and s.text]
        return texts[-1] if texts else ""


def run_agent(
    client: Converser,
    system: str,
    task: str,
    tools: list[Tool],
    model_id: str = DEFAULT_MODEL_ID,
    max_turns: int = MAX_TURNS,
) -> Transcript:
    """Let the agent work until it stops asking for tools.

    Returns everything it did. The caller decides what that means; this
    function has no opinion about the task.
    """
    by_name = {t.name: t for t in tools}
    tool_config = {"tools": [t.spec() for t in tools]}
    messages: list[dict[str, Any]] = [
        {"role": "user", "content": [{"text": task}]}
    ]
    transcript = Transcript()

    for _ in range(max_turns):
        response = client.converse(
            modelId=model_id,
            system=[{"text": system}],
            messages=messages,
            toolConfig=tool_config,
            inferenceConfig={"maxTokens": 2048, "temperature": 0.0},
        )

        message = response["output"]["message"]
        messages.append(message)

        requested = [b["toolUse"] for b in message.get("content", []) if "toolUse" in b]
        for block in message.get("content", []):
            if "text" in block and block["text"].strip():
                transcript.steps.append(Step(kind="text", text=block["text"].strip()))

        if not requested:
            transcript.stopped_because = response.get("stopReason", "end_turn")
            return transcript

        results = []
        for call in requested:
            tool = by_name.get(call["name"])
            if tool is None:
                outcome: Any = {"error": f"no such tool: {call['name']}"}
            else:
                try:
                    outcome = tool.handler(**call.get("input", {}))
                except Exception as exc:  # a bad tool call is the agent's to handle
                    outcome = {"error": f"{type(exc).__name__}: {exc}"}

            transcript.steps.append(
                Step(kind="tool", name=call["name"], args=call.get("input", {}), result=outcome)
            )
            results.append({
                "toolResult": {
                    "toolUseId": call["toolUseId"],
                    "content": [{"json": _jsonable(outcome)}],
                }
            })

        messages.append({"role": "user", "content": results})

    transcript.stopped_because = "max_turns"
    return transcript


def _jsonable(value: Any) -> dict[str, Any]:
    """Bedrock wants a JSON object in a toolResult, not a bare scalar."""
    if isinstance(value, dict):
        return json.loads(json.dumps(value, default=str))
    return {"result": json.loads(json.dumps(value, default=str))}


def bedrock_client(region: str = "us-east-1", profile: str | None = None) -> Converser:
    """A real client. Imported lazily so tests never need boto3 configured."""
    import boto3

    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    return session.client("bedrock-runtime", region_name=region)
