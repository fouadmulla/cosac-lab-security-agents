"""Trigger shim: wakes an AgentCore runtime.

Neither a CloudWatch Logs subscription nor an EventBridge rule can call
InvokeAgentRuntime, so something has to sit between them. This is that
something, and it is deliberately the smallest thing that can be: it forwards
the event and returns the answer.

No decision is taken here. No AWS resource is touched here. Every tool call,
every policy verdict and every write happens inside the runtime -- which is
the point of moving the agents there, and would be undone by letting this
file grow.
"""

from __future__ import annotations

import json
import os

import boto3

REGION = os.environ.get("AWS_REGION", "us-east-1")
RUNTIME_ARN = os.environ["AGENT_RUNTIME_ARN"]

_client = boto3.client("bedrock-agentcore", region_name=REGION)


def handler(event: dict, _context=None) -> dict:
    response = _client.invoke_agent_runtime(
        agentRuntimeArn=RUNTIME_ARN,
        payload=json.dumps(event or {}).encode(),
        contentType="application/json",
        accept="application/json",
    )

    body = response["response"].read()
    try:
        result = json.loads(body or b"{}")
    except json.JSONDecodeError:
        result = {"raw": body.decode(errors="replace")[:2000]}

    # Straight to the log group the operator already has open.
    print(json.dumps(result, default=str), flush=True)
    return result
