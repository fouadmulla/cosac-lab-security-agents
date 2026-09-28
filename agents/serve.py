"""AgentCore Runtime entrypoint.

AgentCore runs this as a long-lived process and speaks HTTP to it:

    GET  /ping          must answer {"status": "Healthy"}
    POST /invocations   the payload, and whatever the agent returns

That is the whole contract. The `bedrock_agentcore` SDK exists to provide it,
but it only wraps an HTTP server, so this uses the standard library instead
and the package vendors nothing but boto3.

Determined empirically against a live runtime, because none of it is in the
CLI reference:
  - code unpacks to /var/task, as in Lambda
  - boto3 is NOT provided, unlike Lambda, and must be vendored
  - a plain http.server satisfies the contract

All four agents run this same file. Which one it is comes from AGENT_KIND, so
that the identical package is deployed four times and only the environment
differs -- which is the claim the whole demonstration rests on.
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# The runtime unpacks the archive here; the agents package sits inside it.
sys.path.insert(0, "/var/task")

PORT = int(os.environ.get("PORT", "8080"))
AGENT_KIND = os.environ.get("AGENT_KIND", "warden").lower()


def _dispatch(payload: dict) -> dict:
    """Hand the payload to whichever agent this runtime is.

    Imported lazily so that a configuration error in one agent cannot stop
    the other from starting, and so that /ping keeps answering even if the
    agent itself is broken -- a runtime that fails its health check is a
    runtime nobody can read the logs of.
    """
    if AGENT_KIND == "custodian":
        from agents.custodian.handler import handler
    else:
        from agents.warden.handler import handler
    return handler(payload, None)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802
        if self.path.rstrip("/") == "/ping":
            self._respond(200, {"status": "Healthy"})
        else:
            self._respond(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        if self.path.rstrip("/") != "/invocations":
            self._respond(404, {"error": "not found"})
            return

        length = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(length) or "{}")
        except json.JSONDecodeError:
            payload = {}

        try:
            result = _dispatch(payload if isinstance(payload, dict) else {})
            self._respond(200, result)
        except Exception as exc:
            # Return the failure rather than dropping the connection, so the
            # caller sees why instead of a timeout.
            traceback.print_exc()
            self._respond(500, {"error": f"{type(exc).__name__}: {exc}"})

    def _respond(self, status: int, body: dict) -> None:
        raw = json.dumps(body, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt, *args):
        # Straight to stdout, which is what reaches CloudWatch.
        print(fmt % args, flush=True)


def main() -> None:
    print(f"agentcore runtime up: kind={AGENT_KIND} port={PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
