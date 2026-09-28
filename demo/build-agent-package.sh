#!/usr/bin/env bash
# Build the AgentCore package.
#
# AgentCore's Python runtime does NOT provide boto3 -- unlike Lambda -- so it
# is vendored here. Discovered by deploying a runtime without it and reading
# ModuleNotFoundError out of CloudWatch, because it is not in the reference.
#
# Produces the identical archive for every agent. Which one a runtime is comes
# from AGENT_KIND in its environment, so all four deploy the same bytes.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
build="$here/.build/agentcore"
out="$1"

rm -rf "$build"
mkdir -p "$build" "$(dirname "$out")"

# serve.py at the archive root: entry_point is resolved relative to /var/task.
cp "$here/agents/serve.py" "$build/serve.py"

# the agents package, importable as `agents.*`
mkdir -p "$build/agents"
( cd "$here/agents" && find . -name '*.py' -not -path '*/__pycache__/*' -exec cp --parents {} "$build/agents/" \; )

python -m pip install boto3 --target "$build" --quiet --no-compile --disable-pip-version-check

( cd "$build" && python -c "
import shutil, sys, os
shutil.make_archive(sys.argv[1][:-4], 'zip', '.')
print('package: %.1f MB' % (os.path.getsize(sys.argv[1]) / 1e6))
" "$out" )
