#!/usr/bin/env bash
# Reproducible end-to-end Docker smoke, no real RPC access or signing.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image="soraforge/authscope:local-smoke"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
chmod 755 "$tmp"
node "$root/deploy/docker/fixtures/create.mjs" "$tmp"
docker build -f "$root/deploy/docker/Dockerfile" -t "$image" "$root"
options=(--rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges)
mount=(-v "$tmp:/input:ro")
owner="$(docker run "${options[@]}" --entrypoint id "$image" -u)"
test "$owner" = "1000"
docker run "${options[@]}" "$image" --help | grep -q 'authscope inspect'
docker run "${options[@]}" "$image" --version | grep -q '^0.1.0$'
docker run "${options[@]}" "${mount[@]}" "$image" inspect /input/empty.json | grep -qi 'not a safety assessment'
docker run "${options[@]}" "${mount[@]}" "$image" inspect /input/before.json --json | grep -q 'withdraw'
docker run "${options[@]}" "${mount[@]}" "$image" diff /input/before.json /input/before.json --json | grep -q '"changed": false'
set +e
docker run "${options[@]}" "${mount[@]}" "$image" diff /input/before.json /input/after.json --json > "$tmp/diff.json"
status=$?
docker run "${options[@]}" "${mount[@]}" "$image" inspect /input/not-here.json > /dev/null 2>&1
missing_status=$?
set -e
test "$status" -eq 1
test "$missing_status" -eq 2
grep -q '"changed": true' "$tmp/diff.json"
echo "Docker smoke passed: uid 1000, offline, read-only, inspect, diff and invalid input."
