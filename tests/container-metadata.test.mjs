import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const docker = readFileSync("deploy/docker/Dockerfile", "utf8");
const smoke = readFileSync("deploy/docker/smoke.sh", "utf8");
const ignore = readFileSync("deploy/docker/Dockerfile.dockerignore", "utf8");

test("runtime container installs from lockfile and uses non-root user", () => {
  assert.match(docker, /FROM node:22\.\d+\.\d+-bookworm-slim AS builder/);
  assert.match(docker, /npm ci --ignore-scripts/);
  assert.match(docker, /npm prune --omit=dev/);
  assert.match(docker, /USER node/);
  assert.match(docker, /ENTRYPOINT \["node"/);
  assert.doesNotMatch(docker, /(?:curl|wget|git clone|USER root)\b/);
});
test("docker smoke script checks sandbox and genuine CLI behavior", () => {
  for (const flag of ["--network none", "--read-only", "--cap-drop ALL",
    "--security-opt no-new-privileges", ":ro", "--entrypoint id", "missing_status"]) {
    assert.ok(smoke.includes(flag), "missing " + flag);
  }
  assert.match(smoke, /docker build/);
  assert.match(ignore, /!package-lock\.json/);
  assert.doesNotMatch(ignore, /!\.env/);
});
