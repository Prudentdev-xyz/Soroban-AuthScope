import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Address, StrKey, xdr } from "@stellar/stellar-sdk";
import { check } from "../integrations/github-actions/scripts/check.mjs";

const cli = resolve("dist/cli.js");
function auth(method) {
  const scAddress = Address.fromString(StrKey.encodeContract(Buffer.alloc(32, 7))).toScAddress();
  return new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
    rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
        new xdr.InvokeContractArgs({ contractAddress: scAddress, functionName: method, args: [] })
      ), subInvocations: []
    })
  }).toXdr("base64");
}
function fixture(t, before, after) {
  const folder = mkdtempSync(join(tmpdir(), "authscope-action-"));
  t.after(() => rmSync(folder, { recursive: true, force: true }));
  writeFileSync(join(folder, "before.json"), JSON.stringify({ auth: before }));
  writeFileSync(join(folder, "after.json"), JSON.stringify({ auth: after }));
  return { folder, env: {
    AUTHSCOPE_WORKSPACE: folder, AUTHSCOPE_BEFORE: "before.json",
    AUTHSCOPE_AFTER: "after.json", AUTHSCOPE_CLI: cli, RUNNER_TEMP: folder,
    GITHUB_OUTPUT: join(folder, "output.txt"),
    GITHUB_STEP_SUMMARY: join(folder, "summary.md")
  }};
}
test("unchanged scope succeeds and writes machine-readable report/summary", async t => {
  const encoded = auth("withdraw"), { env } = fixture(t, [encoded], [encoded]);
  const result = await check({ env });
  assert.equal(result.exitCode, 0);
  assert.equal(result.changed, false);
  assert.deepEqual(JSON.parse(readFileSync(result.reportPath, "utf8")).changes, []);
  assert.match(readFileSync(env.GITHUB_OUTPUT, "utf8"), /changed=false/);
  assert.match(readFileSync(env.GITHUB_STEP_SUMMARY, "utf8"), /No authorization scope changes/);
});
test("changed scope can fail or run in informational mode", async t => {
  const { env } = fixture(t, [auth("withdraw")], [auth("withdraw"), auth("transfer")]);
  const strict = await check({ env });
  assert.equal(strict.exitCode, 1);
  assert.equal(strict.changed, true);
  assert.equal(strict.additions, 1);
  assert.equal(strict.removals, 0);
  const advisory = await check({ env: { ...env, AUTHSCOPE_FAIL_ON_CHANGE: "false" } });
  assert.equal(advisory.exitCode, 0);
  assert.equal(advisory.changed, true);
});
test("malformed input or missing file fails, never reports clean", async t => {
  const { folder, env } = fixture(t, ["BAD!"], [auth("good")]);
  await assert.rejects(check({ env }), /diff failed/);
  await assert.rejects(check({ env: { ...env, AUTHSCOPE_BEFORE: "missing.json" } }));
  await assert.rejects(check({ env: { ...env, AUTHSCOPE_BEFORE: "../outside.json" } }));
  assert.match(readFileSync(join(folder, "before.json"), "utf8"), /BAD!/);
});
test("invalid gate setting fails explicitly", async t => {
  const { env } = fixture(t, [auth("a")], [auth("b")]);
  await assert.rejects(check({ env: { ...env, AUTHSCOPE_FAIL_ON_CHANGE: "yes" } }),
    /fail-on-change/);
});
