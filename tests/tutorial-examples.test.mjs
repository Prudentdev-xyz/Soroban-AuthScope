import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
function run(script, args) {
  const child = spawnSync(process.execPath, [resolve(root, script), ...args], {
    cwd: root, encoding: "utf8", timeout: 15000,
    env: { ...process.env, NODE_OPTIONS: "" }
  });
  assert.equal(child.error, undefined, child.stderr);
  assert.equal(child.signal, null);
  return child;
}
test("the tutorial generates genuine SDK XDR and demonstrates inspect and diff", t => {
  const folder = mkdtempSync(join(tmpdir(), "authscope-lab-"));
  t.after(() => rmSync(folder, { recursive: true, force: true }));
  const result = run("examples/authscope-lab/generate.mjs", [folder]);
  assert.equal(result.status, 0, result.stderr);
  const before = join(folder, "before.json");
  const after = join(folder, "after.json");
  const same = join(folder, "unchanged.json");
  const beforeData = JSON.parse(readFileSync(before, "utf8"));
  assert.equal(beforeData.auth.length, 1);
  assert.match(beforeData.auth[0], /^[A-Za-z0-9+/=]+$/);
  const inspection = run("dist/cli.js", ["inspect", after, "--json"]);
  assert.equal(inspection.status, 0, inspection.stderr);
  const parsed = JSON.parse(inspection.stdout);
  assert.equal(parsed.entries[0].root.children[0].method, "transfer");
  assert.equal(run("dist/cli.js", ["diff", before, same]).status, 0);
  const changed = run("dist/cli.js", ["diff", before, after, "--json"]);
  assert.equal(changed.status, 1);
  assert.ok(JSON.parse(changed.stdout).changes.some(x =>
    x.kind === "added" && x.path.includes("transfer")));
  assert.doesNotMatch(changed.stdout, /privateKey|secretKey|signatureExpirationLedger/);
});
test("generator refuses missing output directory", () => {
  const r = run("examples/authscope-lab/generate.mjs", []);
  assert.equal(r.status, 2);
});
