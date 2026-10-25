#!/usr/bin/env node
/** Offline composite-action driver; never evaluates shell input or accesses RPC. */
import { spawnSync } from "node:child_process";
import { appendFile, mkdtemp, realpath, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const self = fileURLToPath(import.meta.url);
const cliDefault = resolve(dirname(self), "../../../dist/cli.js");
function inside(root, path) {
  const r = relative(root, path);
  return r === "" || (r !== ".." && !r.startsWith(".." + sep) && !isAbsolute(r));
}
export async function check({ env = process.env, invoke = spawnSync } = {}) {
  const { AUTHSCOPE_WORKSPACE: workspace, AUTHSCOPE_BEFORE: before,
    AUTHSCOPE_AFTER: after } = env;
  const failOnChange = env.AUTHSCOPE_FAIL_ON_CHANGE ?? "true";
  if (!workspace || !before || !after || !["true", "false"].includes(failOnChange)) {
    throw new Error("Invalid workspace, snapshot path or fail-on-change flag");
  }
  const root = await realpath(workspace);
  async function checkPath(p) {
    const absolute = resolve(root, p);
    if (!inside(root, absolute) || !inside(root, await realpath(absolute))) {
      throw new Error("Input is outside the checked-out workspace");
    }
    return absolute;
  }
  const [left, right] = await Promise.all([checkPath(before), checkPath(after)]);
  const child = invoke(process.execPath,
    [env.AUTHSCOPE_CLI ?? cliDefault, "diff", left, right, "--json"], {
      cwd: root, encoding: "utf8", timeout: 20000, maxBuffer: 4 * 1024 * 1024,
      env: { ...process.env, NODE_OPTIONS: "" }
    });
  if (child.error || child.signal || ![0, 1].includes(child.status)) {
    throw new Error("AuthScope diff failed: malformed or unsupported authorization input");
  }
  let result;
  try { result = JSON.parse(child.stdout); }
  catch { throw new Error("Diff output is not valid JSON"); }
  if (result?.schemaVersion !== 1 || !Array.isArray(result.changes) ||
      typeof result.changed !== "boolean" || result.changed !== (child.status === 1)) {
    throw new Error("Unexpected AuthScope diff schema");
  }
  const added = result.changes.filter(x => x.kind === "added").length;
  const removed = result.changes.filter(x => x.kind === "removed").length;
  const temp = await mkdtemp(join(env.RUNNER_TEMP || tmpdir(), "authscope-report-"));
  const reportFile = join(temp, "diff.json");
  await writeFile(reportFile, JSON.stringify(result, null, 2) + "\n", { mode: 0o600 });
  if (env.GITHUB_OUTPUT) {
    await appendFile(env.GITHUB_OUTPUT, [
      "changed=" + result.changed,
      "additions=" + added,
      "removals=" + removed,
      "report-path=" + reportFile, ""
    ].join("\n"));
  }
  if (env.GITHUB_STEP_SUMMARY) {
    await appendFile(env.GITHUB_STEP_SUMMARY,
      "## Soroban AuthScope\n\n" +
      (result.changed ? "Authorization scope changes detected: review required.\n\n" :
                        "No authorization scope changes detected.\n\n") +
      "| Added paths | Removed paths |\n|---:|---:|\n|" +
      added + "|" + removed + "|\n\n" +
      "Scope changes are **not** proof of a security vulnerability.\n");
  }
  return {
    changed: result.changed, additions: added, removals: removed, reportPath: reportFile,
    exitCode: result.changed && failOnChange === "true" ? 1 : 0
  };
}
if (process.argv[1] && resolve(process.argv[1]) === self) {
  try {
    const result = await check();
    console.log("AuthScope: " + (result.changed ? "scope changed" : "scope unchanged") +
      "; report written locally");
    process.exitCode = result.exitCode;
  } catch {
    console.error("AuthScope: cannot evaluate authorization snapshots; no clean result was issued.");
    process.exitCode = 2;
  }
}
