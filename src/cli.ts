#!/usr/bin/env node
import { open } from "node:fs/promises";
import { inspect, compare, type Snapshot, type Invocation } from "./core.js";

const HELP = [
  "Soroban AuthScope — offline Soroban authorization inspector",
  "",
  "Usage:",
  "  authscope inspect <simulation.json> [--json]",
  "  authscope diff <before.json> <after.json> [--json]",
  "  authscope --help",
  "  authscope --version",
  "",
  "Inputs: base64 SorobanAuthorizationEntry strings or stored Stellar RPC simulateTransaction JSON.",
  "Exit codes: 0 success / unchanged; 1 changed scope; 2 malformed input / argument; 3 unsupported or incomplete simulation."
].join("\n");
function format(node: Invocation, level=0): string {
  return "  ".repeat(level) + "- " + node.contract + "." + node.method +
    " (args sha256 " + node.argumentsSha256.slice(0, 12) + "…)" +
    node.children.map(child => "\n" + format(child, level + 1)).join("");
}
function display(snapshot: Snapshot): string {
  const lines = ["Authorization entries: " + snapshot.authorizationCount];
  for (const item of snapshot.entries) {
    lines.push("Authorizer: " + item.authorizer + " (" + item.credential + ")");
    for (const delegate of item.delegates) lines.push("  Delegate: " + delegate);
    lines.push(format(item.root));
  }
  if (!snapshot.entries.length) lines.push("No authorization entries in input; not a safety assessment.");
  return lines.join("\n");
}
async function readSnapshot(path: string): Promise<Snapshot> {
  let handle;
  try { handle = await open(path, "r"); }
  catch { throw Error("Malformed input file"); }
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > 4 * 1024 * 1024) throw Error("Input file exceeds 4 MiB limit");
    const pieces: Uint8Array[] = [];
    const buffer = Buffer.alloc(65536);
    let n = 0;
    while (true) {
      const {bytesRead} = await handle.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      n += bytesRead;
      if (n > 4 * 1024 * 1024) throw Error("Input file exceeds 4 MiB limit");
      pieces.push(Buffer.from(buffer.subarray(0, bytesRead)));
    }
    const text = new TextDecoder("utf-8", {fatal:true}).decode(Buffer.concat(pieces));
    let input: unknown;
    try { input = JSON.parse(text) as unknown; }
    catch { throw Error("Malformed JSON input"); }
    return inspect(input);
  } finally { await handle.close(); }
}
export async function main(args: readonly string[]): Promise<number> {
  if (args.length === 0 || (args.length === 1 && ["--help", "-h"].includes(args[0]!))) {
    console.log(HELP); return 0;
  }
  if (args.length === 1 && args[0] === "--version") { console.log("0.1.0"); return 0; }
  const json = args.includes("--json"), positional = args.filter(x => x !== "--json");
  if (args.filter(x => x === "--json").length > 1 ||
      !((positional[0] === "inspect" && positional.length === 2) ||
        (positional[0] === "diff" && positional.length === 3)) ||
      positional.slice(1).some(x => x.startsWith("-"))) {
    console.error("Usage error. Run authscope --help."); return 2;
  }
  try {
    if (positional[0] === "inspect") {
      const report = await readSnapshot(positional[1]!);
      console.log(json ? JSON.stringify(report, null, 2) : display(report));
      return 0;
    }
    const before = await readSnapshot(positional[1]!), after = await readSnapshot(positional[2]!);
    const result = compare(before, after);
    console.log(json ? JSON.stringify(result, null, 2) :
      (result.changed ? result.changes.map(x => x.kind.toUpperCase() + " x" + x.count +
        " " + x.authorizer + ": " + x.path).join("\n") : "No authorization-scope changes."));
    return result.changed ? 1 : 0;
  } catch (error) {
    // Do not print caller input paths or SDK exceptions containing sensitive data.
    const message = error instanceof Error ? error.message : "";
    if (/Simulation has an error|no auth array|Expected an auth array or simulation results|Expected JSON authorization input/.test(message)) {
      console.error("AuthScope: Unsupported or incomplete simulation; no authorization conclusion.");
      return 3;
    }
    console.error("AuthScope: Malformed input or invalid authorization XDR.");
    return 2;
  }
}
process.exitCode = await main(process.argv.slice(2));
