#!/usr/bin/env node
/** Dependency-free structural validator for the published AuthScope JSON Schema v1 fields.
 * Strict fields and lengths mirror schemas/v1/*.schema.json. Runtime-only semantic
 * checks (count equality, bounded recursion) supplement JSON Schema.
 */
import { open } from "node:fs/promises";
import { pathToFileURL } from "node:url";

export const MAX_INPUT_BYTES = 4 * 1024 * 1024;
const MAX_DEPTH = 24, MAX_NODES = 50000, MAX_ERRORS = 12;
const credentials = new Set([
  "sorobanCredentialsSourceAccount", "sorobanCredentialsAddress",
  "sorobanCredentialsAddressV2", "sorobanCredentialsAddressWithDelegates"
]);
const kinds = new Set(["contract", "createContract", "createContractV2"]);
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);

export function validateReport(value, { type = "auto" } = {}) {
  if (!["auto", "snapshot", "comparison"].includes(type)) throw new TypeError("Unknown report type");
  const errors = [];
  const fail = (path, reason) => { if (errors.length < MAX_ERRORS) errors.push(`${path}: ${reason}`); };
  const fields = (value, path, required, optional = []) => {
    if (!object(value)) { fail(path, "expected an object"); return false; }
    for (const key of required) if (!Object.hasOwn(value, key)) fail(`${path}.${key}`, "required field missing");
    for (const key of Object.keys(value)) if (![...required, ...optional].includes(key)) fail(`${path}.${key}`, "unknown field");
    return true;
  };
  const text = (value, path, max) => {
    if (typeof value !== "string" || !value.length || value.length > max) fail(path, `expected nonempty string (max ${max} chars)`);
  };
  const integer = (value, path, min, max = Number.MAX_SAFE_INTEGER) => {
    if (!Number.isSafeInteger(value) || value < min || value > max) fail(path, `expected integer from ${min} to ${max}`);
  };
  if (!object(value)) return { valid: false, type: null, errors: ["$: expected an object"] };
  if (value.schemaVersion !== 1) fail("$.schemaVersion", "unsupported schema version; expected 1");
  const detected = type === "auto" ? (Object.hasOwn(value, "entries") ? "snapshot" :
    Object.hasOwn(value, "changes") ? "comparison" : null) : type;
  if (!detected) fail("$", "cannot determine Snapshot or Comparison format");
  let nodes = 0, delegateNodes = 0;
  const delegateSigner = (node, path, depth) => {
    if (++delegateNodes > MAX_NODES || depth > MAX_DEPTH) { fail(path, "delegate tree exceeds safety limits"); return; }
    if (!fields(node, path, ["address", "children"])) return;
    text(node.address, `${path}.address`, 256);
    if (!Array.isArray(node.children) || node.children.length > 2000) { fail(`${path}.children`, "invalid delegate children"); return; }
    for (let i = 0; i < node.children.length && errors.length < MAX_ERRORS; i++)
      delegateSigner(node.children[i], `${path}.children[${i}]`, depth + 1);
  };
  const invocation = (node, path, depth) => {
    if (++nodes > MAX_NODES) { fail(path, "too many invocation nodes"); return; }
    if (depth > MAX_DEPTH) { fail(path, "invocation depth exceeds 24"); return; }
    if (!fields(node, path, ["kind", "contract", "method", "argumentsSha256", "children"])) return;
    if (!kinds.has(node.kind)) fail(`${path}.kind`, "unknown invocation kind");
    text(node.contract, `${path}.contract`, 256);
    text(node.method, `${path}.method`, 256);
    if (typeof node.argumentsSha256 !== "string" || !/^[a-f0-9]{64}$/.test(node.argumentsSha256))
      fail(`${path}.argumentsSha256`, "expected lowercase SHA-256 hex digest");
    if (!Array.isArray(node.children) || node.children.length > 2000) {
      fail(`${path}.children`, "expected array of at most 2000 nodes"); return;
    }
    for (let i = 0; i < node.children.length && errors.length < MAX_ERRORS; i++) invocation(node.children[i], `${path}.children[${i}]`, depth + 1);
  };
  if (detected === "snapshot") {
    if (fields(value, "$", ["schemaVersion", "authorizationCount", "entries"])) {
      integer(value.authorizationCount, "$.authorizationCount", 0, 128);
      if (!Array.isArray(value.entries) || value.entries.length > 128) fail("$.entries", "expected array of at most 128 entries");
      else {
        if (value.authorizationCount !== value.entries.length) fail("$.authorizationCount", "must equal entries.length");
        for (let i = 0; i < value.entries.length && errors.length < MAX_ERRORS; i++) {
          const entry = value.entries[i], path = `$.entries[${i}]`;
          if (!fields(entry, path, ["credential", "authorizer", "delegates", "root"], ["delegateTree"])) continue;
          if (!credentials.has(entry.credential)) fail(`${path}.credential`, "unknown credential type");
          text(entry.authorizer, `${path}.authorizer`, 256);
          if (!Array.isArray(entry.delegates) || entry.delegates.length > 2000) fail(`${path}.delegates`, "expected array of at most 2000 delegates");
          else entry.delegates.forEach((delegate, j) => text(delegate, `${path}.delegates[${j}]`, 256));
          if (entry.delegateTree !== undefined) {
            if (!Array.isArray(entry.delegateTree) || entry.delegateTree.length > 2000)
              fail(`${path}.delegateTree`, "expected array of at most 2000 delegate signers");
            else for (let j = 0; j < entry.delegateTree.length && errors.length < MAX_ERRORS; j++)
              delegateSigner(entry.delegateTree[j], `${path}.delegateTree[${j}]`, 0);
          }
          invocation(entry.root, `${path}.root`, 0);
        }
      }
    }
  } else if (detected === "comparison") {
    if (fields(value, "$", ["schemaVersion", "changed", "beforeCount", "afterCount", "changes"])) {
      if (typeof value.changed !== "boolean") fail("$.changed", "expected boolean");
      integer(value.beforeCount, "$.beforeCount", 0, 128);
      integer(value.afterCount, "$.afterCount", 0, 128);
      if (!Array.isArray(value.changes) || value.changes.length > 50000) fail("$.changes", "expected array of at most 50000 deltas");
      else {
        if (value.changed !== (value.changes.length !== 0)) fail("$.changed", "must agree with changes.length");
        for (let i = 0; i < value.changes.length && errors.length < MAX_ERRORS; i++) {
          const delta = value.changes[i], path = `$.changes[${i}]`;
          if (!fields(delta, path, ["kind", "authorizer", "path", "count"])) continue;
          if (delta.kind !== "added" && delta.kind !== "removed") fail(`${path}.kind`, "unknown delta kind");
          text(delta.authorizer, `${path}.authorizer`, 262144);
          text(delta.path, `${path}.path`, 32768);
          integer(delta.count, `${path}.count`, 1);
        }
      }
    }
  }
  return { valid: errors.length === 0, type: detected, errors };
}

export async function readBoundedJson(filename) {
  const handle = await open(filename, "r");
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > MAX_INPUT_BYTES) throw Error("Input exceeds 4 MiB limit or is not a file");
    const buffers = [], block = Buffer.alloc(65536);
    let size = 0;
    while (true) {
      const { bytesRead } = await handle.read(block, 0, block.length, null);
      if (!bytesRead) break;
      size += bytesRead;
      if (size > MAX_INPUT_BYTES) throw Error("Input exceeds 4 MiB limit");
      buffers.push(Buffer.from(block.subarray(0, bytesRead)));
    }
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(buffers)));
  } finally { await handle.close(); }
}

export async function main(args) {
  if (args.length === 1 && ["--help", "-h"].includes(args[0])) {
    console.log("Usage: node tools/schema-check/index.mjs <report.json> [--type snapshot|comparison|auto]");
    return 0;
  }
  const validArgs = (args.length === 1 || (args.length === 3 && args[1] === "--type")) &&
    typeof args[0] === "string" && !args[0].startsWith("-") &&
    (args.length === 1 || ["snapshot", "comparison", "auto"].includes(args[2]));
  if (!validArgs) { console.error("Usage: schema-check <report.json> [--type snapshot|comparison|auto]"); return 2; }
  try {
    const data = await readBoundedJson(args[0]);
    const result = validateReport(data, { type: args[2] ?? "auto" });
    if (!result.valid) { console.error(result.errors.join("\n")); return 2; }
    console.log(`Valid AuthScope ${result.type} schemaVersion 1`);
    return 0;
  } catch {
    console.error("Invalid/unreadable JSON or input exceeds 4 MiB; no data was uploaded.");
    return 2;
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main(process.argv.slice(2));
}
