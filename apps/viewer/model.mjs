/** AuthScope v1 browser-only model: no network, XDR decoding, storage or eval. */
export const MAX_BYTES = 4 * 1024 * 1024;
const MAX_DEPTH = 24, MAX_NODES = 50000;
const credentials = new Set(["sorobanCredentialsSourceAccount", "sorobanCredentialsAddress",
  "sorobanCredentialsAddressV2", "sorobanCredentialsAddressWithDelegates"]);
const kinds = new Set(["contract", "createContract", "createContractV2"]);
const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
const fields = (value, names, optional = []) => object(value) &&
  Object.keys(value).every(name => names.includes(name) || optional.includes(name)) &&
  names.every(name => Object.hasOwn(value, name));
const text = (value, max) => typeof value === "string" && value.length > 0 && value.length <= max;
const count = (value, min, max) => Number.isSafeInteger(value) && value >= min && value <= max;

export function validateLocalReport(value) {
  if (!object(value)) throw Error("Report must be a JSON object.");
  if (value.schemaVersion !== 1) throw Error("Unsupported schemaVersion; expected 1.");
  if (Object.hasOwn(value, "entries")) {
    if (!fields(value, ["schemaVersion", "authorizationCount", "entries"]) ||
        !Array.isArray(value.entries) || value.entries.length > 128 ||
        !count(value.authorizationCount, 0, 128) || value.authorizationCount !== value.entries.length)
      throw Error("Invalid Snapshot fields or authorization count.");
    let nodes = 0, delegateNodes = 0;
    function signer(node, depth) {
      if (++delegateNodes > MAX_NODES || depth > MAX_DEPTH) throw Error("Delegate tree exceeds safety limits.");
      if (!fields(node, ["address", "children"]) || !text(node.address, 256) ||
          !Array.isArray(node.children) || node.children.length > 2000) throw Error("Invalid delegate tree node.");
      node.children.forEach(child => signer(child, depth + 1));
    }
    function invocation(node, depth) {
      if (++nodes > MAX_NODES || depth > MAX_DEPTH) throw Error("Invocation tree exceeds safety limits.");
      if (!fields(node, ["kind", "contract", "method", "argumentsSha256", "children"]) ||
          !kinds.has(node.kind) || !text(node.contract, 256) || !text(node.method, 256) ||
          typeof node.argumentsSha256 !== "string" || !/^[a-f0-9]{64}$/.test(node.argumentsSha256) ||
          !Array.isArray(node.children) || node.children.length > 2000)
        throw Error("Invalid invocation tree node.");
      node.children.forEach(child => invocation(child, depth + 1));
    }
    for (const entry of value.entries) {
      if (!fields(entry, ["credential", "authorizer", "delegates", "root"], ["delegateTree"]) ||
          !credentials.has(entry.credential) || !text(entry.authorizer, 256) ||
          !Array.isArray(entry.delegates) || entry.delegates.length > 2000 ||
          !entry.delegates.every(delegate => text(delegate, 256)))
        throw Error("Invalid authorization entry or missing credential.");
      if (entry.delegateTree !== undefined) {
        if (!Array.isArray(entry.delegateTree) || entry.delegateTree.length > 2000) throw Error("Invalid delegateTree.");
        entry.delegateTree.forEach(root => signer(root, 0));
      }
      invocation(entry.root, 0);
    }
    return "snapshot";
  }
  if (Object.hasOwn(value, "changes")) {
    if (!fields(value, ["schemaVersion", "changed", "beforeCount", "afterCount", "changes"]) ||
        typeof value.changed !== "boolean" || !count(value.beforeCount, 0, 128) ||
        !count(value.afterCount, 0, 128) || !Array.isArray(value.changes) ||
        value.changes.length > 50000 || value.changed !== (value.changes.length > 0))
      throw Error("Invalid Comparison fields or changed flag.");
    for (const delta of value.changes) {
      if (!fields(delta, ["kind", "authorizer", "path", "count"]) ||
          !["added", "removed"].includes(delta.kind) || !text(delta.authorizer, 262144) ||
          !text(delta.path, 32768) || !count(delta.count, 1, Number.MAX_SAFE_INTEGER))
        throw Error("Invalid scope delta.");
    }
    return "comparison";
  }
  throw Error("Not a v1 Snapshot or Comparison report.");
}

export async function readLocalFile(file, expectedType) {
  if (!file || !text(file.name, 255) || !/\.json$/i.test(file.name) ||
      !count(file.size, 0, MAX_BYTES) ||
      (file.type && !["application/json", "text/plain", "application/octet-stream"].includes(file.type)))
    throw Error("Choose a JSON file up to 4 MiB.");
  const content = await file.text(); // Browser File API, never upload or persist.
  if (new TextEncoder().encode(content).length > MAX_BYTES) throw Error("File is larger than 4 MiB.");
  let parsed;
  try { parsed = JSON.parse(content); }
  catch { throw Error("Malformed JSON file."); }
  const type = validateLocalReport(parsed);
  if (type !== expectedType) throw Error(`Expected a ${expectedType} JSON report.`);
  return parsed;
}

function canonicalSigners(values) {
  return values.map(value => [value.address,canonicalSigners(value.children)])
    .sort((a,b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
}
const identity = entry => JSON.stringify([entry.credential, entry.authorizer,
  entry.delegateTree === undefined ? [...entry.delegates].sort() : canonicalSigners(entry.delegateTree)]);
const step = node => JSON.stringify([node.kind, node.contract, node.method, node.argumentsSha256]);

function allCalls(snapshot) {
  const rows = [];
  for (const entry of snapshot?.entries ?? []) {
    const authorizer = identity(entry);
    function visit(node, parents, depth) {
      const steps = [...parents, step(node)], path = steps.join(" > ");
      rows.push({ authorizer, path, node, depth });
      for (const child of node.children) visit(child, steps, depth + 1);
    }
    visit(entry.root, [], 0);
  }
  return rows;
}
const keyOf = call => JSON.stringify([call.authorizer, call.path]);
function totals(rows) {
  const map = new Map();
  for (const row of rows) { const key = keyOf(row); map.set(key, (map.get(key) ?? 0) + 1); }
  return map;
}

/** Mirrors the multiset comparison used by core.ts, including nested paths. */
export function compareSnapshots(before, after) {
  validateLocalReport(before); validateLocalReport(after);
  const a = totals(allCalls(before)), b = totals(allCalls(after));
  const keys = new Set([...a.keys(), ...b.keys()]), changes = [];
  for (const key of keys) {
    const difference = (b.get(key) ?? 0) - (a.get(key) ?? 0);
    if (!difference) continue;
    const [authorizer, path] = JSON.parse(key);
    changes.push({ kind: difference > 0 ? "added" : "removed", authorizer, path, count: Math.abs(difference) });
  }
  changes.sort((x,y) => JSON.stringify(x).localeCompare(JSON.stringify(y)));
  return {schemaVersion: 1, changed: changes.length > 0,
    beforeCount: before.authorizationCount, afterCount: after.authorizationCount, changes};
}

export function annotatedEntries(snapshot, other, direction) {
  if (!snapshot) return [];
  const otherTotals = other ? totals(allCalls(other)) : null;
  const seen = new Map();
  function nodeView(node, authorizer, parents) {
    const steps = [...parents, step(node)], key = JSON.stringify([authorizer, steps.join(" > ")]);
    const ordinal = (seen.get(key) ?? 0) + 1;
    seen.set(key, ordinal);
    const status = otherTotals === null ? "neutral" : ordinal > (otherTotals.get(key) ?? 0) ? direction : "unchanged";
    return {status, kind: node.kind, contract: node.contract, method: node.method,
      argumentsSha256: node.argumentsSha256, children: node.children.map(child => nodeView(child, authorizer, steps))};
  }
  return snapshot.entries.map(entry => ({credential: entry.credential, authorizer: entry.authorizer,
    delegates: [...entry.delegates], delegateTree: entry.delegateTree ?? [],
    root: nodeView(entry.root, identity(entry), [])}));
}

export function resolveView(before, after, comparison) {
  const generated = before && after ? compareSnapshots(before, after) : null;
  if (comparison && generated) {
    const order = changes => [...changes].sort((a,b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
    if (comparison.beforeCount !== generated.beforeCount || comparison.afterCount !== generated.afterCount ||
        JSON.stringify(order(comparison.changes)) !== JSON.stringify(generated.changes))
      throw Error("Loaded comparison does not match the two snapshots.");
  }
  const report = comparison ?? generated;
  return { before: annotatedEntries(before, after, "removed"),
    after: annotatedEntries(after, before, "added"), comparison: report,
    additions: report?.changes.filter(x => x.kind === "added") ?? [],
    removals: report?.changes.filter(x => x.kind === "removed") ?? [] };
}

/** Read a v1 tuple path without evaluating code; preserves quoted separators. */
export function pathLabel(path) {
  try {
    const result = [], pattern = /\[(?:"(?:\\.|[^"\\])*"(?:,"(?:\\.|[^"\\])*"){3})\]/gy;
    let offset = 0;
    while (offset < path.length && result.length < 25) {
      pattern.lastIndex = offset;
      const match = pattern.exec(path);
      if (!match) return "Invocation path metadata unavailable";
      const item = JSON.parse(match[0]);
      result.push(`${item[1]}.${item[2]}`);
      offset = pattern.lastIndex;
      if (offset < path.length) {
        if (path.slice(offset, offset + 3) !== " > ") return "Invocation path metadata unavailable";
        offset += 3;
      }
    }
    return offset === path.length && result.length ? result.join(" → ") : "Invocation path metadata unavailable";
  } catch { return "Invocation path metadata unavailable"; }
}
