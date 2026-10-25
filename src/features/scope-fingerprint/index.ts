import { createHash } from "node:crypto";
import type { Authorization, Invocation, Snapshot } from "../../core.js";

export interface FingerprintItem { fingerprint: string; count: number; sourceIndexes: number[] }
export interface FingerprintDelta { kind: "added" | "removed"; fingerprint: string; count: number; sourceIndexes: number[] }
export interface FingerprintComparison {
  changed: boolean;
  topologyIncomplete: boolean;
  before: FingerprintItem[];
  after: FingerprintItem[];
  changes: FingerprintDelta[];
}
function digest(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function validString(value: unknown): value is string { return typeof value === "string" && value.length > 0; }
function node(value: Invocation, seen: { count: number }, depth = 0): unknown {
  if (!value || typeof value !== "object" || depth > 24 || ++seen.count > 2000 ||
    !["contract", "createContract", "createContractV2"].includes(value.kind) ||
    !validString(value.contract) || !validString(value.method) ||
    !/^[a-f0-9]{64}$/.test(value.argumentsSha256) || !Array.isArray(value.children)) {
    throw Error("Invalid invocation snapshot");
  }
  const children = value.children.map(child => node(child, seen, depth + 1));
  return [value.kind, value.contract, value.method, value.argumentsSha256,
    children.map(digest).sort()];
}
function signer(value: unknown, counter: { n: number }, depth = 0): unknown {
  if (!value || typeof value !== "object" || depth > 24 || ++counter.n > 2000) throw Error("Invalid delegate topology");
  const item = value as { address?: unknown; children?: unknown };
  if (!validString(item.address) || !Array.isArray(item.children) || item.children.length > 2000) {
    throw Error("Invalid delegate topology");
  }
  return [item.address, item.children.map(child => signer(child, counter, depth + 1)).map(digest).sort()];
}
function fingerprint(entry: Authorization): string {
  if (!validString(entry.credential) || !validString(entry.authorizer) ||
    !Array.isArray(entry.delegates) || entry.delegates.some(x => !validString(x))) {
    throw Error("Invalid authorization snapshot");
  }
  const signerCounter = { n: 0 };
  const topology = entry.delegateTree === undefined ? ["legacy", [...entry.delegates].sort()] :
    ["hierarchy", entry.delegateTree.map(x => signer(x, signerCounter)).map(digest).sort()];
  return digest([entry.credential, entry.authorizer, topology, node(entry.root, { count: 0 })]);
}
export function fingerprintSnapshot(snapshot: Snapshot): FingerprintItem[] {
  if (!snapshot || snapshot.schemaVersion !== 1 || !Array.isArray(snapshot.entries) ||
    snapshot.entries.length > 128 || snapshot.authorizationCount !== snapshot.entries.length) {
    throw Error("Invalid snapshot counts or schema");
  }
  const items = new Map<string, FingerprintItem>();
  snapshot.entries.forEach((entry, index) => {
    const key = fingerprint(entry);
    const existing = items.get(key);
    if (existing) { existing.count++; existing.sourceIndexes.push(index); }
    else items.set(key, { fingerprint: key, count: 1, sourceIndexes: [index] });
  });
  return [...items.values()].sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
}
/** Compares unordered root multisets; sibling order is immaterial, nesting and counts are material. */
export function compareFingerprints(before: Snapshot, after: Snapshot): FingerprintComparison {
  const a = fingerprintSnapshot(before), b = fingerprintSnapshot(after);
  const old = new Map(a.map(x => [x.fingerprint, x]));
  const next = new Map(b.map(x => [x.fingerprint, x]));
  const changes: FingerprintDelta[] = [];
  for (const key of [...new Set([...old.keys(), ...next.keys()])].sort()) {
    const difference = (next.get(key)?.count ?? 0) - (old.get(key)?.count ?? 0);
    if (difference) {
      const source = difference > 0 ? next.get(key)! : old.get(key)!;
      changes.push({ kind: difference > 0 ? "added" : "removed", fingerprint: key,
        count: Math.abs(difference), sourceIndexes: source.sourceIndexes });
    }
  }
  return { changed: changes.length > 0,
    topologyIncomplete: [...before.entries, ...after.entries].some(x => x.delegateTree === undefined),
    before: a, after: b, changes };
}
