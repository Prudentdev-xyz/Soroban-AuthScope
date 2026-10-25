import { createHash } from "node:crypto";
import { Address, xdr } from "@stellar/stellar-sdk";
import { normalizeSimulation } from "./features/simulation-normalizer/index.js";

/** Read-only, offline summaries. Signatures, nonces and raw args never appear in reports. */
export interface Invocation {
  kind: "contract" | "createContract" | "createContractV2";
  contract: string;
  method: string;
  argumentsSha256: string;
  children: Invocation[];
}
export interface Authorization {
  credential: string;
  authorizer: string;
  delegates: string[];
  /** Hierarchical signers, absent only in snapshots written before this field existed. */
  delegateTree?: DelegateSigner[];
  root: Invocation;
}
export interface DelegateSigner { address: string; children: DelegateSigner[] }
export interface Snapshot {
  schemaVersion: 1;
  authorizationCount: number;
  entries: Authorization[];
}
export interface ScopeDelta {
  kind: "added" | "removed";
  authorizer: string;
  path: string;
  count: number;
}
export interface Comparison {
  schemaVersion: 1;
  changed: boolean;
  beforeCount: number;
  afterCount: number;
  changes: ScopeDelta[];
}
const MAX_ENTRIES = 128, MAX_ENTRY_BYTES = 128 * 1024, MAX_DEPTH = 24, MAX_NODES = 2000;
function addr(value: xdr.ScAddress): string {
  try { return Address.fromScAddress(value).toString(); }
  catch { throw Error("Unsupported SCAddress variant"); }
}
function hash(parts: readonly Uint8Array[]): string {
  const hasher = createHash("sha256");
  for (const part of parts) {
    const length = Buffer.alloc(4);
    length.writeUInt32BE(part.length);
    hasher.update(length);
    hasher.update(part);
  }
  return hasher.digest("hex");
}
function tree(node: xdr.SorobanAuthorizedInvocation, depth: number, counter: { n: number }): Invocation {
  counter.n++;
  if (depth > MAX_DEPTH || counter.n > MAX_NODES) throw Error("Authorization tree exceeds safety limits");
  const fn = node.function;
  let details: Omit<Invocation, "children">;
  if (fn.type === "sorobanAuthorizedFunctionTypeContractFn") {
    const value = fn.value as xdr.InvokeContractArgs;
    details = {
      kind: "contract", contract: addr(value.contractAddress),
      method: value.functionName.toString(),
      argumentsSha256: hash(value.args.map(a => a.toXdr()))
    };
  } else if (fn.type === "sorobanAuthorizedFunctionTypeCreateContractHostFn") {
    details = {
      kind: "createContract", contract: "(contract creation)", method: "createContract",
      argumentsSha256: hash([(fn.value as xdr.CreateContractArgs).toXdr()])
    };
  } else if (fn.type === "sorobanAuthorizedFunctionTypeCreateContractV2HostFn") {
    details = {
      kind: "createContractV2", contract: "(contract creation)", method: "createContractV2",
      argumentsSha256: hash([(fn.value as xdr.CreateContractArgsV2).toXdr()])
    };
  } else throw Error("Unsupported SorobanAuthorizedFunction variant");
  return {
    ...details,
    children: node.subInvocations.map(child => tree(child, depth + 1, counter))
  };
}
function signerTree(value: xdr.SorobanDelegateSignature, depth: number, counter: { n: number }): DelegateSigner {
  counter.n++;
  if (depth > MAX_DEPTH || counter.n > MAX_NODES) throw Error("Delegate tree exceeds safety limits");
  return { address: addr(value.address),
    children: value.nestedDelegates.map(next => signerTree(next, depth + 1, counter)) };
}
function flattenSigner(value: DelegateSigner): string[] {
  return [value.address, ...value.children.flatMap(flattenSigner)];
}
function canonicalSigners(values: DelegateSigner[]): unknown[] {
  return values.map(value => [value.address, canonicalSigners(value.children)])
    .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
}
function parseBase64(text: string): Authorization {
  if (text.length > Math.ceil(MAX_ENTRY_BYTES / 3) * 4 + 8 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text)) {
    throw Error("Invalid authorization base64");
  }
  const bytes = Buffer.from(text, "base64");
  if (!bytes.length || bytes.length > MAX_ENTRY_BYTES || bytes.toString("base64") !== text) {
    throw Error("Invalid or oversized authorization base64");
  }
  let entry: xdr.SorobanAuthorizationEntry;
  try { entry = xdr.SorobanAuthorizationEntry.fromXdr(bytes); }
  catch { throw Error("Invalid SorobanAuthorizationEntry XDR"); }
  const credential = entry.credentials;
  let authorizer = "transaction source";
  let delegates: string[] = [];
  let delegateTree: DelegateSigner[] = [];
  if (credential.type === "sorobanCredentialsAddress" ||
      credential.type === "sorobanCredentialsAddressV2") {
    authorizer = addr((credential.value as xdr.SorobanAddressCredentials).address);
  } else if (credential.type === "sorobanCredentialsAddressWithDelegates") {
    const value = credential.value as xdr.SorobanAddressCredentialsWithDelegates;
    authorizer = addr(value.addressCredentials.address);
    const counter = { n: 0 };
    delegateTree = value.delegates.map(d => signerTree(d, 0, counter));
    delegates = delegateTree.flatMap(flattenSigner);
  } else if (credential.type !== "sorobanCredentialsSourceAccount") {
    throw Error("Unsupported SorobanCredentials variant");
  }
  return {
    credential: credential.type, authorizer, delegates, delegateTree,
    root: tree(entry.rootInvocation, 0, { n: 0 })
  };
}
export function extractAuth(input: unknown): string[] {
  const entries = normalizeSimulation(input).authorizations;
  if (entries.length > MAX_ENTRIES) throw Error("Too many authorization entries");
  return entries;
}
export function inspect(input: unknown): Snapshot {
  const data = extractAuth(input);
  return { schemaVersion: 1, authorizationCount: data.length, entries: data.map(parseBase64) };
}
function count(snapshot: Snapshot): Map<string, { authorizer: string; path: string; total: number }> {
  const map = new Map<string, { authorizer: string; path: string; total: number }>();
  for (const entry of snapshot.entries) {
    const identity = JSON.stringify([entry.credential, entry.authorizer,
      entry.delegateTree === undefined ? [...entry.delegates].sort() : canonicalSigners(entry.delegateTree)]);
    function visit(node: Invocation, ancestors: readonly string[]): void {
      const step = JSON.stringify([node.kind, node.contract, node.method, node.argumentsSha256]);
      const path = [...ancestors, step];
      const key = JSON.stringify([identity, path]);
      const old = map.get(key);
      map.set(key, { authorizer: identity, path: path.join(" > "), total: (old?.total ?? 0) + 1 });
      for (const child of node.children) visit(child, path);
    }
    visit(entry.root, []);
  }
  return map;
}
/** Multiset comparison ignores signature, nonce and root ordering, but includes call hierarchy. */
export function compare(before: Snapshot, after: Snapshot): Comparison {
  const a = count(before), b = count(after);
  const changes: ScopeDelta[] = [];
  for (const key of new Set([...a.keys(), ...b.keys()])) {
    const old = a.get(key), next = b.get(key), difference = (next?.total ?? 0) - (old?.total ?? 0);
    if (!difference) continue;
    const data = difference > 0 ? next : old;
    if (!data) throw Error("Scope comparison failure");
    changes.push({
      kind: difference > 0 ? "added" : "removed",
      authorizer: data.authorizer, path: data.path, count: Math.abs(difference)
    });
  }
  changes.sort((x,y) => JSON.stringify(x).localeCompare(JSON.stringify(y)));
  return {
    schemaVersion: 1, changed: changes.length !== 0,
    beforeCount: before.authorizationCount, afterCount: after.authorizationCount,
    changes
  };
}
