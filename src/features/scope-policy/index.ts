import { createHash } from "node:crypto";
import type { Comparison, ScopeDelta } from "../../core.js";

export interface PolicyAuthorizer {
  credential: string;
  authorizer: string;
  /** Legacy v1 reports without delegateTree use a sorted flat list. */
  delegates?: string[];
  /** Current v1 comparison identities preserve hierarchical delegate signers. */
  delegateTree?: PolicyDelegateSigner[];
}
export interface PolicyDelegateSigner { address: string; children: PolicyDelegateSigner[] }
export interface PolicyContract {
  address: string;
  functions: string[];
}
export interface ScopePolicy {
  schemaVersion: 1;
  allowedAuthorizers?: PolicyAuthorizer[];
  allowedContracts?: PolicyContract[];
  blockUnapprovedAuthorizers?: boolean;
  blockUnapprovedContracts?: boolean;
  maxAddedOccurrencesPerPath?: number;
  allowRemovals?: boolean;
}
export type Decision = "approved" | "review" | "blocked";
export interface PolicyFinding {
  id: string;
  decision: Decision;
  ruleIds: string[];
  message: string;
  change: ScopeDelta;
}
export interface PolicyResult {
  decision: Decision;
  findings: PolicyFinding[];
  summary: string;
}
type ParsedCall = { kind: string; contract: string; method: string; fingerprint: string };
const allowedPolicyFields = new Set(["schemaVersion", "allowedAuthorizers", "allowedContracts",
  "blockUnapprovedAuthorizers", "blockUnapprovedContracts", "maxAddedOccurrencesPerPath", "allowRemovals"]);
const object = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);
function exactText(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 256 &&
    !/[\x00-\x1f*?]/.test(value) && value.trim() === value;
}
function validDelegateTree(value: unknown, depth = 0, budget = {nodes:0}): value is PolicyDelegateSigner[] {
  if (!Array.isArray(value) || value.length > 2000 || depth > 24) return false;
  return value.every(node => {
    if (++budget.nodes > 2000 || !object(node) ||
        Object.keys(node).sort().join(",") !== "address,children" || !exactText(node.address)) return false;
    return validDelegateTree(node.children, depth + 1, budget);
  });
}
function canonicalSigners(values: PolicyDelegateSigner[]): unknown[] {
  return values.map(node => [node.address, canonicalSigners(node.children)])
    .sort((a,b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
}
function parsedIdentity(value: unknown): PolicyAuthorizer | null {
  try {
    const tuple: unknown = JSON.parse(value as string);
    if (!Array.isArray(tuple) || tuple.length !== 3 ||
        !exactText(tuple[0]) || !exactText(tuple[1]) ||
        !Array.isArray(tuple[2])) return null;
    if (tuple[2].every(exactText))
      return { credential: tuple[0], authorizer: tuple[1], delegates: tuple[2] };
    let nodes = 0;
    function decodeTree(value: unknown, depth: number): PolicyDelegateSigner | null {
      if (++nodes > 2000 || depth > 24 || !Array.isArray(value) || value.length !== 2 ||
          !exactText(value[0]) || !Array.isArray(value[1])) return null;
      const children = value[1].map((child: unknown) => decodeTree(child, depth + 1));
      if (children.some((child: PolicyDelegateSigner | null) => child === null)) return null;
      return {address:value[0],children:children as PolicyDelegateSigner[]};
    }
    const tree = tuple[2].map((node: unknown) => decodeTree(node, 0));
    if (tree.some((node: PolicyDelegateSigner | null) => node === null)) return null;
    return { credential: tuple[0], authorizer: tuple[1], delegateTree: tree as PolicyDelegateSigner[] };
  } catch { return null; }
}
/** Decoder for the v1 JSON tuple path representation, including quoted separators. */
function parsedPath(value: unknown): ParsedCall[] | null {
  if (typeof value !== "string" || !value.length || value.length > 32768) return null;
  const calls: ParsedCall[] = [];
  let start = 0;
  try {
    while (start < value.length && calls.length <= 24) {
      if (value[start] !== "[") return null;
      let quoted = false, escaped = false, depth = 0, end = -1;
      for (let i = start; i < value.length; i++) {
        const char = value[i];
        if (quoted) {
          if (escaped) escaped = false;
          else if (char === "\\") escaped = true;
          else if (char === '"') quoted = false;
        } else if (char === '"') quoted = true;
        else if (char === "[") depth++;
        else if (char === "]" && --depth === 0) { end = i + 1; break; }
      }
      if (end < 0) return null;
      const tuple: unknown = JSON.parse(value.slice(start, end));
      if (!Array.isArray(tuple) || tuple.length !== 4 || !tuple.every(exactText)) return null;
      calls.push({kind:tuple[0]!,contract:tuple[1]!,method:tuple[2]!,fingerprint:tuple[3]!});
      start = end;
      if (start < value.length) {
        if (value.slice(start, start + 3) !== " > ") return null;
        start += 3;
      }
    }
    return start === value.length && calls.length > 0 && calls.length <= 25 ? calls : null;
  } catch { return null; }
}
function normalizedIdentity(identity: PolicyAuthorizer): string {
  return JSON.stringify([identity.credential, identity.authorizer,
    identity.delegateTree !== undefined ? canonicalSigners(identity.delegateTree) : [...identity.delegates!].sort()]);
}

/** Reject ambiguous policy definitions up front; there is deliberately no wildcard matching. */
export function validatePolicy(input: unknown): ScopePolicy {
  if (!object(input) || input.schemaVersion !== 1 ||
      Object.keys(input).some(field => !allowedPolicyFields.has(field))) throw TypeError("Invalid policy or unsupported policy version");
  for (const flag of ["blockUnapprovedAuthorizers", "blockUnapprovedContracts", "allowRemovals"])
    if (input[flag] !== undefined && typeof input[flag] !== "boolean") throw TypeError(`Invalid ${flag}`);
  if (input.maxAddedOccurrencesPerPath !== undefined &&
      (!Number.isSafeInteger(input.maxAddedOccurrencesPerPath) || (input.maxAddedOccurrencesPerPath as number) < 1 ||
        (input.maxAddedOccurrencesPerPath as number) > 100000)) throw TypeError("Invalid maxAddedOccurrencesPerPath");
  if (input.allowedAuthorizers !== undefined) {
    if (!Array.isArray(input.allowedAuthorizers) || !input.allowedAuthorizers.length || input.allowedAuthorizers.length > 256)
      throw TypeError("allowedAuthorizers must be a nonempty bounded list");
    for (const entry of input.allowedAuthorizers) {
      if (!object(entry) || !exactText(entry.credential) || !exactText(entry.authorizer) ||
          !["authorizer,credential,delegates", "authorizer,credential,delegateTree"].includes(Object.keys(entry).sort().join(",")) ||
          !(entry.delegates !== undefined ? Array.isArray(entry.delegates) &&
            entry.delegates.length <= 2000 && entry.delegates.every(exactText) : validDelegateTree(entry.delegateTree)))
        throw TypeError("Invalid authorizer rule; use exact credential/authorizer and delegates or delegateTree");
    }
    const identities = (input.allowedAuthorizers as PolicyAuthorizer[]).map(normalizedIdentity);
    if (new Set(identities).size !== identities.length) throw TypeError("Duplicate authorizer rule");
  }
  if (input.allowedContracts !== undefined) {
    if (!Array.isArray(input.allowedContracts) || !input.allowedContracts.length || input.allowedContracts.length > 256)
      throw TypeError("allowedContracts must be a nonempty bounded list");
    const keys = new Set<string>();
    for (const entry of input.allowedContracts) {
      if (!object(entry) || Object.keys(entry).sort().join(",") !== "address,functions" ||
          typeof entry.address !== "string" || !/^C[A-Z2-7]{55}$/.test(entry.address) ||
          !Array.isArray(entry.functions) || !entry.functions.length || entry.functions.length > 256 ||
          !entry.functions.every(exactText) || new Set(entry.functions).size !== entry.functions.length)
        throw TypeError("Invalid allowedContracts entry; only exact contract addresses/functions are accepted");
      for (const fn of entry.functions) {
        const key = JSON.stringify([entry.address, fn]);
        if (keys.has(key)) throw TypeError("Duplicate contract/function rule");
        keys.add(key);
      }
    }
  }
  if (input.blockUnapprovedAuthorizers && !input.allowedAuthorizers)
    throw TypeError("blockUnapprovedAuthorizers requires an explicit allowlist");
  if (input.blockUnapprovedContracts && !input.allowedContracts)
    throw TypeError("blockUnapprovedContracts requires an explicit allowlist");
  return input as unknown as ScopePolicy;
}

function priority(value: Decision): number { return value === "blocked" ? 2 : value === "review" ? 1 : 0; }
function worst(a: Decision, b: Decision): Decision { return priority(a) >= priority(b) ? a : b; }
function id(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex").slice(0, 16);
}

/** Never mutates the policy or comparison; no IO, secret handling, or security assertions. */
export function evaluateScopePolicy(comparison: Comparison, definition: unknown): PolicyResult {
  const policy = validatePolicy(definition);
  if (comparison?.schemaVersion !== 1 || !Array.isArray(comparison.changes))
    throw TypeError("Expected Comparison schemaVersion 1");
  const sorted = [...comparison.changes].sort((a,b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  const occurrences = new Map<string, number>();
  for (const delta of sorted) if (delta?.kind === "added" && Number.isSafeInteger(delta.count) && delta.count > 0) {
    const key = JSON.stringify([delta.authorizer, delta.path]);
    occurrences.set(key, (occurrences.get(key) ?? 0) + delta.count);
  }
  const allowedIdentities = new Set(policy.allowedAuthorizers?.map(normalizedIdentity) ?? []);
  const allowedCalls = new Set(policy.allowedContracts?.flatMap(item => item.functions.map(fn => JSON.stringify([item.address, fn]))) ?? []);
  const findings: PolicyFinding[] = [];
  for (let i = 0; i < sorted.length; i++) {
    const change = sorted[i]!;
    const identity = parsedIdentity(change?.authorizer), calls = parsedPath(change?.path);
    const rules: string[] = [];
    let decision: Decision = "approved";
    const note = (state: Decision, rule: string) => { decision = worst(decision, state); rules.push(rule); };
    if (!change || !["added", "removed"].includes(change.kind) ||
        !Number.isSafeInteger(change.count) || change.count < 1 || !identity || !calls ||
        calls.some(call => !["contract", "createContract", "createContractV2"].includes(call.kind) ||
          !/^[a-f0-9]{64}$/.test(call.fingerprint))) {
      note("review", "unreadable-change-metadata");
    } else if (change.kind === "removed") {
      note(policy.allowRemovals ? "approved" : "review", policy.allowRemovals ? "explicit-removal-approval" : "removed-scope-review");
    } else {
      if (!policy.allowedAuthorizers) note("review", "authorizer-not-evaluated");
      else if (allowedIdentities.has(normalizedIdentity(identity))) note("approved", "authorizer-allowlisted");
      else note(policy.blockUnapprovedAuthorizers ? "blocked" : "review", "unapproved-authorizer");
      if (!policy.allowedContracts) note("review", "contract-not-evaluated");
      else for (const call of calls) {
        if (call.kind !== "contract" || !/^C[A-Z2-7]{55}$/.test(call.contract)) {
          note("review", "contract-address-unavailable");
        } else if (allowedCalls.has(JSON.stringify([call.contract, call.method]))) {
          note("approved", "contract-function-allowlisted");
        } else note(policy.blockUnapprovedContracts ? "blocked" : "review", "unapproved-contract-function");
      }
      const repeated = occurrences.get(JSON.stringify([change.authorizer, change.path])) ?? 0;
      if (policy.maxAddedOccurrencesPerPath === undefined) note("review", "call-multiplicity-not-evaluated");
      else if (repeated > policy.maxAddedOccurrencesPerPath) note("blocked", "added-call-limit-exceeded");
      else note("approved", "added-call-limit-satisfied");
    }
    const uniqueRules = [...new Set(rules)].sort();
    findings.push({
      id: `policy-${id([change, i, uniqueRules])}`, decision, ruleIds: uniqueRules,
      message: `${change?.kind === "removed" ? "Removed" : "Added"} scope: ${decision}. Matched ${uniqueRules.join(", ")}. This is a policy result, not a security verdict.`,
      change: { ...change }
    });
  }
  const decision = findings.reduce<Decision>((current, next) => worst(current, next.decision), "approved");
  return {
    decision, findings,
    summary: `${decision}: ${findings.length} scope delta(s) evaluated under explicit local policy; no exploitability or transaction-validity conclusion.`
  };
}
