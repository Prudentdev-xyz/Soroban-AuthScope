import { createHash } from "node:crypto";
import type { Comparison, ScopeDelta, Snapshot, DelegateSigner } from "../../core.js";

type Step = { kind: string; contract: string; method: string; fingerprint: string };
type Identity = { credential: string; authorizer: string; delegates: string[]; signerRepresentation: unknown[] };
type Item = { delta: ScopeDelta; identity: Identity | null; steps: Step[] | null };
export type ExplanationCategory = "authorizer-change" | "argument-fingerprint-change" |
  "nested-invocation-added" | "nested-invocation-removed" |
  "root-authorization-added" | "root-authorization-removed" |
  "scope-added" | "scope-removed";
export interface Explanation {
  id: string;
  category: ExplanationCategory;
  assessment: "review-required";
  count: number;
  message: string;
  /** Exact values from Comparison, including public contract addresses and digests. */
  sourceChanges: ScopeDelta[];
  /** Context from supplied snapshots, if any; never an assertion of validity. */
  snapshotPresence?: { before: boolean; after: boolean };
}
export interface ExplanationReport {
  schemaVersion: 1;
  status: "unchanged" | "review-required";
  summary: string;
  explanations: Explanation[];
}
export interface ExplainOptions {
  before?: Snapshot;
  after?: Snapshot;
  display?: { redactAddresses?: boolean; truncateAt?: number; fingerprintChars?: number };
}

function identity(value: string): Identity | null {
  try {
    const data: unknown = JSON.parse(value);
    if (!Array.isArray(data) || data.length !== 3 ||
        typeof data[0] !== "string" || typeof data[1] !== "string" ||
        !Array.isArray(data[2])) return null;
    const delegates: string[] = [];
    let visited = 0;
    function walk(value: unknown, depth: number): boolean {
      if (++visited > 2000 || depth > 24 || !Array.isArray(value) || value.length !== 2 ||
          typeof value[0] !== "string" || !Array.isArray(value[1])) return false;
      delegates.push(value[0]);
      return value[1].every((child: unknown) => walk(child, depth + 1));
    }
    if (data[2].every((x: unknown) => typeof x === "string")) delegates.push(...data[2]);
    else if (!data[2].every((x: unknown) => walk(x, 0))) return null;
    return { credential: data[0], authorizer: data[1], delegates, signerRepresentation: data[2] };
  } catch { return null; }
}
function canonicalSigners(values: DelegateSigner[]): unknown[] {
  return values.map(value => [value.address, canonicalSigners(value.children)])
    .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
}

/** Scan JSON arrays, not a naive split: method names may contain ' > '. */
export function parseCallPath(value: string): Step[] | null {
  if (typeof value !== "string" || value.length > 32768) return null;
  const steps: Step[] = [];
  let offset = 0;
  try {
    while (offset < value.length && steps.length <= 24) {
      if (value[offset] !== "[") return null;
      let quoted = false, escaped = false, depth = 0, end = -1;
      for (let i = offset; i < value.length; i++) {
        const ch = value[i];
        if (quoted) {
          if (escaped) escaped = false;
          else if (ch === "\\") escaped = true;
          else if (ch === '"') quoted = false;
        } else if (ch === '"') quoted = true;
        else if (ch === "[") depth++;
        else if (ch === "]" && --depth === 0) { end = i + 1; break; }
      }
      if (end < 0) return null;
      const data: unknown = JSON.parse(value.slice(offset, end));
      if (!Array.isArray(data) || data.length !== 4 || !data.every(x => typeof x === "string")) return null;
      steps.push({ kind: data[0]!, contract: data[1]!, method: data[2]!, fingerprint: data[3]! });
      offset = end;
      if (offset < value.length) {
        if (value.slice(offset, offset + 3) !== " > ") return null;
        offset += 3;
      }
    }
    return offset === value.length && steps.length > 0 && steps.length <= 25 ? steps : null;
  } catch { return null; }
}

function display(value: string, options: ExplainOptions): string {
  const config = options.display;
  let shown = value;
  if (config?.redactAddresses) shown = shown.replace(/\b[CGM][A-Z2-7]{55}\b/g, match => `${match.slice(0, 5)}…${match.slice(-4)}`);
  const limit = config?.truncateAt;
  if (Number.isInteger(limit) && limit! >= 12 && shown.length > limit!) shown = `${shown.slice(0, limit!)}…`;
  return shown;
}
function callDescription(steps: Step[] | null, options: ExplainOptions): string {
  if (!steps) return "an invocation with unreadable path metadata";
  return steps.map(step => {
    const contract = display(step.contract, options), method = display(step.method, options);
    return `${contract}.${method} (${step.kind})`;
  }).join(" → ");
}
function signerDescription(info: Identity | null, options: ExplainOptions): string {
  if (!info) return "an unidentified authorizer";
  const delegates = info.delegates.length ? ` with delegates ${info.delegates.map(x => display(x, options)).join(", ")}` : "";
  return `${display(info.authorizer, options)} (${display(info.credential, options)})${delegates}`;
}
function digest(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex").slice(0, 16);
}
function present(snapshot: Snapshot | undefined, info: Identity | null): boolean {
  if (!info || !snapshot) return false;
  return snapshot.entries.some(entry => entry.credential === info.credential &&
    entry.authorizer === info.authorizer &&
    JSON.stringify(entry.delegateTree === undefined ? [...entry.delegates].sort() : canonicalSigners(entry.delegateTree)) ===
      JSON.stringify(info.signerRepresentation));
}
function normalize(delta: ScopeDelta): Item {
  return { delta, identity: identity(delta.authorizer), steps: parseCallPath(delta.path) };
}
function sameSteps(a: Step[], b: Step[]): boolean { return JSON.stringify(a) === JSON.stringify(b); }
function pairCategory(a: Item, b: Item): ExplanationCategory | null {
  if (!a.steps || !b.steps || !a.identity || !b.identity || a.delta.count !== b.delta.count) return null;
  if (sameSteps(a.steps, b.steps) && a.delta.authorizer !== b.delta.authorizer) return "authorizer-change";
  if (a.delta.authorizer !== b.delta.authorizer || a.steps.length !== b.steps.length) return null;
  let changedFingerprints = 0;
  for (let i = 0; i < a.steps.length; i++) {
    const left = a.steps[i]!, right = b.steps[i]!;
    if (left.kind !== right.kind || left.contract !== right.contract || left.method !== right.method) return null;
    if (left.fingerprint !== right.fingerprint) changedFingerprints++;
  }
  return changedFingerprints === 1 ? "argument-fingerprint-change" : null;
}

/** Pure, deterministic, read-only explanation; no HTML is generated or evaluated. */
export function explainScope(comparison: Comparison, options: ExplainOptions = {}): ExplanationReport {
  const deltas = [...comparison.changes].sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))).map(normalize);
  const used = new Set<number>();
  const explanations: Explanation[] = [];
  function add(category: ExplanationCategory, items: Item[], message: string): void {
    const sources = items.map(x => ({ ...x.delta }));
    const info = items.find(x => x.identity)?.identity ?? null;
    const explanation: Explanation = {
      id: `scope-${digest([category, sources])}`, category,
      assessment: "review-required", count: items[0]!.delta.count,
      message, sourceChanges: sources
    };
    if (options.before || options.after) explanation.snapshotPresence = {
      before: present(options.before, info), after: present(options.after, info)
    };
    explanations.push(explanation);
  }
  for (let i = 0; i < deltas.length; i++) {
    if (used.has(i)) continue;
    const first = deltas[i]!;
    if (first.delta.kind !== "removed") continue;
    for (let j = 0; j < deltas.length; j++) {
      if (i === j || used.has(j) || deltas[j]!.delta.kind !== "added") continue;
      const next = deltas[j]!, category = pairCategory(first, next);
      if (!category) continue;
      used.add(i); used.add(j);
      const target = callDescription(next.steps, options);
      const message = category === "authorizer-change"
        ? `The same invocation path (${target}) appears under ${signerDescription(first.identity, options)} before and ${signerDescription(next.identity, options)} after. Review the authorizer difference; this is not proof of escalation.`
        : (() => {
          const index = first.steps!.findIndex((step, position) => step.fingerprint !== next.steps![position]!.fingerprint);
          const digits = options.display?.fingerprintChars;
          const length = Number.isInteger(digits) && digits! >= 4 && digits! <= 64 ? digits! : 64;
          const oldDigest = first.steps![index]!.fingerprint.slice(0, length);
          const newDigest = next.steps![index]!.fingerprint.slice(0, length);
          const suffix = length < 64 ? "…" : "";
          return `Argument fingerprint changed for ${target} under ${signerDescription(next.identity, options)} (${oldDigest}${suffix} → ${newDigest}${suffix}). The digest does not reveal amounts or argument contents.`;
        })();
      add(category, [first, next], message);
      break;
    }
  }
  for (let i = 0; i < deltas.length; i++) {
    if (used.has(i)) continue;
    const item = deltas[i]!;
    const direction = item.delta.kind, nested = !!item.steps && item.steps.length > 1;
    const category = !item.steps ? `scope-${direction}` : nested ?
      `nested-invocation-${direction}` : `root-authorization-${direction}`;
    const message = `${direction === "added" ? "Added" : "Removed"} ${nested ? "nested invocation" : "authorization scope"} (×${item.delta.count}): ${callDescription(item.steps, options)}; authorizer ${signerDescription(item.identity, options)}. Review required; no security impact is inferred.`;
    add(category as ExplanationCategory, [item], message);
  }
  explanations.sort((a,b) => a.id.localeCompare(b.id));
  return {
    schemaVersion: 1,
    status: explanations.length ? "review-required" : "unchanged",
    summary: explanations.length ? `${explanations.length} scope difference group(s) require review. Authorization changes alone do not establish exploitability or transaction validity.` :
      "No authorization-scope differences in this comparison; this does not establish safety or transaction validity.",
    explanations
  };
}

export function formatScopeExplanation(report: ExplanationReport): string {
  return [report.summary, ...report.explanations.map(item => `[${item.id}] ${item.message}`)].join("\n");
}
