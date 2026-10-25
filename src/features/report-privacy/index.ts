import { createHash } from "node:crypto";

type RecordValue = Record<string, unknown>;
export interface PrivacyOptions {
  identifiers?: "redact" | "hash";
}
const LIMIT = 2000;
function object(value: unknown): RecordValue {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw Error("Invalid report shape");
  return value as RecordValue;
}
function array(value: unknown): unknown[] {
  if (!Array.isArray(value) || value.length > LIMIT) throw Error("Invalid report shape or size");
  return value;
}
function string(value: unknown): string {
  if (typeof value !== "string" || value.length > 4096) throw Error("Invalid report field");
  return value;
}
function number(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > LIMIT) throw Error("Invalid report count");
  return value as number;
}
function identifier(value: unknown, mode: "redact" | "hash"): string {
  const input = string(value);
  return mode === "hash" ? `sha256:${createHash("sha256").update(input).digest("hex")}` : "[redacted]";
}
/** Allowlist projection: unknown fields (including signature material) never survive. */
export function toPublicReport(input: unknown, options: PrivacyOptions = {}): RecordValue {
  if (options.identifiers !== undefined && !["redact", "hash"].includes(options.identifiers)) throw Error("Invalid privacy option");
  const mode = options.identifiers ?? "redact";
  const visited = new WeakSet<object>();
  let nodes = 0;
  function guard(value: unknown, depth: number): RecordValue {
    if (depth > 24 || ++nodes > LIMIT) throw Error("Report exceeds safety limits");
    const item = object(value);
    if (visited.has(item)) throw Error("Cyclic or repeated report object");
    visited.add(item);
    return item;
  }
  function invocation(value: unknown, depth: number): RecordValue {
    const v = guard(value, depth);
    if (!["contract", "createContract", "createContractV2"].includes(string(v.kind))) throw Error("Invalid invocation kind");
    const hash = string(v.argumentsSha256);
    if (!/^[a-f0-9]{64}$/.test(hash)) throw Error("Invalid arguments hash");
    const method = string(v.method);
    if (!/^[A-Za-z0-9_]{1,32}$/.test(method)) throw Error("Unsafe method field");
    return {kind:v.kind, contract:identifier(v.contract,mode), method, argumentsSha256:hash,
      children:array(v.children).map(child=>invocation(child,depth+1))};
  }
  const report = guard(input,0);
  if (report.schemaVersion !== 1) throw Error("Unsupported report schema");
  if ("entries" in report) {
    const entries = array(report.entries).map(value=>{
      const entry = guard(value,1);
      const credential = string(entry.credential);
      if (!/^sorobanCredentials(?:SourceAccount|Address|AddressV2|AddressWithDelegates)$/.test(credential)) throw Error("Invalid credential kind");
      return {credential,authorizer:identifier(entry.authorizer,mode),
        delegates:array(entry.delegates).map(x=>identifier(x,mode)),root:invocation(entry.root,2)};
    });
    if (number(report.authorizationCount) !== entries.length) throw Error("Invalid authorization count");
    return {schemaVersion:1,authorizationCount:entries.length,entries};
  }
  if ("changes" in report) {
    const changes = array(report.changes).map(value=>{
      const change=guard(value,1);
      if (change.kind !== "added" && change.kind !== "removed") throw Error("Invalid change kind");
      // Paths and identity are JSON-encoded identifiers and may embed sensitive addresses.
      return {kind:change.kind,authorizer:identifier(change.authorizer,mode),
        path:identifier(change.path,mode),count:number(change.count)};
    });
    if (typeof report.changed !== "boolean" || report.changed !== (changes.length > 0)) throw Error("Invalid changed flag");
    return {schemaVersion:1,changed:report.changed,beforeCount:number(report.beforeCount),
      afterCount:number(report.afterCount),changes};
  }
  throw Error("Unsupported report shape");
}

/** Sanitizes potentially untrusted diagnostic strings; deliberately discards their contents. */
export function redactDiagnostics(_text: unknown): string {
  return "[diagnostic redacted]";
}
