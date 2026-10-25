/** Strict, offline adapter for supported simulateTransaction JSON shapes. */
export interface NormalizedSimulation {
  classification: "authorized" | "no-authorizations";
  shape: "raw-rpc" | "sdk-parsed" | "auth-array";
  authorizations: string[];
}
const MAX_AUTH = 128;
const MAX_TEXT = 4 * 1024 * 1024;
function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function authList(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > MAX_AUTH ||
    value.some(item => typeof item !== "string" || item.length === 0 || item.length > 180000)) {
    throw Error("Malformed or oversized simulation authorization list");
  }
  return value as string[];
}
export function normalizeSimulation(input: unknown): NormalizedSimulation {
  if (JSON.stringify(input)?.length > MAX_TEXT) throw Error("Simulation response exceeds limit");
  let shape: NormalizedSimulation["shape"];
  let entries: string[];
  if (Array.isArray(input)) {
    shape = "auth-array";
    entries = authList(input);
  } else {
    if (!record(input)) throw Error("Expected simulation response object");
    if ("error" in input && input.error != null) throw Error("Simulation has an error");
    let value = input;
    if ("result" in input) {
      if (!record(input.result) || "auth" in input || "results" in input) {
        throw Error("Inconsistent JSON-RPC wrapper");
      }
      value = input.result;
      shape = "raw-rpc";
    } else shape = "sdk-parsed";
    if ("error" in value && value.error != null) throw Error("Simulation has an error");
    if ("auth" in value && "results" in value) throw Error("Ambiguous authorization fields");
    if ("results" in value) {
      if (!Array.isArray(value.results) || value.results.length > MAX_AUTH) throw Error("Malformed results array");
      entries = [];
      for (const item of value.results) {
        if (!record(item) || !("auth" in item)) throw Error("Simulation results entry has no auth array");
        entries.push(...authList(item.auth));
        if (entries.length > MAX_AUTH) throw Error("Too many authorization entries");
      }
    } else if ("auth" in value) entries = authList(value.auth);
    else throw Error("Authorization data unavailable");
  }
  return { shape, classification: entries.length ? "authorized" : "no-authorizations", authorizations: entries };
}
