export { inspect, extractAuth, compare } from "./core.js";
export type { Invocation, Authorization, Snapshot, ScopeDelta, Comparison } from "./core.js";
export { normalizeSimulation } from "./features/simulation-normalizer/index.js";
export type { NormalizedSimulation } from "./features/simulation-normalizer/index.js";
export { fingerprintSnapshot, compareFingerprints } from "./features/scope-fingerprint/index.js";
export type { FingerprintItem, FingerprintDelta, FingerprintComparison } from "./features/scope-fingerprint/index.js";
