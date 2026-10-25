# Scope policy (issue #11)

Standalone, deterministic and offline evaluator for `Comparison.changes`. It
never approves ambiguous/missing identity or invocation metadata, and defaults
to **review** for every change unless explicitly configured. `blocked` means a
stated local policy rule was violated, **not** that an exploit occurred.

```ts
import { evaluateScopePolicy } from "./dist/features/scope-policy/index.js";
const policy = {
  schemaVersion: 1,
  allowedAuthorizers: [{
    credential: "sorobanCredentialsSourceAccount",
    authorizer: "transaction source", delegates: []
  }],
  allowedContracts: [{address: "<a real C... Stellar contract address>", functions: ["approve"]}],
  blockUnapprovedAuthorizers: true,
  blockUnapprovedContracts: true,
  maxAddedOccurrencesPerPath: 1,
  allowRemovals: false
};
const result = evaluateScopePolicy(comparison, policy);
console.log(result.decision, result.findings);
```

Replace the illustrative contract placeholder with an actual `C` address.
Use the example JSON in `src/features/scope-policy/policy.example.json` and
`npm ci --ignore-scripts && npm run check && npm test` to run the tests.

All contract/function pairs, credential/authorizer/delegate identities, and
the maximum added occurrence count must match exactly for added scope to be
approved. Explicit denial switches turn known allowlist failures into blocked
results. Removing scope needs an explicit `allowRemovals: true` to be approved.
For hierarchical delegated credentials in current reports, replace the
authorizer rule's `delegates` field with `delegateTree`, a nested list of
`{address, children}` nodes; the hierarchy is matched exactly. Legacy v1
reports without this field can still use the flat `delegates` list.
Empty allowlists, unknown keys, broad wildcards, duplicate rules and a blocking
rule without its allowlist are rejected. New contract creation without a known
address or corrupted/redacted comparison data remains review, never approved.
No network, wallet, keys, signing or contract execution is performed.
