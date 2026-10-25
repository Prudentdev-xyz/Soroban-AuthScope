# Scope explainer (issue #10)

This is a standalone, offline, side-effect-free TypeScript module. It consumes
the `Comparison` type already exported by `src/core.ts` and optionally the two
`Snapshot` objects. It makes no network, wallet, contract, or signing calls.

```ts
import { inspect, compare } from "./dist/index.js";
import { explainScope, formatScopeExplanation } from "./dist/features/scope-explainer/index.js";

const before = inspect(beforeSimulationJson);
const after = inspect(afterSimulationJson);
const explanation = explainScope(compare(before, after), {
  before, after, display: { redactAddresses: true, fingerprintChars: 12 }
});
console.log(formatScopeExplanation(explanation));
```

Run `npm ci --ignore-scripts && npm run check && npm test` and inspect
`tests/scope-explainer.test.mjs` for runnable examples.

The module groups paired removals/additions with identical call paths under
different authorizers or identical functions under different argument
fingerprints. Pairing is a **correlation**, not a causal claim. Public full
contract addresses and fingerprints remain unchanged in `sourceChanges` even
when human-facing messages opt into address redaction/truncation. No amounts,
contents, signature validity, privilege escalation, or exploitability are
inferred from opaque hashes. All output is plain text / structured data; a UI
must insert it with `textContent`, not `innerHTML`.
