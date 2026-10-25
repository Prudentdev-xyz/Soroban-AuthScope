# First AuthScope inspection: authorizations and nested contract calls

**Audience:** Soroban contract developers. **Requires:** Node 22+, npm.

Soroban authorization is scoped to contract invocations. A contract can call
`require_auth` to require authorization, and its authorized invocation may
include nested contract calls. Inspecting that tree helps reviewers understand
what an account might be asked to authorize before and after a change.

## Generate genuine XDR encodings in synthetic examples

From the repository root, run:

```sh
npm ci --ignore-scripts
npm run build
node examples/authscope-lab/generate.mjs ./examples/authscope-lab/generated
node dist/cli.js inspect ./examples/authscope-lab/generated/before.json
node dist/cli.js inspect ./examples/authscope-lab/generated/after.json --json
```

The XDR is **really encoded using the Stellar SDK**, but the contract ID and
function calls are deterministic **synthetic samples**. No contract is deployed,
no simulation is sent to RPC and no real user authorization occurs.

The *before* snapshot has a source-account credential authorizing one
`withdraw(5)` invocation. The *after* snapshot has the same root call with a
nested `transfer(5)` invocation. AuthScope hashes the XDR-encoded arguments;
it does **not** display the amount `5` directly.

## Compare two snapshots

```sh
node dist/cli.js diff ./examples/authscope-lab/generated/before.json ./examples/authscope-lab/generated/unchanged.json
# exit code 0: no change

node dist/cli.js diff ./examples/authscope-lab/generated/before.json ./examples/authscope-lab/generated/after.json --json
# exit code 1: one nested invocation was added
```

A change means **review required**, not proof of exploitation. In particular,
the tool neither verifies signatures nor evaluates actual contract state.
The source-account credential denotes the transaction source, not an
independently supplied secret key or evidence that a signature was verified.
Other supported credential variants can contain address identity and delegate
information. Avoid publishing live simulation data without inspecting it for
sensitive application metadata. Argument SHA-256 values can correlate invocations
even though they do not expose raw argument values.

## Troubleshooting

- `npm ci` fails: use Node 22+ and ensure a network connection for the
  one-time locked dependency installation. No project lifecycle scripts run
  with `--ignore-scripts`.
- `Cannot find module dist/cli.js`: run `npm run build` first.
- `Input could not be read or decoded`: ensure the file is UTF-8 JSON and
  contains valid base64-encoded `SorobanAuthorizationEntry` XDR.
- `Unsupported ...`: the pinned SDK might not understand a newer XDR arm.
  Upgrade only after adding conformance fixtures and reviewing upstream docs.
- Real-world input: save a successful `simulateTransaction` JSON response
  using your own Stellar development tooling. AuthScope itself is offline.
  The synthetic lab is **not** a substitute for real testnet validation.

References: [Stellar SDK authorization guide](https://stellar.github.io/js-stellar-sdk/guides/07-contract-auth/),
[contract authorization testing](https://developers.stellar.org/docs/build/guides/testing/test-contract-auth).
