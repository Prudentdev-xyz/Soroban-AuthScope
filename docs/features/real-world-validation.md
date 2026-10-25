# Reproducible public testnet evidence (#5)

`examples/real-simulation/captured.json` was recorded from a **real, successful
Stellar public Testnet `simulateTransaction` response**, not SDK-fabricated XDR.
Its `provenance` object records capture time (UTC), public RPC endpoint, ledger,
contract, method and SDK version. The fixture contains only the unmodified
`results[0].auth` authorization XDR and this metadata; private keys, headers,
bearer tokens, account identifiers and complete transactions are excluded.

The captured invocation is an unsigned, read-only simulation of the native
XLM Stellar Asset Contract `transfer` of one stroop back to the source account.
It invokes `require_auth` and produces a source-account credential. Because
no transaction was signed or submitted, no assets moved. The script discovers
the public source's sequence from Horizon; the chosen source address is not
saved to the fixture.

Run offline verification:

```bash
npm ci --ignore-scripts
npm run check
npm test
node dist/cli.js inspect examples/real-simulation/captured.json --json
node dist/cli.js diff examples/real-simulation/captured.json examples/real-simulation/captured.json --json
```

Expected inspect facts: `authorizationCount: 1`, credential
`sorobanCredentialsSourceAccount`, authorizer `transaction source`, contract
`CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC`, method
`transfer`, argument SHA-256
`704dd6c2851c30c15a4389f7a660183d36b4a50d48520d2c5ead228c731f4a61`,
and `children: []`. Diffing the fixture with itself returns exit 0 and no change.

`tests/real-simulation.test.mjs` additionally builds a **clearly synthetic
counterfactual** by adding a nested `transfer` invocation to the recorded root
and verifies that the CLI detects the added scope (exit 1). This variant is not
a claim that the actual testnet transaction contained that nested invocation.

To capture a fresh live fixture, first remove or rename the existing file in
your own working copy, choose an existing funded public testnet account, and
deliberately opt in:

```bash
AUTHSCOPE_CAPTURE_TESTNET=yes AUTHSCOPE_TESTNET_SOURCE=<PUBLIC_G_ADDRESS> \
  node examples/real-simulation/capture.mjs
```

The capture utility creates the fixture exclusively (`wx`), never overwrites
it, and makes only public Horizon read and RPC simulation requests. Live access
is **not part of CI**. Testnet state and contract availability can change;
checked-in fixtures are deterministic. Do not commit keys or private metadata.
