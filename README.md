# Soroban AuthScope

A Soroban developer tool for inspecting and comparing authorization scope. **Early MVP under development.** Maintained by [SoraForge](https://github.com/SoraForge), independently of the Stellar Development Foundation.

## Purpose

Soroban authorization entries include a root invocation and nested sub-invocations. When contract code changes, a transaction may require a different authorization scope. AuthScope decodes official Stellar XDR authorization entries and compares the permitted invocation structures between two saved simulations.

The tool is **offline and read-only**. It does not sign or verify signatures, execute contracts, connect wallets, or contact RPC. It reports public addresses and method names; argument values are represented by hashes. Authorization scope changes indicate items to review, not proven security vulnerabilities.

## Getting started

Requires Node.js 22+ and npm.

```bash
git clone https://github.com/SoraForge/Soroban-AuthScope.git
cd Soroban-AuthScope
npm ci --ignore-scripts
npm test
node dist/cli.js --help
node dist/cli.js inspect ./simulation.json
node dist/cli.js inspect ./simulation.json --json
node dist/cli.js diff ./before.json ./after.json --json
```

Supported input: a JSON array of base64 `SorobanAuthorizationEntry` XDR strings, a JSON object with `auth` array, or an RPC `simulateTransaction` response with a `results` array of entries containing `auth` arrays. The program does not retrieve simulations; create them with your own normal developer tools.

**Exit codes:** 0 successful inspection/no scope change; 1 changed scope; 2 invalid input or argument. `diff` ignores the order of independent authorizations, preserves repeated calls, nesting, credential variants and hashed argument differences.

**Limits:** Maximum 128 entries, 128 KiB per entry, and 4 MiB per input file, with bounded invocation-tree depth. Reports are diagnostic, not proof that any authorization is legitimate or secure. The CLI does not expose signatures or nonces, but public addresses and argument hashes may still reveal project metadata—review before sharing.

## Architecture

- `src/core.ts`: decode and inspect Stellar SDK v17 XDR; build structured trees and scope comparisons.
- `src/cli.ts`: offline local-file CLI with text/JSON output and controlled exit statuses.
- `src/index.ts`: public TypeScript APIs.
- `tests/core.test.mjs`: end-to-end XDR fixtures constructed using the official SDK.

## References

- [Stellar Soroban Authorization XDR](https://github.com/stellar/stellar-xdr/blob/main/Stellar-transaction.x)
- [Stellar authorization guide](https://stellar.github.io/js-stellar-sdk/guides/07-contract-auth/)
- [Stellar SDK v17 migration guide](https://stellar.github.io/js-stellar-sdk/migration/xdr-migration/)

## Governance

Apache-2.0 licensed. Dependency upgrades are manual; no Dependabot is configured. This project has not been approved for Drips Wave.
