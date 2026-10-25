# Simulation input normalization (#2)

`normalizeSimulation(input)` is an offline, exported adapter. It returns
`{ shape, classification, authorizations }`. `classification` is either
`authorized` or `no-authorizations`; malformed, failed, and incomplete responses
throw instead. The same strict adapter powers `inspect` and the CLI.

Supported shapes (not a claim of support for every SDK/RPC version):

- Raw successful JSON-RPC `simulateTransaction`: `{ "result": { "results": [{ "auth": ["<base64 XDR>"] }] } }`.
- SDK-parsed result object: `{ "results": [{ "auth": ["<base64 XDR>"] }] }`.
- SDK-style flattened `{ "auth": ["<base64 XDR>"] }`, or an explicitly supplied array of entries.

An empty `results: []` or an explicit `auth: []` is classified as
`no-authorizations`. An absent `results`/`auth`, a missing `auth` on a
nonempty result, non-array or mixed-type auth, RPC errors, ambiguous wrappers,
more than 128 entries, and responses over 4 MiB are rejected. The adapter
does not validate entry XDR; call `inspect` for that validation. All returned
XDR is kept in memory; no logging is performed.

The shapes correspond to Stellar's [JSON-RPC structure](https://developers.stellar.org/docs/data/apis/rpc/api-reference/structure/json-rpc)
and [SDK authorization guide](https://stellar.github.io/js-stellar-sdk/guides/07-contract-auth/).
