# Credential inspection (#3)

`inspect` decodes the official SDK XDR credential arms:

| Arm | Report |
| --- | --- |
| `sorobanCredentialsSourceAccount` | `transaction source` sentinel, **not** an independently signing address |
| `sorobanCredentialsAddress` | legacy address credential |
| `sorobanCredentialsAddressV2` | distinct CAP-71 V2 address credential |
| `sorobanCredentialsAddressWithDelegates` | address plus hierarchical `delegateTree` |

Each `delegateTree` node has `{ address, children }`. The original flat
`delegates` address list remains for backward compatibility. In the v1 snapshot
schema the new field is additive; older saved snapshots may omit it. Nested
delegates remain children of the signer delegating to them; changing a parent
changes comparison identity even if the same addresses remain in the flat list.

SDK-generated tests cover each arm and two levels of nested delegation with
nested signatures, as well as malformed XDR. Unknown credential variants fail
closed. Signature contents, nonces, and expiration ledgers are not included in
the report. **Inspection never verifies signatures, expiration, delegation
policy, or on-chain authority**, nor does it contact a network or sign anything.

See [CAP-71](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0071.md)
and the [protocol 27 migration guide](https://stellar.github.io/js-stellar-sdk/migration/protocol-27-soroban-auth/).
