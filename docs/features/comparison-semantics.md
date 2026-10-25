# Canonical scope fingerprints (#4)

The exported `fingerprintSnapshot` and `compareFingerprints` functions consume
validated, already decoded `Snapshot` objects, without network calls.

Each root fingerprint is SHA-256 over a canonical encoding of the credential
arm, authorizer, ordered invocation ancestry, full invocation subtree,
argument hashes, and hierarchical delegate signers. Children and independent
roots are **unordered multisets**; their multiplicity is retained. Reordering
siblings is thus immaterial, whereas moving a child to a new parent, adding
a duplicate, or changing an argument, authorizer, credential or delegate edge
changes a fingerprint. No security/vulnerability verdict is implied.

`compareFingerprints` returns `before`, `after`, and `added`/`removed` changes,
including count and zero-based `sourceIndexes` for provenance in the respective
snapshot. A prior schema-v1 snapshot lacking `delegateTree` sets
`topologyIncomplete: true`; such data cannot prove delegated topology
equivalence. The canonicalizer uses a tagged legacy identity in that case.

This is intentionally a standalone regression oracle; `compare` still offers
its original path-oriented, human-readable changes. Tests demonstrate added
children, reparenting, duplicates, arguments, credential and authorizer
changes, and previously invisible delegate reparenting.
