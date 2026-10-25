# Versioned report schemas

Draft 2020-12 schemas for the JSON emitted by `authscope inspect ... --json` and
`authscope diff ... --json` are in `v1/`. Versions are explicit: both report types
require `schemaVersion: 1`. Unknown fields and versions are errors; additive or
breaking shape changes require a new schema version, new fixtures and documented
migration guidance rather than silently changing v1 field meanings.

Run `node tools/schema-check/index.mjs report.json` (use `--type snapshot` or
`--type comparison` if desired). The validator is dependency-free and offline.
It follows the published schemas, with additional consistency and safety checks:
entry counts and `changed` flags must match their arrays, input must be ≤4 MiB,
and recursion is limited to 24 levels / 50,000 invocation nodes. Errors are
bounded and name fields without echoing sensitive values. Input reports contain
public identities and argument fingerprints, **not** proof of transaction
validity or safety.

The `authorizer` and `path` properties of a delta are serialized JSON identity
and call-path tuples produced by the current `compare` implementation; they
are not flat addresses or raw argument values. Version 1 preserves that format.
`Snapshot` authorization entries allow an optional recursive `delegateTree`
of `{address, children}` signers introduced by current upstream while keeping
older v1 files with `delegates` only valid. Current comparisons use canonical
delegate hierarchies in their encoded authorizer identity; older comparisons
can still contain flat delegate lists.

`fixtures/` contains valid Snapshot/Comparison examples and intentionally
invalid reports (missing credential, unknown delta kind, negative count).
For representative real XDR-generated CLI output, the automated schema tests
construct official Stellar SDK entries and validate the CLI's own output.
