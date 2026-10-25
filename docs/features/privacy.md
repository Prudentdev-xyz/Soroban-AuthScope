# Safe report projection

`toPublicReport(snapshotOrComparison, {identifiers: "redact" | "hash"})` is a pure allowlist projection from `src/features/report-privacy/index.ts`. The default redacts authorizers, delegates, contracts and diff paths. The optional SHA-256 mode produces stable one-way identifiers, **not encryption**; publicly known addresses are not inherently secret, and dictionary matching remains possible. Argument SHA-256 digests are correlation identifiers, not a confidentiality guarantee.

Unknown fields—including signature XDR, nonces, keys, bearer tokens, passwords and URLs—are dropped. The function rejects malformed schemas, cycles, deep trees and excessive collections instead of serializing them. `redactDiagnostics(text)` intentionally returns a constant message, avoiding accidental reproduction of credentials or raw XDR. Originals are not modified. Reports still expose method names, credentials types, counts and structural relationships; review before sharing.

Locally captured testnet fixtures may reveal addresses, invocation topology or other participant metadata. Obtain consent, minimize retention, never commit secrets or private keys, project reports before sharing and delete unneeded fixtures. No network or project data is collected by these utilities.
