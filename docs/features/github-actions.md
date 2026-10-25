# GitHub Actions integration

The [self-contained composite action](../../integrations/github-actions/action.yml)
checks two **existing, locally captured** authorization snapshots using the
official AuthScope `diff` CLI. It does not fetch from RPC, execute contracts,
sign transactions, or ask for wallet credentials.

Copy the [consumer workflow](../../integrations/github-actions/example-consumer-workflow.yml)
into the **consumer** repository's `.github/workflows/authscope.yml`.
The example's `uses: ...@main` works after these changes are merged. For
security-sensitive workflows pin to an audited immutable commit SHA.

**Inputs:** `before`, `after` are paths within the caller's checkout.
`fail-on-change` is `"true"` (default, changed-scope makes the job fail) or
`"false"` (the job reports changes without failing).

**Outputs:** `changed` (`true/false`), `additions`, `removals` and
`report-path` (temporary local machine-readable JSON report).
The action publishes a sanitized, count-only GitHub step summary. Reports
contain public contract IDs, addresses and argument hashes; uploading one
with `actions/upload-artifact` is *optional* and should be deliberate.

The consuming repository needs only `permissions: contents: read` and
`actions/checkout`. The composite action itself installs its own **locked**
dependencies with `npm ci --ignore-scripts`, builds TypeScript in its separate
GitHub-managed action checkout and invokes the standalone `check.mjs` driver.
Inputs are never interpolated into shell commands.

**Exit behavior:** unchanged -> 0; changed -> 1 when strict, 0 when advisory;
invalid/unreadable/unsupported snapshot -> nonzero and no false clean result.
The action's diff is an aid to human review, not proof of a vulnerability.
