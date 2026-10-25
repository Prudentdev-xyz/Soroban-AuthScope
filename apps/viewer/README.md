# Offline AuthScope viewer (issue #13)

Accessible static viewer for **saved** JSON outputs of `authscope inspect --json`
and `authscope diff --json`. There is no backend, RPC, wallet, or upload.

1. From the repository root: `npm ci --ignore-scripts && npm test`.
2. Start a **local** static server: `python3 -m http.server 8080 --bind 127.0.0.1 --directory apps/viewer`.
3. Open `http://127.0.0.1:8080` in a browser. The files are entirely local; no
   remote scripts, fonts, analytics or APIs are used.
4. Import a snapshot into Before or After to expand its nested invocation
   trees. Import both for a local before/after comparison and added/removed
   highlighting. Optionally import a saved Comparison by itself or alongside
   both snapshots (they must match).

Each file must be `.json`, at most 4 MiB, with `schemaVersion: 1`. The viewer
rejects malformed data, unknown fields, missing credentials, invalid tree
structures and unsupported versions, with bounded recursion. Public contract
addresses, signer identities and fingerprints are visible; do not share
sensitive project metadata casually. No raw arguments are available or inferred.
Scope changes are **review items**, not proof of transaction validity, a
privilege escalation, or an exploit. The viewer does not decode XDR; generate
reports with the command-line tool first.

Run tests with `node --test apps/viewer/tests/*.test.mjs`. The tests include
real reports produced by the existing CLI, file-import behavior, tree expansion,
diff highlighting, hostile names and static accessibility/network checks.
