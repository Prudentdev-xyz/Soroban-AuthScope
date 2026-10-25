# Explicitly opt-in read-only Stellar RPC simulation capture

AuthScope itself operates **offline**. This optional standalone CLI captures
a real `simulateTransaction` response for later inspection; it never signs,
submits, broadcasts, deploys contracts, or queries a wallet.

## How to capture

First, obtain a **prepared transaction envelope XDR** (base64) using your normal
Stellar SDK development workflow, without exposing any secret key. Save the
base64 envelope as `envelope.txt` (not JSON). This tool does not create or
sign transaction envelopes.

From the repository root:

```sh
npm ci --ignore-scripts
node tools/rpc-capture/index.mjs --help
node tools/rpc-capture/index.mjs --allow-network \
  --rpc-url https://soroban-testnet.stellar.org \
  --envelope ./envelope.txt --out ./simulation.json

node dist/cli.js inspect ./simulation.json --json
```

Run `npm run build` before the final command. The generated file contains a
filtered `result.results[].auth` list (base64 Soroban XDR) and capture
provenance, without other opaque RPC fields. Output is created with restrictive
permissions and never overwritten. Only a successful, structurally supported
simulation yields a saved file; an RPC error never becomes a clean result.

## Network and privacy safeguards

- No request without explicit `--allow-network`.
- HTTPS with public DNS hostname and port 443 only; reject embedded credentials,
  query strings, loopback, link-local, private, reserved IPs and internal domains.
- Resolve IPv4 before connecting, reject mixed private/public resolutions and
  pin the connection to the validated address with TLS hostname verification
  (no DNS-rebinding at request time). IPv6-only endpoints are unsupported.
- No redirects, 10-second timeout, 1 MiB response ceiling, bounded XDR input.
- Only JSON-RPC 2.0 `simulateTransaction`, with a preexisting envelope.
  Never `submitTransaction`, key access, or arbitrary remote commands.
- Errors do not print endpoint credentials, supplied XDR or raw RPC response.
- The saved authorization entries can reveal public identities and correlate
  argument hashes. Review them before posting. Simulation is **not execution**.

CI tests use injected fake transports, not a live RPC service. Users must
deliberately opt in to any real testnet capture.
