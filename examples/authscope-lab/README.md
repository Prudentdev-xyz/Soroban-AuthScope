# Authorization Scope Learning Lab

These fixtures are **synthetic**, generated offline with the official pinned
\`@stellar/stellar-sdk\` XDR library. They are *not* captured from a real network,
not signed, and not evidence that a Soroban contract has actually executed.

From the repository root:

\`\`\`sh
npm ci --ignore-scripts
npm run build
node examples/authscope-lab/generate.mjs ./examples/authscope-lab/generated
node dist/cli.js inspect ./examples/authscope-lab/generated/before.json
node dist/cli.js inspect ./examples/authscope-lab/generated/after.json --json
node dist/cli.js diff ./examples/authscope-lab/generated/before.json ./examples/authscope-lab/generated/unchanged.json
node dist/cli.js diff ./examples/authscope-lab/generated/before.json ./examples/authscope-lab/generated/after.json --json
\`\`\`

The unchanged diff exits **0**. The final diff exits **1** because a child
\`transfer\` invocation was added. This does **not** prove a vulnerability;
the authorization scope requires human review.

See [the guided tutorial](../../docs/tutorials/first-inspection.md).
