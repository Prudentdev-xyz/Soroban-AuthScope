#!/usr/bin/env node
/** Explicit opt-in read-only capture. No wallet keys, submitTransaction or broadcast. */
import { open, writeFile } from "node:fs/promises";
import { captureSimulation } from "./lib.mjs";

const HELP = [
  "Soroban AuthScope — opt-in read-only simulateTransaction capture",
  "Usage:",
  "  node tools/rpc-capture/index.mjs --allow-network --rpc-url <https-url>",
  "    --envelope <existing-xdr-base64-file> --out <new-json-file>",
  "No signing, submitting, broadcasting or wallet operations.",
  "Network access is denied without --allow-network. Output must not already exist."
].join("\n");
async function readSmall(path) {
  const file = await open(path, "r");
  try {
    const stats = await file.stat();
    if (!stats.isFile() || stats.size > 256 * 1024) throw Error("Envelope input too large");
    const buffer = Buffer.alloc(256 * 1024 + 1);
    const { bytesRead } = await file.read(buffer, 0, buffer.length, 0);
    if (bytesRead > 256 * 1024) throw Error("Envelope input too large");
    return new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, bytesRead));
  } finally { await file.close(); }
}
export async function main(args) {
  if (args.length === 1 && ["--help", "-h"].includes(args[0])) {
    console.log(HELP); return 0;
  }
  const argsMap = new Map();
  for (let i = 0; i < args.length; i++) {
    const key = args[i];
    if (key === "--allow-network") {
      if (argsMap.has(key)) { console.error("Duplicate option"); return 2; }
      argsMap.set(key, "true"); continue;
    }
    if (!["--rpc-url", "--envelope", "--out"].includes(key) ||
        argsMap.has(key) || !args[i + 1] || args[i + 1].startsWith("--")) {
      console.error("Usage error. Run --help."); return 2;
    }
    argsMap.set(key, args[++i]);
  }
  if (argsMap.size !== 4 || !argsMap.has("--allow-network")) {
    console.error("Network capture requires explicit --allow-network and all three arguments.");
    return 2;
  }
  try {
    const encoded = await readSmall(argsMap.get("--envelope"));
    const report = await captureSimulation({
      rpcUrl: argsMap.get("--rpc-url"),
      envelopeXdr: encoded, allowNetwork: true
    });
    await writeFile(argsMap.get("--out"), JSON.stringify(report, null, 2) + "\n",
      { flag: "wx", mode: 0o600 });
    console.log("Simulation authorization data captured for offline inspection (not submitted).");
    return 0;
  } catch {
    // No raw envelope, credential, user path, RPC payload or auth XDR in errors.
    console.error("Capture failed. Check HTTPS endpoint, envelope XDR, permissions and RPC simulation status.");
    return 2;
  }
}
if (process.argv[1] && process.argv[1].endsWith("index.mjs")) {
  process.exitCode = await main(process.argv.slice(2));
}
