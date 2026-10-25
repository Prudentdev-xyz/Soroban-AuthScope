import { resolve4 } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { xdr } from "@stellar/stellar-sdk";

const MAX_ENVELOPE_BYTES = 128 * 1024;
const MAX_RPC_BYTES = 1024 * 1024;
export const REQUEST_ID = "authscope-capture";

export function validateRpcUrl(input) {
  let url;
  try { url = new URL(input); }
  catch { throw Error("Invalid RPC endpoint URL"); }
  if (url.protocol !== "https:" || url.username || url.password ||
      (url.port && url.port !== "443") || url.search || url.hash) {
    throw Error("RPC endpoint must be HTTPS on port 443 with no credentials or query");
  }
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (isIP(host) || !host.includes(".") ||
      /\.(?:local|localhost|internal|invalid|test|example)$/i.test(host) ||
      host === "localhost" ||
      !host.split(".").every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))) {
    throw Error("RPC endpoint must have a public DNS hostname");
  }
  return url;
}
export function isPublicIPv4(input) {
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(input)) return false;
  const n = input.split(".").map(Number);
  if (n.length !== 4 || n.some(x => x > 255)) return false;
  const [a,b,c] = n;
  if (a === undefined || b === undefined || c === undefined) return false;
  // Reject non-global, documentation, benchmarking, multicast and reserved ranges.
  if (a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 168 || b === 0 || (b === 88 && c === 99) ||
                      (b === 0 && c === 2))) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113)) return false;
  return true;
}
export async function pinnedPublicIPv4(host, lookup = resolve4) {
  let answers;
  try { answers = await lookup(host); }
  catch { throw Error("RPC hostname could not be resolved"); }
  if (!Array.isArray(answers) || !answers.length ||
      answers.length > 30 || answers.some(x => !isPublicIPv4(x))) {
    throw Error("RPC hostname resolves to a forbidden or untrusted address");
  }
  return answers[0];
}
export function validateEnvelope(text) {
  const value = text.trim();
  if (!value || value.length > Math.ceil(MAX_ENVELOPE_BYTES / 3) * 4 + 8 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw Error("Invalid transaction envelope base64");
  }
  const bytes = Buffer.from(value, "base64");
  if (!bytes.length || bytes.length > MAX_ENVELOPE_BYTES ||
      bytes.toString("base64") !== value) {
    throw Error("Invalid or oversized transaction envelope");
  }
  try { xdr.TransactionEnvelope.fromXdr(bytes); }
  catch { throw Error("Invalid Stellar TransactionEnvelope XDR"); }
  return value;
}
/** HTTPS transport with DNS pinning (no rebinding), TLS verification, no redirects. */
export async function postPinnedRpc(url, payload, {
  lookup = resolve4, request = httpsRequest, timeoutMs = 10000
} = {}) {
  const chosen = await pinnedPublicIPv4(url.hostname, lookup);
  const body = JSON.stringify(payload);
  if (Buffer.byteLength(body) > MAX_ENVELOPE_BYTES * 2) {
    throw Error("RPC request exceeds safe size");
  }
  return await new Promise((resolve, reject) => {
    const req = request(url, {
      method: "POST", agent: false, timeout: timeoutMs,
      servername: url.hostname,
      lookup: (_host, _options, done) => done(null, chosen, 4),
      headers: {
        "content-type": "application/json",
        "accept": "application/json",
        "content-length": Buffer.byteLength(body)
      }
    }, response => {
      if (response.statusCode !== 200) {
        req.destroy(new Error(response.statusCode >= 300 && response.statusCode < 400
          ? "RPC redirects are forbidden" : "RPC returned non-success HTTP status"));
        response.resume();
        return;
      }
      const chunks = [];
      let count = 0;
      response.on("data", chunk => {
        count += chunk.length;
        if (count > MAX_RPC_BYTES) {
          req.destroy(Error("RPC response exceeds 1 MiB limit"));
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => {
        try {
          const text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
          resolve(JSON.parse(text));
        } catch {
          reject(Error("RPC response is not valid UTF-8 JSON"));
        }
      });
      response.on("error", reject);
    });
    req.on("error", reject);
    req.setTimeout(timeoutMs, () => req.destroy(Error("RPC request timeout")));
    req.end(body);
  });
}
export async function captureSimulation({
  rpcUrl, envelopeXdr, allowNetwork = false, postJson = postPinnedRpc,
  now = () => new Date()
}) {
  if (!allowNetwork) throw Error("Network access denied: supply --allow-network");
  const url = validateRpcUrl(rpcUrl);
  const transaction = validateEnvelope(envelopeXdr);
  const query = { jsonrpc: "2.0", id: REQUEST_ID,
    method: "simulateTransaction", params: { transaction } };
  let raw;
  try { raw = await postJson(url, query); }
  catch { throw Error("RPC request failed, timed out or was refused"); }
  if (!raw || typeof raw !== "object" || raw.jsonrpc !== "2.0" ||
      raw.id !== REQUEST_ID || raw.error != null || !raw.result ||
      typeof raw.result !== "object" || raw.result.error != null) {
    throw Error("RPC simulation failed or response envelope is invalid");
  }
  const source = raw.result;
  if (!Array.isArray(source.results) || source.results.length > 128) {
    throw Error("Simulation lacks a supported results array");
  }
  const results = source.results.map(item => {
    if (!item || !Array.isArray(item.auth) ||
        item.auth.length > 128 || item.auth.some(x =>
          typeof x !== "string" || x.length > 200000 ||
          !/^[A-Za-z0-9+/]*={0,2}$/.test(x))) {
      throw Error("Simulation authorization entries missing or invalid");
    }
    return { auth: [...item.auth] };
  });
  // Store only the data needed by the existing offline inspect command.
  const metadata = {};
  for (const key of ["latestLedger", "protocolVersion"]) {
    if (Number.isSafeInteger(source[key]) && source[key] >= 0) metadata[key] = source[key];
  }
  return {
    capture: {
      kind: "simulateTransaction",
      status: "simulated-not-submitted",
      rpcHost: url.hostname,
      capturedAt: now().toISOString()
    },
    result: { ...metadata, results }
  };
}
