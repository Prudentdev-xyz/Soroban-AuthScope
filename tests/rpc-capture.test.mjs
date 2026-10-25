import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { spawnSync } from "node:child_process";
import { Account, Networks, Operation, StrKey, TransactionBuilder } from "@stellar/stellar-sdk";
import {
  REQUEST_ID, validateRpcUrl, validateEnvelope, isPublicIPv4,
  pinnedPublicIPv4, postPinnedRpc, captureSimulation
} from "../tools/rpc-capture/lib.mjs";

function transaction() {
  const source = new Account(StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 11)), "1");
  const tx = new TransactionBuilder(source, { fee: "100", networkPassphrase: Networks.TESTNET })
    .addOperation(Operation.manageData({ name: "sample", value: "test" }))
    .setTimeout(0).build();
  return tx.toXDR();
}
const rpc = "https://soroban-testnet.stellar.org";
function simulation() {
  return { jsonrpc: "2.0", id: REQUEST_ID, result: {
    latestLedger: 100, protocolVersion: 23,
    results: [{ auth: [] }], secret: "SHOULD_NOT_LEAK"
  }};
}
test("requires explicit consent before any transport invocation", async () => {
  let called = false;
  await assert.rejects(captureSimulation({
    rpcUrl: rpc, envelopeXdr: transaction(),
    postJson: async () => { called = true; return simulation(); }
  }), /Network access denied/);
  assert.equal(called, false);
});
test("validated simulateTransaction uses named transaction and sanitizes output", async () => {
  let seenUrl, seenQuery;
  const result = await captureSimulation({
    rpcUrl: rpc, envelopeXdr: transaction(), allowNetwork: true,
    now: () => new Date("2026-01-01T00:00:00.000Z"),
    postJson: async (url, query) => { seenUrl = url; seenQuery = query; return simulation(); }
  });
  assert.equal(seenUrl.hostname, "soroban-testnet.stellar.org");
  assert.equal(seenQuery.method, "simulateTransaction");
  assert.deepEqual(Object.keys(seenQuery.params), ["transaction"]);
  assert.equal(validateEnvelope(seenQuery.params.transaction), transaction());
  assert.equal(result.capture.status, "simulated-not-submitted");
  assert.equal(result.capture.capturedAt, "2026-01-01T00:00:00.000Z");
  assert.deepEqual(result.result.results, [{ auth: [] }]);
  assert.doesNotMatch(JSON.stringify(result), /SHOULD_NOT_LEAK/);
  assert.doesNotMatch(JSON.stringify(result), /"transaction"/);
});
test("rejects malformed XDR, unsafe URLs and credential-bearing endpoints", async () => {
  assert.throws(() => validateEnvelope("AAAA"), /XDR/);
  for (const endpoint of [
    "http://soroban-testnet.stellar.org", "https://localhost",
    "https://127.0.0.1", "https://169.254.169.254",
    "https://user:password@soroban-testnet.stellar.org",
    "https://soroban-testnet.stellar.org:8443",
    "https://rpc.example.com?secret=x", "https://private.internal"
  ]) assert.throws(() => validateRpcUrl(endpoint));
});
test("rejects DNS with private or reserved IPs and allows global-only answers", async () => {
  for (const address of [
    "127.0.0.1", "10.2.3.4", "172.16.0.1", "192.168.1.1",
    "169.254.169.254", "100.64.0.1", "192.0.2.5",
    "198.51.100.3", "203.0.113.4", "224.0.0.1"
  ]) assert.equal(isPublicIPv4(address), false, address);
  assert.equal(isPublicIPv4("8.8.8.8"), true);
  await assert.rejects(pinnedPublicIPv4("example.org", async () => ["8.8.8.8", "10.0.0.9"]), /forbidden/);
  assert.equal(await pinnedPublicIPv4("example.org", async () => ["8.8.8.8"]), "8.8.8.8");
});
test("simulation errors, invalid auth and transport timeouts never produce output", async () => {
  const options = { rpcUrl: rpc, envelopeXdr: transaction(), allowNetwork: true };
  await assert.rejects(captureSimulation({ ...options,
    postJson: async () => { throw Error("timeout: user bearer SECRET"); }
  }), /RPC request failed/);
  await assert.rejects(captureSimulation({ ...options,
    postJson: async () => ({jsonrpc:"2.0", id:REQUEST_ID, error: {code:-32600,message:"secret"}})
  }), /simulation failed/);
  await assert.rejects(captureSimulation({ ...options,
    postJson: async () => ({jsonrpc:"2.0", id:REQUEST_ID, result: {results:[{}]}})
  }), /authorization entries missing/);
});
function fakeHttps(status, bytes = "{}") {
  return (_url, options, callback) => {
    assert.equal(options.method, "POST");
    assert.equal(options.headers.authorization, undefined);
    const request = new EventEmitter();
    request.setTimeout = () => request;
    request.destroy = err => queueMicrotask(() => request.emit("error", err));
    request.end = () => queueMicrotask(() => {
      const response = new EventEmitter();
      response.statusCode = status;
      response.resume = () => {};
      callback(response);
      if (status === 200) {
        response.emit("data", Buffer.from(bytes));
        response.emit("end");
      }
    });
    return request;
  };
}
test("pinned TLS transport refuses redirects and oversized HTTP responses", async () => {
  const url = validateRpcUrl(rpc);
  const options = { lookup: async () => ["8.8.8.8"] };
  await assert.rejects(postPinnedRpc(url, {}, {...options,request:fakeHttps(302)}), /redirects/);
  await assert.rejects(postPinnedRpc(url, {}, {
    ...options, request:fakeHttps(200,"x".repeat(1024*1024+2))
  }), /exceeds/);
  const body = await postPinnedRpc(url, {}, {...options,request:fakeHttps(200,'{"ok":true}')});
  assert.deepEqual(body, { ok: true });
});
test("capture CLI stays offline without explicit opt-in and never prints source XDR", () => {
  const r = spawnSync(process.execPath, ["tools/rpc-capture/index.mjs",
    "--rpc-url", rpc, "--envelope", "example.txt", "--out", "capture.json"], {
      encoding: "utf8", timeout: 10000
    });
  assert.equal(r.status, 2);
  assert.equal(r.stdout, "");
  assert.match(r.stderr, /requires explicit/);
});
