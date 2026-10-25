import test from "node:test";
import assert from "node:assert/strict";
import { normalizeSimulation } from "../dist/index.js";

const sample = "AAAAAQ==";
test("raw JSON-RPC and SDK-parsed results agree", () => {
  const raw = { jsonrpc: "2.0", id: 1, result: { latestLedger: 1, results: [{ auth: [sample] }] } };
  const parsed = { latestLedger: 1, results: [{ auth: [sample] }] };
  assert.deepEqual(normalizeSimulation(raw).authorizations, normalizeSimulation(parsed).authorizations);
  assert.equal(normalizeSimulation(raw).shape, "raw-rpc");
  assert.equal(normalizeSimulation(parsed).shape, "sdk-parsed");
  assert.equal(normalizeSimulation({auth:[]}).classification, "no-authorizations");
  assert.equal(normalizeSimulation({result:{results:[]}}).classification, "no-authorizations");
});
test("errors and absent fields never masquerade as no authorization", () => {
  for (const bad of [
    {error:{code:-1}}, {result:{error:"failed"}}, {result:{}},
    {results:[{}]}, {results:[null]}, {results:12}, {auth:null},
    {auth:[sample,2]}, {auth:[""]}, {auth:Array(129).fill(sample)},
    {auth:[],results:[]}, {result:{auth:[]},auth:[]},
    {result:{results:[{auth:{}}]}}
  ]) assert.throws(() => normalizeSimulation(bad));
});
