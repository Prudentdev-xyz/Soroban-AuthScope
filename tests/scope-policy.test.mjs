import test from "node:test";
import assert from "node:assert/strict";
import { Address, StrKey, xdr } from "@stellar/stellar-sdk";
import { inspect, compare } from "../dist/index.js";
import { evaluateScopePolicy, validatePolicy } from "../dist/features/scope-policy/index.js";

const contract = StrKey.encodeContract(Buffer.alloc(32, 7));
const otherContract = StrKey.encodeContract(Buffer.alloc(32, 8));
const signer = Address.fromString(StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 4))).toScAddress();
function entry(method, {address = contract, signed = false} = {}) {
  return new xdr.SorobanAuthorizationEntry({
    credentials: signed ? xdr.SorobanCredentials.sorobanCredentialsAddressV2(
      new xdr.SorobanAddressCredentials({ address: signer, nonce: 3n, signatureExpirationLedger: 12,
        signature:xdr.ScVal.scvVoid() })) : xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
    rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function:xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
        new xdr.InvokeContractArgs({contractAddress: Address.fromString(address).toScAddress(), functionName:method,args:[]})),
      subInvocations: []
    })
  }).toXdr("base64");
}
const diff = (before,after) => compare(inspect(before),inspect(after));
const strict = {
  schemaVersion:1,
  allowedAuthorizers:[{credential:"sorobanCredentialsSourceAccount",authorizer:"transaction source",delegates:[]}],
  allowedContracts:[{address:contract,functions:["approve","transfer"]}],
  blockUnapprovedAuthorizers:true,blockUnapprovedContracts:true,maxAddedOccurrencesPerPath:1
};
test("explicit allowlists and count limit approve a permitted call", () => {
  const comparison = diff([], [entry("approve")]);
  const original = structuredClone(comparison);
  const result = evaluateScopePolicy(comparison,strict);
  assert.equal(result.decision,"approved");
  assert.deepEqual(comparison,original);
  assert.deepEqual(result,evaluateScopePolicy(comparison,strict));
  assert.ok(result.findings[0].id.startsWith("policy-"));
});
test("new unapproved signer is blocked by the identity policy", () => {
  const result=evaluateScopePolicy(diff([], [entry("approve",{signed:true})]),strict);
  assert.equal(result.decision,"blocked");
  assert.ok(result.findings[0].ruleIds.includes("unapproved-authorizer"));
});
test("added contract/function outside allowlist is blocked", () => {
  const result=evaluateScopePolicy(diff([], [entry("approve",{address:otherContract})]),strict);
  assert.equal(result.decision,"blocked");
  assert.ok(result.findings[0].ruleIds.includes("unapproved-contract-function"));
});
test("repeated additional call over exact maximum is blocked", () => {
  const sample=entry("transfer");
  const result=evaluateScopePolicy(diff([sample],[sample,sample,sample]),strict);
  assert.equal(result.decision,"blocked");
  assert.ok(result.findings[0].ruleIds.includes("added-call-limit-exceeded"));
});
test("current hierarchical delegate identity is matched exactly", () => {
  const snapshot=inspect([entry("approve")]);
  const authorizer=StrKey.encodeEd25519PublicKey(Buffer.alloc(32,12));
  const delegate=StrKey.encodeEd25519PublicKey(Buffer.alloc(32,13));
  const nested=StrKey.encodeEd25519PublicKey(Buffer.alloc(32,14));
  snapshot.entries[0].credential="sorobanCredentialsAddressWithDelegates";
  snapshot.entries[0].authorizer=authorizer;
  snapshot.entries[0].delegates=[delegate,nested];
  snapshot.entries[0].delegateTree=[{address:delegate,children:[{address:nested,children:[]}]}];
  const comparison=compare(inspect([]),snapshot);
  const rule={...strict,allowedAuthorizers:[{credential:"sorobanCredentialsAddressWithDelegates",
    authorizer,delegateTree:[{address:delegate,children:[{address:nested,children:[]}]}]}]};
  assert.equal(evaluateScopePolicy(comparison,rule).decision,"approved");
  const flattened={...rule,allowedAuthorizers:[{credential:"sorobanCredentialsAddressWithDelegates",
    authorizer,delegates:[delegate,nested]}]};
  assert.equal(evaluateScopePolicy(comparison,flattened).decision,"blocked");
});
test("default changed scope requires review, unchanged is approved, removals require opt-in", () => {
  assert.equal(evaluateScopePolicy(diff([], [entry("approve")]),{schemaVersion:1}).decision,"review");
  assert.equal(evaluateScopePolicy(diff([], []),{schemaVersion:1}).decision,"approved");
  assert.equal(evaluateScopePolicy(diff([entry("approve")], []),strict).decision,"review");
  assert.equal(evaluateScopePolicy(diff([entry("approve")], []),{schemaVersion:1,allowRemovals:true}).decision,"approved");
});
test("redacted and missing metadata can never silently pass", () => {
  const invalid=diff([], [entry("approve")]);
  invalid.changes[0].path="[redacted]";
  assert.equal(evaluateScopePolicy(invalid,strict).decision,"review");
  invalid.changes[0].path="";
  assert.equal(evaluateScopePolicy(invalid,strict).decision,"review");
});
test("invalid definitions and accidental wildcards are rejected", () => {
  const bad = [
    {schemaVersion:2}, {schemaVersion:1,unknown:true},
    {schemaVersion:1,blockUnapprovedAuthorizers:true},
    {schemaVersion:1,allowedAuthorizers:[{credential:"*",authorizer:"transaction source",delegates:[]}]},
    {schemaVersion:1,allowedContracts:[{address:"*",functions:["approve"]}]},
    {schemaVersion:1,allowedContracts:[{address:contract,functions:["*"]}]},
    {schemaVersion:1,maxAddedOccurrencesPerPath:-1},
    {schemaVersion:1,allowedContracts:[]}
  ];
  for(const policy of bad) assert.throws(()=>validatePolicy(policy),TypeError);
});
