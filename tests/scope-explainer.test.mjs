import test from "node:test";
import assert from "node:assert/strict";
import { Address, StrKey, xdr } from "@stellar/stellar-sdk";
import { inspect, compare } from "../dist/index.js";
import { explainScope, formatScopeExplanation, parseCallPath } from "../dist/features/scope-explainer/index.js";

const contract = Address.fromString(StrKey.encodeContract(Buffer.alloc(32, 7))).toScAddress();
const signer = Address.fromString(StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 9))).toScAddress();
const invocation = (name, args = [], children = []) => new xdr.SorobanAuthorizedInvocation({
  function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
    new xdr.InvokeContractArgs({ contractAddress: contract, functionName: name, args })), subInvocations: children
});
function entry(name, { children = [], args = [], signed = false } = {}) {
  const credentials = signed ? xdr.SorobanCredentials.sorobanCredentialsAddressV2(
    new xdr.SorobanAddressCredentials({address: signer, nonce: 7n, signatureExpirationLedger: 1000,
      signature: xdr.ScVal.scvVoid()})) : xdr.SorobanCredentials.sorobanCredentialsSourceAccount();
  return new xdr.SorobanAuthorizationEntry({ credentials, rootInvocation: invocation(name, args, children) }).toXdr("base64");
}
const report = (before, after, options = {}) => explainScope(compare(inspect(before), inspect(after)), options);

test("nested addition has contract/function context and never invents financial facts", () => {
  const before = [entry("withdraw")], after = [entry("withdraw", {children:[invocation("transfer")]})];
  const result = report(before, after);
  assert.equal(result.status, "review-required");
  assert.equal(result.explanations.length, 1);
  assert.equal(result.explanations[0].category, "nested-invocation-added");
  assert.match(result.explanations[0].message, /withdraw.*transfer/);
  assert.doesNotMatch(formatScopeExplanation(result), /amount of|unsafe|exploitable|valid transaction|privilege escalation/i);
});
test("removed root authorization is review-required; unchanged comparison is not labeled safe", () => {
  assert.equal(report([entry("approve")], []).explanations[0].category, "root-authorization-removed");
  const noChange = report([entry("approve")], [entry("approve")]);
  assert.deepEqual(noChange.explanations, []);
  assert.match(noChange.summary, /does not establish safety/);
});
test("signer change is accurately correlated without alleging escalation", () => {
  const result = report([entry("transfer")], [entry("transfer", {signed:true})]);
  assert.equal(result.explanations.length, 1);
  assert.equal(result.explanations[0].category, "authorizer-change");
  assert.match(result.explanations[0].message, /transaction source/);
  assert.match(result.explanations[0].message, /Review the authorizer difference/);
  assert.doesNotMatch(result.explanations[0].message, /is a privilege escalation/i);
});
test("changed argument fingerprint is not decoded into amounts", () => {
  const before = [entry("transfer", {args:[xdr.ScVal.scvU32(5)]})];
  const after = [entry("transfer", {args:[xdr.ScVal.scvU32(8)]})];
  const result = report(before, after);
  assert.equal(result.explanations.length, 1);
  assert.equal(result.explanations[0].category, "argument-fingerprint-change");
  assert.match(result.explanations[0].message, /digest does not reveal amounts/);
  assert.doesNotMatch(result.explanations[0].message, /5 tokens|8 tokens|transfer amount/i);
});
test("stable explanations preserve raw metadata when display is redacted", () => {
  const before = inspect([entry("transfer")]);
  const after = inspect([entry("transfer", {signed:true})]);
  const delta = compare(before, after);
  const copy = structuredClone(delta);
  const first = explainScope(delta, { before, after, display:{redactAddresses:true,truncateAt:36} });
  const second = explainScope({...delta,changes:[...delta.changes].reverse()}, {before,after,display:{redactAddresses:true,truncateAt:36}});
  assert.deepEqual(first,second);
  assert.deepEqual(delta,copy);
  assert.ok(first.explanations[0].sourceChanges.some(x => x.authorizer.includes("sorobanCredentialsAddressV2")));
  assert.match(first.explanations[0].message,/…/);
});
test("current hierarchical delegates are explained and checked against snapshots", () => {
  const after=inspect([entry("approve")]);
  after.entries[0].credential="sorobanCredentialsAddressWithDelegates";
  after.entries[0].delegateTree=[{address:"GDELEGATE",children:[{address:"GNESTED",children:[]}]}];
  after.entries[0].delegates=["GDELEGATE","GNESTED"];
  const before=inspect([]);
  const explained=explainScope(compare(before,after),{before,after});
  assert.equal(explained.explanations[0].snapshotPresence.after,true);
  assert.match(explained.explanations[0].message,/GDELEGATE.*GNESTED/);
});
test("quoted separators and malicious method labels remain ordinary text", () => {
  const method = '<img onerror=1> > test';
  const delta = compare(inspect([]), inspect([entry(method)]));
  assert.equal(parseCallPath(delta.changes[0].path)[0].method, method);
  const result = explainScope(delta);
  assert.match(result.explanations[0].message, /<img onerror=1>/);
  assert.ok(!formatScopeExplanation(result).includes("<script>"));
});
