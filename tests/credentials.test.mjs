import test from "node:test";
import assert from "node:assert/strict";
import { Address, StrKey, xdr } from "@stellar/stellar-sdk";
import { inspect, compare, compareFingerprints } from "../dist/index.js";
const account=n=>Address.fromString(StrKey.encodeEd25519PublicKey(Buffer.alloc(32,n))).toScAddress();
const credentials=(address)=>new xdr.SorobanAddressCredentials({address,nonce:42n,signatureExpirationLedger:1234,signature:xdr.ScVal.scvBytes(Buffer.from("nested-secret-signature"))});
const invocation=new xdr.SorobanAuthorizedInvocation({
  function:xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(new xdr.InvokeContractArgs({
    contractAddress:Address.fromString(StrKey.encodeContract(Buffer.alloc(32,7))).toScAddress(),
    functionName:"authorize",args:[]
  })),subInvocations:[]
});
const encoded=creds=>new xdr.SorobanAuthorizationEntry({credentials:creds,rootInvocation:invocation}).toXdr("base64");
const delegate=(n,children=[])=>new xdr.SorobanDelegateSignature({address:account(n),signature:xdr.ScVal.scvBytes(Buffer.from("nested-secret-signature")),nestedDelegates:children});
test("source account, legacy address, and ADDRESS_V2 are distinguished",()=>{
  const cases=[
    xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
    xdr.SorobanCredentials.sorobanCredentialsAddress(credentials(account(1))),
    xdr.SorobanCredentials.sorobanCredentialsAddressV2(credentials(account(1)))
  ];
  const report=inspect(cases.map(encoded));
  assert.deepEqual(report.entries.map(x=>x.credential),[
    "sorobanCredentialsSourceAccount","sorobanCredentialsAddress","sorobanCredentialsAddressV2"]);
  assert.equal(report.entries[0].authorizer,"transaction source");
  assert.match(report.entries[1].authorizer,/^G/);
  assert.notEqual(report.entries[1].credential,report.entries[2].credential);
  assert.doesNotMatch(JSON.stringify(report),/nested-secret-signature|signatureExpirationLedger|nonce|1234/);
});
test("two-level delegated trees preserve edges and detect reparenting",()=>{
  const make=delegates=>encoded(xdr.SorobanCredentials.sorobanCredentialsAddressWithDelegates(
    new xdr.SorobanAddressCredentialsWithDelegates({addressCredentials:credentials(account(1)),delegates})));
  const nested=inspect([make([delegate(2,[delegate(3,[delegate(4)])])])]);
  const flat=inspect([make([delegate(2),delegate(3,[delegate(4)])])]);
  assert.equal(nested.entries[0].delegateTree[0].children[0].children[0].address,
    Address.fromScAddress(account(4)).toString());
  assert.deepEqual(nested.entries[0].delegates.length,3);
  assert.deepEqual(flat.entries[0].delegates.length,3);
  assert.equal(compare(nested,flat).changed,true);
  assert.equal(compareFingerprints(nested,flat).changed,true);
  assert.doesNotMatch(JSON.stringify(nested),/nested-secret-signature|signatureExpirationLedger|nonce/);
});
test("malformed and unsupported entries fail closed",()=>{
  assert.throws(()=>inspect(["AAAA"]),/Invalid/);
  assert.throws(()=>inspect(["not base64*"]),/Invalid/);
});
