import test from "node:test";
import assert from "node:assert/strict";
import {toPublicReport,redactDiagnostics} from "../dist/features/report-privacy/index.js";

const hash="a".repeat(64);
const root={kind:"contract",contract:"CSECRET",method:"transfer",argumentsSha256:hash,children:[]};
test("snapshot and nested delegate data are projected without extra secrets",()=>{
  const sample={schemaVersion:1,authorizationCount:1,entries:[{credential:"sorobanCredentialsSourceAccount",authorizer:"GSECRET",delegates:["GDELEGATE"],root:{...root,children:[root]},signature:"secret"}],bearer:"token"};
  const original=JSON.stringify(sample);
  const result=toPublicReport(sample);
  assert.doesNotMatch(JSON.stringify(result),/SECRET|DELEGATE|secret|token/);
  assert.equal(result.entries[0].root.children.length,1);
  assert.equal(JSON.stringify(sample),original);
  assert.equal(toPublicReport(sample,{identifiers:"hash"}).entries[0].authorizer.length,71);
});
test("diff paths are redacted along with identity",()=>{
  const result=toPublicReport({schemaVersion:1,changed:true,beforeCount:0,afterCount:1,changes:[{kind:"added",authorizer:"password=hello",path:"https://user:pass@example.org",count:1,signature:"xyz"}]});
  assert.doesNotMatch(JSON.stringify(result),/pass|hello|xyz/);
});
test("malformed, cyclic and excessive inputs fail safely",()=>{
  assert.throws(()=>toPublicReport({schemaVersion:1,entries:[]}));
  const cyclic={...root};cyclic.children=[cyclic];
  assert.throws(()=>toPublicReport({schemaVersion:1,authorizationCount:1,entries:[{credential:"x",authorizer:"x",delegates:[],root:cyclic}]}));
  assert.throws(()=>toPublicReport({schemaVersion:1,authorizationCount:0,entries:[],password:"x"},{identifiers:"none"}));
  assert.equal(redactDiagnostics("Bearer token https://user:pass@example.com"),"[diagnostic redacted]");
});
