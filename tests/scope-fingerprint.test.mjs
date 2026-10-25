import test from "node:test";
import assert from "node:assert/strict";
import { compareFingerprints, fingerprintSnapshot } from "../dist/index.js";
const h = "a".repeat(64), j = "b".repeat(64);
function call(method, children=[], argumentsSha256=h) {
  return {kind:"contract",contract:"CEXAMPLE",method,argumentsSha256,children};
}
function auth(root, authorizer="G1", credential="sorobanCredentialsAddress", delegateTree=[]) {
  return {credential,authorizer,delegates:[],delegateTree,root};
}
function snap(...entries) {return {schemaVersion:1,authorizationCount:entries.length,entries};}
const root = auth(call("root",[call("a"),call("b")]));
test("stable across independent root and sibling permutations", () => {
  const variant = auth(call("root",[call("b"),call("a")]));
  assert.equal(compareFingerprints(snap(root,auth(call("other"))),snap(auth(call("other")),variant)).changed,false);
  assert.deepEqual(fingerprintSnapshot(snap(root)),fingerprintSnapshot(snap(root)));
});
test("structural and identity changes produce scoped provenance", () => {
  const variants = [
    auth(call("root",[call("a"),call("b"),call("c")])),
    auth(call("root",[call("a",[call("b")])])),
    auth(call("root",[call("a"),call("a"),call("b")])),
    auth(call("root",[call("a",[],j),call("b")])),
    auth(root.root,"G2"), auth(root.root,"G1","sorobanCredentialsAddressV2")
  ];
  for (const candidate of variants) {
    const diff=compareFingerprints(snap(root),snap(candidate));
    assert.equal(diff.changed,true);
    assert.deepEqual(diff.changes.map(x=>x.kind).sort(),["added","removed"]);
    assert.deepEqual(diff.changes.map(x=>x.sourceIndexes),[[0],[0]]);
  }
  const duplicate=compareFingerprints(snap(root),snap(root,root));
  assert.deepEqual(duplicate.changes.map(x=>[x.kind,x.count]),[["added",1]]);
});
test("delegate hierarchy is semantically significant, legacy absence is disclosed", () => {
  const a=auth(call("root"),"G1","sorobanCredentialsAddressWithDelegates",[{address:"A",children:[{address:"B",children:[]}]}]);
  const b=auth(call("root"),"G1","sorobanCredentialsAddressWithDelegates",[{address:"A",children:[]},{address:"B",children:[]}]);
  assert.equal(compareFingerprints(snap(a),snap(b)).changed,true);
  const legacy={...a,delegateTree:undefined};
  assert.equal(compareFingerprints(snap(legacy),snap(legacy)).topologyIncomplete,true);
  assert.throws(()=>fingerprintSnapshot(snap({...a,root:call("root",[],"bad")})));
});
