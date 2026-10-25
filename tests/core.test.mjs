import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { Address, StrKey, xdr } from "@stellar/stellar-sdk";
import { inspect, compare } from "../dist/index.js";

const exe = resolve("dist/cli.js");
const contract = Address.fromString(StrKey.encodeContract(Buffer.alloc(32, 7))).toScAddress();
function invocation(name, children = []) {
  return new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
      new xdr.InvokeContractArgs({contractAddress: contract, functionName:name, args:[]})
    ),
    subInvocations: children
  });
}
function entry(name, children = []) {
  return new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
    rootInvocation: invocation(name, children)
  }).toXdr("base64");
}
function fixture(t, value) {
  const directory = mkdtempSync(join(tmpdir(), "authscope-e2e-"));
  t.after(() => rmSync(directory, {force:true, recursive:true}));
  const path = join(directory, "sim.json");
  writeFileSync(path, JSON.stringify(value));
  return path;
}
function run(...args) {
  const child = spawnSync(process.execPath, [exe, ...args], {
    encoding:"utf8",timeout:12000,env:{...process.env,NODE_OPTIONS:""}
  });
  assert.equal(child.error,undefined);
  return child;
}
test("help and version", () => {
  assert.equal(run("--help").status,0);
  assert.match(run("--help").stdout,/authscope inspect/);
  assert.equal(run("--version").stdout.trim(),"0.1.0");
});
test("decodes SDK-generated base64 XDR with nested authorization", t => {
  const file=fixture(t,{result:{results:[{auth:[entry("withdraw",[invocation("transfer")])]}]}});
  const r=run("inspect",file,"--json");
  assert.equal(r.status,0,r.stderr);
  const body=JSON.parse(r.stdout);
  assert.equal(body.authorizationCount,1);
  assert.equal(body.entries[0].root.method,"withdraw");
  assert.equal(body.entries[0].root.children[0].method,"transfer");
  assert.match(body.entries[0].root.contract,/^C/);
  assert.doesNotMatch(r.stdout,/signatureExpirationLedger|nonce|privateKey/);
});
test("stable diff ignores ordering of independent authorization entries", () => {
  const a=entry("alpha"), b=entry("beta");
  assert.equal(compare(inspect([a,b]),inspect([b,a])).changed,false);
});
test("new nested call is detected",t => {
  const first=fixture(t,{auth:[entry("withdraw")]});
  const second=fixture(t,{auth:[entry("withdraw",[invocation("transfer")])]});
  const r=run("diff",first,second,"--json");
  assert.equal(r.status,1,r.stderr);
  const data=JSON.parse(r.stdout);
  assert.equal(data.changed,true);
  assert.ok(data.changes.some(x=>x.kind==="added"&&x.path.includes("transfer")));
});
test("unchanged diff exits zero",t => {
  const first=fixture(t,[entry("approve")]);
  assert.equal(run("diff",first,first).status,0);
});
test("empty auth input is not labeled secure",t => {
  const output=run("inspect",fixture(t,{auth:[]}));
  assert.equal(output.status,0);
  assert.match(output.stdout,/not a safety assessment/);
});
test("invalid data fails without disclosing file contents",t => {
  for(const data of [{auth:["wrong*"]},{auth:["AAAA"]},{auth:["A".repeat(180000)]}]) {
    const output=run("inspect",fixture(t,data));
    assert.equal(output.status,2);
    assert.equal(output.stdout,"");
  }
  const path=fixture(t,{auth:[]});
  writeFileSync(path,"{broken");
  assert.equal(run("inspect",path).status,2);
  assert.equal(run("inspect",path+"-missing").status,2);
});
test("rejects RPC simulation errors and absent auth fields",() => {
  assert.throws(()=>inspect({result:{error:"error"}}),/Simulation has an error/);
  assert.throws(()=>inspect({results:[{}]}),/no auth array/);
});
