import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { xdr } from "@stellar/stellar-sdk";
import { inspect } from "../dist/index.js";

const file=resolve("examples/real-simulation/captured.json");
function cli(...args) {
  const processResult=spawnSync(process.execPath,[resolve("dist/cli.js"),...args],{encoding:"utf8",timeout:12000});
  assert.equal(processResult.error,undefined);
  return processResult;
}
test("recorded public testnet simulation is authentic in shape and decodes offline", t=>{
  const captured=JSON.parse(readFileSync(file,"utf8"));
  assert.equal(captured.provenance.kind,"live-testnet-simulation");
  assert.equal(captured.provenance.network,"Stellar Testnet");
  assert.ok(Date.parse(captured.provenance.capturedAt));
  assert.equal(captured.result.results[0].auth.length,1);
  const snapshot=inspect(captured);
  assert.equal(snapshot.entries[0].root.contract,captured.provenance.contract);
  assert.equal(snapshot.entries[0].root.method,"transfer");
  assert.equal(cli("inspect",file,"--json").status,0);
  assert.equal(cli("diff",file,file).status,0);

  // Counterfactual generated for comparison only. It is NOT captured network evidence.
  const entry=xdr.SorobanAuthorizationEntry.fromXdr(captured.result.results[0].auth[0],"base64");
  const child=new xdr.SorobanAuthorizedInvocation({function:entry.rootInvocation.function,subInvocations:[]});
  const changed=new xdr.SorobanAuthorizationEntry({
    credentials:entry.credentials,
    rootInvocation:new xdr.SorobanAuthorizedInvocation({
      function:entry.rootInvocation.function,subInvocations:[child]
    })
  }).toXdr("base64");
  const dir=mkdtempSync(join(tmpdir(),"authscope-live-fixture-"));
  t.after(()=>rmSync(dir,{recursive:true,force:true}));
  const modified=join(dir,"counterfactual.json");
  writeFileSync(modified,JSON.stringify({auth:[changed]}));
  const diff=cli("diff",file,modified,"--json");
  assert.equal(diff.status,1,diff.stderr);
  assert.ok(JSON.parse(diff.stdout).changes.some(x=>x.kind==="added"&&x.path.includes("transfer")));
});
