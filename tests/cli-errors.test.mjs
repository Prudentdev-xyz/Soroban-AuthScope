import test from "node:test";
import assert from "node:assert/strict";
import {spawnSync} from "node:child_process";
import {mkdtempSync,writeFileSync,rmSync} from "node:fs";
import {join,resolve} from "node:path";
import {tmpdir} from "node:os";
const exe=resolve("dist/cli.js");
function run(...args){return spawnSync(process.execPath,[exe,...args],{encoding:"utf8",timeout:10000});}
test("documented CLI statuses and clean streams",t=>{
  const dir=mkdtempSync(join(tmpdir(),"authscope-cli-"));t.after(()=>rmSync(dir,{recursive:true,force:true}));
  const file=(name,value)=>{const p=join(dir,name);writeFileSync(p,JSON.stringify(value));return p;};
  const empty=file("empty.json",{auth:[]});
  const missing=file("missing.json",{result:{results:[{}]}});
  const failed=file("failed.json",{error:{message:"Bearer secret"}});
  const malformed=file("bad.json",{auth:["bad*xdr"]});
  assert.equal(run("--help").status,0);assert.equal(run("--version").status,0);
  assert.equal(run("inspect",empty).status,0);
  assert.equal(run("diff",empty,empty).status,0);
  for(const args of [["inspect",missing],["inspect",failed]]) {
    const r=run(...args);assert.equal(r.status,3);assert.equal(r.stdout,"");assert.doesNotMatch(r.stderr,/secret|Bearer|\bat /);
  }
  for(const args of [["inspect",malformed],["inspect",join(dir,"absent")],["inspect",empty,"--bad"],["inspect",empty,"--json","--json"],["inspect",empty,"--help"]]) {
    const r=run(...args);assert.equal(r.status,2);assert.equal(r.stdout,"");
  }
});
