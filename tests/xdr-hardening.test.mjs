import test from "node:test";
import assert from "node:assert/strict";
import {spawnSync} from "node:child_process";
import {inspectBounded,BUDGET} from "../tools/xdr-hardening/index.mjs";
test("120 deterministic malformed base64 and wrapper mutations remain bounded",()=>{
  const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=*";
  for(let i=0;i<120;i++) {
    const length=1+(i*37)%400;
    const value=Array.from({length},(_,j)=>alphabet[(i*13+j*17)%alphabet.length]).join("");
    const input=i%5===0?{result:{results:[{auth:[value]}]}}:i%5===1?{auth:[value]}:i%5===2?{auth:[value.slice(0,-1)]}:i%5===3?{results:[{auth:[value]}]}:{auth:[value],error:"invalid"};
    assert.throws(()=>inspectBounded(input),undefined,`mutation ${i}`);
  }
});
test("aggregate budgets and malformed recursive wrappers",()=>{
  assert.throws(()=>inspectBounded({auth:Array(128).fill("A".repeat(5000))}),/aggregate budget/);
  assert.throws(()=>inspectBounded({result:{results:[null]}}));
  assert.equal(BUDGET.depth,24);
});
test("pathological input is isolated by subprocess timeout",()=>{
  const program=`import {inspectBounded} from './tools/xdr-hardening/index.mjs';try{inspectBounded({auth:['A'.repeat(1000000)]});process.exit(1)}catch{process.exit(0)}`;
  const r=spawnSync(process.execPath,["--input-type=module","-e",program],{encoding:"utf8",timeout:3000});
  assert.equal(r.error,undefined);assert.equal(r.status,0);assert.equal(r.stdout,"");
});
