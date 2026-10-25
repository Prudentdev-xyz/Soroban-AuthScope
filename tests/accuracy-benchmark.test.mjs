import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {evaluate} from "../tools/accuracy-benchmark/index.mjs";
test("ten traceable synthetic cases include four unchanged",()=>{
  const cases=JSON.parse(readFileSync(new URL("../tools/accuracy-benchmark/cases.json",import.meta.url)));
  assert.ok(cases.length>=8);
  assert.ok(cases.filter(x=>x.expected.length===0).length>=4);
  const result=evaluate(cases);
  assert.equal(result.totals.fp,0);
  assert.equal(result.totals.fn,0);
  assert.equal(result.totals.tn,4);
  assert.equal(result.precision,1);
});
test("false positives, misses and empty denominators",()=>{
  const change={kind:"added",authorizer:"a",path:"p",count:1};
  const c=(expected,observed)=>({id:"x",category:"test",provenance:"synthetic",expected,observed:{changes:observed}});
  const r=evaluate([c([change],[]),c([],[change])]);
  assert.equal(r.totals.fn,1);assert.equal(r.totals.fp,1);
  assert.equal(r.precision,0);assert.equal(r.recall,0);
  assert.equal(evaluate([]).precision,null);
  assert.throws(()=>evaluate([c([],null)]));
  assert.throws(()=>evaluate([{}]));
});
