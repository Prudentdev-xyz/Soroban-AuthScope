import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Address, StrKey, xdr } from "@stellar/stellar-sdk";
import { inspect, compare } from "../../../dist/index.js";
import { readLocalFile, validateLocalReport, compareSnapshots, annotatedEntries, resolveView,
  pathLabel, MAX_BYTES } from "../model.mjs";
import { initViewer } from "../app.js";

const contract = Address.fromString(StrKey.encodeContract(Buffer.alloc(32,7))).toScAddress();
const invocation = (name,children=[]) => new xdr.SorobanAuthorizedInvocation({
  function:xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
    new xdr.InvokeContractArgs({contractAddress:contract,functionName:name,args:[]})),subInvocations:children
});
const entry = (name,children=[]) => new xdr.SorobanAuthorizationEntry({
  credentials:xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),rootInvocation:invocation(name,children)
}).toXdr("base64");
const before = inspect([entry("withdraw")]);
const after = inspect([entry("withdraw",[invocation("transfer")])]);
const diff = compare(before,after);
const file = (value, name="report.json") => ({name,type:"application/json",size:Buffer.byteLength(JSON.stringify(value)),
  text:async()=>JSON.stringify(value)});

class Element {
  constructor(tag="div") {this.tag=tag;this.children=[];this.textContent="";this.className="";this.hidden=false;this.value="";this.files=[];this.listeners={};this.attributes={};}
  append(...nodes) {this.children.push(...nodes);}
  replaceChildren(...nodes) {this.children=[...nodes];}
  addEventListener(name,listener) {this.listeners[name]=listener;}
  setAttribute(name,value) {this.attributes[name]=value;}
  async trigger(name) {await this.listeners[name]?.();}
  get text() {return [this.textContent,...this.children.map(child=>child.text)].join(" ");}
  find(predicate) {return [this,...this.children.flatMap(child=>child.find(predicate))].filter(predicate);}
}
class Document {
  constructor() {this.elements=Object.fromEntries(["before-file","after-file","diff-file","clear","overview","tree-grid",
    "changes","status","error","before-status","after-status","diff-status"].map(id=>[id,new Element()]));}
  getElementById(id) {return this.elements[id];}
  createElement(tag) {return new Element(tag);}
}

test("real CLI-generated Snapshot and Comparison reports validate locally", () => {
  assert.equal(validateLocalReport(before),"snapshot");
  assert.equal(validateLocalReport(diff),"comparison");
  assert.deepEqual(compareSnapshots(before,after),diff);
  assert.equal(resolveView(before,after,diff).additions.length,1);
  assert.match(pathLabel(diff.changes[0].path),/withdraw.*transfer/);
});
test("nested expansion and added-scope highlights are represented in the view model", () => {
  const entries=annotatedEntries(after,before,"added");
  assert.equal(entries[0].root.status,"unchanged");
  assert.equal(entries[0].root.children[0].status,"added");
  assert.equal(entries[0].root.children[0].method,"transfer");
  assert.equal(compareSnapshots(before,before).changed,false);
});
test("file import checks type, byte size, JSON and schema version",async () => {
  assert.deepEqual(await readLocalFile(file(after),"snapshot"),after);
  await assert.rejects(readLocalFile(file(after),"comparison"),/Expected a comparison/);
  await assert.rejects(readLocalFile({...file(after),name:"bad.html"},"snapshot"),/Choose a JSON/);
  await assert.rejects(readLocalFile({...file(after),size:MAX_BYTES+1},"snapshot"),/4 MiB/);
  await assert.rejects(readLocalFile(file({...after,schemaVersion:2}),"snapshot"),/Unsupported schemaVersion/);
  await assert.rejects(readLocalFile({name:"invalid.json",size:4,type:"",text:async()=>"nope"},"snapshot"),/Malformed JSON/);
  assert.throws(()=>validateLocalReport({...before,entries:[{...before.entries[0],credential:null}]}),/Invalid authorization/);
});
test("functional UI loads files, renders expandable trees and groups differences",async () => {
  const doc=new Document();initViewer(doc);
  doc.elements["before-file"].files=[file(before,"before.json")];
  await doc.elements["before-file"].trigger("change");
  doc.elements["after-file"].files=[file(after,"after.json")];
  await doc.elements["after-file"].trigger("change");
  assert.equal(doc.elements.error.hidden,true);
  assert.match(doc.elements.status.text,/review required/);
  const tree=doc.elements["tree-grid"];
  assert.equal(tree.find(x=>x.tag==="summary").length,3);
  assert.ok(tree.find(x=>x.tag==="details"&&x.className==="added").length>0);
  assert.match(doc.elements.changes.text,/transfer/);
  await doc.elements.clear.trigger("click");
  assert.equal(doc.elements["tree-grid"].children.length,0);
});
test("unchanged comparison and invalid local data show clear states",async () => {
  const doc=new Document();initViewer(doc);
  doc.elements["diff-file"].files=[file(compare(before,before),"diff.json")];
  await doc.elements["diff-file"].trigger("change");
  assert.match(doc.elements.status.text,/No scope change detected/);
  doc.elements["diff-file"].files=[file({...diff,schemaVersion:500},"invalid.json")];
  await doc.elements["diff-file"].trigger("change");
  assert.equal(doc.elements.error.hidden,false);
  assert.match(doc.elements.error.text,/Unsupported schemaVersion/);
});
test("hostile function names stay inert, even inside side-by-side tree UI",async () => {
  const hostile='<img src=x onerror=alert(1)>'; // from real SDK XDR
  const injected=inspect([entry(hostile)]);
  const doc=new Document();initViewer(doc);
  doc.elements["after-file"].files=[file(injected,"hostile.json")];
  await doc.elements["after-file"].trigger("change");
  assert.match(doc.elements["tree-grid"].text,/<img src=x onerror/);
  assert.equal(doc.elements["tree-grid"].find(x=>x.tag==="img").length,0);
});
test("static accessibility, responsiveness and network-free smoke checks", () => {
  const html=readFileSync(resolve("apps/viewer/index.html"),"utf8");
  const css=readFileSync(resolve("apps/viewer/style.css"),"utf8");
  const js=readFileSync(resolve("apps/viewer/app.js"),"utf8");
  assert.match(html,/<main>/);assert.match(html,/role="alert"/);assert.match(html,/aria-live="polite"/);
  assert.match(html,/for="before-file"/);assert.match(css,/:focus-visible/);assert.match(css,/@media \(max-width:/);
  assert.doesNotMatch(html+js,/(?:innerHTML\s*=|\bfetch\s*\(|https?:\/\/|<script[^>]+src="https?:)/);
  assert.match(js,/textContent/);assert.match(js,/createElement\("details"|el\("details"/);
});
