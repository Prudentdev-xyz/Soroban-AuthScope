import { inspect, extractAuth } from "../../dist/core.js";

export const BUDGET = Object.freeze({entries:128, totalBase64Bytes:512*1024, nodes:2000, depth:24, delegates:2000});

/** Additional whole-input budget around the existing per-entry decoder. */
export function inspectBounded(input) {
  // This adapter accepts explicit arrays; callers with RPC wrappers can use extractAuth.
  const entries = extractAuth(input);
  const bytes = entries.reduce((sum,entry)=>sum+entry.length,0);
  if (bytes > BUDGET.totalBase64Bytes) throw Error("Authorization input exceeds aggregate budget");
  const result = inspect(input);
  let nodes=0, delegates=0;
  function walk(invocation,depth) {
    if (++nodes > BUDGET.nodes || depth > BUDGET.depth) throw Error("Authorization tree exceeds aggregate budget");
    for(const child of invocation.children) walk(child,depth+1);
  }
  for(const entry of result.entries) {
    delegates+=entry.delegates.length;
    if(delegates > BUDGET.delegates) throw Error("Delegates exceed aggregate budget");
    walk(entry.root,0);
  }
  return result;
}
