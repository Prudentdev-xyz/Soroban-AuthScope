/** Evaluate labeled, saved comparison JSON. No network or inference of ground truth. */
export function evaluate(cases) {
  if (!Array.isArray(cases) || cases.length > 10000) throw Error("Invalid benchmark cases");
  const totals={tp:0,fp:0,fn:0,tn:0};
  const categories={};
  const rows=[];
  for(const item of cases) {
    if (!item || typeof item !== "object" || typeof item.id !== "string" ||
        typeof item.category !== "string" || !["synthetic","recorded"].includes(item.provenance) ||
        !Array.isArray(item.expected) || !item.observed || !Array.isArray(item.observed.changes))
      throw Error("Malformed benchmark case");
    const key=change=>{
      if (!change || !["added","removed"].includes(change.kind) ||
          typeof change.authorizer !== "string" || typeof change.path !== "string" ||
          !Number.isSafeInteger(change.count) || change.count < 1) throw Error("Malformed change observation");
      return JSON.stringify([change.kind,change.authorizer,change.path]);
    };
    const collect=list=>{
      const map=new Map();
      for(const change of list) {const k=key(change);map.set(k,(map.get(k)??0)+change.count);}
      return map;
    };
    const expected=collect(item.expected), observed=collect(item.observed.changes);
    const result={tp:0,fp:0,fn:0,tn:0};
    for(const k of new Set([...expected.keys(),...observed.keys()])) {
      const e=expected.get(k)??0,o=observed.get(k)??0;
      result.tp+=Math.min(e,o);result.fp+=Math.max(0,o-e);result.fn+=Math.max(0,e-o);
    }
    if(expected.size===0 && observed.size===0) result.tn=1;
    for(const metric of Object.keys(totals)) totals[metric]+=result[metric];
    const categoryKey=`${item.provenance}/${item.category}`;
    const current=categories[categoryKey]??{tp:0,fp:0,fn:0,tn:0};
    for(const metric of Object.keys(totals)) current[metric]+=result[metric];
    categories[categoryKey]=current;
    rows.push({id:item.id,provenance:item.provenance,category:item.category,...result});
  }
  const precision=totals.tp+totals.fp ? totals.tp/(totals.tp+totals.fp) : null;
  const recall=totals.tp+totals.fn ? totals.tp/(totals.tp+totals.fn) : null;
  return {cases:rows.length,totals,precision,recall,categories,rows};
}
