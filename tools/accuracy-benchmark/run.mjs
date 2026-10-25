import { readFileSync } from "node:fs";
import { evaluate } from "./index.mjs";
try {
  if(process.argv.length!==3) throw Error("Expected one fixture path");
  const data=readFileSync(process.argv[2],"utf8");
  if(data.length>4*1024*1024) throw Error("Fixture exceeds limit");
  console.log(JSON.stringify(evaluate(JSON.parse(data)),null,2));
} catch {
  console.error("Invalid benchmark fixture");
  process.exitCode=2;
}
