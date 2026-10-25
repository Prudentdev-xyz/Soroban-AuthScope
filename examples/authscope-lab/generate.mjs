#!/usr/bin/env node
/** Deterministic OFFLINE synthetic Soroban XDR fixtures; no keys or RPC calls. */
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Address, StrKey, xdr } from "@stellar/stellar-sdk";

const output = process.argv[2];
if (!output || process.argv.length !== 3) {
  console.error("Usage: node examples/authscope-lab/generate.mjs <output-directory>");
  process.exitCode = 2;
} else {
  const contract = Address.fromString(
    StrKey.encodeContract(Buffer.alloc(32, 7))
  ).toScAddress();
  function invoke(method, amount, children = []) {
    return new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
        new xdr.InvokeContractArgs({
          contractAddress: contract,
          functionName: method,
          args: [xdr.ScVal.scvU32(amount)]
        })
      ),
      subInvocations: children
    });
  }
  function encoded(root) {
    return new xdr.SorobanAuthorizationEntry({
      credentials: xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
      rootInvocation: root
    }).toXdr("base64");
  }
  const before = { auth: [encoded(invoke("withdraw", 5))] };
  const after = { auth: [encoded(invoke("withdraw", 5, [invoke("transfer", 5)]))] };
  await mkdir(resolve(output), { recursive: true });
  for (const [name, snapshot] of [
    ["before.json", before],
    ["after.json", after],
    ["unchanged.json", structuredClone(before)]
  ]) {
    await writeFile(resolve(output, name), JSON.stringify(snapshot, null, 2) + "\n", {
      flag: "w", mode: 0o600
    });
  }
  console.log("Generated 3 synthetic, SDK-encoded Soroban authorization fixtures in " + resolve(output));
}
