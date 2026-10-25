#!/usr/bin/env node
/** Docker-only synthetic XDR fixtures, generated with the official SDK. */
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { Address, StrKey, xdr } from "@stellar/stellar-sdk";

const target = process.argv[2];
if (!target) { console.error("Output directory required"); process.exitCode = 2; }
else {
  const contract = Address.fromString(StrKey.encodeContract(Buffer.alloc(32, 9))).toScAddress();
  function auth(method) {
    return new xdr.SorobanAuthorizationEntry({
      credentials: xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
      rootInvocation: new xdr.SorobanAuthorizedInvocation({
        function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
          new xdr.InvokeContractArgs({ contractAddress: contract, functionName: method, args: [] })
        ),
        subInvocations: []
      })
    }).toXdr("base64");
  }
  await mkdir(resolve(target), { recursive: true });
  for (const [file, value] of [
    ["before.json", { auth: [auth("withdraw")] }],
    ["after.json", { auth: [auth("withdraw"), auth("transfer")] }],
    ["empty.json", { auth: [] }]
  ]) {
    await writeFile(resolve(target, file), JSON.stringify(value) + "\n");
  }
}
