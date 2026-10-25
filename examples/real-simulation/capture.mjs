/** Explicit opt-in, unsigned read-only public testnet simulation capture. */
import { Account, Address, Asset, Networks, Operation, TransactionBuilder, xdr } from "@stellar/stellar-sdk";
import { writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";

if (process.env.AUTHSCOPE_CAPTURE_TESTNET !== "yes") {
  throw Error("Set AUTHSCOPE_CAPTURE_TESTNET=yes to opt in to a live testnet simulation");
}
const source = process.env.AUTHSCOPE_TESTNET_SOURCE;
if (!source || !/^G[A-Z2-7]{55}$/.test(source)) throw Error("Set AUTHSCOPE_TESTNET_SOURCE to an existing funded public G address");
const endpoint = "https://soroban-testnet.stellar.org";
const horizon = `https://horizon-testnet.stellar.org/accounts/${source}`;
function fetchJSON(url, data) {
  const args = ["--fail", "--silent", "--show-error", "--max-time", "20"];
  if (data) args.push("-H", "Content-Type: application/json", "--data", JSON.stringify(data));
  args.push(url);
  return JSON.parse(execFileSync("curl", args, {encoding:"utf8",maxBuffer:4*1024*1024}));
}
const account = fetchJSON(horizon);
const contract = Asset.native().contractId(Networks.TESTNET);
const tx = new TransactionBuilder(new Account(source, account.sequence), {
  fee: "10000", networkPassphrase: Networks.TESTNET
}).addOperation(Operation.invokeContractFunction({
  contract, function: "transfer",
  args: [new Address(source).toScVal(), new Address(source).toScVal(), xdr.ScVal.scvI128(new xdr.Int128Parts({hi:0n,lo:1n}))]
})).setTimeout(30).build();
// No signing and no submitTransaction. Only simulate a transfer of one stroop to self.
const response = fetchJSON(endpoint, {jsonrpc:"2.0",id:1,method:"simulateTransaction",params:{transaction:tx.toXDR()}});
const result = response.result;
if (result.error || !result.results?.[0]?.auth?.length) throw Error("Simulation failed or produced no authorization entries");
const network = fetchJSON(endpoint, {jsonrpc:"2.0",id:2,method:"getNetwork"}).result;
if (network.passphrase !== Networks.TESTNET || !Number.isInteger(network.protocolVersion)) {
  throw Error("Unexpected testnet identity or protocol version");
}
const auth = result.results[0].auth;
if (auth.some(x => typeof x !== "string")) throw Error("Malformed RPC auth entries");
const fixture = {
  provenance: {
    kind: "live-testnet-simulation", capturedAt: new Date().toISOString(),
    network: "Stellar Testnet", rpc: endpoint, contract,
    function: "transfer", sdk: "@stellar/stellar-sdk 17.2.1",
    source: "public-testnet-account", protocolVersion: network.protocolVersion,
    resultLedger: result.latestLedger
  },
  result: { results: [{auth}] }
};
await writeFile(new URL("./captured.json", import.meta.url), JSON.stringify(fixture,null,2)+"\n", {flag:"wx"});
console.log("Captured live simulation authorization fixture (no signatures or private keys).");
