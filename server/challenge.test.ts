import "https://deno.land/std@0.201.0/dotenv/load.ts";
import { getChallenge, getToken } from "./challenge.ts";
import { authorizeEntry, Keypair, SorobanRpc, xdr } from "npm:stellar-sdk";
import { Buffer } from "node:buffer";
import { assert } from "jsr:@std/assert/assert";

const rpc = new SorobanRpc.Server(Deno.env.get("RPC_URL")!);

async function signAsClient(
  authEntry: xdr.SorobanAuthorizationEntry,
): Promise<xdr.SorobanCredentials> {
  const keypair = Keypair.fromSecret(Deno.env.get("WALLET_SIGNER")!);
  const validUntilLedgerSeq = (await rpc.getLatestLedger()).sequence + 1;
  const networkPassphrase = "Test SDF Network ; September 2015";

  const result = await authorizeEntry(
    authEntry,
    keypair,
    validUntilLedgerSeq,
    networkPassphrase,
  );
  return result.credentials();
}

Deno.test("challenge without client domain", async () => {
  const challengeRequest = {
    address: Deno.env.get("WALLET_ADDRESS")!,
    memo: "123",
    home_domain: "localhost:8080",
    client_domain: undefined,
  };

  const challenge = await getChallenge(challengeRequest);

  assert(challenge.authorization_entries.length === 1);
  assert(challenge.server_signatures.length === 1);
  assert(challenge.network_passphrase === "Test SDF Network ; September 2015");

  const authorizationEntry = Buffer.from(
    challenge.authorization_entries[0],
    "base64",
  );
  const authorizationEntryXdr = xdr.SorobanAuthorizationEntry.fromXDR(
    authorizationEntry,
  );

  const tokenRequest = {
    authorization_entries: challenge.authorization_entries,
    server_signatures: challenge.server_signatures,
    credentials: [(await signAsClient(authorizationEntryXdr)).toXDR("base64")],
  };

  const token = await getToken(tokenRequest);
  console.log(token);

  assert(token.token !== undefined);
});
