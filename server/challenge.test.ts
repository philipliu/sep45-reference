import "https://deno.land/std@0.201.0/dotenv/load.ts";
import { getChallenge, getToken } from "./challenge.ts";
import { authorizeEntry, Keypair, SorobanRpc, xdr } from "npm:stellar-sdk";
import { Buffer } from "node:buffer";
import { assert } from "jsr:@std/assert/assert";

const rpc = new SorobanRpc.Server(Deno.env.get("RPC_URL")!);

async function signAsClient(
  authEntry: xdr.SorobanAuthorizationEntry,
): Promise<xdr.SorobanAuthorizationEntry> {
  const keypair = Keypair.fromSecret(Deno.env.get("WALLET_SIGNER")!);
  const validUntilLedgerSeq = (await rpc.getLatestLedger()).sequence + 10;
  const networkPassphrase = "Test SDF Network ; September 2015";

  return await authorizeEntry(
    authEntry,
    keypair,
    validUntilLedgerSeq,
    networkPassphrase,
  );
}

Deno.test("challenge without client domain", async () => {
  const challengeRequest = {
    account: Deno.env.get("WALLET_ADDRESS")!,
    memo: "123",
    home_domain: "localhost:8080",
    client_domain: undefined,
  };

  const challenge = await getChallenge(challengeRequest);

  assert(challenge.authorization_entries.length === 2);
  assert(challenge.network_passphrase === "Test SDF Network ; September 2015");

  const authorizationEntry = Buffer.from(
    challenge.authorization_entries[0],
    "base64",
  );
  const clientSignedAuthEntry = await signAsClient(
    xdr.SorobanAuthorizationEntry.fromXDR(
      authorizationEntry,
    ),
  );
  // The client should simulate the transaction with the authorization entries
  // to check that the server signature is valid in addition to making sure that
  // the transaction is not malicious.

  const tokenRequest = {
    authorization_entries: [
      clientSignedAuthEntry.toXDR("base64"),
      challenge.authorization_entries[1],
    ],
  };

  const token = await getToken(tokenRequest);
  console.log(token);

  assert(token.token !== undefined);
});
