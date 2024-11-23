import {
  Address,
  BASE_FEE,
  Contract,
  Keypair,
  nativeToScVal,
  Networks,
  SorobanRpc,
  TransactionBuilder,
  xdr,
} from "npm:stellar-sdk";
import { createHash } from "node:crypto";
import { fetchSigningKey } from "./toml.ts";

const webAuthContract = new Contract(Deno.env.get("WEB_AUTH_CONTRACT_ID")!);
const serverKeypair = Keypair.fromSecret(Deno.env.get("SERVER_SIGNING_KEY")!);
const rpc = new SorobanRpc.Server("https://soroban-testnet.stellar.org:443");

export type ChallengeRequest = {
  address: string;
  memo: string | undefined;
  home_domain: string | undefined;
  client_domain: string | undefined;
};

export type ChallengeResponse = {
  authorization_entries: string[];
  server_signatures: string[];
  network_passphrase: string;
};

export async function challenge(
  request: ChallengeRequest,
): Promise<ChallengeResponse> {
  const sourceAccount = await rpc.getAccount(serverKeypair.publicKey());

  const walletAddress = Address.fromString(request.address).toScVal();
  let clientDomainAddress: Address | undefined = undefined;
  if (request.client_domain !== undefined) {
    const signingKey = await fetchSigningKey(request.client_domain);
    console.log("Client domain signing key:", signingKey);
    clientDomainAddress = Address.fromString(signingKey);
  }
  const clientDomainScVal = clientDomainAddress
    ? clientDomainAddress.toScVal()
    : xdr.ScVal.scvVoid();

  const args = [
    walletAddress,
    nativeToScVal(request.memo),
    nativeToScVal(request.home_domain),
    nativeToScVal(request.home_domain),
    nativeToScVal(request.client_domain),
    clientDomainScVal,
    xdr.ScVal.scvVoid(), // TODO: consume nonce
  ];
  const builtTransaction = new TransactionBuilder(sourceAccount, {
    fee: BASE_FEE,
    networkPassphrase: Networks.TESTNET,
  })
    .addOperation(webAuthContract.call("web_auth_verify", ...args))
    .setTimeout(300)
    .build();

  // Simulate the transaction to get the authorization entries
  const simulatedTransaction = await rpc.simulateTransaction(builtTransaction);
  // Check if the response is a success
  let authEntries: xdr.SorobanAuthorizationEntry[];
  if ("result" in simulatedTransaction) {
    const result = simulatedTransaction.result!;
    authEntries = result.auth;
  } else {
    throw new Error("Transaction simulation failed");
  }

  // Sign the hashes of the authorization entries
  const signatures = authEntries.map((entry) => {
    // Get the SHA-256 hash of the entry and sign it
    return createHash("sha256").update(entry.toXDR()).digest("hex");
  });

  return {
    authorization_entries: authEntries.map((entry) =>
      entry.toXDR().toString("base64")
    ),
    server_signatures: signatures,
    network_passphrase: Networks.TESTNET,
  } as ChallengeResponse;
}
