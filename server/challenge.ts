import {
  Address,
  authorizeEntry,
  BASE_FEE,
  Contract,
  Keypair,
  nativeToScVal,
  Networks,
  scValToNative,
  SorobanRpc,
  TransactionBuilder,
  xdr,
} from "npm:stellar-sdk";
import { createHash } from "node:crypto";
import { fetchSigningKey } from "./toml.ts";
import { Buffer } from "node:buffer";
import jwt from "npm:jsonwebtoken";
import { generateNonce, verifyNonce } from "./nonce.ts";

const webAuthContract = new Contract(Deno.env.get("WEB_AUTH_CONTRACT_ID")!);
const sourceKeypair = Keypair.fromSecret(Deno.env.get("SOURCE_SIGNING_KEY")!);
const sep10SigningKeypair = Keypair.fromSecret(
  Deno.env.get("SERVER_SIGNING_KEY")!,
);
const rpc = new SorobanRpc.Server(Deno.env.get("RPC_URL")!);

export type ChallengeRequest = {
  address: string;
  home_domain: string | undefined;
  client_domain: string | undefined;
};

export type ChallengeResponse = {
  authorization_entries: string[];
  network_passphrase: string;
};

export async function getChallenge(
  request: ChallengeRequest,
): Promise<ChallengeResponse> {
  const sourceAccount = await rpc.getAccount(sourceKeypair.publicKey());

  const walletAddress = Address.fromString(request.address).toScVal();
  let clientDomainAddress: Address | undefined = undefined;
  if (request.client_domain !== undefined) {
    const signingKey = await fetchSigningKey(request.client_domain);
    clientDomainAddress = Address.fromString(signingKey);
  }
  const clientDomainScVal = clientDomainAddress
    ? clientDomainAddress.toScVal()
    : xdr.ScVal.scvVoid();
  const nonce = await generateNonce(request.address);

  const args = [
    walletAddress,
    nativeToScVal(request.home_domain),
    nativeToScVal(Address.fromString(sep10SigningKeypair.publicKey())),
    nativeToScVal(request.home_domain),
    nativeToScVal(request.client_domain),
    clientDomainScVal,
    nativeToScVal(nonce),
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

  // Sign the server's authorization entry
  const finalAuthEntries = authEntries.map(async (entry) => {
    if (
      entry.credentials().switch() ===
        xdr.SorobanCredentialsType.sorobanCredentialsAddress() &&
      entry.credentials().address().address().switch() ===
        xdr.ScAddressType.scAddressTypeAccount()
    ) {
      const validUntilLedgerSeq = (await rpc.getLatestLedger()).sequence + 1;
      const signed = await authorizeEntry(
        entry,
        sep10SigningKeypair,
        validUntilLedgerSeq,
        Networks.TESTNET,
      );
      return signed;
    }
    return entry;
  });

  const resolvedEntries = await Promise.all(finalAuthEntries);

  return {
    authorization_entries: resolvedEntries.map((entry) =>
      entry.toXDR().toString("base64")
    ),
    network_passphrase: Networks.TESTNET,
  } as ChallengeResponse;
}

export type TokenRequest = {
  authorization_entries: string[];
};

export type TokenResponse = {
  token: string;
};

export async function getToken(
  request: TokenRequest,
): Promise<TokenResponse> {
  // Extract args from authorization entry
  const authEntries = request.authorization_entries.map((entry) =>
    xdr.SorobanAuthorizationEntry.fromXDR(Buffer.from(entry, "base64"))
  );
  const args = authEntries[0].rootInvocation().function().contractFn().args();

  // Check if the nonce exist and is unused
  const nonce = scValToNative(args[6]);
  const key = scValToNative(args[0]);
  if (!(await verifyNonce(key, nonce))) {
    throw new Error("Invalid nonce");
  }

  // Construct the transaction using the clients credentials
  //
  // Note: the server does not need to validate the authorization entries because the following
  // scenarios are covered by simulation
  // 1. if the server's signature is invalid
  // 2. if the client's signature is missing
  // 3. if the auth entries contain different arguments
  const invokeOp = webAuthContract.call("web_auth_verify", ...args);
  invokeOp.body().invokeHostFunctionOp().auth(authEntries);

  const sourceAccount = await rpc.getAccount(sep10SigningKeypair.publicKey());
  const builtTransaction = new TransactionBuilder(sourceAccount, {
    fee: BASE_FEE,
    networkPassphrase: Networks.TESTNET,
  })
    .addOperation(invokeOp)
    .setTimeout(300)
    .build();

  // Simulate the transaction in enforcing mode to verify the credentials
  const simulatedTransaction = await rpc.simulateTransaction(
    builtTransaction,
  );

  // Check if the response is a success
  if ("result" in simulatedTransaction) {
    // Simulation was successful
  } else {
    throw new Error("Transaction simulation failed");
  }

  const webAuthDomain = scValToNative(args[3]);
  const account = [scValToNative(args[0]), scValToNative(args[1])].join(":");
  const clientDomain = scValToNative(args[4]);
  const homeDomain = scValToNative(args[2]);

  const token = jwt.sign({
    iss: webAuthDomain,
    sub: account,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 300,
    jti: createHash("sha256").update(Buffer.from(invokeOp.toXDR())).digest(
      "hex",
    ),
    client_domain: clientDomain,
    home_domain: homeDomain,
  }, Deno.env.get("JWT_SECRET")!);

  return {
    token: token,
  } as TokenResponse;
}
