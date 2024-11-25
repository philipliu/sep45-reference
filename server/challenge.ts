import {
  Address,
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
const serverKeypair = Keypair.fromSecret(Deno.env.get("SERVER_SIGNING_KEY")!);
const rpc = new SorobanRpc.Server(Deno.env.get("RPC_URL")!);

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

export async function getChallenge(
  request: ChallengeRequest,
): Promise<ChallengeResponse> {
  const sourceAccount = await rpc.getAccount(serverKeypair.publicKey());

  const walletAddress = Address.fromString(request.address).toScVal();
  let clientDomainAddress: Address | undefined = undefined;
  if (request.client_domain !== undefined) {
    const signingKey = await fetchSigningKey(request.client_domain);
    clientDomainAddress = Address.fromString(signingKey);
  }
  const clientDomainScVal = clientDomainAddress
    ? clientDomainAddress.toScVal()
    : xdr.ScVal.scvVoid();
  const nonce = await generateNonce(request.address + request.memo);

  const args = [
    walletAddress,
    nativeToScVal(request.memo),
    nativeToScVal(request.home_domain),
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

  // Sign the hashes of the authorization entries
  const signatures = authEntries.map((entry) => {
    // Get the SHA-256 hash of the entry and sign it
    const hash = createHash("sha256").update(entry.toXDR()).digest("hex");
    return serverKeypair.sign(Buffer.from(hash, "hex")).toString("hex");
  });

  return {
    authorization_entries: authEntries.map((entry) =>
      entry.toXDR().toString("base64")
    ),
    server_signatures: signatures,
    network_passphrase: Networks.TESTNET,
  } as ChallengeResponse;
}

export type TokenRequest = {
  authorization_entries: string[];
  server_signatures: string[];
  credentials: string[];
};

export type TokenResponse = {
  token: string;
};

export async function getToken(
  request: TokenRequest,
): Promise<TokenResponse> {
  // Validate the authorization entries
  const authEntries = request.authorization_entries.map((entry) =>
    xdr.SorobanAuthorizationEntry.fromXDR(Buffer.from(entry, "base64"))
  );
  request.server_signatures.forEach((signature, index) => {
    const entry = authEntries[index];
    const hash = createHash("sha256").update(entry.toXDR()).digest();
    if (!serverKeypair.verify(hash, Buffer.from(signature, "hex"))) {
      throw new Error("Invalid signature");
    }
  });

  // Extract args from authorization entry
  const args = authEntries[0].rootInvocation().function().contractFn().args();

  // Check if the nonce exist and is unused
  const nonce = scValToNative(args[6]);
  const key = scValToNative(args[0]) + scValToNative(args[1]);
  if (!(await verifyNonce(key, nonce))) {
    throw new Error("Invalid nonce");
  }

  // Attach credentials to auth entries
  const signedAuthEntries = request.credentials.map((credentialXdr, index) => {
    const credential = xdr.SorobanCredentials.fromXDR(
      Buffer.from(credentialXdr, "base64"),
    );

    return new xdr.SorobanAuthorizationEntry({
      credentials: credential,
      rootInvocation: authEntries[index].rootInvocation(),
    });
  });

  // Construct the transaction using the clients credentials
  const invokeOp = webAuthContract.call("web_auth_verify", ...args);
  invokeOp.body().invokeHostFunctionOp().auth(signedAuthEntries);

  const sourceAccount = await rpc.getAccount(serverKeypair.publicKey());
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
  const memo = scValToNative(args[1]);
  const clientDomain = scValToNative(args[4]);
  const homeDomain = scValToNative(args[2]);

  const token = jwt.sign({
    iss: webAuthDomain,
    sub: memo,
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
