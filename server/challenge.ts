import {
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
import xdrParser from "npm:@stellar/js-xdr";

const webAuthContract = new Contract(Deno.env.get("WEB_AUTH_CONTRACT_ID")!);
const sourceKeypair = Keypair.fromSecret(Deno.env.get("SOURCE_SIGNING_KEY")!);
const sep10SigningKeypair = Keypair.fromSecret(
  Deno.env.get("SERVER_SIGNING_KEY")!,
);
const rpc = new SorobanRpc.Server(Deno.env.get("RPC_URL")!);

export type ChallengeRequest = {
  account: string;
  home_domain: string;
  client_domain: string | undefined;
};

export type ChallengeResponse = {
  authorization_entries: string;
  network_passphrase: string;
};

export async function getChallenge(
  request: ChallengeRequest,
): Promise<ChallengeResponse> {
  const sourceAccount = await rpc.getAccount(sourceKeypair.publicKey());

  let clientDomainAddress: string | undefined = undefined;
  if (request.client_domain !== undefined) {
    clientDomainAddress = await fetchSigningKey(request.client_domain);
  }
  const nonce = await generateNonce(request.account);

  const fields = [
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("account"),
      val: nativeToScVal(request.account),
    }),
    ...(request.client_domain !== undefined
      ? [
        new xdr.ScMapEntry({
          key: xdr.ScVal.scvSymbol("client_domain"),
          val: nativeToScVal(request.client_domain),
        }),
        new xdr.ScMapEntry({
          key: xdr.ScVal.scvSymbol("client_domain_account"),
          val: nativeToScVal(clientDomainAddress),
        }),
      ]
      : []),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("home_domain"),
      val: nativeToScVal(request.home_domain),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("nonce"),
      val: nativeToScVal(nonce),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("web_auth_domain"),
      val: nativeToScVal(request.home_domain),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("web_auth_domain_account"),
      val: nativeToScVal(sep10SigningKeypair.publicKey()),
    }),

  ];

  const args = [
    xdr.ScVal.scvMap(fields),
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

  const authEntriesType = new xdrParser.Array(
    xdr.SorobanAuthorizationEntry,
    resolvedEntries.length,
  );
  const writer = new xdrParser.XdrWriter();
  authEntriesType.write(resolvedEntries, writer);
  const xdrBuffer = writer.finalize();

  return {
    authorization_entries: xdrBuffer.toString("base64"),
    network_passphrase: Networks.TESTNET,
  } as ChallengeResponse;
}

export type TokenRequest = {
  authorization_entries: string;
};

export type TokenResponse = {
  token: string;
};

export async function getToken(
  request: TokenRequest,
): Promise<TokenResponse> {
  const readBuffer = Buffer.from(request.authorization_entries, "base64");
  // TODO: this should use VarArray
  const authEntriesType = new xdrParser.Array(
    xdr.SorobanAuthorizationEntry,
    2,
  );
  const reader = new xdrParser.XdrReader(readBuffer);
  const authEntries: xdr.SorobanAuthorizationEntry[] = authEntriesType.read(
    reader,
  );

  // Extract args from authorization entry
  const args = authEntries[0].rootInvocation().function().contractFn().args();
  const argEntries = args[0].map()!;

  // Check if the nonce exist and is unused
  const nonce = scValToNative(
    argEntries.find((entry) => entry.key().sym().toString() === "nonce")!.val(),
  );
  const account = scValToNative(
    argEntries.find((entry) => entry.key().sym().toString() === "account")!
      .val(),
  );
  if (!(await verifyNonce(account, nonce))) {
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

  const webAuthDomain = scValToNative(
    argEntries.find((entry) =>
      entry.key().sym().toString() === "web_auth_domain"
    )!
      .val(),
  );
  // The client domain is optional, only convert to scValToNative if it exists
  const clientDomainArg = argEntries.find((entry) =>
    entry.key().sym().toString() === "client_domain"
  );
  const clientDomain = clientDomainArg !== undefined
    ? scValToNative(clientDomainArg.val())
    : undefined;

  const homeDomain = scValToNative(
    argEntries.find((entry) => entry.key().sym().toString() === "home_domain")!
      .val(),
  );

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
