import "https://deno.land/std@0.201.0/dotenv/load.ts";
import { getChallenge, getToken } from "./challenge.ts";
import {
  authorizeEntry,
  hash,
  Keypair,
  Networks,
  SorobanRpc,
  StrKey,
  xdr,
} from "npm:stellar-sdk";
import { Buffer } from "node:buffer";
import { assert } from "jsr:@std/assert/assert";
import xdrParser from "npm:@stellar/js-xdr";

const rpc = new SorobanRpc.Server(Deno.env.get("RPC_URL")!);

async function signAsClient(
  authEntry: xdr.SorobanAuthorizationEntry,
  keypair: Keypair,
): Promise<xdr.SorobanAuthorizationEntry> {
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

  assert(challenge.authorization_entries !== undefined);
  assert(challenge.network_passphrase === "Test SDF Network ; September 2015");

  const readBuffer = Buffer.from(
    challenge.authorization_entries,
    "base64",
  );
  const authEntriesType = new xdrParser.VarArray(
    xdr.SorobanAuthorizationEntry,
    2147483647,
  );
  const reader = new xdrParser.XdrReader(readBuffer);
  const authorizationEntries: Array<xdr.SorobanAuthorizationEntry> =
    authEntriesType
      .read(reader);

  const clientSignedAuthEntry = await signAsClient(
    authorizationEntries[0],
    Keypair.fromSecret(Deno.env.get("WALLET_SIGNER")!),
  );

  // Nested authorization: Admin must authorize the __check_auth invocation

  const additionalSigner = Keypair.fromSecret(
    Deno.env.get("OTHER_SIGNER")!,
  );

  // Get the payload hash for the account's invocation
  const preimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
    new xdr.HashIdPreimageSorobanAuthorization({
      networkId: hash(Buffer.from(Networks.TESTNET)),
      nonce: clientSignedAuthEntry.credentials().address().nonce(),
      signatureExpirationLedger: clientSignedAuthEntry.credentials().address()
        .signatureExpirationLedger(),
      invocation: clientSignedAuthEntry.rootInvocation(),
    }),
  );
  const preimageHash = hash(preimage.toXDR());

  // Create admin authorization entry for the exact __check_auth invocation
  // that will call admin.require_auth()
  
  const validUntilLedgerSeq = (await rpc.getLatestLedger()).sequence + 10;
  const adminNonce = clientSignedAuthEntry.credentials().address().nonce().toBigInt() + 1n;

  const adminCredentials = new xdr.SorobanAddressCredentials({
    address: xdr.ScAddress.scAddressTypeAccount(
      additionalSigner.xdrAccountId(),
    ),
    nonce: new xdr.Int64(adminNonce),
    signatureExpirationLedger: validUntilLedgerSeq,
    signature: xdr.ScVal.scvVoid(),
  });

  // Create the exact __check_auth invocation that will call admin.require_auth()
  const checkAuthInvocation = new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction
      .sorobanAuthorizedFunctionTypeContractFn(
        new xdr.InvokeContractArgs({
          contractAddress: xdr.ScAddress.scAddressTypeContract(
            clientSignedAuthEntry.credentials().address().address()
              .contractId(),
          ),
          functionName: "__check_auth",
          args: [
            xdr.ScVal.scvBytes(preimageHash), // signature_payload
            xdr.ScVal.scvVec([
              xdr.ScVal.scvMap([
                new xdr.ScMapEntry({
                  key: xdr.ScVal.scvSymbol("public_key"),
                  val: xdr.ScVal.scvBytes(Keypair.fromSecret(Deno.env.get("WALLET_SIGNER")!).rawPublicKey()),
                }),
                new xdr.ScMapEntry({
                  key: xdr.ScVal.scvSymbol("signature"),
                  val: xdr.ScVal.scvBytes(
                    clientSignedAuthEntry.credentials().address().signature().vec()![0].map()![1].val().bytes()!
                  ),
                }),
              ]),
            ]), // signatures
            xdr.ScVal.scvVec([
              xdr.ScVal.scvVec([
                xdr.ScVal.scvSymbol("Contract"),
                xdr.ScVal.scvMap([
                  new xdr.ScMapEntry({
                    key: xdr.ScVal.scvSymbol("args"),
                    val: xdr.ScVal.scvVec(
                      clientSignedAuthEntry.rootInvocation().function()
                        .contractFn().args(),
                    ),
                  }),
                  new xdr.ScMapEntry({
                    key: xdr.ScVal.scvSymbol("contract"),
                    val: xdr.ScVal.scvAddress(
                      clientSignedAuthEntry.rootInvocation().function()
                        .contractFn().contractAddress(),
                    ),
                  }),
                  new xdr.ScMapEntry({
                    key: xdr.ScVal.scvSymbol("fn_name"),
                    val: xdr.ScVal.scvSymbol(
                      clientSignedAuthEntry.rootInvocation().function()
                        .contractFn().functionName(),
                    ),
                  }),
                ]),
              ])
            ]), // auth_context with the full web_auth_verify context
          ],
        }),
      ),
    subInvocations: [],
  });

  // Admin authorization entry for __check_auth invocation
  const adminAuthEntry = new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
      adminCredentials,
    ),
    rootInvocation: checkAuthInvocation, // Admin authorizes the __check_auth call
  });

  const finalAdminSignedEntry = await signAsClient(
    adminAuthEntry,
    additionalSigner,
  );

  const signedEntries: Array<xdr.SorobanAuthorizationEntry> = [
    clientSignedAuthEntry,           // Account contract authorization for web_auth_verify 
    finalAdminSignedEntry,           // Admin authorization for __check_auth
    authorizationEntries[1],         // Server authorization for web_auth_verify  
  ];
  
  // Clean up

  const authEntriesWriteType = new xdrParser.VarArray(
    xdr.SorobanAuthorizationEntry,
    2147483647,
  );
  const writer = new xdrParser.XdrWriter();
  authEntriesWriteType.write(signedEntries, writer);
  const writeBuffer = writer.finalize();

  const tokenRequest = {
    authorization_entries: writeBuffer.toString("base64"),
  };

  const token = await getToken(tokenRequest);
  console.log(token);

  assert(token.token !== undefined);
});

Deno.test("challenge with simple account (no nested auth)", async () => {
  const challengeRequest = {
    account: "CDT6XOLRYC6URFC46TT3G6PBZMSFXVBVUSMX67NV4IZVZWUSZTEEAMC3", // account_simple contract
    memo: "123",
    home_domain: "localhost:8080",
    client_domain: undefined,
  };

  const challenge = await getChallenge(challengeRequest);

  assert(challenge.authorization_entries !== undefined);
  assert(challenge.network_passphrase === "Test SDF Network ; September 2015");

  const readBuffer = Buffer.from(
    challenge.authorization_entries,
    "base64",
  );
  const authEntriesType = new xdrParser.VarArray(
    xdr.SorobanAuthorizationEntry,
    2147483647,
  );
  const reader = new xdrParser.XdrReader(readBuffer);
  const authorizationEntries: Array<xdr.SorobanAuthorizationEntry> =
    authEntriesType
      .read(reader);

  // For simple account, we only need the client signature
  const clientSignedAuthEntry = await signAsClient(
    authorizationEntries[0],
    Keypair.fromSecret(Deno.env.get("WALLET_SIGNER")!),
  );

  // Simple account doesn't require admin auth, so we just use the client and server entries
  authorizationEntries[0] = clientSignedAuthEntry;
  
  // No additional auth entries needed for simple account
  const authEntriesWriteType = new xdrParser.VarArray(
    xdr.SorobanAuthorizationEntry,
    2147483647,
  );
  const writer = new xdrParser.XdrWriter();
  authEntriesWriteType.write(authorizationEntries, writer);
  const writeBuffer = writer.finalize();

  const tokenRequest = {
    authorization_entries: writeBuffer.toString("base64"),
  };

  const token = await getToken(tokenRequest);
  console.log(token);

  assert(token.token !== undefined);
});

Deno.test("challenge with require_auth_for_args", async () => {
  const challengeRequest = {
    account: "CBG46NAJ7KGU2T32JYB5SV7YELCRKPXYQ3BIWPUABEDIAYL6W77FETP7", // account_with_args contract
    memo: "123",
    home_domain: "localhost:8080",
    client_domain: undefined,
  };

  const challenge = await getChallenge(challengeRequest);

  assert(challenge.authorization_entries !== undefined);
  assert(challenge.network_passphrase === "Test SDF Network ; September 2015");

  const readBuffer = Buffer.from(
    challenge.authorization_entries,
    "base64",
  );
  const authEntriesType = new xdrParser.VarArray(
    xdr.SorobanAuthorizationEntry,
    2147483647,
  );
  const reader = new xdrParser.XdrReader(readBuffer);
  const authorizationEntries: Array<xdr.SorobanAuthorizationEntry> =
    authEntriesType
      .read(reader);

  const clientSignedAuthEntry = await signAsClient(
    authorizationEntries[0],
    Keypair.fromSecret(Deno.env.get("WALLET_SIGNER")!),
  );

  // For require_auth_for_args, admin needs to authorize with just the payload hash
  const additionalSigner = Keypair.fromSecret(
    Deno.env.get("OTHER_SIGNER")!,
  );

  // Get the payload hash for the account's invocation
  const preimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
    new xdr.HashIdPreimageSorobanAuthorization({
      networkId: hash(Buffer.from(Networks.TESTNET)),
      nonce: clientSignedAuthEntry.credentials().address().nonce(),
      signatureExpirationLedger: clientSignedAuthEntry.credentials().address()
        .signatureExpirationLedger(),
      invocation: clientSignedAuthEntry.rootInvocation(),
    }),
  );
  const preimageHash = hash(preimage.toXDR());

  // Create admin authorization entry for require_auth_for_args
  const validUntilLedgerSeq = (await rpc.getLatestLedger()).sequence + 10;
  const adminNonce = clientSignedAuthEntry.credentials().address().nonce().toBigInt() + 1n;

  const adminCredentials = new xdr.SorobanAddressCredentials({
    address: xdr.ScAddress.scAddressTypeAccount(
      additionalSigner.xdrAccountId(),
    ),
    nonce: new xdr.Int64(adminNonce),
    signatureExpirationLedger: validUntilLedgerSeq,
    signature: xdr.ScVal.scvVoid(),
  });

  // For require_auth_for_args, the invocation only needs the payload hash as argument
  const adminInvocation = new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction
      .sorobanAuthorizedFunctionTypeContractFn(
        new xdr.InvokeContractArgs({
          contractAddress: xdr.ScAddress.scAddressTypeContract(
            StrKey.decodeContract("CBG46NAJ7KGU2T32JYB5SV7YELCRKPXYQ3BIWPUABEDIAYL6W77FETP7"),
          ),
          functionName: "__check_auth",
          args: [xdr.ScVal.scvBytes(preimageHash)],
        }),
      ),
    subInvocations: [],
  });

  const adminAuthEntry = new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
      adminCredentials,
    ),
    rootInvocation: adminInvocation,
  });

  const signedAdminAuthEntry = await authorizeEntry(
    adminAuthEntry,
    additionalSigner,
    validUntilLedgerSeq,
    Networks.TESTNET,
  );

  // Update authorization entries array
  authorizationEntries[0] = clientSignedAuthEntry;
  authorizationEntries.push(signedAdminAuthEntry);

  const authEntries = authorizationEntries.concat(
    authorizationEntries.slice(1),
  );

  const authEntriesWriteType = new xdrParser.VarArray(
    xdr.SorobanAuthorizationEntry,
    2147483647,
  );
  const writer = new xdrParser.XdrWriter();
  authEntriesWriteType.write(authEntries, writer);
  const writeBuffer = writer.finalize();

  const tokenRequest = {
    authorization_entries: writeBuffer.toString("base64"),
  };

  const token = await getToken(tokenRequest);
  console.log(token);

  assert(token.token !== undefined);
});
