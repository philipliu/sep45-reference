import "https://deno.land/std@0.201.0/dotenv/load.ts";
import { getChallenge, getToken } from "./challenge.ts";
import {
  authorizeEntry,
  hash,
  Keypair,
  Networks,
  SorobanRpc,
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
  const authEntriesType = new xdrParser.Array(
    xdr.SorobanAuthorizationEntry,
    2,
  );
  const reader = new xdrParser.XdrReader(readBuffer);
  const authorizationEntries: Array<xdr.SorobanAuthorizationEntry> =
    authEntriesType
      .read(reader);

  const clientSignedAuthEntry = await signAsClient(
    authorizationEntries[0],
    Keypair.fromSecret(Deno.env.get("WALLET_SIGNER")!),
  );

  const additionalSigner = Keypair.fromSecret(
    Deno.env.get("ADDITIONAL_SIGNER")!,
  );

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
            xdr.ScVal.scvBytes(preimageHash),
            clientSignedAuthEntry.credentials().address().signature(),
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
            ]),
          ],
        }),
      ),
    subInvocations: [],
  });


  const additionalCredentials = new xdr.SorobanAddressCredentials({
    address: xdr.ScAddress.scAddressTypeAccount(
      additionalSigner.xdrAccountId(),
    ),
    nonce: new xdr.Int64(
      clientSignedAuthEntry.credentials().address().nonce().toBigInt()
        .valueOf() + 10n,
    ),
    signatureExpirationLedger: 0,
    signature: xdr.ScVal.scvVoid(),
  });

  const checkAuthInvocationEntry = new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
      additionalCredentials,
    ),
    rootInvocation: checkAuthInvocation,
  });

  const clientNestedSignedAuthEntry = await signAsClient(
    checkAuthInvocationEntry,
    additionalSigner,
  );

  // The client should simulate the transaction with the authorization entries
  // to check that the server signature is valid in addition to making sure that
  // the transaction is not malicious.

  const signedEntries: Array<xdr.SorobanAuthorizationEntry> = [
    clientSignedAuthEntry,
    clientNestedSignedAuthEntry,
    authorizationEntries[1],
  ];

  const authEntriesWriteType = new xdrParser.Array(
    xdr.SorobanAuthorizationEntry,
    3,
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
