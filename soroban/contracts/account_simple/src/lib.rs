#![no_std]

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype, crypto::Hash, BytesN, Env, Vec,
};

pub use soroban_sdk::auth::Context as AuthContext;

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    Signer(BytesN<32>),
}

#[contracttype]
#[derive(Clone)]
pub struct Signature {
    pub public_key: BytesN<32>,
    pub signature: BytesN<64>,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    UnknownSigner = 1,
    TooManySignatures = 2,
}

#[contract]
pub struct AccountSimple;

#[contractimpl]
impl AccountSimple {
    pub fn __constructor(env: Env, signer: BytesN<32>) {
        env.storage().instance().set(&DataKey::Signer(signer), &());
    }
    
    pub fn add_signer(env: Env, signer: BytesN<32>) {
        // Simple contract: anyone can add signers (no admin)
        env.storage().instance().set(&DataKey::Signer(signer), &());
    }
}

#[contractimpl]
impl CustomAccountInterface for AccountSimple {
    type Error = Error;
    type Signature = Vec<Signature>;

    #[allow(non_snake_case)]
    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signatures: Self::Signature,
        _auth_context: Vec<Context>,
    ) -> Result<(), Error> {
        // Simple validation: just check if signature is valid, no nested auth
        if signatures.len() > 1 {
            return Err(Error::TooManySignatures);
        }

        let signature = signatures.get_unchecked(0);

        // Check if signer exists
        if env
            .storage()
            .instance()
            .get::<_, ()>(&DataKey::Signer(signature.public_key.clone()))
            .is_none()
        {
            return Err(Error::UnknownSigner);
        }

        // Verify signature
        env.crypto()
            .ed25519_verify(&signature.public_key, &signature_payload.into(), &signature.signature);

        Ok(())
    }
}