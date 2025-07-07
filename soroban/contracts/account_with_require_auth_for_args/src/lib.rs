#![no_std]

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype, crypto::Hash, Address, BytesN, Env, Vec, IntoVal,
};

pub use soroban_sdk::auth::Context as AuthContext;

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    Admin,
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
    InvalidContext = 1,
    NotEnoughSigners = 2,
    TooManySignatures = 3,
    UnknownSigner = 4,
    InvalidSignature = 5,
}

#[contract]
pub struct AccountWithArgsContract;

#[contractimpl]
impl AccountWithArgsContract {
    pub fn __constructor(env: Env, admin: Address, signer: BytesN<32>) {
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Signer(signer), &());
    }
}

#[contractimpl]
impl CustomAccountInterface for AccountWithArgsContract {
    type Error = Error;
    type Signature = Vec<Signature>;

    #[allow(non_snake_case)]
    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signatures: Self::Signature,
        _auth_context: Vec<Context>,
    ) -> Result<(), Error> {
        if signatures.len() > 1 {
            return Err(Error::TooManySignatures);
        }

        let signature = signatures.get_unchecked(0);

        if env
            .storage()
            .instance()
            .get::<_, ()>(&DataKey::Signer(signature.public_key.clone()))
            .is_none()
        {
            return Err(Error::UnknownSigner);
        }

        // Key difference: Use require_auth_for_args with only the signature_payload
        if let Some(admin) = env.storage().instance().get::<_, Address>(&DataKey::Admin) {
            admin.require_auth_for_args((signature_payload.clone(),).into_val(&env));
        }

        env.crypto()
            .ed25519_verify(&signature.public_key, &signature_payload.into(), &signature.signature);

        Ok(())
    }
}