#![cfg(test)]

use ed25519_dalek::Keypair;
use ed25519_dalek::Signer;
use rand::thread_rng;
use soroban_sdk::auth::Context;
use soroban_sdk::auth::ContractContext;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::testutils::BytesN as _;
use soroban_sdk::vec;
use soroban_sdk::Address;
use soroban_sdk::BytesN;
use soroban_sdk::Env;
use soroban_sdk::IntoVal;
use soroban_sdk::Symbol;
use soroban_sdk::Val;

extern crate std;

use crate::Account;
use crate::AccountArgs;
use crate::AccountError;
use crate::{AccountClient, Signature};

fn generate_keypair() -> Keypair {
    Keypair::generate(&mut thread_rng())
}

fn signer_public_key(e: &Env, signer: &Keypair) -> BytesN<32> {
    signer.public.to_bytes().into_val(e)
}

fn sign(e: &Env, signer: &Keypair, payload: &BytesN<32>) -> Val {
    Signature {
        public_key: signer_public_key(e, signer),
        signature: signer
            .sign(payload.to_array().as_slice())
            .to_bytes()
            .into_val(e),
    }
    .into_val(e)
}

fn token_auth_context(e: &Env, token_id: &Address, fn_name: Symbol, amount: i128) -> Context {
    Context::Contract(ContractContext {
        contract: token_id.clone(),
        fn_name,
        args: ((), (), amount).into_val(e),
    })
}

#[test]
fn test() {
    let env = Env::default();
    env.mock_all_auths();

    let signer = generate_keypair();
    let admin = Address::generate(&env);

    let account_contract = AccountClient::new(
        &env,
        &env.register(
            Account,
            AccountArgs::__constructor(
                &admin,
                &BytesN::from_array(&env, signer.public.as_bytes()),
            ),
        ),
    );

    let payload = BytesN::random(&env);
    let token = Address::generate(&env);

    env.try_invoke_contract_check_auth::<AccountError>(
        &account_contract.address,
        &payload,
        vec![&env, sign(&env, &signer, &payload)].into(),
        &vec![
            &env,
            token_auth_context(&env, &token, Symbol::new(&env, "transfer"), 1000),
        ],
    )
    .unwrap();

    std::dbg!(&env.auths()[0].1); 
}