#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, BytesN, Env, Map, String,
};

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
}

#[contract]
pub struct WebAuthContract;

trait Upgradable {
    fn upgrade(e: Env, new_wasm_hash: BytesN<32>);
}

#[contractimpl]
impl Upgradable for WebAuthContract {
    fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}

#[contracterror]
pub enum WebAuthError {
    MissingArgument = 1,
}

#[contractimpl]
impl WebAuthContract {
    pub fn __constructor(env: Env, admin: Address) -> () {
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    pub fn web_auth_verify(env: Env, args: Map<String, String>) -> Result<(), WebAuthError> {
        if let Some(address) = args.get(String::from_str(&env, "account")) {
            let addr = Address::from_string(&address);
            addr.require_auth();
        } else {
            return Err(WebAuthError::MissingArgument);
        }

        if let Some(home_domain_address) = args.get(String::from_str(&env, "home_domain_address")) {
            let home_domain_addr = Address::from_string(&home_domain_address);
            home_domain_addr.require_auth();
        } else {
            return Err(WebAuthError::MissingArgument);
        }

        if let Some(client_domain_address) =
            args.get(String::from_str(&env, "client_domain_address"))
        {
            let client_domain_addr = Address::from_string(&client_domain_address);
            client_domain_addr.require_auth();
        }

        Ok(())
    }
}
