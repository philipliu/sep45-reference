#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, BytesN, Env, String,
};

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
}

#[contracterror]
#[derive(Clone, Copy)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
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

#[contractimpl]
impl WebAuthContract {
    pub fn init(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        Ok(())
    }

    pub fn web_auth_verify(
        _env: Env,
        address: Address,
        _memo: Option<String>,            // IGNORED
        _home_domain: Option<String>,     // IGNORED
        _web_auth_domain: Option<String>, // IGNORED
        _client_domain: Option<String>,   // IGNORED
        client_domain_address: Option<Address>,
        _nonce: Option<String>, // IGNORED, used by the Server to ensure challenge is unique
    ) {
        address.require_auth();
        // Optional: require a signature from the client domain address
        if let Some(client_domain_address) = client_domain_address {
            client_domain_address.require_auth();
        }
    }
}
