use config::{Config, Environment};
use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct EnvConfig {
    pub enable_node: Option<bool>,
    pub node_url: Option<Vec<String>>,
    pub chain_id: Option<u8>,
    pub deploy_contract: Option<bool>,
    pub accounts: Option<Vec<String>>,
}

impl EnvConfig {
    pub fn new() -> Self {
        let config = Config::builder()
            .add_source(
                Environment::default()
                    .prefix("APTOS_TESTCONTAINER")
                    .separator("__")
                    .list_separator(",")
                    .try_parsing(true)
                    .ignore_empty(true),
            )
            .build()
            .unwrap();
        config.try_deserialize().unwrap()
    }
}
