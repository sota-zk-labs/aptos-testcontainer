use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;
use std::{fs, path};

use anyhow::{ensure, Error, Result};
use aptos_sdk::crypto::ValidCryptoMaterialStringExt;
use aptos_sdk::types::LocalAccount;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use rand::distributions::Alphanumeric;
use rand::Rng;
use regex::Regex;
use testcontainers::core::{ExecCommand, IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use walkdir::{DirEntry, WalkDir};

use crate::errors::AptosContainerError::{CommandFailed, DockerExecFailed};

pub struct AptosContainer {
    container: ContainerAsync<GenericImage>,
    contract_path: String,
    contracts: Mutex<HashSet<String>>,
}

const APTOS_IMAGE: &str = "sotazklabs/aptos-tools";
const APTOS_IMAGE_TAG: &str = "mainnet";
const FILTER_PATTERN: &str = r"^(?:\.git|target\/|.idea|Cargo.lock|build\/|.aptos\/)";

const ROOT_ACCOUNT_PRIVATE_KEY_ENV: &str = "ROOT_ACCOUNT_PRIVATE_KEY";
const CONTENT_MAX_CHARS: usize = 120000; // 120 KB

impl AptosContainer {
    pub async fn init() -> Result<Self> {
        let container = GenericImage::new(APTOS_IMAGE, APTOS_IMAGE_TAG)
            .with_exposed_port(8080.tcp())
            .with_wait_for(WaitFor::message_on_stderr(
                "Setup is complete, you can now use the localnet!",
            ))
            .with_entrypoint("aptos")
            .with_cmd(vec!["node", "run-localnet", "--performance", "--no-faucet"])
            .with_startup_timeout(Duration::from_secs(5))
            .start()
            .await?;

        Ok(Self {
            container,
            contract_path: "/contract".to_string(),
            contracts: Default::default(),
        })
    }
}

impl AptosContainer {
    pub async fn get_node_url(&self) -> Result<String> {
        Ok(format!(
            "http://{}:{}",
            self.container.get_host().await?,
            self.container.get_host_port_ipv4(8080).await?
        ))
    }

    pub async fn faucet(&self, account: &LocalAccount) -> Result<()> {
        let command = format!("aptos account transfer --private-key ${} --account {} --amount 30000000 --assume-yes",
                              ROOT_ACCOUNT_PRIVATE_KEY_ENV,
                              account.address().to_string());
        let (stdout, stderr) = self.run_command(&command).await?;
        ensure!(
            stdout.contains(r#""vm_status": "Executed successfully""#),
            CommandFailed {
                command,
                stderr: format!("stdout: {} \n\n stderr: {}", stdout, stderr)
            }
        );
        Ok(())
    }

    pub async fn get_root_account_private_key(&self) -> Result<String> {
        let command = format!("echo ${}", ROOT_ACCOUNT_PRIVATE_KEY_ENV);
        let (stdout, _) = self.run_command(&command).await?;
        ensure!(
            !stdout.is_empty(),
            CommandFailed {
                command,
                stderr: "env not found".to_string()
            }
        );
        Ok(stdout.trim().to_string())
    }

    pub async fn upload_contract(
        &self,
        local_dir: &str,
        account: &LocalAccount,
        named_addresses: &HashMap<String, String>,
        override_contract: bool,
    ) -> Result<()> {
        let absolute = path::absolute(local_dir)?;
        let absolute = absolute.to_str().unwrap();
        let mut inserted_contracts = self.contracts.lock().await;
        if !override_contract && inserted_contracts.contains(absolute) {
            return Ok(());
        }

        let contract_path =
            Path::new(&self.contract_path).join(AptosContainer::generate_random_string(6));
        let contract_path_str = contract_path.to_str().unwrap();

        // clear previous run
        let command = format!("rm -rf {}", contract_path_str);
        let (_, stderr) = self.run_command(&command).await?;
        ensure!(stderr.is_empty(), CommandFailed { command, stderr });

        // copy files into the container
        for entry in AptosContainer::get_files(local_dir) {
            let source_path = entry.path();
            let relative_path = source_path.strip_prefix(local_dir).unwrap();
            let dest_path = contract_path.join(relative_path);
            let content = fs::read(source_path)?;
            let encoded_content = BASE64_STANDARD.encode(&content);
            for chunk in encoded_content
                .chars()
                .collect::<Vec<char>>()
                .chunks(CONTENT_MAX_CHARS)
            {
                let command = format!(
                    "mkdir -p \"$(dirname '{}')\" && (echo '{}' | base64 --decode >> '{}')",
                    dest_path.to_str().unwrap(),
                    chunk.iter().collect::<String>(),
                    dest_path.to_str().unwrap()
                );
                let (_, stderr) = self.run_command(&command).await?;
                ensure!(stderr.is_empty(), CommandFailed { command, stderr });
            }
        }

        // copy the credential into the container
        let credential_file_content = Self::get_credential_file_content(account);
        let command = format!(
            "mkdir -p '{}/.aptos' && (echo '{}' | cat > '{}/.aptos/config.yaml')",
            contract_path_str, credential_file_content, contract_path_str
        );
        let (_, stderr) = self.run_command(&command).await?;
        ensure!(stderr.is_empty(), CommandFailed { command, stderr });

        // run move publish
        let named_address_params = named_addresses
            .iter()
            .map(|(k, v)| format!("--named-addresses {}={}", k, v))
            .reduce(|acc, cur| format!("{} {}", acc, cur))
            .unwrap_or("".to_string());

        let command = format!(
            "cd {} && aptos move publish --skip-fetch-latest-git-deps --assume-yes {}",
            contract_path_str, named_address_params
        );
        let (stdout, stderr) = self.run_command(&command).await?;
        ensure!(
            stdout.contains(r#""vm_status": "Executed successfully""#),
            CommandFailed {
                command,
                stderr: format!("stdout: {} \n\n stderr: {}", stdout, stderr)
            }
        );

        inserted_contracts.insert(absolute.to_string());
        Ok(())
    }

    pub fn get_files(local_dir: &str) -> Vec<DirEntry> {
        WalkDir::new(local_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter_map(|entry| {
                let source_path = entry.path();
                if !source_path.is_file() {
                    return None;
                }
                // Determine the relative path from the source directory
                let relative_path = source_path.strip_prefix(local_dir).unwrap();
                let re = Regex::new(FILTER_PATTERN).unwrap();
                if re.is_match(relative_path.to_str().unwrap()) {
                    return None;
                }

                let metadata = fs::metadata(source_path).unwrap();
                let file_size = metadata.len();
                let file_size_mb = file_size as f64 / (1024.0 * 1024.0);
                if file_size_mb > 1_f64 {
                    return None;
                }
                Some(entry)
            })
            .collect()
    }
    pub async fn run_command(&self, command: &str) -> Result<(String, String)> {
        let mut result = self
            .container
            .exec(ExecCommand::new(vec!["/bin/sh", "-c", command]))
            .await?;
        result
            .exit_code()
            .await?
            .map(|code| Err(Error::new(DockerExecFailed(code))))
            .unwrap_or(Ok(()))?;
        let mut stdout = String::new();
        result.stdout().read_to_string(&mut stdout).await?;
        let mut stderr = String::new();
        result.stderr().read_to_string(&mut stderr).await?;
        Ok((stdout, stderr))
    }

    fn generate_random_string(length: usize) -> String {
        let rng = rand::thread_rng();
        let random_string: String = rng
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect();
        random_string
    }

    fn get_credential_file_content(account: &LocalAccount) -> String {
        let private_key = account.private_key().to_encoded_string().unwrap();
        let public_key = account.public_key().to_encoded_string().unwrap();
        let account = account.address().to_string();
        format!(
            r#"---
profiles:
  default:
    network: Local
    private_key: "{}"
    public_key: "{}"
    account: "{}"
    rest_url: "http://localhost:8080"
    faucet_url: "http://localhost:8081"
"#,
            private_key, public_key, account
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::test_config::aptos_container_test;

    use super::*;

    #[tokio::test]
    async fn upload_contract_test() {
        let aptos_container = aptos_container_test::lazy_aptos_container().await.unwrap();

        let module_account = LocalAccount::from_private_key("0x73791ce34b2414d4afcb87561b0c442e48a3260f1c96de31da80f7cf2eec8113", 0).unwrap();
        aptos_container.faucet(&module_account).await.unwrap();

        let mut named_addresses = HashMap::new();
        named_addresses.insert(
            "verifier_addr".to_string(),
            module_account.address().to_string(),
        );
        aptos_container
            .upload_contract(
                "./contract-sample",
                &module_account,
                &named_addresses,
                false,
            )
            .await
            .unwrap();
        let node_url = aptos_container.get_node_url().await.unwrap();
        println!("node_url = {:#?}", node_url);
    }
    #[tokio::test]
    async fn duplicated_test2() {
        let aptos_container = aptos_container_test::lazy_aptos_container().await.unwrap();

        let module_account = LocalAccount::from_private_key("0x73791ce34b2414d4afcb87561b0c442e48a3260f1c96de31da80f7cf2eec8113", 0).unwrap();
        aptos_container.faucet(&module_account).await.unwrap();

        let mut named_addresses = HashMap::new();
        named_addresses.insert(
            "verifier_addr".to_string(),
            module_account.address().to_string(),
        );
        aptos_container
            .upload_contract(
                "./contract-sample",
                &module_account,
                &named_addresses,
                false,
            )
            .await
            .unwrap();
        let node_url = aptos_container.get_node_url().await.unwrap();
        println!("node_url = {:#?}", node_url);
    }
}
