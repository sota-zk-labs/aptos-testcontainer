use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{ensure, Error, Result};
use aptos_sdk::crypto::ValidCryptoMaterialStringExt;
use aptos_sdk::types::LocalAccount;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use rand::distributions::Alphanumeric;
use rand::Rng;
use regex::Regex;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use testcontainers::core::{ExecCommand, IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use tokio::io::AsyncReadExt;
use walkdir::{DirEntry, WalkDir};

use crate::errors::AptosContainerError::{CommandFailed, DockerExecFailed};

pub struct AptosContainer {
    container: ContainerAsync<GenericImage>,
    contract_path: String,
}

const APTOS_IMAGE: &str = "sotazklabs/aptos-tools";
const APTOS_IMAGE_TAG: &str = "mainnet";
const FILTER_PATTERN: &str = r"^(?:\.git|target\/|.idea|Cargo.lock|build\/|.aptos\/)";
const CONTENT_MAX_CHARS: usize = 120000; // 120 KB

impl AptosContainer {
    pub async fn init() -> Result<Self> {
        let container = GenericImage::new(APTOS_IMAGE, APTOS_IMAGE_TAG)
            .with_exposed_port(8080.tcp())
            .with_wait_for(WaitFor::message_on_stderr("Setup is complete, you can now use the localnet!"))
            .with_entrypoint("aptos")
            .with_cmd(vec!["node", "run-localnet", "--performance"])
            .with_startup_timeout(Duration::from_secs(20))
            .start()
            .await?;
        Ok(Self {
            container,
            contract_path: "/contract".to_string(),
        })
    }
}

impl AptosContainer {
    pub async fn get_node_url(&self) -> Result<String> {
        Ok(format!("http://{}:{}", self.container.get_host().await?, self.container.get_host_port_ipv4(8080).await?))
    }

    pub async fn faucet(&self, account: &LocalAccount) -> Result<()> {
        let command = format!("echo '{}' | aptos init --network local --assume-yes", account.private_key().to_encoded_string().unwrap());
        let (stdout, stderr) = self.run_command(&command).await?;
        ensure!(stdout == r#"{
  "Result": "Success"
}
"#, CommandFailed{command,stderr: format!("stdout: {} \n\n stderr: {}", stdout, stderr)});
        Ok(())
    }

    pub async fn upload_contract(&self, local_dir: &str, account: &LocalAccount, named_addresses: &HashMap<String, String>) -> Result<()> {
        let contract_path = Path::new(&self.contract_path).join(AptosContainer::generate_random_string(6));
        let contract_path_str = contract_path.to_str().unwrap();

        // clear previous run
        let command = format!("rm -rf {}", contract_path_str);
        let (_, stderr) = self.run_command(&command).await?;
        ensure!(stderr.is_empty(), CommandFailed{command,stderr});

        // copy files into the container
        for entry in AptosContainer::get_files(local_dir) {
            let source_path = entry.path();
            let relative_path = source_path.strip_prefix(local_dir).unwrap();
            let dest_path = contract_path.join(relative_path);
            let content = fs::read(source_path)?;
            let encoded_content = BASE64_STANDARD.encode(&content);
            for chunk in encoded_content.chars().collect::<Vec<char>>().chunks(CONTENT_MAX_CHARS) {
                let command = format!("mkdir -p \"$(dirname '{}')\" && (echo '{}' | base64 --decode >> '{}')",
                                      dest_path.to_str().unwrap(),
                                      chunk.iter().collect::<String>(),
                                      dest_path.to_str().unwrap());
                let (_, stderr) = self.run_command(&command).await?;
                ensure!(stderr.is_empty(), CommandFailed{command,stderr});
            }
        }

        // copy the credential into the container
        let credential_file_content = Self::get_credential_file_content(account);
        let command = format!("mkdir -p '{}/.aptos' && (echo '{}' | cat > '{}/.aptos/config.yaml')",
                              contract_path_str,
                              credential_file_content,
                              contract_path_str);
        let (_, stderr) = self.run_command(&command).await?;
        ensure!(stderr.is_empty(), CommandFailed{command,stderr});

        // run move publish
        let named_address_params = named_addresses.iter().map(|(k, v)| {
            format!("--named-addresses {}={}", k, v)
        }).reduce(|acc, cur| {
            format!("{} {}", acc, cur)
        }).unwrap_or("".to_string());

        let command = format!("cd {} && aptos move publish --skip-fetch-latest-git-deps --assume-yes {}", contract_path_str, named_address_params);
        let (stdout, stderr) = self.run_command(&command).await?;
        ensure!(stdout.contains(r#""vm_status": "Executed successfully""#), CommandFailed{command,stderr: format!("stdout: {} \n\n stderr: {}", stdout, stderr)});
        Ok(())
    }

    pub fn get_files(local_dir: &str) -> Vec<DirEntry> {
        WalkDir::new(local_dir).into_iter().filter_map(|e| e.ok()).filter_map(|entry| {
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
        }).collect()
    }
    pub async fn run_command(&self, command: &str) -> Result<(String, String)> {
        let mut result = self.container.exec(ExecCommand::new(vec!["/bin/sh", "-c", command])).await?;
        result.exit_code().await?.map(|code| {
            Err(Error::new(DockerExecFailed(code)))
        }).unwrap_or(Ok(()))?;
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
        format!(r#"---
profiles:
  default:
    network: Local
    private_key: "{}"
    public_key: "{}"
    account: "{}"
    rest_url: "http://localhost:8080"
    faucet_url: "http://localhost:8081"
"#, private_key, public_key, account)
    }
}


#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use lazy_static::lazy_static;
    use tokio::sync::Mutex;

    use super::*;

    lazy_static! {
        static ref APTOS_CONTAINER: Arc<Mutex<Option<AptosContainer>>> = Arc::new(Mutex::new(None));
    }

    async fn init_aptos_container() {
        let mut container = APTOS_CONTAINER.lock().await;
        if container.is_none() {
            let aptos_container = AptosContainer::init().await.unwrap();
            *container = Some(aptos_container);
        };
    }

    #[tokio::test]
    async fn upload_contract_test() {
        init_aptos_container().await;

        let module_account = LocalAccount::from_private_key("0x73791ce34b2414d4afcb87561b0c442e48a3260f1c96de31da80f7cf2eec8113", 0).unwrap();
        let sender_account = LocalAccount::from_private_key("0xa7599766d8aaace6959eb7e315c1c76af44276641dff8912c9356e3d0799c80d", 0).unwrap();

        let aptos_container = APTOS_CONTAINER.lock().await;
        let aptos_container = aptos_container.as_ref().unwrap();

        aptos_container.faucet(&module_account).await.unwrap();
        aptos_container.faucet(&sender_account).await.unwrap();

        let mut named_addresses = HashMap::new();
        named_addresses.insert("verifier_addr".to_string(), module_account.address().to_string());
        aptos_container.upload_contract("./contract-sample", &module_account, &named_addresses).await.unwrap();
        let node_url = aptos_container.get_node_url().await.unwrap();
        println!("node_url = {:#?}", node_url);
    }
    #[tokio::test]
    async fn duplicated_test2() {
        init_aptos_container().await;

        let module_account = LocalAccount::from_private_key("0x73791ce34b2414d4afcb87561b0c442e48a3260f1c96de31da80f7cf2eec8113", 0).unwrap();
        let sender_account = LocalAccount::from_private_key("0xa7599766d8aaace6959eb7e315c1c76af44276641dff8912c9356e3d0799c80d", 0).unwrap();

        let aptos_container = APTOS_CONTAINER.lock().await;
        let aptos_container = aptos_container.as_ref().unwrap();

        aptos_container.faucet(&module_account).await.unwrap();
        aptos_container.faucet(&sender_account).await.unwrap();

        let mut named_addresses = HashMap::new();
        named_addresses.insert("verifier_addr".to_string(), module_account.address().to_string());
        aptos_container.upload_contract("./contract-sample", &module_account, &named_addresses).await.unwrap();
    }
}
