use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;
use std::{fs, path};

use anyhow::{ensure, Error, Result};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use rand::distributions::Alphanumeric;
use rand::Rng;
use regex::Regex;
use testcontainers::core::{ExecCommand, IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, Mutex, RwLock};
use walkdir::{DirEntry, WalkDir};

use crate::errors::AptosContainerError::{CommandFailed, DockerExecFailed};

const MOVE_TOML: &[u8] = include_bytes!("../contract-samples/sample1/Move.toml");

pub struct AptosContainer {
    container: ContainerAsync<GenericImage>,
    contract_path: String,
    contracts: Mutex<HashSet<String>>,
    accounts: RwLock<Vec<String>>,

    accounts_channel_rx: Mutex<Option<Receiver<String>>>,
    accounts_channel_tx: RwLock<Option<Sender<String>>>,
}

const APTOS_IMAGE: &str = "sotazklabs/aptos-tools";
const APTOS_IMAGE_TAG: &str = "mainnet";
const FILTER_PATTERN: &str = r"^(?:\.git|target\/|.idea|Cargo.lock|build\/|.aptos\/)";

const ACCOUNTS_ENV: &str = "ACCOUNTS";
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
            .with_startup_timeout(Duration::from_secs(10))
            .start()
            .await?;

        Ok(Self {
            container,
            contract_path: "/contract".to_string(),
            contracts: Default::default(),
            accounts: Default::default(),
            accounts_channel_rx: Default::default(),
            accounts_channel_tx: Default::default(),
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

    pub async fn run(&self, number_of_accounts: usize, callback: impl FnOnce(Vec<String>) -> Pin<Box<dyn Future<Output=Result<()>>>>) -> Result<()>
    {
        self.lazy_init_accounts().await?;

        let mut accounts = vec![];
        // TODO: check received messages size
        self.accounts_channel_rx.lock().await.as_mut().unwrap().recv_many(&mut accounts, number_of_accounts).await;

        let result = callback(accounts.clone()).await;

        let guard = self.accounts_channel_tx.read().await;
        for account in accounts {
            guard.as_ref().unwrap().send(account).await.unwrap();
        }
        result
    }

    pub async fn get_initiated_accounts(&self) -> Result<Vec<String>> {
        self.lazy_init_accounts().await?;
        Ok(self.accounts.read().await.clone())
    }

    pub async fn lazy_init_accounts(&self) -> Result<()> {
        let mut guard = self.accounts_channel_tx
            .write()
            .await;

        if guard.is_some() {
            return Ok(());
        }

        let command = format!("echo ${}", ACCOUNTS_ENV);
        let (stdout, stderr) = self.run_command(&command).await?;
        ensure!(
            !stdout.is_empty(),
            CommandFailed {
                command,
                stderr: format!("stdout: {} \n\n stderr: {}", stdout, stderr)
            }
        );
        let accounts = stdout.trim().split(",").map(|s| s.to_string()).collect::<Vec<String>>();
        let (tx, rx) = mpsc::channel(accounts.len());
        for account in accounts.iter() {
            tx.send(account.to_string()).await.unwrap()
        }

        *self.accounts.write().await = accounts;
        *self.accounts_channel_rx.lock().await = Some(rx);

        *guard = Some(tx);
        Ok(())
    }

    pub async fn get_root_account_private_key(&self) -> Result<String> {
        let command = format!("echo ${}", ACCOUNTS_ENV);
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

    async fn copy_contracts(
        &self,
        local_dir: impl AsRef<Path>,
    ) -> Result<PathBuf> {
        let contract_path =
            Path::new(&self.contract_path).join(AptosContainer::generate_random_string(6));
        let contract_path_str = contract_path.to_str().unwrap();

        // clear previous run
        let command = format!("rm -rf {}", contract_path_str);
        let (_, stderr) = self.run_command(&command).await?;
        ensure!(stderr.is_empty(), CommandFailed { command, stderr });

        // copy files into the container
        let local_dir_str = local_dir.as_ref().to_str().unwrap();
        for entry in AptosContainer::get_files(local_dir_str) {
            let source_path = entry.path();
            let relative_path = source_path.strip_prefix(local_dir_str)?;
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
        Ok(contract_path)
    }

    pub async fn run_script(
        &self,
        local_dir: impl AsRef<Path>,
        private_key: &str,
        named_addresses: &HashMap<String, String>,
        script_paths: Vec<&str>,
    ) -> Result<()> {
        let contract_path = self.copy_contracts(local_dir).await?;
        let contract_path_str = contract_path.to_str().unwrap();
        let named_address_params = named_addresses
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .reduce(|acc, cur| format!("{},{}", acc, cur))
            .map(|named_addresses| format!("--named-addresses {}", named_addresses))
            .unwrap_or("".to_string());

        for script_path in script_paths {
            // compile script
            let command = format!(
                "cd {}/{} && aptos move compile-script --skip-fetch-latest-git-deps {}",
                contract_path_str, script_path, named_address_params.as_str()
            );
            let (stdout, stderr) = self.run_command(&command).await?;
            ensure!(
                stdout.contains(r#""script_location":"#),
                CommandFailed {
                    command,
                    stderr: format!("stdout: {} \n\n stderr: {}", stdout, stderr)
                }
            );

            // run script
            let command = format!(
                "cd {}/{} && aptos move run-script  --compiled-script-path script.mv --private-key {} --url http://localhost:8080 --assume-yes",
                contract_path_str, script_path, private_key
            );
            let (stdout, stderr) = self.run_command(&command).await?;
            ensure!(
                stdout.contains(r#""vm_status": "Executed successfully""#),
                CommandFailed {
                    command,
                    stderr: format!("stdout: {} \n\n stderr: {}", &stdout, stderr)
                }
            );
        }
        Ok(())
    }

    pub async fn upload_contract(
        &self,
        local_dir: &str,
        private_key: &str,
        named_addresses: &HashMap<String, String>,
        sub_packages: Option<Vec<&str>>,
        override_contract: bool,
    ) -> Result<()> {
        let absolute = path::absolute(local_dir)?;
        let absolute = absolute.to_str().unwrap();
        let mut inserted_contracts = self.contracts.lock().await;
        if !override_contract && inserted_contracts.contains(absolute) {
            return Ok(());
        }

        let contract_path = self.copy_contracts(local_dir).await?;
        let contract_path_str = contract_path.to_str().unwrap();

        if sub_packages.is_none() {
            // Override Move.toml
            let dest_path = contract_path.join("Move.toml");
            let encoded_content = BASE64_STANDARD.encode(MOVE_TOML);
            let command = format!(
                "mkdir -p \"$(dirname '{}')\" && (echo '{}' | base64 --decode > '{}')",
                dest_path.to_str().unwrap(),
                encoded_content,
                dest_path.to_str().unwrap()
            );
            let (_, stderr) = self.run_command(&command).await?;
            ensure!(stderr.is_empty(), CommandFailed { command, stderr });
        }

        // run move publish
        let named_address_params = named_addresses
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .reduce(|acc, cur| format!("{},{}", acc, cur))
            .map(|named_addresses| format!("--named-addresses {}", named_addresses))
            .unwrap_or("".to_string());
        match sub_packages {
            None => {
                let command = format!(
                    "cd {} && aptos move publish --skip-fetch-latest-git-deps --private-key {} --assume-yes {} --url http://localhost:8080 --included-artifacts none",
                    contract_path_str, private_key, named_address_params
                );
                let (stdout, stderr) = self.run_command(&command).await?;
                ensure!(
                    stdout.contains(r#""vm_status": "Executed successfully""#),
                    CommandFailed {
                        command,
                        stderr: format!("stdout: {} \n\n stderr: {}", stdout, stderr)
                    });
            }
            Some(sub_packages) => {
                for sub_package in sub_packages {
                    let command = format!(
                        "cd {}/{} && aptos move publish --skip-fetch-latest-git-deps --private-key {} --assume-yes {} --url http://localhost:8080 --included-artifacts none",
                        contract_path_str, sub_package, private_key, named_address_params
                    );
                    let (stdout, stderr) = self.run_command(&command).await?;
                    ensure!(
                    stdout.contains(r#""vm_status": "Executed successfully""#),
                    CommandFailed {
                        command,
                        stderr: format!("stdout: {} \n\n stderr: {}", stdout, stderr)
                    });
                }
            }
        }

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
}

#[cfg(test)]
#[cfg(feature = "testing")]
mod tests {
    use aptos_sdk::types::LocalAccount;

    use crate::test_utils::aptos_container_test_utils::{lazy_aptos_container, run};

    use super::*;

    #[tokio::test]
    async fn run_script_test() {
        run(2, |accounts| {
            Box::pin(async move {
                let aptos_container = lazy_aptos_container().await?;
                let module_account_private_key = accounts.first().unwrap();
                let module_account = LocalAccount::from_private_key(module_account_private_key, 0).unwrap();
                let mut named_addresses = HashMap::new();
                named_addresses.insert(
                    "verifier_addr".to_string(),
                    module_account.address().to_string(),
                );
                named_addresses.insert(
                    "lib_addr".to_string(),
                    module_account.address().to_string(),
                );
                aptos_container
                    .run_script(
                        "./contract-samples/sample2",
                        module_account_private_key,
                        &named_addresses,
                        vec!["verifier"],
                    )
                    .await.unwrap();
                let node_url = aptos_container.get_node_url().await?;
                println!("node_url = {:#?}", node_url);
                Ok(())
            })
        }).await.unwrap();
    }
    #[tokio::test]
    async fn upload_contract_1_test() {
        run(2, |accounts| {
            Box::pin(async move {
                let aptos_container = lazy_aptos_container().await?;
                let module_account_private_key = accounts.first().unwrap();
                let module_account = LocalAccount::from_private_key(module_account_private_key, 0).unwrap();
                let mut named_addresses = HashMap::new();
                named_addresses.insert(
                    "verifier_addr".to_string(),
                    module_account.address().to_string(),
                );
                aptos_container
                    .upload_contract(
                        "./contract-samples/sample1",
                        module_account_private_key,
                        &named_addresses,
                        None,
                        false,
                    )
                    .await.unwrap();
                let node_url = aptos_container.get_node_url().await?;
                println!("node_url = {:#?}", node_url);
                Ok(())
            })
        }).await.unwrap();
    }

    #[tokio::test]
    async fn upload_contract_1_test_duplicated() {
        run(2, |accounts| {
            Box::pin(async move {
                let aptos_container = lazy_aptos_container().await?;
                let module_account_private_key = accounts.first().unwrap();
                let module_account = LocalAccount::from_private_key(module_account_private_key, 0).unwrap();
                let mut named_addresses = HashMap::new();
                named_addresses.insert(
                    "verifier_addr".to_string(),
                    module_account.address().to_string(),
                );
                aptos_container
                    .upload_contract(
                        "./contract-samples/sample1",
                        module_account_private_key,
                        &named_addresses,
                        None,
                        false,
                    )
                    .await.unwrap();
                let node_url = aptos_container.get_node_url().await?;
                println!("node_url = {:#?}", node_url);
                Ok(())
            })
        }).await.unwrap();
    }

    #[tokio::test]
    async fn upload_contract_2_test() {
        run(2, |accounts| {
            Box::pin(async move {
                let aptos_container = lazy_aptos_container().await?;
                let module_account_private_key = accounts.first().unwrap();
                let module_account = LocalAccount::from_private_key(module_account_private_key, 0).unwrap();
                let mut named_addresses = HashMap::new();
                named_addresses.insert(
                    "verifier_addr".to_string(),
                    module_account.address().to_string(),
                );
                named_addresses.insert(
                    "lib_addr".to_string(),
                    module_account.address().to_string(),
                );
                aptos_container
                    .upload_contract(
                        "./contract-samples/sample2",
                        module_account_private_key,
                        &named_addresses,
                        Some(vec!["libs", "verifier"]),
                        false,
                    )
                    .await.unwrap();
                let node_url = aptos_container.get_node_url().await?;
                println!("node_url = {:#?}", node_url);
                Ok(())
            })
        }).await.unwrap();
    }
}
