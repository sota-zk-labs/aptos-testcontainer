use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;
use std::{fs, path};

use anyhow::{ensure, Error, Result};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use log::debug;
use rand::distributions::Alphanumeric;
use rand::Rng;
use regex::Regex;
use testcontainers::core::{ExecCommand, IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::Instant;
use walkdir::{DirEntry, WalkDir};

use crate::config::EnvConfig;
use crate::errors::AptosContainerError::{CommandFailed, DockerExecFailed};

const MOVE_TOML: &[u8] = include_bytes!("../contract-samples/sample1/Move.toml");

/// `AptosContainer` is a struct that encapsulates the configuration and runtime details
/// for managing an Aptos node and its associated resources within a Docker container.
///
/// # Fields
///
/// * `node_url` - URL for accessing the Aptos node from external systems.
///
/// * `inner_url` - Internal URL for accessing the Aptos node from within the container
///     or local environment.
///
/// * `chain_id` - Chain ID for the network.
///
/// * `deploy_contract` - Flag indicating whether to deploy contracts to the Aptos node.
///     Optional list of account addresses to override default accounts.
///
/// * `override_accounts` - If set to `true`, contracts will be deployed upon initialization.
///
/// * `container` - The Docker container instance running the Aptos node or shell.
///
/// * `contract_path` - Path to the directory where contract files are stored.
///
/// * `contracts` - A mutex-protected set of contracts.
///
/// * `accounts` - A read-write lock protecting a list of account addresses.
///
/// * `accounts_channel_rx` - A mutex-protected optional receiver for account-related
///     communication channels.
///
/// * `accounts_channel_tx` - A read-write lock protecting an optional sender for account-related
///     communication channels.
pub struct AptosContainer {
    node_url: String,
    inner_url: String,
    chain_id: u8,
    deploy_contract: bool,
    override_accounts: Option<Vec<String>>,
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
    /// Initializes a `AptosContainer`.
    ///
    /// # Returns
    /// A new `AptosContainer` instance.
    ///
    /// # Example
    /// ```rust
    /// use aptos_testcontainer::aptos_container::AptosContainer;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let aptos_container = AptosContainer::init().await.unwrap();
    /// }
    /// ```
    pub async fn init() -> Result<Self> {
        // Load configuration from environment
        let config = EnvConfig::new();
        let enable_node = config.enable_node.unwrap_or(true);

        // Set up the container's entrypoint, command, and wait condition based on whether the node is enabled.
        let (entrypoint, cmd, wait_for) = if enable_node {
            (
                "aptos",
                vec!["node", "run-localnet", "--performance", "--no-faucet"],
                WaitFor::message_on_stderr("Setup is complete, you can now use the localnet!"),
            )
        } else {
            ("/bin/sh", vec!["-c", "sleep infinity"], WaitFor::Nothing)
        };

        // Create and start a new Docker container with the specified image and settings.
        let container = GenericImage::new(APTOS_IMAGE, APTOS_IMAGE_TAG)
            .with_exposed_port(8080.tcp())
            .with_wait_for(wait_for)
            .with_entrypoint(entrypoint)
            .with_cmd(cmd)
            .with_startup_timeout(Duration::from_secs(10))
            .start()
            .await?;

        // Configure URLs and other parameters based on whether the node is enabled.
        let (node_url, inner_url, deploy_contract, override_accounts, chain_id) = if enable_node {
            let node_url = format!(
                "http://{}:{}",
                container.get_host().await?,
                container.get_host_port_ipv4(8080).await?
            );
            (
                node_url.to_string(),
                "http://localhost:8080".to_string(),
                true,
                None,
                4,
            )
        } else {
            let node_url = config.node_url.unwrap().first().unwrap().to_string();
            (
                node_url.clone(),
                node_url,
                config.deploy_contract.unwrap_or(true),
                Some(config.accounts.unwrap()),
                config.chain_id.unwrap(),
            )
        };

        Ok(Self {
            node_url,
            inner_url,
            deploy_contract,
            chain_id,
            container,
            override_accounts,
            contract_path: "/contract".to_string(),
            contracts: Default::default(),
            accounts: Default::default(),
            accounts_channel_rx: Default::default(),
            accounts_channel_tx: Default::default(),
        })
    }
}

impl AptosContainer {
    /// Get `node_url` from `AptosContainer`
    pub fn get_node_url(&self) -> String {
        self.node_url.clone()
    }
    /// Get `chain_id` from `AptosContainer`
    pub fn get_chain_id(&self) -> u8 {
        self.chain_id
    }
    /// Get `accounts` from `override_accounts` in `AptosContainer` if override_accounts
    /// is `Some`. If `None` call to `lazy_init_accounts` to init and return `accounts`.
    pub async fn get_initiated_accounts(&self) -> Result<Vec<String>> {
        match &self.override_accounts {
            Some(accounts) => Ok(accounts.clone()),
            None => {
                self.lazy_init_accounts().await?;
                Ok(self.accounts.read().await.clone())
            }
        }
    }
    /// Generates a random alphanumeric string of the specified length.
    ///
    /// # Arguments
    ///
    /// * `length` - The length of the random string to generate.
    ///
    /// # Returns
    ///
    /// * `String` - A string of random alphanumeric characters of the specified length.
    ///
    fn generate_random_string(length: usize) -> String {
        // Initialize a random number generator.
        let rng = rand::thread_rng();
        // Create an iterator that samples random characters from the Alphanumeric set.
        let random_string: String = rng
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect();
        random_string
    }

    /// Executes a shell command inside the Docker container.
    ///
    /// # Arguments
    ///
    /// * `command` - A string representing the shell command to execute inside the container.
    ///
    /// # Returns
    ///
    /// * `Result<(String, String)>` - A tuple containing the `stdout` and `stderr` outputs from
    ///     the command execution.
    ///
    /// # Example
    /// ```rust
    /// use aptos_testcontainer::aptos_container::AptosContainer;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let aptos_container = AptosContainer::init().await.unwrap();
    ///     let command = "bin/sh -c mkdir my_file".to_string();
    ///     let (_, stderr) = aptos_container.run_command(&command).await.unwrap();
    ///     println!("stderr: {:?}", stderr)
    /// }
    /// ```
    pub async fn run_command(&self, command: &str) -> Result<(String, String)> {
        // Execute the command inside the container using `/bin/sh -c`.
        let mut result = self
            .container
            .exec(ExecCommand::new(vec!["/bin/sh", "-c", command]))
            .await?;

        // Check the exit code of the command.
        result
            .exit_code()
            .await?
            .map(|code| Err(Error::new(DockerExecFailed(code))))
            .unwrap_or(Ok(()))?;
        // Initialize empty strings for capturing stdout and stderr.
        let mut stdout = String::new();
        let mut stderr = String::new();

        // Read the command's stdout into the `stdout` string.
        result.stdout().read_to_string(&mut stdout).await?;
        // Read the command's stderr into the `stderr` string.
        result.stderr().read_to_string(&mut stderr).await?;
        Ok((stdout, stderr))
    }

    /// Recursively retrieves a list of files from directory.
    ///
    /// # Arguments
    ///
    /// * `local_dir` - A string slice representing the path to the local directory to search for files.
    ///
    /// # Returns
    ///
    /// * `Vec<DirEntry>` - A vector of `DirEntry` objects representing the files that match the
    ///     filtering criteria.
    fn get_files(local_dir: &str) -> Vec<DirEntry> {
        WalkDir::new(local_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter_map(|entry| {
                let source_path = entry.path();
                // Ignore files located in build folders.
                if source_path.to_str().unwrap().contains("/build/") {
                    return None;
                }

                // Only consider files, not directories.
                if !source_path.is_file() {
                    return None;
                }
                // Determine the relative path from the source directory
                let relative_path = source_path.strip_prefix(local_dir).unwrap();
                // Compile the regex pattern and check if the relative path matches the pattern.
                let re = Regex::new(FILTER_PATTERN).unwrap();
                if re.is_match(relative_path.to_str().unwrap()) {
                    return None;
                }

                // Check file size, excluding files larger than 1 MB.
                let metadata = fs::metadata(source_path).unwrap();
                let file_size = metadata.len();
                let file_size_mb = file_size as f64 / (1024.0 * 1024.0);
                if file_size_mb > 1_f64 {
                    return None;
                }
                // Include the entry if it passes all filters.
                Some(entry)
            })
            .collect()
    }

    /// Lazily initializes the accounts if it has been initialized yet.
    /// This ensures that accounts are set up either from an external source or
    /// from environment variables only once, and avoids redundant initialization.
    ///
    /// # Example
    /// ```rust
    /// use aptos_testcontainer::aptos_container::AptosContainer;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let aptos_containe = AptosContainer::init().await.unwrap();
    ///     let accounts = aptos_containe.lazy_init_accounts().await.unwrap();
    /// }
    /// ```
    pub async fn lazy_init_accounts(&self) -> Result<()> {
        // If override accounts are provided, skip initialization and return early.
        if self.override_accounts.is_some() {
            return Ok(());
        }

        // Lock the accounts_channel_tx to check if it's already initialized.
        let mut guard = self.accounts_channel_tx.write().await;

        // If accounts_channel_tx is already initialized, return early.
        if guard.is_some() {
            return Ok(());
        }

        // Prepare to fetch the accounts from the environment variable.
        let command = format!("echo ${}", ACCOUNTS_ENV);
        // Run the command to retrieve the accounts and capture stdout and stderr.
        let (stdout, stderr) = self.run_command(&command).await?;
        // Ensure that the command returned valid output; otherwise, raise an error.
        ensure!(
            !stdout.is_empty(),
            CommandFailed {
                command,
                stderr: format!("stdout: {} \n\n stderr: {}", stdout, stderr)
            }
        );

        // Parse the stdout into a list of account strings.
        let accounts = stdout
            .trim()
            .split(",")
            .map(|s| s.to_string())
            .collect::<Vec<String>>();
        // Create a new mpsc channel with a buffer size equal to the number of accounts.
        let (tx, rx) = mpsc::channel(accounts.len());
        // Send each account into the channel.
        for account in accounts.iter() {
            tx.send(account.to_string()).await?
        }
        // Lock the accounts field and write the parsed accounts into it.
        *self.accounts.write().await = accounts;
        // Lock the accounts_channel_rx and assign the receiver.
        *self.accounts_channel_rx.lock().await = Some(rx);
        // Assign the sender to accounts_channel_tx to finalize the initialization.
        *guard = Some(tx);
        // Return success.
        Ok(())
    }

    /// Copies contract files from a local directory into the container's filesystem. The files
    /// are base64-encoded and transferred in chunks to avoid issues with large files.
    ///
    /// # Arguments
    ///
    /// * `local_dir` - A path that refers to the local directory containing the contract files
    ///     to be copied into the container.
    ///
    /// # Returns
    ///
    /// * `Result<PathBuf>` - Returns the path where the contracts are copied in the container,
    ///     or an error if the copying process fails.
    async fn copy_contracts(&self, local_dir: impl AsRef<Path>) -> Result<PathBuf> {
        // Generate a random destination path by appending a random string to contract_path.
        let contract_path =
            Path::new(&self.contract_path).join(AptosContainer::generate_random_string(6));
        let contract_path_str = contract_path.to_str().unwrap();

        // Clear the previous run by removing any existing files at the target path.
        let command = format!("rm -rf {}", contract_path_str);
        let (_, stderr) = self.run_command(&command).await?;
        // Ensure there are no errors when executing the removal command.
        ensure!(stderr.is_empty(), CommandFailed { command, stderr });

        // Copy files into the container
        let local_dir_str = local_dir.as_ref().to_str().unwrap();
        // Iterate over each file in the local directory.
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

    /// This async function handles account initialization and execution of a callback function with the provided or received accounts.
    ///
    /// # Parameters:
    /// - `number_of_accounts`: The number of accounts required for the operation.
    /// - `callback`: A closure that takes the accounts and returns a `Future` wrapped in a `Pin` and boxed as a dynamic trait `Future<Output = Result<()>>`.
    ///
    /// # Example
    /// ```rust
    /// use aptos_testcontainer::aptos_container::AptosContainer;
    /// use aptos_testcontainer::utils::get_account_address;
    /// use std::collections::HashMap;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let aptos_containe = AptosContainer::init().await.unwrap();
    ///     let _ = aptos_containe.run(2, |accounts| {
    ///             Box::pin(async move {
    ///                 let aptos_container = AptosContainer::init().await.unwrap();
    ///                 let accounts = aptos_container.get_initiated_accounts().await.unwrap();
    ///                 let module_account_private_key = accounts.first().unwrap();
    ///                 let module_account_address = get_account_address(module_account_private_key);
    ///                 let mut named_addresses = HashMap::new();
    ///                 named_addresses.insert("verifier_addr".to_string(), module_account_address);
    ///                 aptos_container
    ///                     .upload_contract(
    ///                         "./contract-samples/sample1",
    ///                         module_account_private_key,
    ///                         &named_addresses,
    ///                         None,
    ///                         false,
    ///                     )
    ///                     .await
    ///                     .unwrap();
    ///                 Ok(())
    ///             })
    ///     });
    /// }
    /// ```
    pub async fn run(
        &self,
        number_of_accounts: usize,
        callback: impl FnOnce(Vec<String>) -> Pin<Box<dyn Future<Output = Result<()>>>>,
    ) -> Result<()> {
        // Ensure that accounts are initialized, if not already done.
        self.lazy_init_accounts().await?;

        // Determine whether to use overridden accounts or to receive them via the channel.
        let accounts = match &self.override_accounts {
            // If override_accounts is Some, clone the provided accounts.
            Some(accounts) => accounts.clone(),
            // Otherwise, receive the accounts from the accounts_channel_rx.
            None => {
                // TODO: check received messages size
                let mut result = vec![];
                // Lock the accounts_channel_rx to ensure exclusive access and receive accounts.
                self.accounts_channel_rx
                    .lock()
                    .await
                    .as_mut()
                    .unwrap()
                    .recv_many(&mut result, number_of_accounts)
                    .await;
                result
            }
        };

        // Invoke the provided callback with the received or overridden accounts.
        let result = callback(accounts.clone()).await;

        if self.override_accounts.is_none() {
            let guard = self.accounts_channel_tx.read().await;
            for account in accounts {
                guard.as_ref().unwrap().send(account).await?;
            }
        }
        result
    }

    /// Executes a script located within the specified directory.
    ///
    /// # Parameters
    /// - `local_dir`: The directory path containing the scripts to be executed.
    /// - `private_key`: The private key of the account that will sign and execute the scripts.
    /// - `named_addresses`: A mapping of named addresses used for the script compilation.
    /// - `script_paths`: A vector of sub-directory paths within the `local_dir` where the scripts are located.
    ///
    /// # Example
    /// ```rust
    /// use std::collections::HashMap;
    /// use aptos_testcontainer::aptos_container::AptosContainer;
    /// use aptos_testcontainer::utils::get_account_address;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let aptos_container = AptosContainer::init().await.unwrap();
    ///     let accounts = aptos_container.get_initiated_accounts().await.unwrap();
    ///     let module_account_private_key = accounts.first().unwrap();
    ///     let module_account_address = get_account_address(module_account_private_key);
    ///
    ///     let mut named_addresses = HashMap::new();
    ///     named_addresses.insert("verifier_addr".to_string(), module_account_address.clone());
    ///     named_addresses.insert("lib_addr".to_string(), module_account_address);
    ///     aptos_container
    ///         .run_script(
    ///         "./contract-samples/sample2",
    ///         module_account_private_key,
    ///         &named_addresses,
    ///         &vec!["verifier"],
    ///         )
    ///     .await
    ///     .unwrap();
    /// }
    /// ```
    pub async fn run_script(
        &self,
        local_dir: impl AsRef<Path>,
        private_key: &str,
        named_addresses: &HashMap<String, String>,
        script_paths: &Vec<&str>,
    ) -> Result<()> {
        // Start the timer for performance measurement
        let now = Instant::now();

        // Copy contract files to the container and get the path
        let contract_path = self.copy_contracts(local_dir).await?;
        debug!("copy_contracts takes: {:.2?}", now.elapsed());

        // Convert contract path to a string
        let contract_path_str = contract_path.to_str().unwrap();

        // Build named addresses as CLI parameters
        let named_address_params = named_addresses
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .reduce(|acc, cur| format!("{},{}", acc, cur))
            .map(|named_addresses| format!("--named-addresses {}", named_addresses))
            .unwrap_or("".to_string());

        // Compile and run each script in the provided paths
        for script_path in script_paths {
            // Compile script
            let command = format!(
                "cd {}/{} && aptos move compile-script --skip-fetch-latest-git-deps {}",
                contract_path_str,
                script_path,
                named_address_params.as_str()
            );
            let (stdout, stderr) = self.run_command(&command).await?;
            ensure!(
                stdout.contains(r#""script_location":"#),
                CommandFailed {
                    command,
                    stderr: format!("stdout: {} \n\n stderr: {}", stdout, stderr)
                }
            );

            // Run script
            let command = format!(
                "cd {}/{} && aptos move run-script  --compiled-script-path script.mv --private-key {} --url {} --assume-yes",
                contract_path_str, script_path, private_key, self.inner_url
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

    /// Uploads smart contracts to the Aptos node, optionally overriding existing contracts and
    /// handling sub-packages.
    ///
    /// # Arguments
    ///
    /// * `local_dir` - The local directory containing the contract files.
    /// * `private_key` - The private key used for publishing the contract.
    /// * `named_addresses` - A hash map of named addresses for the contracts.
    /// * `sub_packages` - Optional list of sub-packages to handle separately. If `None`, the entire
    ///   contract directory is handled as a whole.
    /// * `override_contract` - A boolean flag indicating whether to override existing contracts.
    ///
    /// # Example
    /// ```rust
    /// use std::collections::HashMap;
    /// use aptos_testcontainer::aptos_container::AptosContainer;
    /// use aptos_testcontainer::utils::get_account_address;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let aptos_container = AptosContainer::init().await.unwrap();
    ///     let accounts = aptos_container.get_initiated_accounts().await.unwrap();
    ///     let module_account_private_key = accounts.first().unwrap();
    ///     let module_account_address = get_account_address(module_account_private_key);
    ///     let mut named_addresses = HashMap::new();
    ///     named_addresses.insert("verifier_addr".to_string(), module_account_address);
    ///     aptos_container
    ///         .upload_contract(
    ///             "./contract-samples/sample1",
    ///             module_account_private_key,
    ///             &named_addresses,
    ///             None,
    ///             false,
    ///         )
    ///     .await
    ///     .unwrap();
    /// }
    /// ```
    pub async fn upload_contract(
        &self,
        local_dir: &str,
        private_key: &str,
        named_addresses: &HashMap<String, String>,
        sub_packages: Option<Vec<&str>>,
        override_contract: bool,
    ) -> Result<()> {
        // Skip the upload process if contracts should not be deployed.
        if !self.deploy_contract {
            return Ok(());
        }

        // Compute absolute path and contract key.
        let absolute = path::absolute(local_dir)?;
        let absolute_contract_path = absolute.to_str().unwrap();
        let contract_key = format!("{}:{}", private_key, absolute_contract_path);

        // Check if the contract has already been uploaded and whether overriding is allowed.
        let mut inserted_contracts = self.contracts.lock().await;
        if !override_contract && inserted_contracts.contains(&contract_key) {
            return Ok(());
        }
        // Copy contracts to a new location and log the time taken.
        let now = Instant::now();
        let contract_path = self.copy_contracts(local_dir).await?;
        debug!("copy_contracts takes: {:.2?}", now.elapsed());

        let contract_path_str = contract_path.to_str().unwrap();

        // Override `Move.toml` if no sub-packages are provided.-
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

        // Run move publish
        let named_address_params = named_addresses
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .reduce(|acc, cur| format!("{},{}", acc, cur))
            .map(|named_addresses| format!("--named-addresses {}", named_addresses))
            .unwrap_or("".to_string());
        match sub_packages {
            None => {
                let command = format!(
                    "cd {} && aptos move publish --skip-fetch-latest-git-deps --private-key {} --assume-yes {} --url {} --included-artifacts none",
                    contract_path_str, private_key, named_address_params, self.inner_url
                );
                let (stdout, stderr) = self.run_command(&command).await?;
                ensure!(
                    stdout.contains(r#""vm_status": "Executed successfully""#),
                    CommandFailed {
                        command,
                        stderr: format!("stdout: {} \n\n stderr: {}", stdout, stderr)
                    }
                );
            }
            Some(sub_packages) => {
                for sub_package in sub_packages {
                    let command = format!(
                        "cd {}/{} && aptos move publish --skip-fetch-latest-git-deps --private-key {} --assume-yes {} --url {} --included-artifacts none",
                        contract_path_str, sub_package, private_key, named_address_params, self.inner_url
                    );
                    let (stdout, stderr) = self.run_command(&command).await?;
                    ensure!(
                        stdout.contains(r#""vm_status": "Executed successfully""#),
                        CommandFailed {
                            command,
                            stderr: format!("stdout: {} \n\n stderr: {}", stdout, stderr)
                        }
                    );
                }
            }
        }

        // Add the contract key to the set of inserted contracts.
        inserted_contracts.insert(contract_key);
        Ok(())
    }
}

#[cfg(test)]
#[cfg(feature = "testing")]
mod tests {
    use log::info;
    use test_log::test;

    use super::*;
    use crate::test_utils::aptos_container_test_utils::{lazy_aptos_container, run};
    use crate::utils::get_account_address;

    #[test(tokio::test)]
    async fn run_script_test() {
        run(2, |accounts| {
            Box::pin(async move {
                let aptos_container = lazy_aptos_container().await?;
                let module_account_private_key = accounts.first().unwrap();
                let module_account_address = get_account_address(module_account_private_key);

                let mut named_addresses = HashMap::new();
                named_addresses.insert("verifier_addr".to_string(), module_account_address.clone());
                named_addresses.insert("lib_addr".to_string(), module_account_address);
                aptos_container
                    .run_script(
                        "./contract-samples/sample2",
                        module_account_private_key,
                        &named_addresses,
                        &vec!["verifier"],
                    )
                    .await
                    .unwrap();
                let node_url = aptos_container.get_node_url();
                info!("node_url = {:#?}", node_url);
                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[test(tokio::test)]
    async fn upload_contract_1_test() {
        run(2, |accounts| {
            Box::pin(async move {
                let aptos_container = lazy_aptos_container().await?;
                let module_account_private_key = accounts.first().unwrap();
                let module_account_address = get_account_address(module_account_private_key);

                let mut named_addresses = HashMap::new();
                named_addresses.insert("verifier_addr".to_string(), module_account_address);
                aptos_container
                    .upload_contract(
                        "./contract-samples/sample1",
                        module_account_private_key,
                        &named_addresses,
                        None,
                        false,
                    )
                    .await
                    .unwrap();
                let node_url = aptos_container.get_node_url();
                info!("node_url = {:#?}", node_url);
                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[test(tokio::test)]
    async fn upload_contract_1_test_duplicated() {
        run(2, |accounts| {
            Box::pin(async move {
                let aptos_container = lazy_aptos_container().await?;
                let module_account_private_key = accounts.first().unwrap();

                let module_account_address = get_account_address(module_account_private_key);

                let mut named_addresses = HashMap::new();
                named_addresses.insert("verifier_addr".to_string(), module_account_address);
                aptos_container
                    .upload_contract(
                        "./contract-samples/sample1",
                        module_account_private_key,
                        &named_addresses,
                        None,
                        false,
                    )
                    .await
                    .unwrap();
                let node_url = aptos_container.get_node_url();
                info!("node_url = {:#?}", node_url);
                Ok(())
            })
        })
        .await
        .unwrap();
    }

    #[test(tokio::test)]
    async fn upload_contract_2_test() {
        run(2, |accounts| {
            Box::pin(async move {
                let aptos_container = lazy_aptos_container().await?;
                let module_account_private_key = accounts.first().unwrap();
                let module_account_address = get_account_address(module_account_private_key);
                let mut named_addresses = HashMap::new();
                named_addresses.insert("verifier_addr".to_string(), module_account_address.clone());
                named_addresses.insert("lib_addr".to_string(), module_account_address);
                aptos_container
                    .upload_contract(
                        "./contract-samples/sample2",
                        module_account_private_key,
                        &named_addresses,
                        Some(vec!["libs", "verifier"]),
                        false,
                    )
                    .await
                    .unwrap();
                let node_url = aptos_container.get_node_url();
                println!("node_url = {:#?}", node_url);
                Ok(())
            })
        })
        .await
        .unwrap();
    }
}
