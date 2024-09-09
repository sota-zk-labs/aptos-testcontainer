/// This module provides utility functions for testing the `AptosContainer` by:
#[cfg(feature = "testing")]
pub mod aptos_container_test_utils {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, OnceLock, Weak};

    use anyhow::Result;
    use tokio::sync::Mutex;

    use crate::aptos_container::AptosContainer;

    static APTOS_CONTAINER: OnceLock<Mutex<Weak<AptosContainer>>> = OnceLock::new();

    /// Lazily initializes and retrieves an `Arc<AptosContainer>`.
    ///
    /// # Returns
    ///
    /// * `Result<Arc<AptosContainer>>` - Returns an `Arc` pointing to the initialized `AptosContainer`.
    ///
    /// # Example
    /// ```rust
    /// use aptos_testcontainer::test_utils::aptos_container_test_utils::lazy_aptos_container;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let aptos_container = lazy_aptos_container().await.unwrap();
    /// }
    /// ```
    pub async fn lazy_aptos_container() -> Result<Arc<AptosContainer>> {
        // Access the global `APTOS_CONTAINER`, initialize it with a new `Mutex<Weak<AptosContainer>>`
        // if it's not already initialized. Lock the `Mutex` to safely access the weak reference.
        let mut guard = APTOS_CONTAINER
            .get_or_init(|| Mutex::new(Weak::new()))
            .lock()
            .await;

        // Attempt to upgrade the weak reference to a strong `Arc<AptosContainer>`.
        let maybe_client = guard.upgrade();

        // If a valid container already exists, return the strong reference.
        if let Some(client) = maybe_client {
            Ok(client)
        } else {
            // Otherwise, initialize a new `AptosContainer`, store a weak reference to it,
            // and return the strong `Arc<AptosContainer>`.
            let client = Arc::new(AptosContainer::init().await?);
            *guard = Arc::downgrade(&client);

            Ok(client)
        }
    }

    /// Asynchronously runs a process that involves managing Aptos accounts using a `AptopsContainer`.
    ///
    /// # Arguments
    ///
    /// * `number_of_accounts` - The number of accounts required to run the process.
    /// * `runner` - A callback function that takes a vector of accounts (`Vec<String>`) and returns
    ///   a `Future`. This function defines the operations to be performed
    ///   once the accounts are initialized or retrieved.
    ///
    /// # Example
    /// ```rust
    /// use std::collections::HashMap;
    /// use aptos_testcontainer::test_utils::aptos_container_test_utils::{lazy_aptos_container, run};
    /// use aptos_testcontainer::utils::get_account_address;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     run(2, |accounts| {
    ///         Box::pin(async move {
    ///             let aptos_container = lazy_aptos_container().await.unwrap();
    ///             let module_account_private_key = accounts.first().unwrap();
    ///             let module_account_address = get_account_address(module_account_private_key);
    ///
    ///             let mut named_addresses = HashMap::new();
    ///             named_addresses.insert("verifier_addr".to_string(), module_account_address.clone());
    ///             aptos_container
    ///                 .upload_contract(
    ///                     "./contract-samples/sample1",
    ///                     module_account_private_key,
    ///                     &named_addresses,
    ///                     None,
    ///                     false,
    ///                 )
    ///                 .await
    ///                 .unwrap();
    ///             Ok(())
    ///         })
    ///     })
    ///     .await
    ///     .unwrap();
    /// }
    /// ```
    pub async fn run(
        number_of_accounts: usize,
        runner: impl FnOnce(Vec<String>) -> Pin<Box<dyn Future<Output = Result<()>>>>,
    ) -> Result<()> {
        let aptos_container = lazy_aptos_container().await?;
        aptos_container.run(number_of_accounts, runner).await
    }
}
