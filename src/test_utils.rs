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
    /// This function checks if an `AptosContainer` has already been initialized and stored in the
    /// global `APTOS_CONTAINER`. If the container exists, it upgrades the weak reference to a strong
    /// `Arc<AptosContainer>` and returns it. If not, it creates a new `AptosContainer`, stores a weak
    /// reference to it, and returns the strong reference.
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
    ///     let aptos_container = lazy_aptos_container().await?;
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

    pub async fn run(
        number_of_accounts: usize,
        runner: impl FnOnce(Vec<String>) -> Pin<Box<dyn Future<Output = Result<()>>>>,
    ) -> Result<()> {
        let aptos_container = lazy_aptos_container().await?;
        aptos_container.run(number_of_accounts, runner).await
    }
}
