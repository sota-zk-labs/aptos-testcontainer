#[cfg(feature = "testing")]
pub mod aptos_container_test_utils {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, OnceLock, Weak};

    use anyhow::Result;
    use tokio::sync::Mutex;

    use crate::aptos_container::AptosContainer;

    static APTOS_CONTAINER: OnceLock<Mutex<Weak<AptosContainer>>> = OnceLock::new();

    pub async fn lazy_aptos_container() -> Result<Arc<AptosContainer>> {
        let mut guard = APTOS_CONTAINER
            .get_or_init(|| Mutex::new(Weak::new()))
            .lock()
            .await;
        let maybe_client = guard.upgrade();

        if let Some(client) = maybe_client {
            Ok(client)
        } else {
            let client = Arc::new(AptosContainer::init().await?);
            *guard = Arc::downgrade(&client);

            Ok(client)
        }
    }

    pub async fn run(number_of_accounts: usize, runner: impl FnOnce(Vec<String>) -> Pin<Box<dyn Future<Output=Result<()>>>>) -> Result<()>
    {
        let aptos_container = lazy_aptos_container().await?;
        aptos_container.run(number_of_accounts, runner).await
    }
}
