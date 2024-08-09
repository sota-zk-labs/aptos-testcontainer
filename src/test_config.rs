pub mod aptos_container_test {
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
}
