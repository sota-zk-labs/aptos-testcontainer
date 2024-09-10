# Aptos Test Container

[![License](https://img.shields.io/github/license/sota-zk-labs/aptos-testcontainer)](./LICENSE)
[![Continuous Integration](https://github.com/sota-zk-labs/aptos-testcontainer/actions/workflows/ci.yaml/badge.svg)](https://github.com/sota-zk-labs/aptos-testcontainer/actions/workflows/ci.yaml/badge.svg)
[![codecov](https://codecov.io/github/sota-zk-labs/aptos-testcontainer/branch/master/graph/badge.svg?token=CKEWC8QC0E)](https://codecov.io/github/sota-zk-labs/aptos-testcontainer)

## Introduction

This module provides a simple and smart test container framework for testing interactions with an Aptos node.

## Usage
Here’s how to use the `aptos-testcontainer` in your tests:

### 1. Initialize the Container

To start an Aptos node in a container and run tests on it, you can use the `lazy_aptos_container` function.

```rust
use aptos_testcontainer::test_utils::aptos_container_test_utils::lazy_aptos_container;

#[tokio::main]
async fn main() {
    let aptos_container = lazy_aptos_container.await?;
}
```

### 2. Run Tests with Aptos Accounts

Use the `run` function to run tests with initialized `accounts`.

And use the `get_account_address` function to convert a given private key to its corresponding account address.
```rust
use aptos_testcontainer::test_utils::aptos_container_test_utils::{lazy_aptos_container, run};
use aptos_testcontainer::utils::get_account_address;

#[tokio::main]
async fn main() {
    run(2, |accounts| {
        Box::pin(async move {
            let aptos_container = lazy_aptos_container().await?;
            let module_account_private_key = accounts.first().unwrap();
            let module_account_address = get_account_address(module_account_private_key);
            Ok(())
        })
    })
        .await
        .unwrap();
}
```

### 3. Upload Contracts and Run Scripts

#### Using to `upload_contract`
```rust
use aptos_testcontainer::test_utils::aptos_container_test_utils::{lazy_aptos_container, run};
use aptos_testcontainer::utils::get_account_address;

#[tokio::main]
async fn main() {
    run(2, |accounts| {
        Box::pin(async move {
            let aptos_container = lazy_aptos_container().await?;
            let module_account_private_key = accounts.first().unwrap();
            let module_account_address = get_account_address(module_account_private_key);

            // The local directory containing the contract files.
            let local_dir = "./contract-samples/sample1";

            let mut named_addresses = HashMap::new();
            named_addresses.insert("verifier_addr".to_string(), module_account_address);
            aptos_container
                .upload_contract(
                    local_dir,
                    module_account_private_key,
                    &named_addresses,
                    None,
                    false,
                )
                .await
                .unwrap();
            Ok(())
        })
    })
        .await
        .unwrap();
}
```

#### Using to `run_scripts`
```rust
use aptos_testcontainer::test_utils::aptos_container_test_utils::{lazy_aptos_container, run};
use aptos_testcontainer::utils::get_account_address;

#[tokio::main]
async fn main() {
    run(2, |accounts| {
        Box::pin(async move {
            let aptos_container = lazy_aptos_container().await?;
            let module_account_private_key = accounts.first().unwrap();
            let module_account_address = get_account_address(module_account_private_key);

            // The directory path containing contract code.
            let local_dir = "./contract-samples/sample2";

            let mut named_addresses = HashMap::new();
            named_addresses.insert("verifier_addr".to_string(), module_account_address.clone());
            named_addresses.insert("lib_addr".to_string(), module_account_address);
            aptos_container
                .run_script(
                    local_dir,
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
```


### Environment Variables

| ENV                                     | EXAMPLE                              | NOTE                                                                                           |
|-----------------------------------------|--------------------------------------|------------------------------------------------------------------------------------------------|
| APTOS\_TESTCONTAINER\_\_ENABLE_NODE     | true                                 | Whether to connect to an Aptos node within the container (set this to false to use other envs) |
| APTOS\_TESTCONTAINER\_\_ACCOUNTS        | private_1,private_2                  | Accounts used in tests, all tests will be provided with these                                  |
| APTOS\_TESTCONTAINER\_\_NODE_URL        | https://api.testnet.aptoslabs.com/v1 | Aptos Node Url to connect                                                                      |
| APTOS\_TESTCONTAINER\_\_DEPLOY_CONTRACT | true                                 | Whether to deploy any contract                                                                 |
| APTOS\_TESTCONTAINER\_\_CHAIN_ID        | 2                                    | Chain ID                                                                                       |

## Configuration
