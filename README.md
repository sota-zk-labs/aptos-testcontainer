# Aptos Test Container

[![License](https://img.shields.io/github/license/sota-zk-labs/aptos-testcontainer)](./LICENSE)
[![Continuous Integration](https://github.com/sota-zk-labs/aptos-testcontainer/actions/workflows/ci.yaml/badge.svg)](https://github.com/sota-zk-labs/aptos-testcontainer/actions/workflows/ci.yaml/badge.svg)
[![codecov](https://codecov.io/github/sota-zk-labs/aptos-testcontainer/branch/master/graph/badge.svg?token=CKEWC8QC0E)](https://codecov.io/github/sota-zk-labs/aptos-testcontainer)

## Introduction

Test container for Aptos Node

## Install

## How To Use

### Environment Variables

| ENV                                     | EXAMPLE                              | NOTE                                                                                           |
|-----------------------------------------|--------------------------------------|------------------------------------------------------------------------------------------------|
| APTOS\_TESTCONTAINER\_\_ENABLE_NODE     | true                                 | Whether to connect to an Aptos node within the container (set this to false to use other envs) |
| APTOS\_TESTCONTAINER\_\_ACCOUNTS        | private_1,private_2                  | Accounts used in tests, all tests will be provided with these                                  |
| APTOS\_TESTCONTAINER\_\_NODE_URL        | https://api.testnet.aptoslabs.com/v1 | Aptos Node Url to connect                                                                      |
| APTOS\_TESTCONTAINER\_\_DEPLOY_CONTRACT | true                                 | Whether to deploy any contract                                                                 |
| APTOS\_TESTCONTAINER\_\_CHAIN_ID        | 2                                    | Chain ID                                                                                       |

## Configuration
