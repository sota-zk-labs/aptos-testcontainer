//! # Overview
//! This module provides a simple and smart test container framework for testing interactions
//! with an Aptos node. The framework is designed to easily initialize and manage a containerized
//! Aptos environment, making it straightforward to write integration tests for Aptos-based
//! applications.

/// Responsible for handling the logic of an Aptos container.
pub mod aptos_container;
mod config;
/// Defines error types and custom error handling related to the Aptos container operations.
pub mod errors;
/// Provides utilities and helper functions for testing the Aptos container.
pub mod test_utils;
/// A helper function used across the test container.
pub mod utils;
