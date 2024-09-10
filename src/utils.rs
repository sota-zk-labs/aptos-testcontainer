use tiny_keccak::Hasher;

/// Converts a given private key to its corresponding account address.
///
/// # Arguments
///
/// * `private_key` - A string slice representing the private key in hexadecimal format.
///
/// # Returns
///
/// * `String` - The derived account address in hexadecimal format.
///
/// # Example
/// ```rust
/// use aptos_testcontainer::aptos_container::AptosContainer;
/// use aptos_testcontainer::utils::get_account_address;
///
/// #[tokio::main]
/// async fn main() {
///     let aptos_container = AptosContainer::init().await.unwrap();
///     let accounts = aptos_container.get_initiated_accounts().await.unwrap();
///     let module_account_private_key = accounts.first().unwrap();
///     let module_account_address = get_account_address(module_account_private_key);
/// }
/// ```
pub fn get_account_address(private_key: &str) -> String {
    // Convert the private key from hexadecimal format to bytes, removing the "0x" prefix if present.
    let signing_key = ed25519_dalek::SigningKey::try_from(
        hex::decode(private_key.trim_start_matches("0x"))
            .unwrap()
            .as_slice(),
    )
    .unwrap();

    // Derive the public key from the signing key.
    let public_key = ed25519_dalek::VerifyingKey::from(&signing_key);

    // Prepare public key bytes for hashing by appending a trailing zero.
    let mut public_key_bytes = public_key.to_bytes().to_vec();
    public_key_bytes.push(0);

    // Initialize SHA3-256 hashing algorithm and update it with the public key bytes.
    let mut sha3 = tiny_keccak::Sha3::v256();
    sha3.update(&public_key_bytes);

    // Finalize the hash and store it in `out_bytes`.
    let mut out_bytes = [0; 32];
    sha3.finalize(&mut out_bytes);

    // Convert the hashed bytes to a hexadecimal string.
    let mut public_key = "".to_string();
    for byte in out_bytes.iter() {
        public_key = format!("{}{:02x}", public_key, byte);
    }
    public_key
}
