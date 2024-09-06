use tiny_keccak::Hasher;

pub fn get_account_address(private_key: &str) -> String {
    let signing_key = ed25519_dalek::SigningKey::try_from(
        hex::decode(private_key.trim_start_matches("0x"))
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let public_key = ed25519_dalek::VerifyingKey::from(&signing_key);
    let mut public_key_bytes = public_key.to_bytes().to_vec();
    public_key_bytes.push(0);
    let mut sha3 = tiny_keccak::Sha3::v256();
    sha3.update(&public_key_bytes);

    let mut out_bytes = [0; 32];
    sha3.finalize(&mut out_bytes);
    let mut public_key = "".to_string();
    for byte in out_bytes.iter() {
        public_key = format!("{}{:02x}", public_key, byte);
    }
    public_key
}
