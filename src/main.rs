use pkcs8::{ObjectIdentifier, PrivateKeyInfo, AlgorithmIdentifierRef, pkcs5::pbes2::Parameters};
use rand::{Rng, thread_rng};

fn main() {
    println!("Generating pcks8 key");

    let password = b"test";

    let signing_key = ed25519_zebra::SigningKey::new(thread_rng());
    let verification_key = ed25519_zebra::VerificationKey::from(&signing_key);

    let sk_bytes: &[u8] = signing_key.as_ref();
    let vk_bytes: &[u8] = verification_key.as_ref();
    assert_eq!(sk_bytes.len(), 32);

    const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
    let air = AlgorithmIdentifierRef {
        oid: ED25519_OID,
        parameters: None,
    };

    let private_key_info = PrivateKeyInfo {
        algorithm: air,
        private_key: sk_bytes,
        public_key: Some(vk_bytes),
    };

    let mut rng = thread_rng();

    let salt: [u8; 32] = rng.gen();
    let aes_iv: [u8; 16] = rng.gen();

    // Uses pbkdf2 sha256 aes256cbc parameters
    let pbes2_params = Parameters::pbkdf2_sha256_aes256cbc(2048, &salt, &aes_iv).unwrap();

    let secret_document = private_key_info.encrypt_with_params(pbes2_params, password).unwrap();

    secret_document.write_der_file("output.der").unwrap();
    println!("Finished writing output.der");

}

