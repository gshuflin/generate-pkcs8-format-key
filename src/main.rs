use std::path::Path;

use ed25519::{pkcs8::{ObjectIdentifier, PrivateKeyInfo}}; 
use pkcs8::{AlgorithmIdentifierRef, pkcs5::pbes2::Parameters};
use rand::{Rng, thread_rng};

enum Library {
    Dalek,
    Zebra,
}

fn main() {
    generate_key(b"test", "output-dalek.der", Library::Dalek);
    generate_key(b"test", "output-zebra.der", Library::Zebra);
}

fn generate_key(password: &[u8], output_filename: impl AsRef<Path>, library: Library) {
    const ED25519_ASN1_HEADER: [u8; 2] = [0x04, 0x20];
    const ED25519_KEY_LENGTH: usize = 32;

    println!("Generating pcks8 key");

    let (sk_bytes, vk_bytes): (Vec<u8>, Vec<u8>) = match library {
        Library::Dalek => {
            let signing_key = ed25519_dalek::SigningKey::generate(&mut thread_rng());
            let verification_key = signing_key.verifying_key();

            let sk_bytes: &[u8; 32] = signing_key.as_bytes();
            let vk_bytes: &[u8; 32] = verification_key.as_bytes();
            (sk_bytes.to_vec(), vk_bytes.to_vec())
        },
        Library::Zebra => {
            let signing_key = ed25519_zebra::SigningKey::new(thread_rng());
            let verification_key = ed25519_zebra::VerificationKey::from(&signing_key);
            let sk_bytes: &[u8] = signing_key.as_ref();
            let vk_bytes: &[u8] = verification_key.as_ref();
            (sk_bytes.to_vec(), vk_bytes.to_vec())
        }
    };
    assert_eq!(sk_bytes.len(), 32);
    assert_eq!(vk_bytes.len(), 32);

    const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
    let air = AlgorithmIdentifierRef {
        oid: ED25519_OID,
        parameters: None,
    };

    let private_key_info = PrivateKeyInfo {
        algorithm: air,
        private_key: sk_bytes.as_ref(),
        public_key: Some(vk_bytes.as_ref()),
    };

    let mut rng = thread_rng();

    let salt: [u8; 32] = rng.gen();
    let aes_iv: [u8; 16] = rng.gen();

    // Uses pbkdf2 sha256 aes256cbc parameters
    let pbes2_params = Parameters::pbkdf2_sha256_aes256cbc(2048, &salt, &aes_iv).unwrap();

    let secret_document = private_key_info.encrypt_with_params(pbes2_params, password).unwrap();

    secret_document.write_der_file(&output_filename).unwrap();
    let p: &Path = output_filename.as_ref();
    println!("Finished writing {}", p.display());
}

