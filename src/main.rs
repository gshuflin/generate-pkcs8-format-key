use std::path::Path;

use ed25519::{pkcs8::{ObjectIdentifier, PrivateKeyInfo}, KeypairBytes}; 
use pkcs8::{AlgorithmIdentifierRef, pkcs5::pbes2::Parameters, LineEnding};
use ed25519_dalek::pkcs8::EncodePrivateKey;
use rand::{Rng, thread_rng};

enum Library {
    Dalek,
    Zebra,
}

enum Format {
    PEM,
    DER
}

fn main() {
    generate_key_zebra(b"test", "new-dalek.der", Format::DER);
    generate_key_zebra(b"test", "new-dalek.pem", Format::PEM);
    /*
    generate_key(b"test", "output-dalek.pem", Library::Dalek, Format::PEM);
    generate_key(b"test", "output-zebra.pem", Library::Zebra, Format::PEM);
    generate_key(b"test", "output-dalek.der", Library::Dalek, Format::DER);
    generate_key(b"test", "output-zebra.der", Library::Zebra, Format::DER);
    */
}

fn generate_key_zebra(password: &[u8], path: impl AsRef<Path>, format: Format) {
    let path: &Path = path.as_ref();
    let signing_key = ed25519_zebra::SigningKey::new(thread_rng());
    //let _verification_key = signing_key.verification_key();

    let sk_bytes: &[u8] = signing_key.as_ref();
    let secret_key: [u8; 32] = sk_bytes.try_into().unwrap();

    println!("Secret key bytes: {:x?} ({})", secret_key, path.display());

    let keypair_bytes: KeypairBytes = KeypairBytes {
        secret_key,
        public_key: None
    };

    match format {
        Format::DER => keypair_bytes.write_pkcs8_der_file(path).unwrap(),
        Format::PEM => keypair_bytes.write_pkcs8_pem_file(path, LineEnding::LF).unwrap(),
    }
}

fn generate_key(password: &[u8], output_filename: impl AsRef<Path>, library: Library, format: Format) {
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

    match format {
        Format::DER => {
            secret_document.write_der_file(&output_filename).unwrap();
        },
        Format::PEM => {
            secret_document.write_pem_file(&output_filename, "PRIVATE KEY", LineEnding::LF).unwrap();
        }
    }
    let p: &Path = output_filename.as_ref();
    println!("Finished writing {}", p.display());
}

