use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use argon2::{Argon2, Algorithm, Version, Params};
use zeroize::Zeroizing;

pub struct MasterKey {
    key: Zeroizing<Box<[u8; 32]>>, // A box, because we want the key in the heap
}

impl MasterKey {
    pub fn new(key_bytes: Box<[u8; 32]>) -> Self {
        MasterKey {
            key: Zeroizing::new(key_bytes),
        }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

// fix that, just a place to drop code for now while I read the doc...
fn temp_derive_key() {

    // get params from conf here and all that.
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(memory, iterations, parallelism, None)?
    );

    let mut key_bytes: Zeroizing<Box<[u8; 32]>> = Zeroizing::new(Box::new([0u8; 32]));
    // derive directly into the boxed slice
    argon2.hash_password_into(password, &salt, key_bytes.as_mut())?;
}
