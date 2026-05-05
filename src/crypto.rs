use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use argon2::{Argon2, Algorithm, Version, Params};
use zeroize::Zeroizing;
use std::time::Instant;
use std::fmt;

use crate::config::Config;
use crate::error::Error;

pub struct MasterKey {
    key: Zeroizing<Box<[u8]>>, // A box, because we want the key in the heap
    creation_time: Instant,  // TODO mechanism to handle that
}

// Won't leak actual secret to logs and such
impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasterKey")
            .field("key", &"**********")
            .field("creation_time", &self.creation_time)
            .finish()
    }
}

impl MasterKey {
    pub fn from_password(password: &Zeroizing<String>, salt: &[u8; 32], config: &Config) -> Result<MasterKey, Error>{
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(config.argon2().memory(), config.argon2().iterations(), config.argon2().parallelism(), None)?
        );

        // derive directly into the boxed slice
        let mut key: Zeroizing<Box<[u8]>> = Zeroizing::new(vec![0u8; 32].into_boxed_slice());
        argon2.hash_password_into(password.as_bytes(), salt, key.as_mut())?;
        Ok(MasterKey {
            key,
            creation_time: Instant::now(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}

pub fn fill_salt(salt: &mut [u8; 32]) {
    OsRng.fill_bytes(salt);
}

pub fn fill_nonce(nonce_bytes: &mut [u8; 12]) {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
    nonce_bytes.copy_from_slice(nonce.as_slice());
}

pub fn encrypt_bytes(master_key: &MasterKey, nonce_bytes: &[u8; 12], plaintext: &Zeroizing<Vec<u8>>) -> Result<Vec<u8>, Error> {
    let key = Key::<Aes256Gcm>::from_slice(master_key.as_bytes());
    let cipher = Aes256Gcm::new(&key);

    let nonce = Nonce::from_slice(nonce_bytes);
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_slice())?;
    Ok(ciphertext)
}

pub fn decrypt_bytes(master_key: &MasterKey, nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let key = Key::<Aes256Gcm>::from_slice(master_key.as_bytes());
    let cipher = Aes256Gcm::new(&key);

    let nonce = Nonce::from_slice(nonce);
    let plaintext = Zeroizing::new(cipher.decrypt(&nonce, ciphertext.as_ref())?);
    Ok(plaintext)
}
