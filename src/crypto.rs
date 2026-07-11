use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use std::fmt;
use std::time::Instant;
use zeroize::Zeroizing;

use crate::config::Config;
use crate::error::Error;

pub(crate) const SALT_LEN: usize = 32;
pub(crate) const NONCE_LEN: usize = 12; // 96-bit nonce per AES-GCM spec
const KEY_LEN: usize = 32; // AES-256 key size
const TAG_LEN: usize = 16;   // AES-GCM authentication tag (128-bit)

pub struct MasterKey {
    key: Zeroizing<Box<[u8]>>, // A box, because we want the key in the heap
    salt: [u8; SALT_LEN],
    creation_time: Instant,    // TODO mechanism to handle that
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
    pub fn from_password_with_salt (
        password: &Zeroizing<String>,
        config: &Config,
        salt: [u8; SALT_LEN],
    ) -> Result<MasterKey, Error> {
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(
                config.argon2().memory(),
                config.argon2().iterations(),
                config.argon2().parallelism(),
                None,
            )?,
        );

        // Derive directly into the boxed slice
        let mut key: Zeroizing<Box<[u8]>> = Zeroizing::new(vec![0u8; KEY_LEN].into_boxed_slice());
        argon2.hash_password_into(password.as_bytes(), &salt, key.as_mut())?;
        Ok(MasterKey {
            key,
            salt,
            creation_time: Instant::now(),
        })
    }

    pub fn from_new_password(
        password: &Zeroizing<String>,
        config: &Config,
    ) -> Result<MasterKey, Error> {
        let mut salt = [0u8; SALT_LEN];
        fill_salt(&mut salt);
        MasterKey::from_password_with_salt(password, config, salt)
    }

    pub(crate) fn salt(&self) -> [u8;SALT_LEN] {
        self.salt
    }
}

fn fill_salt(salt: &mut [u8; SALT_LEN]) {
    OsRng.fill_bytes(salt);
}

fn fill_nonce(nonce_bytes: &mut [u8; NONCE_LEN]) {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
    nonce_bytes.copy_from_slice(nonce.as_slice());
}

pub fn encrypt_bytes(
    master_key: &MasterKey,
    extra_aad: &[u8],
    plaintext: &Zeroizing<Vec<u8>>,
) -> Result<Vec<u8>, Error> {
    let mut nonce_byte = [0u8; NONCE_LEN];
    fill_nonce(&mut nonce_byte);

    let key = Key::<Aes256Gcm>::from_slice(&master_key.key);
    let cipher = Aes256Gcm::new(&key);

    let nonce = Nonce::from_slice(&nonce_byte);
    let aad: Vec<u8> = [extra_aad, master_key.salt.as_slice()].concat();

    let mut blob = Vec::with_capacity(NONCE_LEN + plaintext.len() + TAG_LEN);
    blob.extend_from_slice(&nonce_byte);
    blob.extend_from_slice(&cipher.encrypt(nonce, Payload { msg: plaintext.as_slice(), aad: &aad })?);
    Ok(blob)
}

pub fn decrypt_bytes(
    master_key: &MasterKey,
    extra_aad: &[u8],
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::Encryption("Unable to decrypt: Bad length".to_string()));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);

    let key = Key::<Aes256Gcm>::from_slice(&master_key.key);
    let cipher = Aes256Gcm::new(&key);

    let nonce = Nonce::from_slice(nonce_bytes);
    let aad: Vec<u8> = [extra_aad, master_key.salt.as_slice()].concat();
    let plaintext = Zeroizing::new(cipher.decrypt(nonce, Payload { msg: ciphertext, aad: &aad },)?);
    Ok(plaintext)
}
