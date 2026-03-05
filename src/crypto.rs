use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use argon2::{Argon2, Algorithm, Version, Params};
use zeroize::Zeroizing;
use std::time::Instant;

use crate::config::Config;
use crate::error::FranksHoardError;


pub struct MasterKey {
    key: Zeroizing<Box<[u8; 32]>>, // A box, abecause we want the key in the heap
    creation_time: Instant,
}

impl MasterKey {
    pub fn from_password(password: &Zeroizing<String>, salt: &[u8; 32], config: &Config) -> Result<MasterKey, FranksHoardError>{

        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(config.argon2.memory, config.argon2.iterations, config.argon2.parallelism, None)?
        );

        // derive directly into the boxed slice
        let mut key: Zeroizing<Box<[u8; 32]>> = Zeroizing::new(Box::new([0u8; 32]));
        argon2.hash_password_into(password.as_bytes(), salt, key.as_mut())?;
        Ok(MasterKey {
            key,
            creation_time: Instant::now(),
        })
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}
