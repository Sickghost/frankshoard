use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::Path;
use postcard::{to_allocvec, from_bytes};
use serde::{Serialize, Deserialize};
use url::Url;
use uuid::Uuid;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::error::FranksHoardError;
use crate::crypto::{self, MasterKey};

#[derive(ZeroizeOnDrop, Serialize, Deserialize, Debug)]
pub struct WebsiteEntry {
    #[zeroize(skip)]
    pub id: Uuid,
    #[zeroize(skip)]
    pub url: Url,
    pub username: String,
    pub password: String,
    pub note: Option<String>,
}

#[derive(ZeroizeOnDrop, Serialize, Deserialize, Debug)]
pub struct NoteEntry {
    #[zeroize(skip)]
    pub id: Uuid,
    pub note: String,
}

#[derive(ZeroizeOnDrop, Serialize, Deserialize, Debug)]
pub enum Entry {
    Website(WebsiteEntry),
    Note(NoteEntry),
}

#[derive(ZeroizeOnDrop, Serialize, Deserialize, Debug)]
pub struct DecryptedVault {
    entries: Vec<Entry>, // data in a Vec are always on the heap, so should be safe to just zero them like that
}

impl DecryptedVault {
    pub fn from_ciphertext(key: &MasterKey, nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Self, FranksHoardError> {
        let bytes = crypto::decrypt_bytes(key, nonce, ciphertext)?;
        let vault: DecryptedVault = from_bytes(&bytes)?;
        Ok(vault)
    }

    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, FranksHoardError> {
        // TODO: serialize to byte
        Err(FranksHoardError::VaultNotFound)
    }

    // Public method to add entries
    pub fn add_entry(&mut self, item: Entry) {
        // todo
        self.entries.push(item);
    }

    // Public getter: Returns a slice for safe, read-only access
    pub fn get_entries(&self) -> &[Entry] {
        // todo
        &self.entries
    }

    pub fn update_entry(&mut self, entry: Entry) -> Result<(), FranksHoardError> {
        // todo
        // Update an existing entry (using uuis to find it)
        Ok(())
    }
}

#[derive(Debug)]
pub struct VaultFile {
    salt: [u8; 32],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

impl VaultFile {
    pub fn build_new_vault(path: &Path) -> Result<Self, FranksHoardError> {
        if path.try_exists()? {
            return Err(FranksHoardError::VaultAlreadyExists);
        } else {
            let mut salt = [0u8; 32];
            crypto::fill_salt(&mut salt);

            let vault_file = VaultFile {
                salt,
                nonce: [0u8; 12],  // we don't care, this nonce will never be used
                ciphertext: Vec::new(),
            };
            Ok(vault_file)
        }
    }

    pub fn from_path(path: &Path) -> Result<Self, FranksHoardError> {
        if path.try_exists()? {
            let bytes = fs::read(path)?;
            let mut cursor = Cursor::new(bytes);

            let mut salt = [0u8; 32];
            if let Err(e) = cursor.read_exact(&mut salt) {
                return Err(FranksHoardError::MalformedVault(e));
            }
            let mut nonce = [0u8; 12];
            if let Err(e) = cursor.read_exact(&mut nonce) {
                return Err(FranksHoardError::MalformedVault(e));
            }
            let mut ciphertext = Vec::new();
            if let Err(e) = cursor.read_to_end(&mut ciphertext) {
                return Err(FranksHoardError::MalformedVault(e));
            }

            let vault_file = VaultFile {
                salt,
                nonce,
                ciphertext,
            };
            Ok(vault_file)
        } else {
            Err(FranksHoardError::VaultNotFound)
        }
    }

    pub fn write(&self, path: &Path) -> Result<(), FranksHoardError> {
        // TODO Write vault to file.
        Ok(())
    }

    pub fn update_cyphertext(&mut self, decrypted_vault: &DecryptedVault, key: &MasterKey) -> Result<(), FranksHoardError> {
        let clear_data: Zeroizing<Vec<u8>> = Zeroizing::new(to_allocvec(&decrypted_vault)?);
        self.ciphertext = crypto::encrypt_bytes(key, &mut self.nonce, &clear_data)?;
        Ok(())
    }
}
