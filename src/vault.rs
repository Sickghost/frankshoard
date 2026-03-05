use rand::{rngs::SysRng, TryRng};
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use url::Url;
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

use crate::error::FranksHoardError;

#[derive(ZeroizeOnDrop)]
pub struct WebsiteEntry {
    #[zeroize(skip)]
    id: Uuid,
    #[zeroize(skip)]
    url: Url,
    username: String,
    password: String,
    note: Option<String>,
}

#[derive(ZeroizeOnDrop)]
pub struct NoteEntry {
    #[zeroize(skip)]
    id: Uuid,
    note: String,
}

#[derive(ZeroizeOnDrop)]
pub enum Entry {
    Website(WebsiteEntry),
    Note(NoteEntry),
}

#[derive(ZeroizeOnDrop)]
pub struct DecryptedVault {
    entries: Vec<Entry>, // data in a Vec are always on the heap, so should be safe to just zero them like that
}

impl DecryptedVault {
    pub fn from_vault_file(vault_file: &VaultFile) -> Result<Self, FranksHoardError> {
        // TODO: Decrypt the vault
        Err(FranksHoardError::VaultNotFound)
    }

    // Public method to add entries
    pub fn add_entry(&mut self, item: Entry) {
        self.entries.push(item);
    }

    // Public getter: Returns a slice for safe, read-only access
    pub fn get_entries(&self) -> &[Entry] {
        &self.entries
    }
}

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
            SysRng.try_fill_bytes(&mut salt)?;
            let mut nonce = [0u8; 12];
            SysRng.try_fill_bytes(&mut nonce)?;

            let vault_file = VaultFile {
                salt,
                nonce,
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
        Ok(())
    }

    pub fn update_cyphertext(&mut self, decrypted_vault: &DecryptedVault) -> Result<(), FranksHoardError> {
        // change the nonce
        SysRng.try_fill_bytes(&mut self.nonce)?;

        // todo serialize and encrypt.  Write crypto and come back here.
        Ok(())
    }
}
