use std::fs;
use std::io::Cursor;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use url::Url;
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

use crate::error::AppError;

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
    entries: Vec<Entry>,
}

impl DecryptedVault {
    pub fn from_vault_file(vault_file: &VaultFile) -> Result<Self, AppError> {
        // TODO: Decrypt the vault
        Err(AppError::VaultNotFound)
    }
}

pub struct VaultFile {
    salt: [u8; 32],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

impl VaultFile {
    pub fn create_empty_vault(path: &Path) -> Result<Self, AppError> {
        // todo implement
        Err(AppError::VaultNotFound)
    }

    pub fn from_path(path: &Path) -> Result<Self, AppError> {
        if path.try_exists()? {
            let bytes = fs::read(path)?;
            let mut cursor = Cursor::new(bytes);

            let mut salt = [0u8; 32];
            cursor.read_exact(&mut salt)?;
            let mut nonce = [0u8; 12];
            cursor.read_exact(&mut nonce)?;
            let mut ciphertext = Vec::new();
            cursor.read_to_end(&mut ciphertext)?;

            let vault_file = VaultFile {
                salt,
                nonce,
                ciphertext,
            };
            Ok(vault_file)
        } else {
            Err(AppError::VaultNotFound)
        }
    }

    pub fn write(&self, path: &Path) -> Result<(), AppError> {
        // todo implement
        Ok(())
    }
}
