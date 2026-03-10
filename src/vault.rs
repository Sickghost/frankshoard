use std::fs;
use std::fs::OpenOptions;
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
pub enum Entry {
    BasicPassword(BasicPasswordEntry),
    Site(SiteEntry),
    Note(NoteEntry),
}

impl Entry {
    pub fn id(&self) -> Uuid {
        match self {
            Entry::BasicPassword(b) => b.id(),
            Entry::Site(s) => s.id(),
            Entry::Note(n) => n.id(),
        }
    }
}

pub trait FromEntry {
    fn from_entry<'a>(entry: &'a Entry) -> Option<&'a Self>;
}

#[derive(ZeroizeOnDrop, Serialize, Deserialize, Debug)]
pub struct BasicPasswordEntry {
    #[zeroize(skip)]
    id: Uuid,
    #[zeroize(skip)]
    pub username: String,
    pub password: String,
}

impl BasicPasswordEntry {
    pub fn new(username: String, password: String) -> Self {
        BasicPasswordEntry {
            id: Uuid::new_v4(),
            username,
            password,
        }
    }

    pub fn id(&self) -> Uuid {
        self.id
    }
}

impl FromEntry for BasicPasswordEntry {
    fn from_entry<'a>(entry: &'a Entry) -> Option<&'a Self> {
        if let Entry::BasicPassword(b) = entry { Some(b) } else { None }
    }
}

#[derive(ZeroizeOnDrop, Serialize, Deserialize, Debug)]
pub struct SiteEntry {
    #[zeroize(skip)]
    id: Uuid,
    #[zeroize(skip)]
    pub url: Url,
    pub username: String,
    pub password: String,
    pub note: Option<String>,
}

impl SiteEntry {
    pub fn new(url: Url, username: String, password: String, note: Option<String>) -> Self {
        SiteEntry {
            id: Uuid::new_v4(),
            url,
            username,
            password,
            note,
        }
    }

    pub fn id(&self) -> Uuid {
        self.id
    }
}

impl FromEntry for SiteEntry {
    fn from_entry<'a>(entry: &'a Entry) -> Option<&'a Self> {
        if let Entry::Site(s) = entry { Some(s) } else { None }
    }
}

#[derive(ZeroizeOnDrop, Serialize, Deserialize, Debug)]
pub struct NoteEntry {
    #[zeroize(skip)]
    id: Uuid,
    pub note: String,
}

impl NoteEntry {
    pub fn new(note: String) -> Self {
        NoteEntry {
            id: Uuid::new_v4(),
            note,
        }
    }

    pub fn id(&self) -> Uuid {
        self.id
    }
}

impl FromEntry for NoteEntry {
    fn from_entry<'a> (entry: &'a Entry) -> Option<&'a Self> {
        if let Entry::Note(n) = entry { Some(n) } else { None }
    }
}

#[derive(ZeroizeOnDrop, Serialize, Deserialize, Debug)]
pub struct DecryptedVault {
    entries: Vec<Entry>, // data in a Vec are always on the heap, so should be safe to just zero them like that
}

impl DecryptedVault {
    pub fn new() -> Self {
        DecryptedVault { entries: Vec::new() }
    }

    pub fn from_ciphertext(key: &MasterKey, nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Self, FranksHoardError> {
        if ciphertext.is_empty() {
            Ok(DecryptedVault { entries: Vec::new() })
        } else {
            let bytes = crypto::decrypt_bytes(key, nonce, ciphertext)?;
            let vault: DecryptedVault = from_bytes(&bytes)?;
            Ok(vault)
        }
    }

    // Public method to add entries
    pub fn add_entry(&mut self, item: Entry) {
        self.entries.push(item);
    }

    pub fn remove_entry(&mut self, id_to_remove: Uuid) {
        if let Some(index) = self.entries.iter().position(|e| e.id() == id_to_remove) {
            self.entries.swap_remove(index);
        }
    }

    // Public getter: Returns a slice for safe, read-only access
    pub fn get_entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn get_entries_of<'a, T: FromEntry + 'a>(&'a self) -> impl Iterator<Item = &'a T> + 'a {
        self.entries.iter().filter_map(|e| T::from_entry(e))
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
        }
        let mut salt = [0u8; 32];
        crypto::fill_salt(&mut salt);
        Ok(VaultFile {
            salt,
            nonce: [0u8; 12],  // 0s because will never be used
            ciphertext: Vec::new(),
        })
    }

    pub fn from_path(path: &Path) -> Result<Self, FranksHoardError> {
        if !path.try_exists()? {
            return Err(FranksHoardError::VaultNotFound);
        }

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

        Ok(VaultFile {
            salt,
            nonce,
            ciphertext,
        })
    }

    pub fn save(&self, path: &Path) -> Result<(), FranksHoardError> {
        // We could do complicated stuff (seek past the salt, truncate and write new nonce and ciphertext,
        // have special code for new file...) to not have to rewrite the salt but honestly, it's only 32 bytes
        // so we just zap the whole file each time.

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let tmp_path = path.with_extension("tmp");

        let mut file = OpenOptions::new().write(true).create(true).truncate(true).open(&tmp_path)?;
        file.write_all(&self.salt)?;
        file.write_all(&self.nonce)?;
        file.write_all(&self.ciphertext)?;
        file.sync_all()?;
        drop(file);

        fs::rename(&tmp_path, path)?;  // TODO: only works on unix-like.  Probnaly should use tempfile crate or something
        Ok(())
    }

    pub fn update_ciphertext(&mut self, decrypted_vault: &DecryptedVault, key: &MasterKey) -> Result<(), FranksHoardError> {
        let clear_data: Zeroizing<Vec<u8>> = Zeroizing::new(to_allocvec(&decrypted_vault)?);
        crypto::fill_nonce(&mut self.nonce);
        self.ciphertext = crypto::encrypt_bytes(key, &self.nonce, &clear_data)?;
        Ok(())
    }

    pub fn salt(&self) -> &[u8; 32] {
        &self.salt
    }

    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}
