use std::fs;
use std::fs::OpenOptions;
use std::fmt;
use std::io::{Cursor, Read, Write};
use std::path::Path;
use postcard::{to_allocvec, from_bytes};
use serde::{Serialize, Deserialize};
use url::Url;
use uuid::Uuid;
use zeroize::{ZeroizeOnDrop, Zeroizing, Zeroize};

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

impl fmt::Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Entry::Site(s) => write!(f, "{}", s),
            Entry::Note(n) => write!(f, "{}", n),
            Entry::BasicPassword(b) => write!(f, "{}", b),
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
    entry_name: String,
    username: String,
    password: String,
}

impl BasicPasswordEntry {
    pub fn new(entry_name: String, username: String, password: String) -> Self {
        BasicPasswordEntry {
            id: Uuid::new_v4(),
            entry_name,
            username,
            password,
        }
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn entry_name(&self) -> &str {
        &self.entry_name
    }

    pub fn set_entry_name(&mut self, new_entry_name: String) {
        self.entry_name.zeroize();
        self.entry_name = new_entry_name;
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn set_username(&mut self, new_username: String) {
        self.username.zeroize();
        self.username = new_username;
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn set_password(&mut self, new_password: String) {
        self.password.zeroize();
        self.password = new_password;
    }
}

impl fmt::Display for BasicPasswordEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Password Entry: [{}]", self.id())?;
        writeln!(f, "Entry Name: {}", self.entry_name())?;
        write!(f, "Username: {}", self.username())
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
    entry_name: String,
    #[zeroize(skip)]
    url: Url,
    username: String,
    password: String,
    note: Option<String>,
}

impl SiteEntry {
    pub fn new(entry_name: String, url: Url, username: String, password: String, note: Option<String>) -> Self {
        SiteEntry {
            id: Uuid::new_v4(),
            entry_name,
            url,
            username,
            password,
            note,
        }
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn entry_name(&self) -> &str {
        &self.entry_name
    }

    pub fn set_entry_name(&mut self, new_entry_name: String) {
        self.entry_name.zeroize();
        self.entry_name = new_entry_name;
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn set_url(&mut self, new_url: Url) {
        self.url = new_url;
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn set_username(&mut self, new_username: String) {
        self.username.zeroize();
        self.username = new_username;
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn set_password(&mut self, new_password: String) {
        self.password.zeroize();
        self.password = new_password;
    }

    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }

    pub fn set_note(&mut self, new_note: Option<String>) {
        self.note.zeroize();
        self.note = new_note;
    }
}

impl fmt::Display for SiteEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Site Entry: [{}]", self.id())?;
        writeln!(f, "Entry Name: {}", self.entry_name())?;
        write!(f, "Url: {}", self.url())?;
        write!(f, "Username: {}", self.username())
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
    entry_name: String,
    note: String,
}

impl NoteEntry {
    pub fn new(entry_name: String, note: String) -> Self {
        NoteEntry {
            id: Uuid::new_v4(),
            entry_name,
            note,
        }
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn entry_name(&self) -> &str {
        &self.entry_name
    }

    pub fn set_entry_name(&mut self, new_entry_name: String) {
        self.entry_name.zeroize();
        self.entry_name = new_entry_name;
    }

    pub fn note(&self) -> &str {
        &self.note
    }

    pub fn set_note(&mut self, new_note: String) {
        self.note.zeroize();
        self.note = new_note;
    }
}

impl fmt::Display for NoteEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Note Entry: [{}]", self.id())
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

    pub fn add_entry(&mut self, item: Entry) -> Result<(), FranksHoardError>{
        if self.entries.iter().any(|e| e.id() == item.id()) {
            return Err(FranksHoardError::EntryAlreadyExists);
        }
        self.entries.push(item);
        Ok(())
    }

    pub fn get_entry(&self, id: Uuid) -> Option<&Entry>{
        self.entries.iter().find(|e| e.id() == id)
    }

    pub fn remove_entry(&mut self, id_to_remove: Uuid) -> Result<(), FranksHoardError>{
        if let Some(index) = self.entries.iter().position(|e| e.id() == id_to_remove) {
            self.entries.swap_remove(index);
            Ok(())
        }
        else {
            Err(FranksHoardError::EntryNotFound)
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
