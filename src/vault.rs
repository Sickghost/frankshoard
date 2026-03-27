use std::fs;
use std::fs::OpenOptions;
use std::fmt;
use std::io::{Cursor, Read, Write};
use std::path::Path;
use postcard::{to_allocvec, from_bytes};
use serde::{Serialize, Deserialize};
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroizing, Zeroize};

use crate::error::Error;
use crate::crypto::{self, MasterKey};
use crate::secretbuf::{SecretBuf};


#[derive(Serialize, Deserialize, Debug)]
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

#[derive(Serialize, Deserialize, Debug)]
pub struct BasicPasswordEntry {
    id: Uuid,
    entry_name: Zeroizing<String>,
    username: Zeroizing<String>,
    password: SecretBuf,
}

impl BasicPasswordEntry {
    pub fn new(entry_name: Zeroizing<String>, username: Zeroizing<String>, password: Zeroizing<String>) -> Result<Self, Error> {

        let pwd_buf = SecretBuf::new(password)?;

        Ok(BasicPasswordEntry {
            id: Uuid::new_v4(),
            entry_name,
            username,
            password: pwd_buf,
        })
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn entry_name(&self) -> &str {
        &self.entry_name
    }

    pub fn set_entry_name(&mut self, new_entry_name: Zeroizing<String>) {
        self.entry_name.zeroize();
        self.entry_name = new_entry_name;
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn set_username(&mut self, new_username: Zeroizing<String>) {
        self.username.zeroize();
        self.username = new_username;
    }

    pub fn password(&self) -> Result<Zeroizing<String>, Error> {
        self.password.as_str()
    }

    pub fn set_password(&mut self, new_password: Zeroizing<String>) -> Result<(), Error> {
        self.password.zeroize();
        self.password = SecretBuf::new(new_password)?;
        Ok(())
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

#[derive(Serialize, Deserialize, Debug)]
pub struct SiteEntry {
    id: Uuid,
    entry_name: Zeroizing<String>,
    url: Url,
    username: Zeroizing<String>,
    password: SecretBuf,
    note: Option<SecretBuf>,
}

impl SiteEntry {
    pub fn new(entry_name: Zeroizing<String>, url: Url, username: Zeroizing<String>, password: Zeroizing<String>, note: Option<Zeroizing<String>>) -> Result<Self, Error> {
        Ok(SiteEntry {
            id: Uuid::new_v4(),
            entry_name,
            url,
            username,
            password: SecretBuf::new(password)?,
            note: note.map(SecretBuf::new).transpose()?,
        })
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn entry_name(&self) -> &str {
        &self.entry_name
    }

    pub fn set_entry_name(&mut self, new_entry_name: Zeroizing<String>) {
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

    pub fn set_username(&mut self, new_username: Zeroizing<String>) {
        self.username.zeroize();
        self.username = new_username;
    }

    pub fn password(&self) -> Result<Zeroizing<String>, Error> {
        self.password.as_str()
    }

    pub fn set_password(&mut self, new_password: Zeroizing<String>) -> Result<(), Error> {
        self.password.zeroize();
        self.password = SecretBuf::new(new_password)?;
        Ok(())
    }

    pub fn note(&self) -> Result<Option<Zeroizing<String>>, Error> {
        match &self.note {
            Some(n) => Ok(Some(n.as_str()?)),
            None => return Ok(None),
        }
    }

    pub fn set_note(&mut self, new_note: Option<Zeroizing<String>>) -> Result<(), Error> {
        self.note.zeroize();
        self.note = new_note.map(SecretBuf::new).transpose()?;
        Ok(())
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

#[derive(Serialize, Deserialize, Debug)]
pub struct NoteEntry {
    id: Uuid,
    entry_name: Zeroizing<String>,
    note: SecretBuf,
}

impl NoteEntry {
    pub fn new(entry_name: Zeroizing<String>, note: Zeroizing<String>) -> Result<Self, Error> {
        Ok(NoteEntry {
            id: Uuid::new_v4(),
            entry_name,
            note: SecretBuf::new(note)?,
        })
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn entry_name(&self) -> &str {
        &self.entry_name
    }

    pub fn set_entry_name(&mut self, new_entry_name: Zeroizing<String>) {
        self.entry_name.zeroize();
        self.entry_name = new_entry_name;
    }

    pub fn note(&self) -> Result<Zeroizing<String>, Error> {
        self.note.as_str()
    }

    pub fn set_note(&mut self, new_note: Zeroizing<String>) -> Result<(), Error> {
        self.note.zeroize();
        Ok(self.note = SecretBuf::new(new_note)?)
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

#[derive(Serialize, Deserialize, Debug)]
pub struct DecryptedVault {
    entries: Vec<Entry>, // data in a Vec are always on the heap, so should be safe to just zero them like that
}

impl DecryptedVault {
    pub fn new() -> Self {
        DecryptedVault { entries: Vec::new() }
    }

    pub fn from_ciphertext(key: &MasterKey, nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Self, Error> {
        if ciphertext.is_empty() {
            Ok(DecryptedVault { entries: Vec::new() })
        } else {
            let bytes = crypto::decrypt_bytes(key, nonce, ciphertext)?;
            let vault: DecryptedVault = from_bytes(&bytes)?;
            Ok(vault)
        }
    }

    pub fn add_entry(&mut self, item: Entry) -> Result<(), Error>{
        if self.entries.iter().any(|e| e.id() == item.id()) {
            return Err(Error::EntryAlreadyExists);
        }
        self.entries.push(item);
        Ok(())
    }

    pub fn get_entry(&self, id: Uuid) -> Option<&Entry>{
        self.entries.iter().find(|e| e.id() == id)
    }

    pub fn remove_entry(&mut self, id_to_remove: Uuid) -> Result<(), Error>{
        if let Some(index) = self.entries.iter().position(|e| e.id() == id_to_remove) {
            self.entries.swap_remove(index);
            Ok(())
        }
        else {
            Err(Error::EntryNotFound)
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
    pub fn build_new_vault(path: &Path) -> Result<Self, Error> {
        if path.try_exists()? {
            return Err(Error::VaultAlreadyExists);
        }
        let mut salt = [0u8; 32];
        crypto::fill_salt(&mut salt);
        let mut nonce = [0u8; 12];
        crypto::fill_nonce(&mut nonce);
        Ok(VaultFile {
            salt,
            nonce,  // Sure, never actually used, but safer anyways and more future proof than not initializing
            ciphertext: Vec::new(),
        })
    }

    pub fn from_path(path: &Path) -> Result<Self, Error> {
        if !path.try_exists()? {
            return Err(Error::VaultNotFound);
        }

        let bytes = Zeroizing::new(fs::read(path)?);  // password manager, we expect small db so we read it all in mem
        let mut cursor = Cursor::new(bytes);

        let mut salt = [0u8; 32];
        if let Err(e) = cursor.read_exact(&mut salt) {
            return Err(Error::MalformedVault(e));
        }
        let mut nonce = [0u8; 12];
        if let Err(e) = cursor.read_exact(&mut nonce) {
            return Err(Error::MalformedVault(e));
        }
        let mut ciphertext = Vec::new();
        if let Err(e) = cursor.read_to_end(&mut ciphertext) {
            return Err(Error::MalformedVault(e));
        }

        Ok(VaultFile {
            salt,
            nonce,
            ciphertext,
        })
    }

    pub fn save(&self, path: &Path) -> Result<(), Error> {
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

    pub fn update_ciphertext(&mut self, decrypted_vault: &DecryptedVault, key: &MasterKey) -> Result<(), Error> {
        let clear_data: Zeroizing<Vec<u8>> = Zeroizing::new(to_allocvec(&decrypted_vault)?);
        crypto::fill_nonce(&mut self.nonce);
        self.ciphertext = crypto::encrypt_bytes(key, &self.nonce, &clear_data)?;
        Ok(())
    }

    pub fn salt(&self) -> &[u8; 32] {
        &self.salt
    }

    /// Make sure you generate a new master_key and use it to update the ciphertext before saving the vault
    /// or you won't be able to decrypt it anymore.
    /// This is intended to be used when the password is changed.
    pub fn update_salt(&mut self) {
        crypto::fill_salt(&mut self.salt);
    }

    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}
