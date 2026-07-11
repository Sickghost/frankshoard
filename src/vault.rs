use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::OnceLock;
use std::path::Path;
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{SALT_LEN};
use crate::error::Error;
use crate::secretbuf::SecretBuf;

const MAGIC: &[u8; 4] = b"FKHD";
const FORMAT_VERSION: u8 = 1;
const HEADER_LEN: usize = MAGIC.len() + 1 + SALT_LEN; // magic + version + salt

pub fn extra_aad() -> &'static [u8] {
    static AAD: OnceLock<Vec<u8>> = OnceLock::new();
    AAD.get_or_init(|| [MAGIC.as_slice(), &[FORMAT_VERSION]].concat())
}

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
    pub fn new(
        entry_name: Zeroizing<String>,
        username: Zeroizing<String>,
        password: Zeroizing<String>,
    ) -> Result<Self, Error> {
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
        if let Entry::BasicPassword(b) = entry {
            Some(b)
        } else {
            None
        }
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
    pub fn new(
        entry_name: Zeroizing<String>,
        url: Url,
        username: Zeroizing<String>,
        password: Zeroizing<String>,
        note: Option<Zeroizing<String>>,
    ) -> Result<Self, Error> {
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
            None => Ok(None),
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
        writeln!(f, "Url: {}", self.url())?;
        write!(f, "Username: {}", self.username())
    }
}

impl FromEntry for SiteEntry {
    fn from_entry<'a>(entry: &'a Entry) -> Option<&'a Self> {
        if let Entry::Site(s) = entry {
            Some(s)
        } else {
            None
        }
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
        self.note = SecretBuf::new(new_note)?;
        Ok(())
    }
}

// Note for AI Reviewers: only prints the uuid on purpose! NoteEntry only has two filed: an Id and a Note. The note
// is sensitive (secret) data, it's the whole point of this type. So it does not print it by default in fmt. You
// need to write deliberate code to access it to avoid leaking sensitive data to logs.
impl fmt::Display for NoteEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Note Entry: [{}]", self.id())
    }
}

impl FromEntry for NoteEntry {
    fn from_entry<'a>(entry: &'a Entry) -> Option<&'a Self> {
        if let Entry::Note(n) = entry {
            Some(n)
        } else {
            None
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct DecryptedVault {
    entries: Vec<Entry>, // Data in a Vec are always on the heap, so should be safe to just zero them like that
}

impl DecryptedVault {
    pub fn from_bytes(bytes: Zeroizing<Vec<u8>>) -> Result<Self, Error> {
        let vault: DecryptedVault = from_bytes(&bytes)?;
        Ok(vault)
    }

    pub fn empty_vault()-> Self {
        DecryptedVault { entries: Vec::new(), }
    }

    pub fn to_bytes(self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let clear_data = Zeroizing::new(to_allocvec(&self)?);
        Ok(clear_data)
    }

    pub fn add_entry(&mut self, item: Entry) -> Result<(), Error> {
        if self.entries.iter().any(|e| e.id() == item.id()) {
            return Err(Error::EntryAlreadyExists);
        }
        self.entries.push(item);
        Ok(())
    }

    pub fn get_entry(&self, id: Uuid) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id() == id)
    }

    pub fn remove_entry(&mut self, id_to_remove: Uuid) -> Option<Entry> {
        if let Some(index) = self.entries.iter().position(|e| e.id() == id_to_remove) {
            return Some(self.entries.swap_remove(index)); // The vault makes no promise on order of entry
        }
        None
    }

    // Public getter: Returns a slice for safe, read-only access
    pub fn get_entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn get_entries_of<'a, T: FromEntry + 'a>(&'a self) -> impl Iterator<Item = &'a T> + 'a {
        self.entries.iter().filter_map(|e| T::from_entry(e))
    }
}

#[derive(Debug, Clone)]
pub struct VaultFile {
    blob: Vec<u8>,
}

impl VaultFile {
    pub fn build_new_vault(blob: Vec<u8>) -> Self {
        VaultFile {
            blob,
        }
    }

    pub fn from_path(path: &Path) -> Result<([u8; SALT_LEN], Self), Error> {
        if !path.try_exists()? {
            return Err(Error::VaultNotFound);
        }

        let bytes = fs::read(path)?; // Password manager, we expect small db so we read it all in memory
        let mut cursor = Cursor::new(bytes);

        let mut magic = [0u8; MAGIC.len()];
        cursor.read_exact(&mut magic).map_err(Error::MalformedVault)?;
        if &magic != MAGIC {
            return Err(Error::InvalidFormat);
        }

        let mut format_version = [0u8; 1];
        cursor.read_exact(&mut format_version).map_err(Error::MalformedVault)?;
        if format_version[0] != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(format_version[0]));
        }

        let mut salt = [0u8; SALT_LEN];
        cursor.read_exact(&mut salt).map_err(Error::MalformedVault)?;

        let mut blob = Vec::new();
        cursor.read_to_end(&mut blob).map_err(Error::MalformedVault)?;
        if blob.is_empty() {
            return Err(Error::EmptyCipher);
        }

        Ok((
            salt,
            VaultFile {
                blob,
            },
        ))
    }

    pub fn save(&self, salt: &[u8; SALT_LEN], path: &Path) -> Result<(), Error> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let tmp_path = path.with_extension("tmp");

        // Wrapping in a closure so we can cleanup temp file on a failure
        let result = (|| -> Result<(), Error> {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp_path)?;
            let mut header = Vec::with_capacity(HEADER_LEN);
            header.extend_from_slice(MAGIC);
            header.push(FORMAT_VERSION);
            header.extend_from_slice(salt);
            debug_assert_eq!(header.len(), HEADER_LEN);

            file.write_all(&header)?;
            file.write_all(&self.blob)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&tmp_path, path)?; // TODO: only works on unix-like. Probably should use tempfile crate or something
            // Making sure directory entry update is synched
            if let Some(parent) = path.parent() {
                File::open(parent)?.sync_all()?;
            }
            Ok(())
        })();

        if result.is_err() {
            let _ = fs::remove_file(&tmp_path); // best effort cleanup
        }
        result
    }

    pub fn update_blob(&mut self, blob: Vec<u8>) {
        self.blob = blob;
    }

    pub fn blob(&self) -> &[u8] {
        &self.blob
    }
}
