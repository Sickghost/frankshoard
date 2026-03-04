use url::Url;

pub struct WebsiteEntry {
    url: Url,
    username: String,
    password: String,
    note: Option<String>,
}

pub struct NoteEntry {
    note: String,
}

pub enum Entry {
    Website(WebsiteEntry),
    Note(NoteEntry),
}


pub struct DecryptedVault {
    entries: Vec<Entry>,
}

pub struct VaultFile {
    salt: [u8; 32],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}
