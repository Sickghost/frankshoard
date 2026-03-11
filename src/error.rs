#[derive(Debug)]
pub enum FranksHoardError {
    Io(std::io::Error),
    Encryption(String),
    VaultAlreadyExists,
    VaultNotFound,
    EntryAlreadyExists,
    EntryNotFound,
    MalformedVault(std::io::Error),
    MasterPasswordError(String),
    TomlError(String),
    HomeDirectoryNotFound,
    UrlParseError(String),
    BinarySerdeError(postcard::Error),
    IllegalState(String),
    NotImplemented(String),
}

impl std::fmt::Display for FranksHoardError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FranksHoardError::Io(e) => write!(f, "IO error: {}", e),
            FranksHoardError::Encryption(str) => write!(f, "Encryption error: {}", str),
            FranksHoardError::VaultAlreadyExists => write!(f, "Vault already exists"),
            FranksHoardError::VaultNotFound => write!(f, "Vault not found"),
            FranksHoardError::EntryAlreadyExists => write!(f, "Entry already exists in vault"),
            FranksHoardError::EntryNotFound => write!(f, "Entry not found in vault"),
            FranksHoardError::MalformedVault(e) => write!(f, "Malformed vault file: {}", e),
            FranksHoardError::MasterPasswordError(str) => write!(f, "Master password error: {}", str),
            FranksHoardError::TomlError(str) => write!(f, "Toml Error : {}", str),
            FranksHoardError::HomeDirectoryNotFound => {write!(f, "Unable to find home directory when building path")}
            FranksHoardError::UrlParseError(str) => write!(f, "Url Parse Error: {}", str),
            FranksHoardError::BinarySerdeError(e) => write!(f, "Error serializing/deserializing vault: {}", e),
            FranksHoardError::IllegalState(str) => write!(f, "Illegal state: {}", str),
            FranksHoardError::NotImplemented(str) => write!(f, "Error, feature not yet implemented: {}", str),
        }
    }
}

impl std::error::Error for FranksHoardError {}

impl From<std::io::Error> for FranksHoardError {
    fn from(e: std::io::Error) -> Self {
        FranksHoardError::Io(e)
    }
}

impl From<aes_gcm::Error> for FranksHoardError {
    fn from(e: aes_gcm::Error) -> Self {
        FranksHoardError::Encryption(e.to_string())
    }
}

impl From<toml::de::Error> for FranksHoardError {
    fn from(e: toml::de::Error) -> Self {
        FranksHoardError::TomlError(e.to_string())
    }
}

impl From<toml::ser::Error> for FranksHoardError {
    fn from(e: toml::ser::Error) -> Self {
        FranksHoardError::TomlError(e.to_string())
    }
}

impl From<url::ParseError> for FranksHoardError {
    fn from(e: url::ParseError) -> Self {
        FranksHoardError::UrlParseError(e.to_string())
    }
}

impl From<argon2::Error> for FranksHoardError {
    fn from(e: argon2::Error) -> Self {
        FranksHoardError::Encryption(e.to_string())
    }
}

impl From<postcard::Error> for FranksHoardError {
    fn from(e: postcard::Error) -> Self {
        FranksHoardError::BinarySerdeError(e)
    }
}
