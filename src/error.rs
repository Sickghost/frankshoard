#[derive(Debug)]
pub enum Error {
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
    SecretTooLong,
    CorruptedSecret,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "IO error: {}", e),
            Error::Encryption(str) => write!(f, "Encryption error: {}", str),
            Error::VaultAlreadyExists => write!(f, "Vault already exists"),
            Error::VaultNotFound => write!(f, "Vault not found"),
            Error::EntryAlreadyExists => write!(f, "Entry already exists in vault"),
            Error::EntryNotFound => write!(f, "Entry not found in vault"),
            Error::MalformedVault(e) => write!(f, "Malformed vault file: {}", e),
            Error::MasterPasswordError(str) => write!(f, "Master password error: {}", str),
            Error::TomlError(str) => write!(f, "Toml Error : {}", str),
            Error::HomeDirectoryNotFound => {write!(f, "Unable to find home directory when building path")}
            Error::UrlParseError(str) => write!(f, "Url Parse Error: {}", str),
            Error::BinarySerdeError(e) => write!(f, "Error serializing/deserializing vault: {}", e),
            Error::IllegalState(str) => write!(f, "Illegal state: {}", str),
            Error::NotImplemented(str) => write!(f, "Error, feature not yet implemented: {}", str),
            Error::SecretTooLong => write!(f, "Error, the secret you are trying to create is too long."),
            Error::CorruptedSecret => write!(f, "Error, the secret could not be retrieved."),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<aes_gcm::Error> for Error {
    fn from(e: aes_gcm::Error) -> Self {
        Error::Encryption(e.to_string())
    }
}

impl From<toml::de::Error> for Error {
    fn from(e: toml::de::Error) -> Self {
        Error::TomlError(e.to_string())
    }
}

impl From<toml::ser::Error> for Error {
    fn from(e: toml::ser::Error) -> Self {
        Error::TomlError(e.to_string())
    }
}

impl From<url::ParseError> for Error {
    fn from(e: url::ParseError) -> Self {
        Error::UrlParseError(e.to_string())
    }
}

impl From<argon2::Error> for Error {
    fn from(e: argon2::Error) -> Self {
        Error::Encryption(e.to_string())
    }
}

impl From<postcard::Error> for Error {
    fn from(e: postcard::Error) -> Self {
        Error::BinarySerdeError(e)
    }
}
