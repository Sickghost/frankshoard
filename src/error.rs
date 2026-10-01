/// Since this is a learning project, I chose to do the error boilerplate code
/// manually rather than using `thiserror` to manage my lib errors.

#[derive(Debug)]
pub enum Error {
    VaultAlreadyExists,
    VaultNotFound,
    EntryAlreadyExists,
    HomeDirectoryNotFound,
    CorruptedSecret,
    Io(std::io::Error),
    Encryption(String),
    MalformedVault(std::io::Error),
    InvalidFormat,
    UnsupportedVersion(u8),
    MasterPasswordError(String),
    TomlError(String),
    UrlParseError(url::ParseError),
    BinarySerdeError(postcard::Error),
    IllegalState(String),
    NotImplemented(String),
    EmptyCipher,
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::VaultAlreadyExists => write!(f, "Vault already exists"),
            Error::VaultNotFound => write!(f, "Vault not found"),
            Error::EntryAlreadyExists => write!(f, "Entry already exists in vault"),
            Error::HomeDirectoryNotFound => {
                write!(f, "Unable to find home directory when building path")
            }
            Error::CorruptedSecret => write!(f, "Error, the secret could not be retrieved."),
            Error::Io(e) => write!(f, "IO error: {}", e),
            Error::Encryption(str) => write!(f, "Encryption error: {}", str),
            Error::MalformedVault(e) => write!(f, "Malformed vault file: {}", e),
            Error::InvalidFormat => write!(f, "Magic mismatch: not a frankshoard file"),
            Error::UnsupportedVersion(ver) => write!(f, "Unexpected format version: {}", ver),
            Error::MasterPasswordError(str) => write!(f, "Master password error: {}", str),
            Error::TomlError(str) => write!(f, "Toml Error : {}", str),
            Error::UrlParseError(e) => write!(f, "Url Parse Error: {}", e),
            Error::BinarySerdeError(e) => write!(f, "Error serializing/deserializing vault: {}", e),
            Error::IllegalState(str) => write!(f, "Illegal state: {}", str),
            Error::NotImplemented(str) => write!(f, "Error, feature not yet implemented: {}", str),
            Error::EmptyCipher => write!(f, "Cipher Text cannot be empty."),
        }
    }
}

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
        Error::UrlParseError(e)
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

pub struct TransitionError<T> {
    error: Error,
    hoard: T,       // The hoard (locked or unlocked) being consumed, returned in case of an error
}

impl<T> std::error::Error for TransitionError<T> {}

impl<T> std::fmt::Display for TransitionError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.error, f)
    }
}

impl<T> std::fmt::Debug for TransitionError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransitionError")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl<T> From<TransitionError<T>> for Error {
    fn from(e: TransitionError<T>) -> Self {
         e.discard()
    }
 }

impl<T> TransitionError<T> {
    pub(crate) fn new(error: Error, hoard: T) -> Self {
        TransitionError {
            error,
            hoard,
        }
    }

    pub fn into_hoard(self) -> T {
        self.hoard
    }

    pub fn discard(self) -> Error {
        self.error
    }

    pub fn error(&self) -> &Error {
        &self.error
    }
}
