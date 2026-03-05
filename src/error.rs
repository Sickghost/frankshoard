#[derive(Debug)]
pub enum FranksHoardError {
    Io(std::io::Error),
    Encryption(String),
    VaultAlreadyExists,
    VaultNotFound,
    MalformedVault(std::io::Error),
    InvalidMasterPassword,
    TomlError(String),
    HomeDirectoryNotFound,
    UrlParseError(String),
    RandError(rand::rngs::SysError),
}

impl std::fmt::Display for FranksHoardError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FranksHoardError::Io(e) => write!(f, "IO error: {}", e),
            FranksHoardError::Encryption(e) => write!(f, "Encryption error: {}", e),
            FranksHoardError::VaultAlreadyExists => write!(f, "Vault already exists"),
            FranksHoardError::VaultNotFound => write!(f, "Vault not found"),
            FranksHoardError::MalformedVault(e) => write!(f, "Malformed vault file: {}", e),
            FranksHoardError::InvalidMasterPassword => write!(f, "Invalid master password"),
            FranksHoardError::TomlError(e) => write!(f, "Toml Error : {}", e),
            FranksHoardError::HomeDirectoryNotFound => {
                write!(f, "Unable to find home directory when building path")
            }
            FranksHoardError::UrlParseError(e) => write!(f, "Url Parse Error: {}", e),
            FranksHoardError::RandError(e) => write!(f, "Random Number Generator Error: {}", e),
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

impl From<rand::rngs::SysError> for FranksHoardError {
    fn from(e: rand::rngs::SysError) -> Self {
        FranksHoardError::RandError(e)
    }
}

impl From<argon2::Error> for FranksHoardError {
    fn from(e: argon2::Error) -> Self {
        FranksHoardError::Encryption(e.to_string())
    }
}
