#[derive(Debug)]
pub enum AppError {
    Io(std::io::Error),
    Encryption(String),
    VaultAlreadyExists,
    VaultNotFound,
    InvalidMasterPassword,
    TomlError(String),
    HomeDirectoryNotFound,
    UrlParseError(String),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AppError::Io(e) => write!(f, "IO error: {}", e),
            AppError::Encryption(e) => write!(f, "Encryption error: {}", e),
            AppError::VaultAlreadyExists => write!(f, "Vault already exists"),
            AppError::VaultNotFound => write!(f, "Vault not found"),
            AppError::InvalidMasterPassword => write!(f, "Invalid master password"),
            AppError::TomlError(e) => write!(f, "Toml Error : {}", e),
            AppError::HomeDirectoryNotFound => write!(f, "Unable to find home directory when building path"),
            AppError::UrlParseError(e) => write!(f, "Url Parse Error: {}", e),
        }
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Io(e)
    }
}

impl From<aes_gcm::Error> for AppError {
    fn from(e: aes_gcm::Error) -> Self {
        AppError::Encryption(e.to_string())
    }
}

impl From<toml::de::Error> for AppError {
    fn from(e: toml::de::Error) -> Self {
        AppError::TomlError(e.to_string())
    }
}

impl From<toml::ser::Error> for AppError {
    fn from(e: toml::ser::Error) -> Self {
        AppError::TomlError(e.to_string())
    }
}

impl From<url::ParseError> for AppError {
    fn from(e: url::ParseError) -> Self {
        AppError::UrlParseError(e.to_string())
    }
}
