use dirs::home_dir;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::FranksHoardError;

#[derive(Deserialize, Serialize)]
pub struct Argon2Conf {
    memory: u32,
    iterations: u32,
    parallelism: u32,
}

impl Argon2Conf {
    pub fn memory(&self) -> u32 {
        self.memory
    }

    pub fn iterations(&self) -> u32 {
        self.iterations
    }

    pub fn parallelism(&self) -> u32 {
        self.parallelism
    }
}

#[derive(Deserialize, Serialize)]
pub struct UIConf {
    master_pwd_timeout_seconds: u32,
}

impl UIConf {
    pub fn master_pwd_timeout_seconds(&self) -> u32 {
        self.master_pwd_timeout_seconds
    }
}

#[derive(Deserialize, Serialize)]
pub struct Config {
    vault_file: PathBuf,
    argon2: Argon2Conf,
    ui: UIConf,
}

impl Config {
    pub fn vault_file(&self) -> &PathBuf {
        self.vault_file()
    }

    pub fn argon2(&self) -> &Argon2Conf {
        &self.argon2
    }

    pub fn ui(&self) -> &UIConf {
        &self.ui
    }
}

impl Config {
    pub fn from_path(path: &Path) -> Result<Self, FranksHoardError> {
        let config_str = fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&config_str)?;
        config.vault_file = expand_tilde(&config.vault_file)?;
        Ok(config)
    }

    pub fn from_default() -> Result<Self, FranksHoardError> {
        let home = home_dir().ok_or(FranksHoardError::HomeDirectoryNotFound)?;
        let conf = Config {
            vault_file: home.join(".frankshoard/vault.db"),
            argon2: Argon2Conf {
                memory: 1953000,
                iterations: 3,
                parallelism: 1,
            },
            ui: UIConf {
                master_pwd_timeout_seconds: 300,
            },
        };
        Ok(conf)
    }

    pub fn default_config_path() -> Result<PathBuf, FranksHoardError> {
        let home = home_dir().ok_or(FranksHoardError::HomeDirectoryNotFound)?;
        Ok(home.join(".config/frankshoard/config.toml"))
    }

    pub fn save_file(&self, path: &Path) -> Result<(), FranksHoardError> {
        let toml_str = toml::to_string(&self)?;

        fs::write(path, toml_str)?;
        Ok(())
    }
}

fn expand_tilde(path: &Path) -> Result<PathBuf, FranksHoardError> {
    if let Ok(stripped) = path.strip_prefix("~") {
        let home = home_dir().ok_or(FranksHoardError::HomeDirectoryNotFound)?;
        return Ok(home.join(stripped));
    }
    Ok(path.to_path_buf())
}
