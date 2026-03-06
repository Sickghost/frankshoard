use dirs::home_dir;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::FranksHoardError;

#[derive(Deserialize, Serialize)]
pub struct Argon2Conf {
    pub memory: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

#[derive(Deserialize, Serialize)]
pub struct UIConf {
    pub master_pwd_timeout_seconds: u32,
}

#[derive(Deserialize, Serialize)]
pub struct Config {
    pub vault_file: PathBuf,
    pub argon2: Argon2Conf,
    pub ui: UIConf,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, FranksHoardError> {
        let config_str = fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&config_str)?;
        config.vault_file = expand_tilde(&config.vault_file)?;
        Ok(config)
    }

    pub fn from_default(save_if_new: bool) -> Result<Self, FranksHoardError> {
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

        if save_if_new {
            let default_path = Config::default_config_path()?;
            if !default_path.exists() {
                conf.save_file(&default_path)?;
            }
        }
        Ok(conf)
    }

    pub fn default_config_path() -> Result<PathBuf, FranksHoardError> {
        let home = home_dir().ok_or(FranksHoardError::HomeDirectoryNotFound)?;
        Ok(home.join(".config/frankshoard/config.toml"))
    }

    fn save_file(&self, path: &Path) -> Result<(), FranksHoardError> {
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
