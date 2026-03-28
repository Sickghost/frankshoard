use dirs::home_dir;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::Error;

#[derive(Deserialize, Serialize, Debug)]
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

#[derive(Deserialize, Serialize, Debug)]
pub struct UIConf {
    master_pwd_timeout_seconds: u32,
}

impl UIConf {
    pub fn master_pwd_timeout_seconds(&self) -> u32 {
        self.master_pwd_timeout_seconds
    }
}

// TODO: Needs rustdoc
#[derive(Deserialize, Serialize, Debug)]
pub struct Config {
    vault_file: PathBuf,
    argon2: Argon2Conf,
    ui: UIConf,
}

impl Config {
    pub fn from_path(path: &Path) -> Result<Self, Error> {
        let config_str = fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&config_str)?;
        config.vault_file = expand_tilde(&config.vault_file)?;
        Ok(config)
    }

    pub fn from_default() -> Result<Self, Error> {
        let home = home_dir().ok_or(Error::HomeDirectoryNotFound)?.join(".frankshoard/vault.db");
        let conf = Config {
            vault_file: home,
            argon2: Argon2Conf {
                memory: 2097152,
                iterations: 3,
                parallelism: 1,
            },
            ui: UIConf {
                master_pwd_timeout_seconds: 300,
            },
        };
        Ok(conf)
    }

    pub fn default_config_path() -> Result<PathBuf, Error> {
        let home = home_dir().ok_or(Error::HomeDirectoryNotFound)?;
        Ok(home.join(".config/frankshoard/config.toml"))
    }

    pub fn save_file(&self, path: &Path) -> Result<(), Error> {
        let toml_str = toml::to_string(&self)?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, toml_str)?;
        Ok(())
    }

    pub fn vault_file(&self) -> &Path {
        &self.vault_file
    }

    pub fn argon2(&self) -> &Argon2Conf {
        &self.argon2
    }

    pub fn ui(&self) -> &UIConf {
        &self.ui
    }
}

fn expand_tilde(path: &Path) -> Result<PathBuf, Error> {
    if let Ok(stripped) = path.strip_prefix("~") {
        let home = home_dir().ok_or(Error::HomeDirectoryNotFound)?;
        return Ok(home.join(stripped));
    }
    Ok(path.to_path_buf())
}
