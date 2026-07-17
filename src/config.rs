use dirs::home_dir;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::io::Write;
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
    pub fn new(memory: u32, iterations: u32, parallelism: u32) -> Self {
        Argon2Conf { memory, iterations, parallelism }
    }

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
    session_timeout_seconds: u32,
}

impl UIConf {
    pub fn new(session_timeout_seconds: u32) -> Self {
        UIConf { session_timeout_seconds }
    }
    pub fn session_timeout_seconds(&self) -> u32 {
        self.session_timeout_seconds
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
    pub fn new(vault_path: PathBuf, argon2: Argon2Conf, ui: UIConf) -> Result<Self, Error> {
        let vault_file = expand_tilde(&vault_path)?;
        Ok(Config { vault_file, argon2, ui })
    }

    pub fn from_path(path: &Path) -> Result<Self, Error> {
        let config_str = fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&config_str)?;
        config.vault_file = expand_tilde(&config.vault_file)?;
        Ok(config)
    }

    pub fn save_file(&self, path: &Path) -> Result<(), Error> {
        let toml_str = toml::to_string(&self)?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
        file.write_all(toml_str.as_bytes())?;
        drop(file);

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
