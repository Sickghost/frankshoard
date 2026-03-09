mod config;
mod error;
mod vault;
mod crypto;

use std::path::PathBuf;
use uuid::Uuid;

use crate::config::Config;
use crate::vault::{VaultFile, DecryptedVault};
use crate::crypto::MasterKey;
use crate::error::FranksHoardError;

pub struct FranksHoard {
    config: Config,
    vault_file: VaultFile,
    decrypted_vault: Option<DecryptedVault>,
    master_key: Option<MasterKey>,
}

impl FranksHoard {

    /// Return a locked vault.  If the config file does not exits, it create a new default one and save it on disk.  If
    /// the vault doens not exits, it creates a new empty one.  Since it's empty, it does not save it.
    pub fn new(config_path: Option<PathBuf>) -> Result<Self, FranksHoardError> {
        // load conf
        let path = match config_path {
            Some(p) => p,
            None => Config::default_config_path()?,
        };

        let config;
        if path.try_exists()? {
            config = Config::from_path(&path)?;
        } else {
            config = Config::from_default()?;
            config.save_file(&path)?;
        }

        let vault_file = if config.vault_file().try_exists()? {
            VaultFile::from_path(config.vault_file())?
        } else {
            VaultFile::build_new_vault(config.vault_file())?
        };

        let franks_hoard = FranksHoard {
            config,
            vault_file,
            decrypted_vault: None,
            master_key: None,
        };
        Ok(franks_hoard)
    }

    pub fn unlock_vault(&mut self, config: &Config, password: String) -> Result<(), FranksHoardError> {
        // TODO
        Ok(())
    }

    pub fn get_entries(&self) {

    }

    pub fn get_entry(&self, uuid: Uuid) -> Result<Entry, FranksHoardError> {

    }

    pub fn delete_entry(&mut self, uuid: Uuid) -> Result<(), FranksHoardError> {
        // TODO
        Ok(())
    }


    pub fn change_password(&mut self) -> Result<(), FranksHoardError> {
        // TODO
        Ok(())
    }
}
