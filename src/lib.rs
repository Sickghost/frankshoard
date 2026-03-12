mod config;
mod error;
mod vault;
mod crypto;

use std::path::PathBuf;
use uuid::Uuid;
use zeroize::Zeroizing;

pub use crate::error::FranksHoardError;
pub use crate::vault::{Entry, SiteEntry, NoteEntry, BasicPasswordEntry};

use crate::vault::{VaultFile, DecryptedVault, FromEntry};
use crate::config::Config;
use crate::crypto::MasterKey;

pub struct LockedHoard {
    config: Config,
    vault_file: VaultFile
}

impl LockedHoard {
    pub fn from_path(config_path: Option<PathBuf>) -> Result<Self, FranksHoardError> {
        let config = LockedHoard::build_config(config_path)?;

        if !config.vault_file().try_exists()? {
            return Err(FranksHoardError::VaultNotFound);
        }
        let vault_file = VaultFile::from_path(config.vault_file())?;

        Ok(LockedHoard {
            config,
            vault_file,
        })
    }

    pub fn new_hoard(config_path: Option<PathBuf>) -> Result<Self, FranksHoardError> {
        let config = LockedHoard::build_config(config_path)?;

        if config.vault_file().try_exists()? {
            return Err(FranksHoardError::VaultAlreadyExists);
        }

        let vault_file = VaultFile::build_new_vault(config.vault_file())?;
        Ok(LockedHoard {
            config,
            vault_file,
        })
    }

    fn build_config(config_path: Option<PathBuf>) -> Result<Config, FranksHoardError> {
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
        Ok(config)
    }

    pub fn unlock(self, password: Zeroizing<String>) -> Result<UnlockedHoard, FranksHoardError> {
        UnlockedHoard::unlock(self, &password)
    }

    pub fn change_password(&mut self, password: Zeroizing<String>, new_password: Zeroizing<String>) -> Result<(), FranksHoardError> {
        let master_key = MasterKey::from_password(&password, self.vault_file.salt(), &self.config)?;
        let decrypted_vault = DecryptedVault::from_ciphertext(&master_key, self.vault_file.nonce(), self.vault_file.ciphertext())?;

        self.vault_file.update_salt();
        let new_master_key = MasterKey::from_password(&new_password, self.vault_file.salt(), &self.config)?;
        self.vault_file.update_ciphertext(&decrypted_vault, &new_master_key)
    }
}

pub struct UnlockedHoard {
    config: Config,
    vault_file: VaultFile,
    master_key: MasterKey,
    decrypted_vault: DecryptedVault
}


impl UnlockedHoard {

    pub(crate) fn unlock(locked_hoard: LockedHoard, password: &Zeroizing<String>) -> Result<Self, FranksHoardError> {
        let master_key = MasterKey::from_password(password, &locked_hoard.vault_file.salt(), &locked_hoard.config)?;
        let decrypted_vault = DecryptedVault::from_ciphertext(&master_key, &locked_hoard.vault_file.nonce(), &locked_hoard.vault_file.ciphertext())?;

        let franks_hoard = UnlockedHoard {
            config: locked_hoard.config,
            vault_file: locked_hoard.vault_file,
            decrypted_vault,
            master_key,
        };
        Ok(franks_hoard)
    }

    pub fn lock(mut self, save: bool) -> Result<LockedHoard, FranksHoardError>{
        self.vault_file.update_ciphertext(&self.decrypted_vault, &self.master_key)?;
        if save {
            self.vault_file.save(self.config.vault_file())?;
        }

        Ok(LockedHoard {
            config: self.config,
            vault_file: self.vault_file,
        })
    }

    pub fn add_entry(&mut self, entry: Entry) -> Result<(), FranksHoardError> {
        self.decrypted_vault.add_entry(entry)
    }

    pub fn get_entries(&self) -> &[Entry] {
        self.decrypted_vault.get_entries()
    }

    pub fn get_entries_of<'a, T: FromEntry + 'a>(&'a self) -> impl Iterator<Item = &'a T> + 'a {
        self.decrypted_vault.get_entries_of::<>()
    }

    pub fn get_entry(&self, uuid: Uuid) -> Option<&Entry> {
        self.decrypted_vault.get_entry(uuid)
    }

    pub fn remove_entry(&mut self, uuid: Uuid) -> Result<(), FranksHoardError> {
        self.decrypted_vault.remove_entry(uuid)
    }
}
