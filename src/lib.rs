mod config;
mod error;
mod vault;
mod crypto;

use std::path::PathBuf;
use uuid::Uuid;
use zeroize::Zeroizing;

pub use crate::error::FranksHoardError;
pub use crate::vault::{Entry, SiteEntry, NoteEntry, BasicPasswordEntry};

use crate::vault::{VaultFile, DecryptedVault};
use crate::config::Config;
use crate::crypto::MasterKey;

pub struct FranksHoard {
    config: Config,
    vault_file: VaultFile,
    master_key: MasterKey,
    decrypted_vault: DecryptedVault,
}

impl FranksHoard {

    //// Opens a vault and returns an unlocked [`FranksHoard`] instance.
    ///
    /// If the vault file does not exist at the configured path, a new empty vault is created.
    /// If a new empty vault was created, it is not saved to disk.
    /// If the config file does not exist at the given path,
    /// a default config is created and saved to disk.
    ///
    /// # Arguments
    /// * `config_path` - Optional path to the config file. If `None`, the default config
    ///   path (`~/.config/frankshoard/config.toml`) is used.
    /// * `password` - The master password used to derive the encryption key.
    ///
    /// # Returns
    /// A fully unlocked [`FranksHoard`] instance with the vault decrypted in memory.
    ///
    /// # Errors
    /// Returns [`FranksHoardError`] if:
    /// * The config file exists but cannot be read or parsed
    /// * The vault file exists but cannot be read or decrypted
    /// * The master password is incorrect
    /// * An IO error occurs
    ///
    /// # Example
    /// ```no_run
    /// use zeroize::Zeroizing;
    /// let password = Zeroizing::new("my_master_password".to_string());
    /// let hoard = FranksHoard::open(None, &password)?;
    /// ```
    pub fn open(config_path: Option<PathBuf>, password: &Zeroizing<String>) -> Result<Self, FranksHoardError> {
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

        let mut vault_file;
        let master_key;
        let decrypted_vault;
        if config.vault_file().try_exists()? {
            vault_file = VaultFile::from_path(config.vault_file())?;
            master_key = MasterKey::from_password(password, vault_file.salt(), &config)?;
            decrypted_vault = DecryptedVault::from_ciphertext(&master_key, vault_file.nonce(), vault_file.ciphertext())?;
        } else {
            vault_file = VaultFile::build_new_vault(config.vault_file())?;
            master_key = MasterKey::from_password(password, vault_file.salt(), &config)?;
            decrypted_vault = DecryptedVault::new();
            vault_file.update_ciphertext(&decrypted_vault, &master_key)?;
        }

        let franks_hoard = FranksHoard {
            config,
            vault_file,
            decrypted_vault,
            master_key,
        };
        Ok(franks_hoard)
    }

    pub fn is_initialize(&self) -> Result<bool, FranksHoardError> {
        // If both decrypted_vault and master_key are None, then no password as been set.
        // If only one of the two is None, that's an unknown state
        if self.decrypted_vault.is_some() && self.master_key.is_some() {
            Ok(true)
        }
        else if self.decrypted_vault.is_none() && self.master_key.is_none() {
            return Ok(false);
        }
        else {
            Err(FranksHoardError::IllegalStateError(format!("Either decrypted_vault or master is None and the other is not.")))
        }
    }

    pub fn init_password(&mut self, password: &Zeroizing<String>) -> Result<(), FranksHoardError> {
        if self.is_initialize()? {
            return Err(FranksHoardError::MasterPasswordError(format!("Pasword already created.")));
        }

        self.master_key = Some(MasterKey::from_password(password, self.vault_file.salt(), &self.config)?);

        Ok(())
    }

    pub fn unlock_vault(&mut self, old_pwd: &Zeroizing<String>, new_pwd: &Zeroizing<String>) -> Result<(), FranksHoardError> {
        // TODO
        Ok(())
    }

    pub fn get_entries(&self) {
        // TODO
    }

    pub fn get_entry(&self, uuid: Uuid) -> Result<Entry, FranksHoardError> {
        Err(FranksHoardError::VaultNotFound)
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



//// TODO Refactor to this, basically
pub struct LockedHoard { config: Config, vault_file: VaultFile }
pub struct UnlockedHoard { config: Config, vault_file: VaultFile, master_key: MasterKey, decrypted_vault: DecryptedVault }

impl LockedHoard {
    pub fn unlock(self, password: &Zeroizing<String>) -> Result<UnlockedHoard, FranksHoardError> { ... }
}
