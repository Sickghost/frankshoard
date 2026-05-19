mod config;
mod error;
mod vault;
mod crypto;
mod secretbuf;

use uuid::Uuid;
use zeroize::Zeroizing;

pub use crate::config::{Argon2Conf, UIConf, Config};
pub use crate::error::Error;
pub use crate::vault::{Entry, SiteEntry, NoteEntry, BasicPasswordEntry};

use crate::vault::{VaultFile, DecryptedVault, FromEntry};
use crate::crypto::MasterKey;

/// An encrypted in-memory representation of a frankshoard vault.
/// A 'LockedHoard` can be created empty, from a saved vault or from an `UnlockedHoard` after locking it.
#[derive(Debug)]
pub struct LockedHoard {
    config: Config,
    vault_file: VaultFile
}

impl LockedHoard {
    /// Load an existing vault from storage.
    ///
    /// # Arguments
    ///
    /// * `config` - An [`Config`] for the vault.
    ///
    /// # Returns
    ///
    /// Returns a [`LockedHoard`] loaded from storage.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] If there is an issue accessing the file system.
    /// Returns [`Error::VaultNotFound`] if the file cannot be found.
    /// Returns [`Error::MalformedVault`] if there was a problem deserializing the file pointed by the provided path.
    pub fn load_hoard(config: Config) -> Result<Self, Error> {
        let vault_file = VaultFile::from_path(config.vault_file())?;
        Ok(LockedHoard {
            config,
            vault_file,
        })
    }

    /// Creates a new empty vault.  Note that the vault file is persisted to
    /// storage as part of it's creation.
    ///
    /// # Security Warning
    ///
    /// To minimize risk of two new vault being created at the same time pointing to the same path, this function should never be called
    /// from different threads at the same time or a race condition could occur.  This almost certainly would lead to vault corruption.
    ///
    /// # Arguments
    ///
    /// * `config` - An [`Config`] for the vault.
    /// * `password` - The new master password for this vault.
    ///
    /// # Returns
    ///
    /// Returns a new empty [`LockedHoard`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::VaultAlreadyExists`] if a vault file already exists at the configured path.
    /// Returns [`Error::Io`] If there is an issue reading the vault file
    pub fn new_hoard(config: Config, password: Zeroizing<String>) -> Result<Self, Error> {
        if config.vault_file().try_exists()? {
            return Err(Error::VaultAlreadyExists);
        }

        let vault_file = VaultFile::build_new_vault(config.vault_file())?;
        let mut locked_hoard = LockedHoard {
            config,
            vault_file,
        };
        let master_key = MasterKey::from_password(&password, &locked_hoard.vault_file.salt(), &locked_hoard.config)?;
        locked_hoard.vault_file.update_ciphertext(&DecryptedVault::default(), &master_key)?;
        locked_hoard.vault_file.save(locked_hoard.config.vault_file())?;
        Ok(locked_hoard)
    }

    /// Unlocks this vault and returns a [`UnlockedHoard`], which contains all decrypted entries in memory.
    ///
    /// # Arguments
    ///
    /// * `password` - The master password for this vault.
    ///
    /// # Returns
    ///
    /// Returns a [`UnlockedHoard`] with an with all entries decrypted.  Note the return vault was NOT saved to storage.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BinarySerdeError`] if there was a problem deserializing the vault entries after decrytion.
    /// Returns [`Error::Encryption`] if there was a problem deriving the master key from the password or decrypting the vault.
    pub fn unlock(self, password: Zeroizing<String>) -> Result<UnlockedHoard, Error> {
        UnlockedHoard::unlock(self, &password)
    }

    /// Decrypt the vault with the `password` and then re-encrypted it using `new_password` and a new salt before persisting it to
    /// storage again.
    ///
    /// # Arguments
    ///
    /// * `password` - The master password of the vault
    /// * `new_password` - The new master password to use with this vault.
    ///
    /// # Errors
    ///
    /// Note that on any error, the vault state is preserve to what it was prior to the call.
    ///
    /// Returns [`Error::BinarySerdeError`] if there was a problem deserializing or serializing the vault entries during encryption/decrytion.
    /// Returns [`Error::Encryption`] if there was a problem deriving the master key from the password or decrypting/encrypting the vault.
    /// Returns [`Error::Io`] if there is an issue persisting the vault  to storage.
    pub fn change_password(&mut self, password: Zeroizing<String>, new_password: Zeroizing<String>) -> Result<(), Error> {
        let snapshot = self.vault_file.clone();

        // Making it "atomic"
        let result = ( || -> Result<(), Error> {
            let master_key = MasterKey::from_password(&password, self.vault_file.salt(), &self.config)?;
            let decrypted_vault = DecryptedVault::from_ciphertext(&master_key, self.vault_file.nonce(), self.vault_file.ciphertext())?;

            self.vault_file.update_salt();
            let new_master_key = MasterKey::from_password(&new_password, self.vault_file.salt(), &self.config)?;
            self.vault_file.update_ciphertext(&decrypted_vault, &new_master_key)?;
            self.vault_file.save(self.config.vault_file())
        })();

        if result.is_err() {
            self.vault_file = snapshot;
        }
        result
    }
}

/// A decrypted in-memory representation of a frankshoard vault.
///
/// `UnlockedHoard` is created from a `LockedHoard`.
///
/// # Security Warning
///
/// This struct contains the [`MasterKey`] and plaintext data. It should be dropped or converted back
/// into a [`LockedHoard`] as soon as operations are complete to minimize the window of time sensitive
/// data resides in memory.
#[derive(Debug)]
pub struct UnlockedHoard {
    config: Config,
    vault_file: VaultFile,
    master_key: MasterKey,
    decrypted_vault: DecryptedVault
}

impl UnlockedHoard {
    /// This unlocks the vault, decrypting all entries in memory.  This method consumes the `LockedHoard` to force the state change.
    ///
    /// # Arguments
    ///
    /// * `locked_hoard` - A `LockedHoard` containing the encrypted representation of the vault.
    /// * `password` - The master password for the vault.
    ///
    /// # Returns
    ///
    /// Returns a [`UnlockedHoard`] with an with all entries decrypted.  Note the return vault was NOT saved to storage.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BinarySerdeError`] if there was a problem deserializing the vault entries after decrytion.
    /// Returns [`Error::Encryption`] if there was a problem deriving the master key from the password or decrypting the vault.
    fn unlock(locked_hoard: LockedHoard, password: &Zeroizing<String>) -> Result<Self, Error> {
        let master_key = MasterKey::from_password(password, &locked_hoard.vault_file.salt(), &locked_hoard.config)?;
        let decrypted_vault = DecryptedVault::from_ciphertext(&master_key, &locked_hoard.vault_file.nonce(), &locked_hoard.vault_file.ciphertext())?;

        Ok(UnlockedHoard {
            config: locked_hoard.config,
            vault_file: locked_hoard.vault_file,
            decrypted_vault,
            master_key,
        })
    }

    /// This locks the vault, encrypts any changes and returns a LockedHoard Object.
    /// Importantly, this does NOT persist the changes to file.  The intent of this method is to
    /// wipe sensitive data from memory while maintaining a reference to the LockedVault.  It's intended
    /// for use after read operations. This method consumes the `UnlockedHoard` to force the state change,
    /// also forcing sensitive data to be zeroed out.
    /// See also [`lock_and_save`]
    ///
    /// # Returns
    ///
    /// Returns a [`LockedHoard`] with an updated ciphertext.  Note the return vault was NOT saved to storage.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BinarySerdeError`] if there was a problem serializing the vault entries before encryption.
    /// Returns [`Error::Encryption`] if there was a problem encrypting the vault.
    pub fn lock_in_mem(mut self) -> Result<LockedHoard, Error>{
        self.vault_file.update_ciphertext(&self.decrypted_vault, &self.master_key)?;
        Ok(LockedHoard {
            config: self.config,
            vault_file: self.vault_file,
        })
    }

    /// This locks the vault, encrypts any changes and returns a LockedHoard Object.
    /// The vault is also persisted to storage.  This method consumes the `UnlockedHoard`
    /// to force the state change, also forcing sensitive data to be zeroed out.
    /// See also [`lock_in_mem`]
    ///
    /// # Returns
    ///
    /// Returns a [`LockedHoard`] with an updated ciphertext.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BinarySerdeError`] if there was a problem serializing the vault entries before encryption.
    /// Returns [`Error::Encryption`] if there was a problem encrypting the vault.
    /// Returns [`Error::Io`] if there is a problem writing file to storage.
    pub fn lock_and_save(mut self) -> Result<LockedHoard, Error>{
        self.vault_file.update_ciphertext(&self.decrypted_vault, &self.master_key)?;
        self.vault_file.save(self.config.vault_file())?;

        Ok(LockedHoard {
            config: self.config,
            vault_file: self.vault_file,
        })
    }

    /// Add an entry to the vault
    ///
    /// # Arguments
    ///
    /// * `entry` - The new entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EntryAlreadyExists`] if an entry with the same uuid already exists.
    pub fn add_entry(&mut self, entry: Entry) -> Result<(), Error> {
        self.decrypted_vault.add_entry(entry)
    }

    /// Returns an slice containing all the entries contained in this vault.  No guarantee is made on the
    /// ordering of this slice from call to call.
    ///
    /// # Returns
    ///
    /// Returns an immutable slice of [`Entry`] containing all the the entries stored in the vault.
    pub fn get_entries(&self) -> &[Entry] {
        self.decrypted_vault.get_entries()
    }

    /// Returns an iterator over all entries of a specific type that implements [`FromEntry`].  Concretly
    /// this means any one of the type used as a field to the [`Entry`] enum variants.  (aka [`SiteEntry`],
    /// [`NoteEntry`] or [`BasicPasswordEntry`])
    ///
    /// Thus this method allows you to filter the vault for one specific entry variant (e.g., only `Note` or
    /// only `Site`) and automatically maps them to the requested type `T`.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The target type that implements [`FromEntry`].
    ///
    /// # Returns
    ///
    /// An iterator over all entries of the specific type.
    ///
    ///
    pub fn get_entries_of<'a, T: FromEntry + 'a>(&'a self) -> impl Iterator<Item = &'a T> + 'a {
        self.decrypted_vault.get_entries_of::<T>()
    }

    /// Returns a reference to an entry.
    ///
    /// # Arguments
    ///
    /// * `uuid` - The uuid of the entry to retrive.
    ///
    /// # Returns
    ///
    /// * `Some(&Entry)` - A reference to the entry if a match is found.
    /// * `None` - If no entry exists with the provided `uuid`.
    pub fn get_entry(&self, uuid: Uuid) -> Option<&Entry> {
        self.decrypted_vault.get_entry(uuid)
    }

    /// Removes an entry from the vault.
    ///
    /// # Arguments
    ///
    /// * `uuid` - The uuid of the entry to remove.
    ///
    /// # Returns
    ///
    /// * `Some(Entry)` -The entry that was removed if a match is found.
    /// * `None` - If no entry exists with the provided `uuid`.
    pub fn remove_entry(&mut self, uuid: Uuid) -> Option<Entry> {
        self.decrypted_vault.remove_entry(uuid)
    }
}
