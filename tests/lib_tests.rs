#[cfg(test)]
mod hoard_test {
    use tempfile::{TempDir, tempdir};
    use url::Url;
    use uuid::Uuid;
    use zeroize::Zeroizing;

    use frankshoard::*; // Imports everything from the public API

    const MASTER_PASSWORD: &str = "q0w1e2r3t4y5u6i7o8p9a;s,d.f!g@h#j$k%lˆz&x*c(v)b-n_m=Q+W<E>R?T/Y\"U\\I|O[A]S{D}F~G`H'J KLZXCVBNM";
    const NEW_MASTER_PASSWORD: &str = "somepassword";
    const WRONG_PASSWORD: &str = "ThisIsAlwaysTheWrongPassword";
    const DEFAULT_VAULT_PATH: &str = ".frankshoard/vault.db";

    fn create_test_config(vault_dir: &TempDir) -> Config {
        let vault_file_path = vault_dir.path().join(DEFAULT_VAULT_PATH);
        let default_argon2 = Argon2Conf::new(2048, 3, 1);
        let default_uiconf = UIConf::new(300);
        Config::new(vault_file_path, default_argon2, default_uiconf).unwrap()
    }

    fn create_test_empty_vault(vault_dir: &TempDir) {
        LockedHoard::new_hoard(
            create_test_config(vault_dir),
            Zeroizing::new(MASTER_PASSWORD.to_string()),
        )
        .unwrap();
    }

    fn create_test_vault_with_entries(vault_dir: &TempDir) -> [Uuid; 6] {
        let locked_hoard = LockedHoard::new_hoard(
            create_test_config(vault_dir),
            Zeroizing::new(MASTER_PASSWORD.to_string()),
        )
        .unwrap();
        let mut unlocked_vault = locked_hoard
            .unlock(Zeroizing::new(MASTER_PASSWORD.to_string()))
            .unwrap();

        let basic_password_entry_1 = Entry::BasicPassword(
            BasicPasswordEntry::new(
                Zeroizing::new("basic password 1".to_string()),
                Zeroizing::new("username".to_string()),
                Zeroizing::new("password".to_string()),
            )
            .unwrap(),
        );
        let basic_password_entry_2 = Entry::BasicPassword(
            BasicPasswordEntry::new(
                Zeroizing::new("basic password 2".to_string()),
                Zeroizing::new("bob@bobby.com".to_string()),
                Zeroizing::new("akdnjlkd893eq".to_string()),
            )
            .unwrap(),
        );

        let site_entry_without_note = Entry::Site(
            SiteEntry::new(
                Zeroizing::new("site entry 1".to_string()),
                Url::parse("https://github.com/Sickghost/frankshoard").unwrap(),
                Zeroizing::new("sickghost@theghost.com".to_string()),
                Zeroizing::new("Ghost?Passw0rd".to_string()),
                None,
            )
            .unwrap(),
        );

        let site_entry_with_note = Entry::Site(
            SiteEntry::new(
                Zeroizing::new("site entry 2".to_string()),
                Url::parse("https://glamourousefarmlife.ca").unwrap(),
                Zeroizing::new("famrboy@farm.org".to_string()),
                Zeroizing::new("ILovePotatoe!!".to_string()),
                Some(Zeroizing::new(
                    "My Secret Question answer is: \"The Potatoe is Hot only During the Winter\""
                        .to_string(),
                )),
            )
            .unwrap(),
        );

        let note_entry_1 = Entry::Note(
            NoteEntry::new(
                Zeroizing::new("note entry 1".to_string()),
                Zeroizing::new(
                    "Vas-y Astérix, tu court plus vite que le cheval qui souffle en tempête."
                        .to_string(),
                ),
            )
            .unwrap(),
        );

        let note_entry_2 = Entry::Note(
            NoteEntry::new(
                Zeroizing::new("note entry 2".to_string()),
                Zeroizing::new(
                    "Lorem ipsum dolor sit amet, consectetur adipiscing elit, \
                 sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. \
                 Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris \
                 nisi ut aliquip ex ea commodo consequat."
                        .to_string(),
                ),
            )
            .unwrap(),
        );

        let bp_1_id: Uuid = basic_password_entry_1.id();
        assert!(unlocked_vault.add_entry(basic_password_entry_1).is_ok());
        let bp_2_id: Uuid = basic_password_entry_2.id();
        assert!(unlocked_vault.add_entry(basic_password_entry_2).is_ok());
        let se_1_id: Uuid = site_entry_without_note.id();
        assert!(unlocked_vault.add_entry(site_entry_without_note).is_ok());
        let se_2_id: Uuid = site_entry_with_note.id();
        assert!(unlocked_vault.add_entry(site_entry_with_note).is_ok());
        let ne_1_id: Uuid = note_entry_1.id();
        assert!(unlocked_vault.add_entry(note_entry_1).is_ok());
        let ne_2_id: Uuid = note_entry_2.id();
        assert!(unlocked_vault.add_entry(note_entry_2).is_ok());

        unlocked_vault.lock_and_save().unwrap();
        [bp_1_id, bp_2_id, se_1_id, se_2_id, ne_1_id, ne_2_id]
    }

    fn get_empty_hoard(vault_dir: &TempDir) -> LockedHoard {
        create_test_empty_vault(&vault_dir);

        let config = create_test_config(&vault_dir);
        let result = LockedHoard::load_hoard(config);
        assert!(result.is_ok(), "expected Ok but got {:?}", result);
        result.unwrap()
    }

    fn get_empty_unlocked_hoard(vault_dir: &TempDir) -> UnlockedHoard {
        let locked_hoard = get_empty_hoard(&vault_dir);
        let result = locked_hoard.unlock(Zeroizing::new(MASTER_PASSWORD.to_string()));
        assert!(result.is_ok(), "expected Ok but got {:?}", result);
        result.unwrap()
    }

    fn get_filled_hoard(vault_dir: &TempDir) -> (LockedHoard, [Uuid; 6]) {
        let uuids = create_test_vault_with_entries(&vault_dir);
        let config = create_test_config(&vault_dir);

        let result = LockedHoard::load_hoard(config);
        assert!(result.is_ok(), "expected Ok but got {:?}", result);
        (result.unwrap(), uuids)
    }

    fn get_filled_unlocked_hoard(vault_dir: &TempDir) -> (UnlockedHoard, [Uuid; 6]) {
        let (locked_hoard, uuids) = get_filled_hoard(&vault_dir);
        let result = locked_hoard.unlock(Zeroizing::new(MASTER_PASSWORD.to_string()));
        assert!(result.is_ok(), "expected Ok but got {:?}", result);
        (result.unwrap(), uuids)
    }

    #[test]
    fn create_new_empty_hoard() {
        let vault_dir = tempdir().unwrap();
        let config = create_test_config(&vault_dir);

        let result = LockedHoard::new_hoard(config, Zeroizing::new(MASTER_PASSWORD.to_string()));
        assert!(result.is_ok(), "expected Ok but got {:?}", result);

        // vault file should exist on disk
        assert!(vault_dir.path().join(DEFAULT_VAULT_PATH).exists());
    }

    #[test]
    fn open_hoard_wrong_path() {
        let vault_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/test_data/no_such_vault.db");
        let config =
            Config::new(vault_path, Argon2Conf::new(2048, 3, 1), UIConf::new(300)).unwrap();

        let err = LockedHoard::load_hoard(config).unwrap_err();
        assert!(matches!(err, Error::VaultNotFound));
    }

    /// TODO:  We need new test, temporarily fix this one so I can commit
    /// Note that right now, because of the implementation, this would only trigger on a vault that is less than 44 bytes
    /// long (the salt + nonce). Anything else will deserialize. Aes-gcm will later complain if the entries have been tempered
    /// with. Only exception is if someone edited the vault and truncated it to only leave the salt and nonce. Then it will decrypt
    /// as an empty vault.
    #[test]
    fn unlock_hoard_malformed_vault() {
        let vault_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/test_data/malformed_vault.db");
        let config =
            Config::new(vault_path, Argon2Conf::new(195300, 3, 1), UIConf::new(300)).unwrap();

        let err = LockedHoard::load_hoard(config).unwrap_err();
        assert!(matches!(err, Error::InvalidFormat));
    }

    #[test]
    fn create_new_hoard_fails_if_already_exists() {
        let vault_dir = tempdir().unwrap();
        create_test_empty_vault(&vault_dir);

        let config = create_test_config(&vault_dir);
        let result = LockedHoard::new_hoard(config, Zeroizing::new(MASTER_PASSWORD.to_string()));
        assert!(matches!(result, Err(Error::VaultAlreadyExists)));
    }

    #[test]
    fn open_exiting_empty_locked_hoard() {
        let vault_dir = tempdir().unwrap();
        let locked_hoard = get_empty_hoard(&vault_dir);

        let result = locked_hoard.unlock(Zeroizing::new(MASTER_PASSWORD.to_string()));
        assert!(result.is_ok(), "expected Ok but got {:?}", result);
        let unlocked_hoard = result.unwrap();
        assert!(unlocked_hoard.get_entries().len() == 0)
    }

    #[test]
    fn open_exiting_filled_locked_hoard() {
        let vault_dir = tempdir().unwrap();
        let (locked_hoard, _) = get_filled_hoard(&vault_dir);

        let result = locked_hoard.unlock(Zeroizing::new(MASTER_PASSWORD.to_string()));
        assert!(result.is_ok(), "expected Ok but got {:?}", result);
        let unlocked_hoard = result.unwrap();
        assert!(unlocked_hoard.get_entries().len() == 6);
    }

    #[test]
    fn unlock_hoard_wrong_password() {
        let vault_dir = tempdir().unwrap();
        let locked_hoard = get_empty_hoard(&vault_dir);

        let err = locked_hoard
            .unlock(Zeroizing::new(WRONG_PASSWORD.to_string()))
            .unwrap_err();
        assert!(matches!(err, Error::Encryption(_)));
    }

    #[test]
    fn change_password_empty_hoard() {
        let vault_dir = tempdir().unwrap();

        let mut locked_hoard = LockedHoard::new_hoard(
            create_test_config(&vault_dir),
            Zeroizing::new(MASTER_PASSWORD.to_string()),
        )
        .unwrap();
        let result = locked_hoard.change_password(
            Zeroizing::new(MASTER_PASSWORD.to_string()),
            Zeroizing::new(NEW_MASTER_PASSWORD.to_string()),
        );
        assert!(result.is_ok(), "expected Ok but got {:?}", result);

        let test_new_pwd_result =
            locked_hoard.unlock(Zeroizing::new(NEW_MASTER_PASSWORD.to_string()));
        assert!(
            test_new_pwd_result.is_ok(),
            "expected Ok but got {:?}",
            result
        );
    }

    #[test]
    fn change_password_filled_hoard() {
        let vault_dir = tempdir().unwrap();
        let (mut locked_hoard, _) = get_filled_hoard(&vault_dir);
        let result = locked_hoard.change_password(
            Zeroizing::new(MASTER_PASSWORD.to_string()),
            Zeroizing::new(NEW_MASTER_PASSWORD.to_string()),
        );
        assert!(result.is_ok(), "expected Ok but got {:?}", result);

        let test_new_pwd_result =
            locked_hoard.unlock(Zeroizing::new(NEW_MASTER_PASSWORD.to_string()));
        assert!(
            test_new_pwd_result.is_ok(),
            "expected Ok but got {:?}",
            result
        );
    }

    #[test]
    fn change_password_wrong_password() {
        let vault_dir = tempdir().unwrap();

        let mut locked_hoard = LockedHoard::new_hoard(
            create_test_config(&vault_dir),
            Zeroizing::new(MASTER_PASSWORD.to_string()),
        )
        .unwrap();
        let err = locked_hoard
            .change_password(
                Zeroizing::new(WRONG_PASSWORD.to_string()),
                Zeroizing::new(NEW_MASTER_PASSWORD.to_string()),
            )
            .unwrap_err();
        assert!(matches!(err, Error::Encryption(_)));
    }

    #[test]
    fn get_entries() {
        let vault_dir = tempdir().unwrap();
        let (unlocked_hoard, uuids) = get_filled_unlocked_hoard(&vault_dir);

        let entries = unlocked_hoard.get_entries();
        assert!(entries.len() == 6);

        // Note: this series of assertion work because no delete occurs before. If that was to change,
        // the test would break because deleting entries will change the internal ordering of the vault.
        assert_eq!(entries[0].id(), uuids[0]);
        assert_eq!(entries[1].id(), uuids[1]);
        assert_eq!(entries[2].id(), uuids[2]);
        assert_eq!(entries[3].id(), uuids[3]);
        assert_eq!(entries[4].id(), uuids[4]);
        assert_eq!(entries[5].id(), uuids[5]);
    }

    #[test]
    fn get_entries_of() {
        let vault_dir = tempdir().unwrap();
        let (unlocked_hoard, uuids) = get_filled_unlocked_hoard(&vault_dir);

        let mut bp_itr = unlocked_hoard.get_entries_of::<BasicPasswordEntry>();
        assert_eq!(bp_itr.next().unwrap().id(), uuids[0]);
        assert_eq!(bp_itr.next().unwrap().id(), uuids[1]);
        assert!(bp_itr.next().is_none());

        let mut site_itr = unlocked_hoard.get_entries_of::<SiteEntry>();
        assert_eq!(site_itr.next().unwrap().id(), uuids[2]);
        assert_eq!(site_itr.next().unwrap().id(), uuids[3]);
        assert!(site_itr.next().is_none());

        let mut note_itr = unlocked_hoard.get_entries_of::<NoteEntry>();
        assert_eq!(note_itr.next().unwrap().id(), uuids[4]);
        assert_eq!(note_itr.next().unwrap().id(), uuids[5]);
        assert!(note_itr.next().is_none());
    }

    #[test]
    fn add_entry_lock_in_mem() {
        let vault_dir = tempdir().unwrap();
        let locked_hoard = LockedHoard::new_hoard(
            create_test_config(&vault_dir),
            Zeroizing::new(MASTER_PASSWORD.to_string()),
        )
        .unwrap();
        let mut unlocked_hoard = locked_hoard
            .unlock(Zeroizing::new(MASTER_PASSWORD.to_string()))
            .unwrap();

        let basic_password_entry = Entry::BasicPassword(
            BasicPasswordEntry::new(
                Zeroizing::new("This Is The Vault Password".to_string()),
                Zeroizing::new("Bubba Hotep".to_string()),
                Zeroizing::new("secret123#!".to_string()),
            )
            .unwrap(),
        );
        let result = unlocked_hoard.add_entry(basic_password_entry);
        assert!(result.is_ok(), "expected Ok but got {:?}", result);
        let lock_result = unlocked_hoard.lock_in_mem();
        assert!(lock_result.is_ok(), "expected Ok but got {:?}", result);

        // Only saved in memory so loading it from storage should not have the entry in it.
        let locked_hoard_reloaded =
            LockedHoard::load_hoard(create_test_config(&vault_dir)).unwrap();
        let unlocked_hoard_reloaded = locked_hoard_reloaded
            .unlock(Zeroizing::new(MASTER_PASSWORD.to_string()))
            .unwrap();
        assert_eq!(unlocked_hoard_reloaded.get_entries().len(), 0);
    }

    #[test]
    fn add_entry_lock_and_save() {
        let vault_dir = tempdir().unwrap();
        let locked_hoard = LockedHoard::new_hoard(
            create_test_config(&vault_dir),
            Zeroizing::new(MASTER_PASSWORD.to_string()),
        )
        .unwrap();
        let mut unlocked_hoard = locked_hoard
            .unlock(Zeroizing::new(MASTER_PASSWORD.to_string()))
            .unwrap();

        let basic_password_entry = Entry::BasicPassword(
            BasicPasswordEntry::new(
                Zeroizing::new("This Is The Vault Password".to_string()),
                Zeroizing::new("Bubba Hotep".to_string()),
                Zeroizing::new("secret123#!".to_string()),
            )
            .unwrap(),
        );

        let result = unlocked_hoard.add_entry(basic_password_entry);
        assert!(result.is_ok(), "expected Ok but got {:?}", result);
        let lock_result = unlocked_hoard.lock_and_save();
        assert!(lock_result.is_ok(), "expected Ok but got {:?}", result);

        // check data was saved
        let locked_hoard_reloaded =
            LockedHoard::load_hoard(create_test_config(&vault_dir)).unwrap();
        let unlocked_hoard_reloaded = locked_hoard_reloaded
            .unlock(Zeroizing::new(MASTER_PASSWORD.to_string()))
            .unwrap();
        assert_eq!(unlocked_hoard_reloaded.get_entries().len(), 1);
    }

    #[test]
    fn delete_entry() {
        let vault_dir = tempdir().unwrap();
        let (mut unlocked_hoard, _) = get_filled_unlocked_hoard(&vault_dir);

        // After deleting, the vault makes no guarantee on order of the entries, so we get ALL uuids
        // first and will delete after.
        let uuids: Vec<Uuid> = unlocked_hoard
            .get_entries()
            .iter()
            .map(|e| e.id())
            .collect();

        for id in uuids {
            let option = unlocked_hoard.remove_entry(id);
            assert!(option.is_some(), "expected Some(Entry) but got None");
            assert_eq!(option.unwrap().id(), id);
        }
        assert!(unlocked_hoard.get_entries().len() == 0)
    }

    #[test]
    fn delete_entry_not_found() {
        let vault_dir = tempdir().unwrap();
        let (mut unlocked_hoard, _) = get_filled_unlocked_hoard(&vault_dir);

        let option = unlocked_hoard.remove_entry(Uuid::new_v4());
        assert!(option.is_none(), "expected None but got {:?}", option);
    }
}
