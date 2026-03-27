#[cfg(test)]
mod hoard_test {
    use tempfile::{tempdir, TempDir};
    use std::path::PathBuf;
    use zeroize::Zeroizing;
    use url::Url;

    use frankshoard::*;  // imports everything from the public api


    const VAULT_PASSWORD: &str = "q0w1e2r3t4y5u6i7o8p9a;s,d.f!g@h#j$k%lˆz&x*c(v)b-n_m=Q+W<E>R?T/Y\"U\\I|O[A]S{D}F~G`H'J KLZXCVBNM";

    /// Part of the kludge to test default file locations (see comments in config.rs).
    /// We use nextest to run test, so we should be ok using the usafe set_var()
    /// Note that this kludge also let us test on a system where the vault is already used without affecting the real vault.
    fn setup_default_paths() -> TempDir {
        let dir = tempdir().unwrap();
        unsafe {
            std::env::set_var("FRANKSHOARD_TEST_CONFIG_PATH", dir.path().join("config.toml"));
            std::env::set_var("FRANKSHOARD_TEST_VAULT_PATH", dir.path().join("vault.db"));
        }
        dir
    }

    // Create a empty vault at the given path. Intended to use with temp files
    fn create_test_empty_vault(path: PathBuf) {
        let locked_hoard = LockedHoard::new_hoard(Some(path)).unwrap();
        locked_hoard.unlock(Zeroizing::new(VAULT_PASSWORD.to_string())).unwrap().lock(true).unwrap();
    }

    // Create a vault at the given path and fill it with two entries of eacht type. Intended to use with temp files
    fn create_test_vault_with_entries(path: PathBuf) {
        let locked_hoard = LockedHoard::new_hoard(Some(path.clone())).unwrap();
        let mut unlocked_vault = locked_hoard.unlock(Zeroizing::new(VAULT_PASSWORD.to_string())).unwrap();

        let basic_password_entry_1 = Entry::BasicPassword(BasicPasswordEntry::new(
            Zeroizing::new("basic password 1".to_string()),
            Zeroizing::new("username".to_string()),
            Zeroizing::new("password".to_string())
        ).unwrap());
        let basic_password_entry_2 = Entry::BasicPassword(BasicPasswordEntry::new(
            Zeroizing::new("basic password 2".to_string()),
            Zeroizing::new("bob@bobby.com".to_string()),
            Zeroizing::new("akdnjlkd893eq".to_string())
        ).unwrap());

        let site_entry_without_note = Entry::Site(SiteEntry::new(
            Zeroizing::new("site entry 1".to_string()),
            Url::parse("https://github.com/Sickghost/frankshoard").unwrap(),
            Zeroizing::new("sickghost@theghost.com".to_string()),
            Zeroizing::new("Ghost?Passw0rd".to_string()),
            None
        ).unwrap());

        let site_entry_with_note = Entry::Site(SiteEntry::new(
            Zeroizing::new("site entry 2".to_string()),
            Url::parse("https://glamourousefarmlife.ca").unwrap(),
            Zeroizing::new("famrboy@farm.org".to_string()),
            Zeroizing::new("ILovePotatoe!!".to_string()),
            Some(Zeroizing::new("My Secret Question answer is: \"The Potatoe is Hot only During the Winter\"".to_string()))
        ).unwrap());

        let note_entry_1 = Entry::Note(NoteEntry::new(
            Zeroizing::new("note entry 1".to_string()),
            Zeroizing::new("Vas-y Astérix, tu court plus vite que le cheval qui souffle en tempête.".to_string())
        ).unwrap());

        let note_entry_2 = Entry::Note(NoteEntry::new(
            Zeroizing::new("note entry 2".to_string()),
            Zeroizing::new(
                "Lorem ipsum dolor sit amet, consectetur adipiscing elit, \
                 sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. \
                 Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris \
                 nisi ut aliquip ex ea commodo consequat.".to_string())
        ).unwrap());

        assert!(unlocked_vault.add_entry(basic_password_entry_1).is_ok());
        assert!(unlocked_vault.add_entry(basic_password_entry_2).is_ok());
        assert!(unlocked_vault.add_entry(site_entry_without_note).is_ok());
        assert!(unlocked_vault.add_entry(site_entry_with_note).is_ok());
        assert!(unlocked_vault.add_entry(note_entry_1).is_ok());
        assert!(unlocked_vault.add_entry(note_entry_2).is_ok());

        unlocked_vault.lock(true).unwrap();
    }

    #[test]
    fn open_exiting_locked_hoard_default_config() {
        let _dir = setup_default_paths();
        let config_path = PathBuf::from(std::env::var("FRANKSHOARD_TEST_CONFIG_PATH").unwrap());
        assert!(!config_path.exists());  // no config exists
        assert!(!PathBuf::from(std::env::var("FRANKSHOARD_TEST_VAULT_PATH").unwrap()).exists());
        create_test_empty_vault(config_path);

        let result = LockedHoard::load_hoard(None);
        assert!(result.is_ok(), "expected Ok but got {:?}", result);
        let locked_hoard = result.unwrap();

        let result = locked_hoard.unlock(Zeroizing::new(VAULT_PASSWORD.to_string()));
        assert!(result.is_ok(), "expected Ok but got {:?}", result);
        let unlocked_hoard = result.unwrap();
        assert!(unlocked_hoard.get_entries().len() == 0)
    }

    #[test]
    fn open_exiting_locked_hoard_custom_path() {

    }

    #[test]
    fn create_new_locked_hoard_default_path() {

    }

    #[test]
    fn create_new_locked_hoard_custom_path() {

    }
}
