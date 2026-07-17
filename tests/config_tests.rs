#[cfg(test)]
mod hoard_test {
    use dirs::home_dir;

    use frankshoard::*; // Imports everything from the public API

    #[test]
    fn config_from_existing_file() {
        let config_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/test_data/config.toml");
        let result = Config::from_path(&config_path);
        assert!(result.is_ok(), "expected Ok but got {:?}", result);
        let config = result.unwrap();

        assert_eq!(config.argon2().memory(), 2097152);
        assert_eq!(config.argon2().iterations(), 3);
        assert_eq!(config.argon2().parallelism(), 1);

        // Make sure tilde expansion worked
        let home = home_dir().unwrap();
        assert_eq!(config.vault_file(), home.join(".frankshoard/test_vault.db"));

        assert_eq!(config.ui().session_timeout_seconds(), 300);
    }

    #[test]
    fn config_from_malformed_file() {
        let config_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/test_data/bad_config.toml");
        let err = Config::from_path(&config_path).unwrap_err();
        assert!(matches!(err, Error::TomlError(_)));
    }

    #[test]
    fn config_from_missing_file() {
        let config_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/test_data/no_such_file.toml");
        let err = Config::from_path(&config_path).unwrap_err();
        assert!(matches!(err, Error::Io(_)));
    }
}
