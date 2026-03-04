use dialoguer::Input;
use dialoguer::Password;
use dialoguer::Confirm;

use crate::error::AppError;
use crate::config;

pub fn run() -> Result<(), AppError> {
    // load conf
    let path_to_conf = config::Config::default_config_path()?;
    let conf = if path_to_conf.exists() {
        config::Config::load(&path_to_conf)?;
    } else {
        config::Config::from_default(true)?;
    };

    // create vault if not present

    Ok(())
}
