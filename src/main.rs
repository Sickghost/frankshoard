use dirs::home_dir;
use clap::{Parser,Subcommand};
use dialoguer::{Input, Password};
use uuid::Uuid;
use zeroize::Zeroizing;
use std::path::PathBuf;
use url::Url;

use frankshoard::{BasicPasswordEntry, Config, Argon2Conf, UIConf, Entry, LockedHoard, NoteEntry, SiteEntry, UnlockedHoard, Error};

const DEFAULT_CONFIG_PATH: &str = ".config/frankshoard/config.toml";
const DEFAULT_VAULT_PATH: &str = ".frankshoard/vault.db";
const DEFAULT_ARGON2_MEMORY: u32 = 2097152;
const DEFAULT_ARGON2_ITR: u32 = 3;
const DEFAULT_ARGON2_PARA: u32 = 1;
const DEFAULT_UI_SESSION_TIMEOUT_SEC: u32 = 300;

#[derive(Parser)]
#[command(name = "frankshoard")]
#[command(about = "A secure password manager used to store secrets (password and notes) along with related data.")]
struct Cli {
    /// Path to the configuration file.  If not provided, will look for a configuration file in `~/.config/frankshoard/config.toml`.  If none
    /// is found there, a config file with default values will be created there.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Supress all printouts beside essential outputs.  Uuids of entries still get printed out to enble scripting
    #[arg(short, long)]
    silent: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Creates a new vault at the path provided by the config.  Will fail if the file already exists.
    Init,

    /// Add and entry to the vault.  Always prints the id of the new entry for future reference.
    Add {
        #[command(subcommand)]
        entry_type: AddCommands,
    },

    /// List content (excluding secrets) of all entries stored in the vault.
    ListAll,

    /// List content (excluding secrets) of all entries of a given type stored in the vault.
    List {
        #[command(subcommand)]
        entry_type: ListCommands,
    },

    /// Remove the given entry from the vault.
    Remove {
        #[arg(long)]
        id: Uuid,
    },

    /// Prints the given entry (except sercrets)
    Entry{
        #[arg(long)]
        id: Uuid,
    },

    /// Prints username field of the given entry (if exists)
    EntryUsername{
        #[arg(long)]
        id: Uuid,
    },

    /// Prints password field of the given entry (if exists)
    EntryPassword{
        #[arg(long)]
        id: Uuid,
    },

    /// Prints note field of the given entry (if exists)
    EntryNote{
        #[arg(long)]
        id: Uuid,
    },

    /// Change the master password of the vault.
    ChangeMasterPassword,
}

#[derive(Subcommand, Debug)]
enum AddCommands {
    BasicPassword {
        /// A name for the entry
        #[arg(long)]
        entry_name: Zeroizing<String>,

        /// The username for this set of credentials
        #[arg(long)]
        username: Zeroizing<String>,
    },
    Site {
        /// A name for the entry
        #[arg(long)]
        entry_name: Zeroizing<String>,

        /// The url to the site associated with this credential
        #[arg(long)]
        url: Url,

        /// The username for this set of credentials
        #[arg(long)]
        username: Zeroizing<String>,

        /// A secret note (optional)
        #[arg(long)]
        note: Option<Zeroizing<String>>,
    },
    Note {
        /// A name for the entry
        #[arg(long)]
        entry_name: Zeroizing<String>,

        /// A secret note
        #[arg(long)]
        note: Option<Zeroizing<String>>,
    },
}

#[derive(Subcommand, Debug)]
enum ListCommands {
    BasicPassword,
    Site,
    Note,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let silent = cli.silent;
    let config = build_config(cli.config)?;
    if let Commands::Init = cli.command {
        return init(config, silent);
    }

    let locked_hoard = LockedHoard::load_hoard(config)?;
    if let Commands::ChangeMasterPassword = cli.command {
        return change_master_password(locked_hoard, silent);
    }

    let password = Zeroizing::new(
        Password::new()
            .with_prompt("Master password")
            .interact()?
    );

    if !silent {
        println!("Unlocking vault...");
    }
    let unlocked_hoard = locked_hoard.unlock(password)?;

    match cli.command {
        Commands::Init => unreachable!(),
        Commands::ChangeMasterPassword => unreachable!(),
        Commands::Add {entry_type} => add(unlocked_hoard, entry_type, silent),
        Commands::ListAll => list_all(unlocked_hoard, silent),
        Commands::List {entry_type} => list(unlocked_hoard, entry_type, silent),
        Commands::Remove { id } => remove(unlocked_hoard, id, silent),
        Commands::Entry { id } => entry(unlocked_hoard, id, silent),
        Commands::EntryUsername { id } => entry_username(unlocked_hoard, id, silent),
        Commands::EntryPassword { id } => entry_password(unlocked_hoard, id, silent),
        Commands::EntryNote { id } => entry_note(unlocked_hoard, id, silent),
    }
}

fn init(config: Config, silent: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Ask for password
    if !silent {
        println!("A new vault needs a master password.  Chose it and record it safely and carefully, if you lose your master password, there is no way to retrieve it.");
    }
    let password = Zeroizing::new(
        Password::new()
            .with_prompt("Enter Master password")
            .with_confirmation("Confirm password", "Passwords do not match")
            .interact()?
    );

    if !silent {
        println!("Creating master key and generating vault...");
    }
    LockedHoard::new_hoard(config, password)?;
    if !silent {
        println!("New vault created.");
    }
    Ok(())
}

fn change_master_password(mut locked_hoard: LockedHoard, silent: bool) -> Result<(), Box<dyn std::error::Error>> {
    let password = Zeroizing::new(
        Password::new()
            .with_prompt("Enter Current Master password")
            .interact()?
    );

    let new_password = Zeroizing::new(
        Password::new()
            .with_prompt("Enter New Master password")
            .with_confirmation("Confirm password", "Passwords do not match")
            .interact()?
    );
    locked_hoard.change_password(password, new_password)?;
    if !silent {
        println!("Password changed successfully.");
    }
    Ok(())
}

fn add(mut unlocked_hoard: UnlockedHoard, entry_type: AddCommands, silent: bool) -> Result<(), Box<dyn std::error::Error>> {

    match entry_type {
        AddCommands::BasicPassword { entry_name, username } => {
            // Ask for password
            let password = Zeroizing::new(Password::new()
                .with_prompt("Please enter password for new entry")
                .with_confirmation("Confirm password", "Passwords do not match")
                .interact()?);

            let entry = Entry::BasicPassword(BasicPasswordEntry::new(entry_name, username, password)?);
            println!("{}", entry.id());
            unlocked_hoard.add_entry(entry)?;
        },
        AddCommands::Site {entry_name, url, username, note} => {
            // Ask for password
            let password = Zeroizing::new(Password::new()
                .with_prompt("Please enter password for new entry")
                .with_confirmation("Confirm password", "Passwords do not match")
                .interact()?);

            let entry = Entry::Site(SiteEntry::new(entry_name, url, username, password, note)?);
            println!("{}", entry.id());
            unlocked_hoard.add_entry(entry)?;
        },
        AddCommands::Note{entry_name, note} => {
            let note_string = match note {
                Some(n) => n,
                None => Zeroizing::new(Input::new()
                    .with_prompt("Please enter your secret note: ")
                    .interact_text()?),
            };
            let entry = Entry::Note(NoteEntry::new(entry_name, note_string)?);
            println!("{}", entry.id());
            unlocked_hoard.add_entry(entry)?;
        },
    }
    if !silent {
        println!("Saving new entry...");
    }
    unlocked_hoard.lock_and_save()?;
    if !silent {
        println!("Entry saved.");
    }
    Ok(())
}

fn list_all(unlocked_hoard: UnlockedHoard, silent: bool) -> Result<(), Box<dyn std::error::Error>> {
    if !silent {
        println!("Printing all entries...")
    }
    let entries = unlocked_hoard.get_entries();
    for entry in entries {
        println!("{}", entry);
    }
    if !silent {
        println!("Done.");
    }
    unlocked_hoard.lock_in_mem()?;
    Ok(())
}

fn list(unlocked_hoard: UnlockedHoard, entry_type: ListCommands, silent: bool) -> Result<(), Box<dyn std::error::Error>> {
    match entry_type {
        ListCommands::BasicPassword => {
            if !silent {
                println!("Printing Basic Password List...");
            }
            for entry in unlocked_hoard.get_entries_of::<BasicPasswordEntry>() {
                println!("{}", entry);
            }
        },
        ListCommands::Site => {
            if !silent {
                println!("Printing Site List...");
            }
            for entry in unlocked_hoard.get_entries_of::<SiteEntry>() {
                println!("{}", entry);
            }
        },
        ListCommands::Note => {
            if !silent {
                println!("Printing Note List...");
            }
            for entry in unlocked_hoard.get_entries_of::<NoteEntry>() {
                println!("{}", entry);
            }
        },
    }
    if !silent {
        println!("Done.");
    }
    unlocked_hoard.lock_in_mem()?;
    Ok(())
}

fn remove(mut unlocked_hoard: UnlockedHoard, uuid: Uuid, silent: bool) -> Result<(), Box<dyn std::error::Error>> {
    let Some(..) = unlocked_hoard.remove_entry(uuid) else {
        if !silent {
            println!("Entry not found: {}", uuid)
        }
        return Ok(());
    };
    unlocked_hoard.lock_and_save()?;
    Ok(())
}

fn entry(unlocked_hoard: UnlockedHoard, uuid: Uuid, silent: bool) -> Result<(), Box<dyn std::error::Error>> {
    let Some(entry) = unlocked_hoard.get_entry(uuid) else {
        if !silent {
            println!("Entry not found: {}", uuid)
        }
        return Ok(())
    };
    println!("{}", entry);
    unlocked_hoard.lock_in_mem()?;
    Ok(())
}

fn entry_username(unlocked_hoard: UnlockedHoard, uuid: Uuid, silent: bool) -> Result<(), Box<dyn std::error::Error>> {
    let Some(entry) = unlocked_hoard.get_entry(uuid) else {
        if !silent {
            println!("Entry not found: {}", uuid)
        }
        return Ok(())
    };
    match entry {
        Entry::BasicPassword(password) => println!("{}", password.username()),
        Entry::Site(site) => println!("{}", site.username()),
        Entry::Note(_) => return Err("Command not supported for entry type".into()),
    }
    unlocked_hoard.lock_in_mem()?;
    Ok(())
}

fn entry_password(unlocked_hoard: UnlockedHoard, uuid: Uuid, silent: bool) -> Result<(), Box<dyn std::error::Error>> {
    let Some(entry) = unlocked_hoard.get_entry(uuid) else {
        if !silent {
            println!("Entry not found: {}", uuid)
        }
        return Ok(())
    };
    match entry {
        Entry::BasicPassword(password) => println!("{}", *password.password()?),
        Entry::Site(site) => println!("{}", *site.password()?),
        Entry::Note(_) => return Err("Command not supported for entry type".into()),
    }
    unlocked_hoard.lock_in_mem()?;
    Ok(())
}

fn entry_note(unlocked_hoard: UnlockedHoard, uuid: Uuid, silent: bool) -> Result<(), Box<dyn std::error::Error>> {
    let Some(entry) = unlocked_hoard.get_entry(uuid) else {
        if !silent {
            println!("Entry not found: {}", uuid)
        }
        return Ok(())
    };
    match entry {
        Entry::BasicPassword(_) => return Err("Command not supported for entry type".into()),
        Entry::Site(site) => {
            match site.note()? {
                Some(n) => println!("{}", *n),
                None => if !silent {println!("No note")},
            }
        },
        Entry::Note(note) => println!("{}", *note.note()?),
    }
    unlocked_hoard.lock_in_mem()?;
    Ok(())
}

fn build_config(config_path: Option<PathBuf>) -> Result<Config, Error> {
    let home = home_dir().ok_or(Error::HomeDirectoryNotFound)?;

    let config_path = match config_path {
        Some(p) => p,
        None => {
            PathBuf::from(home.join(DEFAULT_CONFIG_PATH))
        },
    };

    if config_path.try_exists()? {
        Config::from_path(&config_path)
    } else {
        let default_vault_file = PathBuf::from(home.join(DEFAULT_VAULT_PATH));
        let default_argon2 = Argon2Conf::new(DEFAULT_ARGON2_MEMORY, DEFAULT_ARGON2_ITR, DEFAULT_ARGON2_PARA);
        let default_uiconf = UIConf::new(DEFAULT_UI_SESSION_TIMEOUT_SEC);
        let default_config = Config::new(default_vault_file, default_argon2, default_uiconf)?;
        default_config.save_file(&config_path)?;
        Ok(default_config)
    }
}
