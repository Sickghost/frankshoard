use clap::{Parser,Subcommand};
use dialoguer::{Password};
use uuid::Uuid;
use zeroize::Zeroizing;
use std::path::PathBuf;
use url::Url;

use frankshoard::{Entry, BasicPasswordEntry, SiteEntry, NoteEntry, LockedHoard, UnlockedHoard};

#[derive(Parser)]
#[command(name = "frankshoard")]
#[command(about = "A secure password manager")]
struct Cli {
    #[arg(short, long)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Init,
    Add {
        #[command(subcommand)]
        entry_type: AddCommands,
    },
    ListAll,
    List {
        #[command(subcommand)]
        entry_type: ListCommands,
    },
    Remove {
        #[arg(long)]
        uuid: Uuid,
    },
    Entry{
        #[arg(long)]
        uuid: Uuid,
    },
    EntryUsername{
        #[arg(long)]
        uuid: Uuid,
    },
    EntryPassword{
        #[arg(long)]
        uuid: Uuid,
    },
    EntryNote{
        #[arg(long)]
        uuid: Uuid,
    },
    ChangeMasterPassword,
}

#[derive(Subcommand, Debug)]
enum AddCommands {
    BasicPassword {
        #[arg(long)]
        entry_name: String,
        #[arg(long)]
        username: String,
    },
    Site {
        #[arg(long)]
        entry_name: String,
        #[arg(long)]
        url: Url,
        #[arg(long)]
        username: String,
        #[arg(long)]
        note: Option<String>,
    },
    Note {
        #[arg(long)]
        entry_name: String,
        #[arg(long)]
        note: String,
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

    if let Commands::Init = cli.command {
        return init(cli.config);
    }

    let locked_hoard = LockedHoard::from_path(cli.config)?;
    if let Commands::ChangeMasterPassword = cli.command {
        return change_master_password(locked_hoard);
    }

    let password = Zeroizing::new(
        Password::new()
            .with_prompt("Master password")
            .interact()?
    );

    println!("Unlocking vault...");
    let unlocked_hoard = locked_hoard.unlock(password)?;

    match cli.command {
        Commands::Init => unreachable!(),
        Commands::ChangeMasterPassword => unreachable!(),
        Commands::Add {entry_type} => add(unlocked_hoard, entry_type),
        Commands::ListAll => list_all(unlocked_hoard),
        Commands::List {entry_type} => list(unlocked_hoard, entry_type),
        Commands::Remove { uuid } => remove(unlocked_hoard, uuid),
        Commands::Entry { uuid } => entry(unlocked_hoard, uuid),
        Commands::EntryUsername { uuid } => entry_username(unlocked_hoard, uuid),
        Commands::EntryPassword { uuid } => entry_password(unlocked_hoard, uuid),
        Commands::EntryNote { uuid } => entry_note(unlocked_hoard, uuid),
    }
}

fn init(path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let locked_hoard = LockedHoard::new_hoard(path)?;

    println!("Creating Vault...");
    // Ask for password
    let password = Zeroizing::new(
        Password::new()
            .with_prompt("Enter Master password")
            .with_confirmation("Confirm password", "Passwords do not match")
            .interact()?
    );

    println!("Creating master key...");
    let unlocked_hoard = locked_hoard.unlock(password)?;
    println!("Saving vault...");
    unlocked_hoard.lock(true)?;

    println!("New vault created.");
    Ok(())
}

fn change_master_password(mut locked_hoard: LockedHoard) -> Result<(), Box<dyn std::error::Error>> {
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
    Ok(())
}

fn add(mut unlocked_hoard: UnlockedHoard, entry_type: AddCommands) -> Result<(), Box<dyn std::error::Error>> {
    // Ask for password
    let password = Password::new()
        .with_prompt("Please enter password for new entry")
        .with_confirmation("Confirm password", "Passwords do not match")
        .interact()?;

    match entry_type {
        AddCommands::BasicPassword { entry_name, username } => unlocked_hoard.add_entry(
            Entry::BasicPassword(BasicPasswordEntry::new(entry_name, username, password))
        )?,
        AddCommands::Site {entry_name, url, username, note} => unlocked_hoard.add_entry(
            Entry::Site(SiteEntry::new(entry_name, url, username, password, note))
        )?,
        AddCommands::Note { entry_name, note } => unlocked_hoard.add_entry(
            Entry::Note(NoteEntry::new(entry_name, note))
        )?,
    }

    println!("Saving new entry...");
    unlocked_hoard.lock(true)?;
    println!("Entry saved.");
    Ok(())
}

fn list_all(unlocked_hoard: UnlockedHoard) -> Result<(), Box<dyn std::error::Error>> {
    let entries = unlocked_hoard.get_entries();
    for entry in entries {
        println!("{}", entry);
    }
    unlocked_hoard.lock(false)?;
    Ok(())
}

fn list(unlocked_hoard: UnlockedHoard, entry_type: ListCommands) -> Result<(), Box<dyn std::error::Error>> {
    match entry_type {
        ListCommands::BasicPassword => {
            println!("Printing Basic Password List...");
            for entry in unlocked_hoard.get_entries_of::<BasicPasswordEntry>() {
                println!("{}", entry);
            }
        },
        ListCommands::Site => {
            println!("Printing Site List...");
            for entry in unlocked_hoard.get_entries_of::<SiteEntry>() {
                println!("{}", entry);
            }
        },
        ListCommands::Note => {
            println!("Printing Note List...");
            for entry in unlocked_hoard.get_entries_of::<NoteEntry>() {
                println!("{}", entry);
            }
        },
    }
    println!("Done.");
    unlocked_hoard.lock(false)?;
    Ok(())
}

fn remove(mut unlocked_hoard: UnlockedHoard, uuid: Uuid) -> Result<(), Box<dyn std::error::Error>> {
    unlocked_hoard.remove_entry(uuid)?;
    unlocked_hoard.lock(true)?;
    Ok(())
}

fn entry(unlocked_hoard: UnlockedHoard, uuid: Uuid) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(entry) = unlocked_hoard.get_entry(uuid) {
        println!("{}", entry);
    }
    unlocked_hoard.lock(false)?;
    Ok(())
}

fn entry_username(unlocked_hoard: UnlockedHoard, uuid: Uuid) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(entry) = unlocked_hoard.get_entry(uuid) {
        match entry {
            Entry::BasicPassword(password) => println!("{}", password.username()),
            Entry::Site(site) => println!("{}", site.username()),
            Entry::Note(_) => return Err("Command not supported for entry type".into()),
        }
    }
    unlocked_hoard.lock(false)?;
    Ok(())
}

fn entry_password(unlocked_hoard: UnlockedHoard, uuid: Uuid) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(entry) = unlocked_hoard.get_entry(uuid) {
        match entry {
            Entry::BasicPassword(password) => println!("{}", password.password()),
            Entry::Site(site) => println!("{}", site.password()),
            Entry::Note(_) => return Err("Command not supported for entry type".into()),
        }
    }
    unlocked_hoard.lock(false)?;
    Ok(())
}

fn entry_note(unlocked_hoard: UnlockedHoard, uuid: Uuid) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(entry) = unlocked_hoard.get_entry(uuid) {
        match entry {
            Entry::BasicPassword(_) => return Err("Command not supported for entry type".into()),
            Entry::Site(site) => println!("{}", site.note().unwrap_or("No note")),
            Entry::Note(note) => println!("{}", note.note()),
        }
    }
    unlocked_hoard.lock(false)?;
    Ok(())
}
