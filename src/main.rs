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

    #[arg(short, long)]
    silent: bool,

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
        entry_name: Zeroizing<String>,
        #[arg(long)]
        username: Zeroizing<String>,
    },
    Site {
        #[arg(long)]
        entry_name: Zeroizing<String>,
        #[arg(long)]
        url: Url,
        #[arg(long)]
        username: Zeroizing<String>,
        #[arg(long)]
        note: Option<Zeroizing<String>>,
    },
    Note {
        #[arg(long)]
        entry_name: Zeroizing<String>,
        #[arg(long)]
        note: Zeroizing<String>,
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
    if let Commands::Init = cli.command {
        return init(cli.config, silent);
    }

    let locked_hoard = LockedHoard::load_hoard(cli.config)?;
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
        Commands::Remove { uuid } => remove(unlocked_hoard, uuid, silent),
        Commands::Entry { uuid } => entry(unlocked_hoard, uuid, silent),
        Commands::EntryUsername { uuid } => entry_username(unlocked_hoard, uuid, silent),
        Commands::EntryPassword { uuid } => entry_password(unlocked_hoard, uuid, silent),
        Commands::EntryNote { uuid } => entry_note(unlocked_hoard, uuid, silent),
    }
}

fn init(path: Option<PathBuf>, silent: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Ask for password
    if !silent {
        println!("A new vault needs a master password.  Chose it and record it safely and carefully, if you lose your master password is not way to retreive it.");
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

    LockedHoard::new_hoard(path, password)?;

    /*if !silent {
        println!("Creating master key...");
    }
    let unlocked_hoard = locked_hoard.unlock(password)?;
    if !silent {
        println!("Saving vault...");
    }
    unlocked_hoard.lock_and_save()?;
    */
    if !silent {
        println!("New vault created.");
    }
    Ok(())
}

fn change_master_password(mut locked_hoard: LockedHoard, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
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
    if verbose {
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
            let entry = Entry::Note(NoteEntry::new(entry_name, note)?);
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
