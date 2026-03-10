use clap::{Parser,Subcommand};
use dialoguer::{Password};
use zeroize::Zeroizing;
use std::path::PathBuf;

use frankshoard::{LockedHoard, UnlockedHoard, FranksHoardError};

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
    List,
    Add {
        #[arg(short, long)]
        service: String,
        #[arg(short, long)]
        username: String,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => init(cli.config),
        other => Err(Box::new(FranksHoardError::NotImplemented(format!("{:?}", other)))),
    }
}

fn init(path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let locked_hoard = LockedHoard::new_hoard(path)?;

    // Ask for password
    let password = Zeroizing::new(
        Password::new()
            .with_prompt("Master password")
            .with_confirmation("Confirm password", "Passwords do not match")
            .interact()?
    );

    let unlocked_hoard = locked_hoard.unlock(password)?;
    unlocked_hoard.lock(true)?;

    Ok(())
}
