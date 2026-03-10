use clap::{Parser,Subcommand};
use dialoguer::{Confirm, Input, Password};

use frankshoard::{FranksHoard, FranksHoardError};

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

fn run() -> Result<(), FranksHoardError>{
    let cli = Cli::parse();


    match cli.command {
        Commands::Init => init(),
        other => Err(FranksHoardError::NotImplementedError(format!("{:?}", other))),
    }
}

fn init(hoard: &mut FranksHoard) -> Result<(), FranksHoardError> {
    if hoard.is_initialize()? {
        println!("Vault is already initialized.");
        return Ok(());
    }
    // Ask for password
    let password = Zeroizing::new(
        Password::new()
            .with_prompt("Master password")
            .with_confirmation("Confirm password", "Passwords do not match")
            .interact()?
    );

    Ok(())
}
