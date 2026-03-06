mod config;
mod error;
mod init;
mod vault;
mod crypto;

use clap::{Parser,Subcommand};


#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
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
    let args = Cli::parse();

    match args.command {
        Commands::Init => {
            if let Err(e) = init::run() {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::List => println!("List"),
        Commands::Add { service, username } => {
            println!("Add service {service} for user {username}")
        }
    }
}
