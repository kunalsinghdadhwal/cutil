#[cfg(feature = "cli")]
use colored::Colorize;
#[cfg(feature = "cli")]
use cutil::cli::run_cli;

#[cfg(feature = "cli")]
fn main() {
    if let Err(e) = run_cli() {
        eprintln!("{} {}", "Error:".red().bold(), e);
        std::process::exit(1);
    }
}

#[cfg(not(feature = "cli"))]
fn main() {
    eprintln!("This binary requires the 'cli' feature to be enabled.");
    eprintln!("Build with: cargo build --features cli");
    std::process::exit(1);
}
