//! The `mcsec` command line scanner.

#![forbid(unsafe_code)]

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use mcsec_core::{ScanLimits, ScanReport};

/// Exit status when a scan runs past its time limit, distinct from other failures.
const TIMEOUT_EXIT_CODE: i32 = 3;

#[derive(Parser)]
#[command(
    name = "mcsec",
    version,
    about = "Scan Minecraft mod jars for vulnerabilities and malware"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a jar and print its report as JSON on stdout
    Scan {
        /// Path to the jar
        path: PathBuf,
        /// Indent the JSON output
        #[arg(long)]
        pretty: bool,
        /// Stop the scan after this many seconds. A jar built to make
        /// analysis slow then fails instead of hanging.
        #[arg(long, default_value_t = 120)]
        timeout_secs: u64,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan {
            path,
            pretty,
            timeout_secs,
        } => {
            start_watchdog(&path, Duration::from_secs(timeout_secs));
            match scan_file(&path) {
                Ok(report) => {
                    let json = if pretty {
                        serde_json::to_string_pretty(&report)
                    } else {
                        serde_json::to_string(&report)
                    };
                    println!("{}", json.expect("report serializes to JSON"));
                    ExitCode::SUCCESS
                }
                Err(message) => {
                    eprintln!("mcsec: {}: {message}", path.display());
                    ExitCode::FAILURE
                }
            }
        }
    }
}

/// Ends the process if the scan is still running after `limit`. Scanning is
/// pure computation with no cleanup, so exiting from another thread is safe.
fn start_watchdog(path: &Path, limit: Duration) {
    let path = path.display().to_string();
    std::thread::spawn(move || {
        std::thread::sleep(limit);
        eprintln!(
            "mcsec: {path}: scan exceeded the time limit of {} seconds",
            limit.as_secs()
        );
        std::process::exit(TIMEOUT_EXIT_CODE);
    });
}

fn scan_file(path: &Path) -> Result<ScanReport, String> {
    let limits = ScanLimits::default();
    let file = File::open(path).map_err(|e| e.to_string())?;

    // Capped one byte past the limit so a file that grows after being opened
    // still cannot be read past it. The core then rejects the oversize input.
    let mut bytes = Vec::new();
    file.take(limits.max_input_size + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;

    mcsec_core::scan_bytes(&bytes, &limits).map_err(|e| e.to_string())
}
