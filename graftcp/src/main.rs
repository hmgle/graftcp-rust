use clap::Parser;
use graftcp_common::Result;
use std::path::PathBuf;
use tracing::{info, error, debug, warn};

/// graftcp - redirect TCP connections through proxy using ptrace
#[derive(Parser, Debug)]
#[command(name = "graftcp")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Redirect TCP connections made by a program to SOCKS5 or HTTP proxy")]
#[command(trailing_var_arg = true)]
pub struct Args {
    /// Configuration file path
    #[arg(short = 'c', long = "conf-file")]
    pub config_file: Option<PathBuf>,
    
    /// graftcp-local's IP address
    #[arg(short = 'a', long = "local-addr", default_value = "localhost")]
    pub local_addr: String,
    
    /// graftcp-local's port
    #[arg(short = 'p', long = "local-port", default_value = "2233")]
    pub local_port: u16,
    
    /// Path of fifo to communicate with graftcp-local
    #[arg(short = 'f', long = "local-fifo", default_value = "/tmp/graftcplocal.fifo")]
    pub local_fifo: PathBuf,
    
    /// Black IP file path (IPs that connect directly)
    #[arg(short = 'b', long = "blackip-file")]
    pub blackip_file: Option<PathBuf>,
    
    /// White IP file path (only redirect these IPs to proxy)
    #[arg(short = 'w', long = "whiteip-file")]
    pub whiteip_file: Option<PathBuf>,
    
    /// Don't ignore local connections (redirect them to proxy too)
    #[arg(short = 'n', long = "not-ignore-local")]
    pub not_ignore_local: bool,
    
    /// Program and its arguments to execute
    #[arg(required = true, num_args = 1..)]
    pub command: Vec<String>,
}

mod ptrace;
mod tracer;
mod fifo;

use tracer::Tracer;

fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();
    
    let args = Args::parse();
    
    // Extract program and arguments from command vector
    let program = &args.command[0];
    let program_args = &args.command[1..];
    
    info!("Starting graftcp v{}", env!("CARGO_PKG_VERSION"));
    info!("Executing: {} {:?}", program, program_args);
    
    // Configuration options
    debug!("Configuration options:");
    debug!("  local_addr: {}", args.local_addr);
    debug!("  local_port: {}", args.local_port);
    debug!("  local_fifo: {:?}", args.local_fifo);
    debug!("  blackip_file: {:?}", args.blackip_file);
    debug!("  whiteip_file: {:?}", args.whiteip_file);
    debug!("  not_ignore_local: {}", args.not_ignore_local);
    
    // Check if we can access the required resources
    // Note: ptrace may work for non-root users in some configurations
    if unsafe { libc::geteuid() } != 0 {
        warn!("Running as non-root user. ptrace functionality may be limited.");
    }
    
    // Create and configure tracer
    let mut tracer = Tracer::new(
        args.local_addr.clone(),
        args.local_port,
        !args.not_ignore_local, // ignore_local is opposite of not_ignore_local
        args.local_fifo.to_string_lossy().to_string(),
    );
    
    info!("Starting ptrace-based execution and tracing");
    
    // Start tracing the target program
    match tracer.start_trace(program, program_args) {
        Ok(()) => {
            info!("Program execution completed successfully");
            std::process::exit(0);
        }
        Err(e) => {
            error!("Tracing failed: {}", e);
            
            // Fallback to direct execution if ptrace fails
            warn!("Falling back to direct execution without ptrace");
            execute_directly(program, program_args)
        }
    }
}

/// Fallback function to execute program directly without ptrace
fn execute_directly(program: &str, args: &[String]) -> ! {
    use std::process::Command;
    
    info!("Executing command directly: {} {}", program, args.join(" "));
    
    match Command::new(program).args(args).status() {
        Ok(exit_status) => {
            if exit_status.success() {
                info!("Program completed successfully");
                std::process::exit(0);
            } else {
                error!("Program exited with status: {}", exit_status);
                std::process::exit(exit_status.code().unwrap_or(1));
            }
        }
        Err(e) => {
            error!("Failed to execute program '{}': {}", program, e);
            std::process::exit(1);
        }
    }
}