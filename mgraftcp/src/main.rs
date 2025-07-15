use clap::Parser;
use graftcp_common::{Config, Result, ProxyMode};
use std::path::PathBuf;
use std::sync::Arc;
use std::net::SocketAddr;
use tracing::{info, error, debug};
use tokio::sync::RwLock;
use tempfile::TempDir;

// Import local modules
use graftcp_local::server::ProxyServer;
use graftcp_local::proxy::ProxyClient;

/// mgraftcp - combined graftcp and graftcp-local in single binary
#[derive(Parser, Debug)]
#[command(name = "mgraftcp")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Combined graftcp and graftcp-local functionality in a single binary")]
pub struct Args {
    /// Black IP file path (IPs that connect directly)
    #[arg(short = 'b', long = "blackip-file")]
    pub blackip_file: Option<PathBuf>,
    
    /// White IP file path (only redirect these IPs to proxy)  
    #[arg(short = 'w', long = "whiteip-file")]
    pub whiteip_file: Option<PathBuf>,
    
    /// Don't ignore local connections (redirect them to proxy too)
    #[arg(short = 'n', long = "not-ignore-local")]
    pub not_ignore_local: bool,
    
    /// Enable debug logging
    #[arg(long = "enable-debug-log")]
    pub enable_debug_log: bool,
    
    /// HTTP proxy address
    #[arg(long = "http_proxy")]
    pub http_proxy: Option<String>,
    
    /// SOCKS5 proxy address
    #[arg(long = "socks5", default_value = "127.0.0.1:1081")]
    pub socks5: String,
    
    /// SOCKS5 username
    #[arg(long = "socks5_username")]
    pub socks5_username: Option<String>,
    
    /// SOCKS5 password
    #[arg(long = "socks5_password")]
    pub socks5_password: Option<String>,
    
    /// Proxy selection mode
    #[arg(long = "select_proxy_mode", default_value = "auto")]
    pub select_proxy_mode: String,
    
    /// Program to execute
    pub program: Option<String>,
    
    /// Arguments for the program
    pub args: Vec<String>,
}

impl Args {
    /// Convert arguments to graftcp-local Config
    fn to_config(&self, listen_addr: SocketAddr) -> Result<Config> {
        let proxy_mode = match self.select_proxy_mode.as_str() {
            "auto" => ProxyMode::Auto,
            "random" => ProxyMode::Random,
            "only_socks5" => ProxyMode::OnlySocks5,
            "only_http_proxy" => ProxyMode::OnlyHttpProxy,
            "direct" => ProxyMode::Direct,
            _ => ProxyMode::Auto,
        };
        
        let socks5_addr = self.socks5.parse().map_err(|e| {
            graftcp_common::GraftcpError::ConfigError(format!("Invalid SOCKS5 address: {}", e))
        })?;
        
        let http_proxy_addr = if let Some(ref addr) = self.http_proxy {
            Some(addr.parse().map_err(|e| {
                graftcp_common::GraftcpError::ConfigError(format!("Invalid HTTP proxy address: {}", e))
            })?)
        } else {
            None
        };
        
        Ok(Config {
            listen_addr,
            socks5_addr: Some(socks5_addr),
            socks5_username: self.socks5_username.clone(),
            socks5_password: self.socks5_password.clone(),
            http_proxy_addr,
            proxy_mode,
            blacklist_ips: Vec::new(), // TODO: load from file
            whitelist_ips: Vec::new(), // TODO: load from file  
            ignore_local: !self.not_ignore_local,
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    // Initialize tracing
    if args.enable_debug_log {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .init();
    }
    
    info!("Starting mgraftcp v{}", env!("CARGO_PKG_VERSION"));
    
    if let Some(ref program) = args.program {
        info!("Executing: {} {:?}", program, args.args);
        
        // Start embedded graftcp-local server
        let listen_addr: SocketAddr = "0.0.0.0:0".parse().unwrap(); // Use ephemeral port
        let config = args.to_config(listen_addr)?;
        
        info!("Starting embedded graftcp-local with config: {:?}", config);
        
        // Initialize components
        let proxy_client = ProxyClient::new(
            config.socks5_addr,
            config.socks5_username.clone(),
            config.socks5_password.clone(),
            config.http_proxy_addr,
            config.proxy_mode.clone(),
        )?;
        
        // Start proxy server and get actual listening address
        let server = ProxyServer::new(config.clone());
        let (listener, actual_addr) = server.start_listen().await?;
        let actual_port = actual_addr.port();
        
        info!("graftcp-local is listening on actual address: {}", actual_addr);
        
        // Start the server with the listener
        let server_handle = tokio::spawn(async move {
            if let Err(e) = server.start_with_listener(listener, proxy_client).await {
                error!("Proxy server error: {}", e);
            }
        });
        
        // Start graftcp tracer for the target program
        let tracer_handle = tokio::spawn(start_graftcp_tracer(
            program.clone(),
            args.args.clone(),
            actual_port,
            args.blackip_file.clone(),
            args.whiteip_file.clone(),
            args.not_ignore_local,
        ));
        
        // Wait for server to finish or tracer to complete
        tokio::select! {
            _ = server_handle => {
                info!("Proxy server completed");
            }
            result = tracer_handle => {
                match result {
                    Ok(Ok(exit_code)) => {
                        info!("Program completed with exit code: {}", exit_code);
                        std::process::exit(exit_code);
                    }
                    Ok(Err(e)) => {
                        error!("Tracer failed: {}", e);
                        return Err(e);
                    }
                    Err(e) => {
                        error!("Tracer task panicked: {}", e);
                        return Err(graftcp_common::GraftcpError::ProcessError(
                            format!("Tracer task panicked: {}", e)
                        ));
                    }
                }
            }
        }
        
    } else {
        error!("No program specified to execute");
        std::process::exit(1);
    }
    
    Ok(())
}

/// Start the graftcp tracer for the target program
async fn start_graftcp_tracer(
    program: String,
    program_args: Vec<String>,
    local_port: u16,
    blackip_file: Option<PathBuf>,
    whiteip_file: Option<PathBuf>,
    not_ignore_local: bool,
) -> Result<i32> {
    use graftcp::tracer::Tracer;
    
    info!("Starting graftcp tracer for program: {}", program);
    debug!("Arguments: {:?}", program_args);
    debug!("Local port: {}", local_port);
    
    // Create tracer with configuration
    let mut tracer = Tracer::new(
        "127.0.0.1".to_string(),
        local_port,
        !not_ignore_local, // ignore_local is opposite of not_ignore_local
    );
    
    // TODO: Load blacklist/whitelist files if provided
    if let Some(ref blackip_file) = blackip_file {
        debug!("Black IP file: {:?}", blackip_file);
        // TODO: implement load_blacklist_file(&mut tracer, blackip_file)?;
    }
    
    if let Some(ref whiteip_file) = whiteip_file {
        debug!("White IP file: {:?}", whiteip_file);
        // TODO: implement load_whitelist_file(&mut tracer, whiteip_file)?;
    }
    
    // Start tracing the program
    tokio::task::spawn_blocking(move || {
        tracer.start_trace(&program, &program_args)
            .map_err(|e| {
                error!("Failed to start tracing: {}", e);
                e
            })
            .map(|_| 0) // Return exit code 0 on success
    }).await.map_err(|e| {
        graftcp_common::GraftcpError::ProcessError(format!("Tracer task failed: {}", e))
    })?
}