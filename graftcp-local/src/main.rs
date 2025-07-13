use clap::Parser;
use graftcp_common::{Result, Config, ProxyMode};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error, warn};

/// graftcp-local - local proxy server for graftcp
#[derive(Parser, Debug)]
#[command(name = "graftcp-local")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Local proxy server that forwards connections from graftcp to SOCKS5/HTTP proxies")]
pub struct Args {
    /// Listen address
    #[arg(short = 'l', long = "listen", default_value = ":2233")]
    pub listen: String,
    
    /// SOCKS5 proxy address
    #[arg(long = "socks5", default_value = "127.0.0.1:1080")]
    pub socks5: String,
    
    /// SOCKS5 username
    #[arg(long = "socks5-username")]
    pub socks5_username: Option<String>,
    
    /// SOCKS5 password
    #[arg(long = "socks5-password")]
    pub socks5_password: Option<String>,
    
    /// HTTP proxy address
    #[arg(long = "http-proxy")]
    pub http_proxy: Option<String>,
    
    /// Proxy selection mode
    #[arg(long = "select-proxy-mode", default_value = "auto")]
    pub select_proxy_mode: String,
    
    /// Configuration file path
    #[arg(short = 'c', long = "config")]
    pub config: Option<PathBuf>,
    
    /// FIFO pipe path for receiving destination info
    #[arg(long = "pipepath", default_value = "/tmp/graftcplocal.fifo")]
    pub pipepath: PathBuf,
    
    /// Log file path
    #[arg(long = "logfile")]
    pub logfile: Option<PathBuf>,
    
    /// Log level (0-6)
    #[arg(long = "loglevel", default_value = "1")]
    pub loglevel: u8,
}

mod proxy;
mod server;
mod fifo;
mod proc_tracker;

use proxy::ProxyClient;
use server::ProxyServer;
use proc_tracker::ProcessTracker;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();
    
    let args = Args::parse();
    
    info!("Starting graftcp-local v{}", env!("CARGO_PKG_VERSION"));
    info!("Listen address: {}", args.listen);
    info!("SOCKS5 proxy: {}", args.socks5);
    if let Some(ref http_proxy) = args.http_proxy {
        info!("HTTP proxy: {}", http_proxy);
    }
    info!("Proxy mode: {}", args.select_proxy_mode);
    info!("FIFO path: {:?}", args.pipepath);
    
    // Parse proxy mode
    let proxy_mode = match args.select_proxy_mode.as_str() {
        "auto" => ProxyMode::Auto,
        "random" => ProxyMode::Random,
        "only_socks5" => ProxyMode::OnlySocks5,
        "only_http_proxy" => ProxyMode::OnlyHttpProxy,
        "direct" => ProxyMode::Direct,
        _ => {
            warn!("Unknown proxy mode '{}', using auto", args.select_proxy_mode);
            ProxyMode::Auto
        }
    };
    
    // Create configuration
    let listen_addr = if args.listen.starts_with(':') {
        format!("0.0.0.0{}", args.listen).parse()?
    } else {
        args.listen.parse()?
    };
    
    let config = Config {
        listen_addr,
        socks5_addr: Some(args.socks5.parse()?),
        socks5_username: args.socks5_username,
        socks5_password: args.socks5_password,
        http_proxy_addr: args.http_proxy.as_ref().map(|addr| addr.parse()).transpose()?,
        pipe_path: args.pipepath.to_string_lossy().to_string(),
        proxy_mode,
        blacklist_ips: Vec::new(),
        whitelist_ips: Vec::new(),
        ignore_local: true,
    };
    
    // Create proxy client
    let proxy_client = ProxyClient::new(
        config.socks5_addr,
        config.socks5_username.clone(),
        config.socks5_password.clone(),
        config.http_proxy_addr,
        config.proxy_mode.clone(),
    )?;
    
    // Create process tracker for storing PID->destination mappings
    let process_tracker = Arc::new(RwLock::new(ProcessTracker::new()));
    
    // Start FIFO reader for receiving destination info from graftcp
    let fifo_tracker = process_tracker.clone();
    let fifo_path = config.pipe_path.clone();
    tokio::spawn(async move {
        if let Err(e) = fifo::start_fifo_reader(&fifo_path, fifo_tracker).await {
            error!("FIFO reader failed: {}", e);
        }
    });
    
    // Create and start proxy server
    let server = ProxyServer::new(config);
    info!("graftcp-local server starting...");
    server.start(proxy_client, process_tracker).await?;
    
    Ok(())
}