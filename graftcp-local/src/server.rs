use graftcp_common::{Result, Config};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, error, warn, debug};
use crate::proxy::ProxyClient;
use crate::proc_tracker::ProcessTracker;

/// Server that handles incoming connections and forwards them through proxies
pub struct ProxyServer {
    config: Config,
}

impl ProxyServer {
    pub fn new(config: Config) -> Self {
        Self { config }
    }
    
    /// Start the proxy server and return the actual listening address
    pub async fn start_listen(&self) -> Result<(TcpListener, std::net::SocketAddr)> {
        let listener = TcpListener::bind(&self.config.listen_addr).await?;
        let actual_addr = listener.local_addr()?;
        info!("graftcp-local listening on {}", actual_addr);
        Ok((listener, actual_addr))
    }
    
    /// Start the proxy server (original method for backward compatibility)
    pub async fn start(
        &self,
        _proxy_client: ProxyClient,
        process_tracker: Arc<RwLock<ProcessTracker>>,
    ) -> Result<()> {
        let (listener, _actual_addr) = self.start_listen().await?;
        self.start_with_listener(listener, _proxy_client, process_tracker).await
    }
    
    /// Start the proxy server with a pre-created listener
    pub async fn start_with_listener(
        &self,
        listener: TcpListener,
        _proxy_client: ProxyClient,
        process_tracker: Arc<RwLock<ProcessTracker>>,
    ) -> Result<()> {
        // Accept incoming connections
        loop {
            match listener.accept().await {
                Ok((stream, remote_addr)) => {
                    info!("Accepted connection from {}", remote_addr);
                    
                    let proxy_client = ProxyClient::new(
                        self.config.socks5_addr,
                        self.config.socks5_username.clone(),
                        self.config.socks5_password.clone(),
                        self.config.http_proxy_addr,
                        self.config.proxy_mode.clone(),
                    )?;
                    
                    let process_tracker = process_tracker.clone();
                    
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream, remote_addr, proxy_client, process_tracker).await {
                            error!("Error handling connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error accepting connection: {}", e);
                }
            }
        }
    }
    
    /// Handle a single client connection
    async fn handle_connection(
        client_stream: TcpStream,
        remote_addr: std::net::SocketAddr,
        proxy_client: ProxyClient,
        process_tracker: Arc<RwLock<ProcessTracker>>,
    ) -> Result<()> {
        // Get local and remote addresses for this connection
        let local_addr = client_stream.local_addr()?;
        
        debug!("Handling connection: {} -> {}", remote_addr, local_addr);
        
        // Try multiple approaches to resolve destination:
        // 1. Check if we have a fake IP mapping via FIFO
        // 2. Use traditional PID-based lookup as fallback
        use graftcp_common::{resolve_fake_ip, is_fake_ip};
        use std::net::IpAddr;
        
        let dest_addr = {
            let mut tracker = process_tracker.write().await;
            
            // First try to find destination via PID mapping (which may contain fake IPs)
            match tracker.find_pid_and_dest_by_connection(&remote_addr, &local_addr) {
                Some((pid, mapped_dest)) => {
                    // Check if mapped_dest is a fake IP
                    match mapped_dest.ip() {
                        IpAddr::V4(ipv4) if is_fake_ip(IpAddr::V4(ipv4)) => {
                            // This is a fake IP from FIFO, resolve to real destination
                            match resolve_fake_ip(ipv4) {
                                Some(real_dest) => {
                                    info!("Resolved fake IP {} to real destination {} (PID: {})", ipv4, real_dest, pid);
                                    real_dest
                                }
                                None => {
                                    error!("Failed to resolve fake IP {} from FIFO (PID: {})", ipv4, pid);
                                    return Err(graftcp_common::GraftcpError::ProcessError(
                                        format!("Cannot resolve fake IP {} from FIFO", ipv4)
                                    ));
                                }
                            }
                        }
                        _ => {
                            // This is a direct real destination mapping
                            info!("Using direct destination mapping: {} (PID: {})", mapped_dest, pid);
                            mapped_dest
                        }
                    }
                }
                None => {
                    error!("Cannot find destination mapping for connection {} -> {}", remote_addr, local_addr);
                    return Err(graftcp_common::GraftcpError::ProcessError(
                        "Cannot find destination mapping for connection".to_string()
                    ));
                }
            }
        };
        
        info!("Final destination resolved: {} -> {}", remote_addr, dest_addr);
        
        // Connect to the real destination through proxy
        let dest_stream = match proxy_client.connect(dest_addr).await {
            Ok(stream) => stream,
            Err(e) => {
                error!("Failed to connect to destination {}: {}", dest_addr, e);
                return Err(e);
            }
        };
        
        info!("Successfully connected to destination {}", dest_addr);
        
        // Start relaying data between client and destination
        Self::relay_data(client_stream, dest_stream).await?;
        
        Ok(())
    }
    
    /// Relay data bidirectionally between two TCP streams
    async fn relay_data(client_stream: TcpStream, dest_stream: TcpStream) -> Result<()> {
        let (mut client_read, mut client_write) = client_stream.into_split();
        let (mut dest_read, mut dest_write) = dest_stream.into_split();
        
        // Spawn two tasks for bidirectional copying
        let client_to_dest = tokio::spawn(async move {
            tokio::io::copy(&mut client_read, &mut dest_write).await
        });
        
        let dest_to_client = tokio::spawn(async move {
            tokio::io::copy(&mut dest_read, &mut client_write).await
        });
        
        // Wait for either direction to complete
        tokio::select! {
            result = client_to_dest => {
                match result {
                    Ok(Ok(bytes)) => debug!("Relayed {} bytes from client to destination", bytes),
                    Ok(Err(e)) => warn!("Error relaying from client to destination: {}", e),
                    Err(e) => warn!("Task error in client->destination relay: {}", e),
                }
            }
            result = dest_to_client => {
                match result {
                    Ok(Ok(bytes)) => debug!("Relayed {} bytes from destination to client", bytes),
                    Ok(Err(e)) => warn!("Error relaying from destination to client: {}", e),
                    Err(e) => warn!("Task error in destination->client relay: {}", e),
                }
            }
        }
        
        debug!("Connection relay completed");
        Ok(())
    }
}