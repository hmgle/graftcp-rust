use graftcp_common::{Result, Config};
use graftcp_common::{resolve_loopback_ip, is_loopback_ip};
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
    
    /// Start the proxy server listening on all loopback addresses (127.0.0.0/8)
    /// This replaces the traditional single-port listening approach  
    pub async fn start_loopback_listen(&self) -> Result<()> {
        info!("Starting loopback-aware proxy server...");
        
        // Listen on 0.0.0.0 to receive connections to ANY IP on the specified port
        // When graftcp redirects connect(real) to connect(loopback_ip:server_port),
        // we'll receive the connection and can see which loopback_ip was used
        let listen_addr = format!("0.0.0.0:{}", self.config.listen_addr.port());
        let listener = TcpListener::bind(&listen_addr).await?;
        let actual_addr = listener.local_addr()?;
        
        info!("graftcp-local listening on {} (captures connections to any 127.x.x.x:{})", 
              actual_addr, actual_addr.port());
        
        // Create proxy client and process tracker
        let proxy_client = ProxyClient::new(
            self.config.socks5_addr,
            self.config.socks5_username.clone(),
            self.config.socks5_password.clone(),
            self.config.http_proxy_addr,
            self.config.proxy_mode.clone(),
        )?;
        
        let process_tracker = Arc::new(RwLock::new(ProcessTracker::new()));
        
        self.start_with_listener(listener, proxy_client, process_tracker).await
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
        _process_tracker: Arc<RwLock<ProcessTracker>>,
    ) -> Result<()> {
        // Get local address for this connection
        let local_addr = client_stream.local_addr()?;
        
        info!("=== NEW CONNECTION ===");
        info!("Remote (client): {}", remote_addr);
        info!("Local (server):  {}", local_addr);
        
        // Extract loopback IP from the local address
        if let Some(loopback_ip) = Self::extract_loopback_ip(&local_addr) {
            info!("✅ Extracted loopback IP: {}", loopback_ip);
            
            // Look up the real destination using the loopback IP
            match resolve_loopback_ip(loopback_ip) {
                Some(real_dest) => {
                    info!("✅ Resolved {} → {}", loopback_ip, real_dest);
                    
                    // Connect to the real destination through proxy
                    let dest_stream = match proxy_client.connect(real_dest).await {
                        Ok(stream) => {
                            info!("✅ Connected to real destination: {}", real_dest);
                            stream
                        },
                        Err(e) => {
                            error!("❌ Failed to connect to destination {}: {}", real_dest, e);
                            return Err(e);
                        }
                    };
                    
                    // Start relaying data between client and destination
                    Self::relay_data(client_stream, dest_stream).await?;
                    info!("✅ Connection relay completed for {}", real_dest);
                }
                None => {
                    error!("❌ Failed to resolve loopback IP: {} (connection {}→{})", 
                           loopback_ip, remote_addr, local_addr);
                    return Err(graftcp_common::GraftcpError::ProcessError(
                        format!("Cannot resolve loopback IP: {}", loopback_ip)
                    ));
                }
            }
        } else {
            warn!("⚠️  Connection to non-loopback address: {} - this might be a direct connection or configuration issue", local_addr);
            warn!("    If you see this frequently, check your graftcp configuration");
            
            // For debugging, let's still try to handle it as a direct connection
            let dest_stream = match proxy_client.connect(local_addr).await {
                Ok(stream) => stream,
                Err(e) => {
                    error!("❌ Failed to connect directly to {}: {}", local_addr, e);
                    return Err(e);
                }
            };
            
            Self::relay_data(client_stream, dest_stream).await?;
        };
        
        Ok(())
    }
    
    /// Extract loopback IP from local address if it's in the loopback range
    fn extract_loopback_ip(addr: &std::net::SocketAddr) -> Option<std::net::Ipv4Addr> {
        match addr.ip() {
            std::net::IpAddr::V4(ipv4) => {
                if is_loopback_ip(std::net::IpAddr::V4(ipv4)) {
                    // Return the loopback IP regardless of whether it's 127.0.0.1 or others
                    // The issue was excluding 127.0.0.1, but that might be a valid allocated IP
                    Some(ipv4)
                } else {
                    None
                }
            }
            _ => None,
        }
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