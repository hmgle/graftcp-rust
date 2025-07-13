use graftcp_common::{Result, Config};
use graftcp_common::fake_ip::{decode_from_loopback_simple, is_loopback_encoded};
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
        // For simplicity, we'll listen on 0.0.0.0:0 and let the OS assign a port
        // In a full implementation, we'd need to use raw sockets or multiple listeners
        // to truly capture all loopback traffic
        
        info!("Starting loopback-aware proxy server...");
        
        // Listen on all interfaces for now - in practice, applications will connect
        // to specific loopback addresses that we've encoded
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let actual_addr = listener.local_addr()?;
        
        info!("graftcp-local listening on {} (loopback mode)", actual_addr);
        info!("Note: In loopback mode, the actual listening address is less important");
        info!("Applications will connect to encoded loopback addresses (127.x.x.x)");
        
        // Create a dummy proxy client and process tracker for compatibility
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
        _process_tracker: Arc<RwLock<ProcessTracker>>, // No longer needed for loopback encoding!
    ) -> Result<()> {
        // Get local address for this connection - this is the encoded loopback address!
        let local_addr = client_stream.local_addr()?;
        
        debug!("Handling connection: {} -> {}", remote_addr, local_addr);
        
        // SIMPLIFIED: Direct decoding from loopback address
        // No FIFO communication, no PID tracking, no global state!
        let dest_addr = if is_loopback_encoded(local_addr.ip()) {
            // Decode the real destination directly from the loopback address
            match decode_from_loopback_simple(local_addr) {
                Some(real_dest) => {
                    info!("Decoded loopback {} to real destination {}", local_addr, real_dest);
                    real_dest
                }
                None => {
                    error!("Failed to decode loopback address: {}", local_addr);
                    return Err(graftcp_common::GraftcpError::ProcessError(
                        format!("Cannot decode loopback address: {}", local_addr)
                    ));
                }
            }
        } else {
            // Not a loopback encoded address - might be direct connection
            warn!("Connection to non-encoded address: {} - treating as direct", local_addr);
            local_addr
        };
        
        info!("Final destination resolved: {} -> {}", local_addr, dest_addr);
        
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