use graftcp_common::{Result, ProxyMode};
use std::net::{SocketAddr, IpAddr};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;
use rand::{Rng, SeedableRng};

/// Proxy client that handles different proxy types
pub struct ProxyClient {
    socks5_addr: Option<SocketAddr>,
    socks5_username: Option<String>,
    socks5_password: Option<String>,
    http_proxy_addr: Option<SocketAddr>,
    proxy_mode: ProxyMode,
}

impl ProxyClient {
    pub fn new(
        socks5_addr: Option<SocketAddr>,
        socks5_username: Option<String>,
        socks5_password: Option<String>,
        http_proxy_addr: Option<SocketAddr>,
        proxy_mode: ProxyMode,
    ) -> Result<Self> {
        Ok(Self {
            socks5_addr,
            socks5_username,
            socks5_password,
            http_proxy_addr,
            proxy_mode,
        })
    }
    
    /// Connect to destination through selected proxy
    pub async fn connect(&self, dest_addr: SocketAddr) -> Result<TcpStream> {
        match self.proxy_mode {
            ProxyMode::Auto => self.connect_auto(dest_addr).await,
            ProxyMode::Random => self.connect_random(dest_addr).await,
            ProxyMode::OnlySocks5 => self.connect_socks5(dest_addr).await,
            ProxyMode::OnlyHttpProxy => self.connect_http_proxy(dest_addr).await,
            ProxyMode::Direct => self.connect_direct(dest_addr).await,
        }
    }
    
    async fn connect_auto(&self, dest_addr: SocketAddr) -> Result<TcpStream> {
        // Try SOCKS5 first, fallback to HTTP proxy, then direct
        if self.socks5_addr.is_some() {
            if let Ok(stream) = self.connect_socks5(dest_addr).await {
                debug!("Connected via SOCKS5 to {}", dest_addr);
                return Ok(stream);
            }
        }
        
        if self.http_proxy_addr.is_some() {
            if let Ok(stream) = self.connect_http_proxy(dest_addr).await {
                debug!("Connected via HTTP proxy to {}", dest_addr);
                return Ok(stream);
            }
        }
        
        debug!("Falling back to direct connection to {}", dest_addr);
        self.connect_direct(dest_addr).await
    }
    
    async fn connect_random(&self, dest_addr: SocketAddr) -> Result<TcpStream> {
        // Collect available proxy methods
        let mut methods = Vec::new();
        
        if self.socks5_addr.is_some() {
            methods.push("socks5");
        }
        
        if self.http_proxy_addr.is_some() {
            methods.push("http_proxy");
        }
        
        // Always include direct connection as fallback
        methods.push("direct");
        
        if methods.is_empty() {
            return Err(graftcp_common::GraftcpError::ConfigError(
                "No proxy methods available for random selection".to_string()
            ));
        }
        
        // Randomly select a method using a simpler approach
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let selected_index = rng.gen_range(0..methods.len());
        let selected_method = methods[selected_index];
        
        debug!("Randomly selected proxy method: {}", selected_method);
        
        match selected_method {
            "socks5" => self.connect_socks5(dest_addr).await,
            "http_proxy" => self.connect_http_proxy(dest_addr).await,
            "direct" => self.connect_direct(dest_addr).await,
            _ => unreachable!(),
        }
    }
    
    async fn connect_socks5(&self, dest_addr: SocketAddr) -> Result<TcpStream> {
        let socks5_addr = self.socks5_addr.ok_or_else(|| {
            graftcp_common::GraftcpError::ConfigError("SOCKS5 address not configured".to_string())
        })?;

        debug!("Connecting to SOCKS5 proxy at {}", socks5_addr);
        let mut stream = TcpStream::connect(socks5_addr).await?;
        
        // SOCKS5 authentication
        self.socks5_auth(&mut stream).await?;
        
        // SOCKS5 connect request
        self.socks5_connect(&mut stream, dest_addr).await?;
        
        debug!("Successfully established SOCKS5 connection to {}", dest_addr);
        Ok(stream)
    }
    
    async fn connect_http_proxy(&self, dest_addr: SocketAddr) -> Result<TcpStream> {
        let http_proxy_addr = self.http_proxy_addr.ok_or_else(|| {
            graftcp_common::GraftcpError::ConfigError("HTTP proxy address not configured".to_string())
        })?;

        debug!("Connecting to HTTP proxy at {}", http_proxy_addr);
        let mut stream = TcpStream::connect(http_proxy_addr).await?;
        
        // Send HTTP CONNECT request
        let connect_request = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nProxy-Connection: keep-alive\r\n\r\n",
            dest_addr.ip(),
            dest_addr.port(),
            dest_addr.ip(),
            dest_addr.port()
        );
        
        stream.write_all(connect_request.as_bytes()).await?;
        
        // Read HTTP response
        let mut response_buffer = Vec::new();
        let mut temp_buffer = [0u8; 1];
        
        // Read until we get \r\n\r\n (end of HTTP headers)
        let mut consecutive_crlf = 0;
        loop {
            stream.read_exact(&mut temp_buffer).await?;
            response_buffer.push(temp_buffer[0]);
            
            match temp_buffer[0] {
                b'\r' | b'\n' => consecutive_crlf += 1,
                _ => consecutive_crlf = 0,
            }
            
            // Check for \r\n\r\n pattern
            if consecutive_crlf >= 4 {
                break;
            }
            
            // Prevent infinite reading
            if response_buffer.len() > 4096 {
                return Err(graftcp_common::GraftcpError::NetworkError(
                    "HTTP proxy response too large".to_string()
                ));
            }
        }
        
        let response = String::from_utf8_lossy(&response_buffer);
        debug!("HTTP proxy response: {}", response.trim());
        
        // Check if connection was successful
        if response.contains("200 Connection established") || response.contains("200 OK") {
            debug!("Successfully established HTTP proxy connection to {}", dest_addr);
            Ok(stream)
        } else {
            Err(graftcp_common::GraftcpError::NetworkError(
                format!("HTTP proxy connection failed: {}", response.trim())
            ))
        }
    }
    
    async fn connect_direct(&self, dest_addr: SocketAddr) -> Result<TcpStream> {
        debug!("Connecting directly to {}", dest_addr);
        let stream = TcpStream::connect(dest_addr).await?;
        Ok(stream)
    }
    
    /// SOCKS5 authentication phase
    async fn socks5_auth(&self, stream: &mut TcpStream) -> Result<()> {
        // Send authentication method selection
        let auth_methods = if self.socks5_username.is_some() && self.socks5_password.is_some() {
            // Username/password authentication
            vec![0x05, 0x02, 0x00, 0x02] // VER, NMETHODS, NO_AUTH, USERNAME_PASSWORD
        } else {
            // No authentication
            vec![0x05, 0x01, 0x00] // VER, NMETHODS, NO_AUTH
        };
        
        stream.write_all(&auth_methods).await?;
        
        // Read server response
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;
        
        if response[0] != 0x05 {
            return Err(graftcp_common::GraftcpError::NetworkError(
                "Invalid SOCKS5 version in response".to_string()
            ));
        }
        
        match response[1] {
            0x00 => {
                // No authentication required
                debug!("SOCKS5: No authentication required");
                Ok(())
            }
            0x02 => {
                // Username/password authentication
                debug!("SOCKS5: Username/password authentication required");
                self.socks5_username_password_auth(stream).await
            }
            0xFF => {
                Err(graftcp_common::GraftcpError::NetworkError(
                    "SOCKS5: No acceptable authentication methods".to_string()
                ))
            }
            _ => {
                Err(graftcp_common::GraftcpError::NetworkError(
                    "SOCKS5: Unsupported authentication method".to_string()
                ))
            }
        }
    }
    
    /// SOCKS5 username/password authentication
    async fn socks5_username_password_auth(&self, stream: &mut TcpStream) -> Result<()> {
        let username = self.socks5_username.as_ref().ok_or_else(|| {
            graftcp_common::GraftcpError::ConfigError("SOCKS5 username not configured".to_string())
        })?;
        let password = self.socks5_password.as_ref().ok_or_else(|| {
            graftcp_common::GraftcpError::ConfigError("SOCKS5 password not configured".to_string())
        })?;
        
        // Send username/password
        let mut auth_request = vec![0x01]; // Version
        auth_request.push(username.len() as u8);
        auth_request.extend_from_slice(username.as_bytes());
        auth_request.push(password.len() as u8);
        auth_request.extend_from_slice(password.as_bytes());
        
        stream.write_all(&auth_request).await?;
        
        // Read response
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;
        
        if response[0] != 0x01 {
            return Err(graftcp_common::GraftcpError::NetworkError(
                "Invalid username/password authentication version".to_string()
            ));
        }
        
        if response[1] != 0x00 {
            return Err(graftcp_common::GraftcpError::NetworkError(
                "SOCKS5 username/password authentication failed".to_string()
            ));
        }
        
        debug!("SOCKS5: Username/password authentication successful");
        Ok(())
    }
    
    /// SOCKS5 connect request
    async fn socks5_connect(&self, stream: &mut TcpStream, dest_addr: SocketAddr) -> Result<()> {
        let mut request = vec![0x05, 0x01, 0x00]; // VER, CMD (CONNECT), RSV
        
        // Add address type and address
        match dest_addr.ip() {
            IpAddr::V4(ipv4) => {
                request.push(0x01); // IPv4
                request.extend_from_slice(&ipv4.octets());
            }
            IpAddr::V6(ipv6) => {
                request.push(0x04); // IPv6
                request.extend_from_slice(&ipv6.octets());
            }
        }
        
        // Add port
        request.extend_from_slice(&dest_addr.port().to_be_bytes());
        
        stream.write_all(&request).await?;
        
        // Read response
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await?;
        
        if response[0] != 0x05 {
            return Err(graftcp_common::GraftcpError::NetworkError(
                "Invalid SOCKS5 version in connect response".to_string()
            ));
        }
        
        if response[1] != 0x00 {
            let error_msg = match response[1] {
                0x01 => "General SOCKS server failure",
                0x02 => "Connection not allowed by ruleset",
                0x03 => "Network unreachable",
                0x04 => "Host unreachable",
                0x05 => "Connection refused",
                0x06 => "TTL expired",
                0x07 => "Command not supported",
                0x08 => "Address type not supported",
                _ => "Unknown SOCKS5 error",
            };
            return Err(graftcp_common::GraftcpError::NetworkError(
                format!("SOCKS5 connect failed: {}", error_msg)
            ));
        }
        
        // Skip the bound address in the response
        match response[3] {
            0x01 => {
                // IPv4: 4 bytes IP + 2 bytes port
                let mut bound_addr = [0u8; 6];
                stream.read_exact(&mut bound_addr).await?;
            }
            0x03 => {
                // Domain name: 1 byte length + domain + 2 bytes port
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut domain_and_port = vec![0u8; len[0] as usize + 2];
                stream.read_exact(&mut domain_and_port).await?;
            }
            0x04 => {
                // IPv6: 16 bytes IP + 2 bytes port
                let mut bound_addr = [0u8; 18];
                stream.read_exact(&mut bound_addr).await?;
            }
            _ => {
                return Err(graftcp_common::GraftcpError::NetworkError(
                    "Unknown address type in SOCKS5 response".to_string()
                ));
            }
        }
        
        debug!("SOCKS5: Successfully connected to {}", dest_addr);
        Ok(())
    }
}