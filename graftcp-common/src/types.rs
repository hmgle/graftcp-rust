use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

/// Socket information for tracking connections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketInfo {
    pub pid: u32,
    pub fd: i32,
    pub magic_fd: u64,
    pub domain: i32,
    pub socket_type: i32,
    pub connect_time: std::time::SystemTime,
}

/// Process information for ptrace tracking
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub flags: u32,
    pub current_syscall_number: i32,
    pub current_writing_socket: Option<SocketInfo>,
}

/// Configuration for proxy selection modes
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub enum ProxyMode {
    #[default]
    Auto,
    Random,
    OnlySocks5,
    OnlyHttpProxy,
    Direct,
}

/// Configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub socks5_addr: Option<SocketAddr>,
    pub socks5_username: Option<String>,
    pub socks5_password: Option<String>,
    pub http_proxy_addr: Option<SocketAddr>,
    pub proxy_mode: ProxyMode,
    pub blacklist_ips: Vec<IpAddr>,
    pub whitelist_ips: Vec<IpAddr>,
    pub ignore_local: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen_addr: "127.0.0.1:2233".parse().unwrap(),
            socks5_addr: Some("127.0.0.1:1080".parse().unwrap()),
            socks5_username: None,
            socks5_password: None,
            http_proxy_addr: None,
            
            proxy_mode: ProxyMode::Auto,
            blacklist_ips: Vec::new(),
            whitelist_ips: Vec::new(),
            ignore_local: true,
        }
    }
}

/// Message format for communication between graftcp and graftcp-local
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub pid: u32,
    pub dest_addr: SocketAddr,
}

/// Constants
pub const MAGIC_FD: u64 = 7777777;
pub const MAGIC_NUM: u32 = 3579;