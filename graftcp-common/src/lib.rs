pub mod error;
pub mod types;
pub mod config;
pub mod fake_ip;

pub use error::{GraftcpError, Result};
pub use types::{SocketInfo, ProcessInfo, ProxyMode, Config, ConnectionInfo, MAGIC_FD, MAGIC_NUM};
pub use config::{load_config, get_config_search_paths};
pub use fake_ip::{
    allocate_loopback_ip, 
    resolve_loopback_ip, 
    is_loopback_ip,
    release_loopback_ip,
    get_loopback_stats
};