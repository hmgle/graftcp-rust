pub mod error;
pub mod types;
pub mod config;
pub mod fake_ip;

pub use error::{GraftcpError, Result};
pub use types::{SocketInfo, ProcessInfo, ProxyMode, Config, ConnectionInfo, MAGIC_FD, MAGIC_NUM};
pub use config::{load_config, get_config_search_paths};
pub use fake_ip::{
    encode_to_loopback_simple, 
    decode_from_loopback_simple, 
    is_loopback_encoded,
    encode_to_loopback_enhanced,
    encode_to_loopback,
    decode_from_loopback
};