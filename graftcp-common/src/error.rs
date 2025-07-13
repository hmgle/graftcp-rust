use thiserror::Error;

/// Common error types used across graftcp components
#[derive(Error, Debug)]
pub enum GraftcpError {
    #[error("ptrace operation failed: {0}")]
    PtraceError(String),
    
    #[error("system call error: {0}")]
    SystemCallError(#[from] nix::Error),
    
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("network error: {0}")]
    NetworkError(String),
    
    #[error("configuration error: {0}")]
    ConfigError(String),
    
    #[error("process error: {0}")]
    ProcessError(String),
    
    #[error("address parse error: {0}")]
    AddrParseError(#[from] std::net::AddrParseError),
}

pub type Result<T> = std::result::Result<T, GraftcpError>;