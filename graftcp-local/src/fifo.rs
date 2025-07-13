use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{info, error, debug, warn};
use graftcp_common::Result;
use crate::proc_tracker::ProcessTracker;

/// Start reading FIFO for destination address information from graftcp
pub async fn start_fifo_reader(
    fifo_path: &str,
    process_tracker: Arc<RwLock<ProcessTracker>>
) -> Result<()> {
    info!("Starting FIFO reader on {}", fifo_path);
    
    // Create FIFO if it doesn't exist
    create_fifo_if_not_exists(fifo_path)?;
    
    loop {
        match open_and_read_fifo(fifo_path, process_tracker.clone()).await {
            Ok(()) => {
                debug!("FIFO reader completed normally, restarting...");
            }
            Err(e) => {
                error!("FIFO reader error: {}, retrying in 1 second...", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
    }
}

/// Create FIFO if it doesn't exist
fn create_fifo_if_not_exists(fifo_path: &str) -> Result<()> {
    if !Path::new(fifo_path).exists() {
        info!("Creating FIFO at {}", fifo_path);
        
        // Use mkfifo system call
        let path_cstring = std::ffi::CString::new(fifo_path)
            .map_err(|e| graftcp_common::GraftcpError::ProcessError(
                format!("Invalid FIFO path: {}", e)
            ))?;
        
        unsafe {
            let result = libc::mkfifo(path_cstring.as_ptr(), 0o666);
            if result != 0 {
                let errno = *libc::__errno_location();
                if errno != libc::EEXIST { // Ignore if already exists
                    return Err(graftcp_common::GraftcpError::ProcessError(
                        format!("Failed to create FIFO {}: errno {}", fifo_path, errno)
                    ));
                }
            }
        }
        
        // Set permissions
        std::fs::set_permissions(fifo_path, std::os::unix::fs::PermissionsExt::from_mode(0o666))
            .map_err(|e| graftcp_common::GraftcpError::ProcessError(
                format!("Failed to set FIFO permissions: {}", e)
            ))?;
    }
    
    Ok(())
}

/// Open FIFO and read lines
async fn open_and_read_fifo(
    fifo_path: &str,
    process_tracker: Arc<RwLock<ProcessTracker>>
) -> Result<()> {
    debug!("Opening FIFO for reading: {}", fifo_path);
    
    // Open FIFO for reading (this will block until graftcp opens it for writing)
    let file = File::open(fifo_path).await
        .map_err(|e| graftcp_common::GraftcpError::ProcessError(
            format!("Failed to open FIFO {}: {}", fifo_path, e)
        ))?;
    
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    
    info!("FIFO opened successfully, reading destination info...");
    
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                // EOF reached, graftcp closed the FIFO
                debug!("FIFO EOF reached, graftcp closed connection");
                break;
            }
            Ok(_) => {
                let trimmed_line = line.trim();
                if !trimmed_line.is_empty() {
                    process_fifo_line(trimmed_line, process_tracker.clone()).await;
                }
            }
            Err(e) => {
                error!("Error reading from FIFO: {}", e);
                break;
            }
        }
    }
    
    Ok(())
}

/// Process a line from FIFO: "dest_ip:dest_port:pid"
async fn process_fifo_line(
    line: &str,
    process_tracker: Arc<RwLock<ProcessTracker>>
) {
    debug!("Processing FIFO line: {}", line);
    
    let parts: Vec<&str> = line.split(':').collect();
    
    if parts.len() < 3 {
        warn!("Invalid FIFO line format: {}", line);
        return;
    }
    
    let (pid, dest_addr) = if parts.len() > 3 {
        // IPv6 format: "ipv6:address:with:colons:port:pid"
        let pid = parts[parts.len() - 1];
        let port = parts[parts.len() - 2];
        let ip_parts = &parts[..parts.len() - 2];
        let ip = ip_parts.join(":");
        let dest_addr = format!("[{}]:{}", ip, port);
        (pid, dest_addr)
    } else {
        // IPv4 format: "ip:port:pid"
        let pid = parts[2];
        let dest_addr = format!("{}:{}", parts[0], parts[1]);
        (pid, dest_addr)
    };
    
    match dest_addr.parse() {
        Ok(socket_addr) => {
            debug!("Storing PID {} -> {}", pid, socket_addr);
            let mut tracker = process_tracker.write().await;
            tracker.store_pid_addr(pid.to_string(), socket_addr);
        }
        Err(e) => {
            warn!("Failed to parse destination address '{}': {}", dest_addr, e);
        }
    }
}