use graftcp_common::Result;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::os::unix::fs::OpenOptionsExt;
use tracing::{debug, warn};

/// FIFO communication manager for sending destination info to graftcp-local
pub struct FifoManager {
    fifo_path: String,
}

impl FifoManager {
    pub fn new(fifo_path: String) -> Self {
        Self { fifo_path }
    }
    
    /// Send destination address and PID to graftcp-local via FIFO
    pub fn send_destination_info(&self, dest_addr: &SocketAddr, pid: u32) -> Result<()> {
        // Format: "dest_ip:dest_port:pid"
        let message = format!("{}:{}\n", dest_addr, pid);
        
        debug!("Sending to FIFO: {}", message.trim());
        
        // Try to open FIFO for writing
        match self.write_to_fifo(&message) {
            Ok(()) => {
                debug!("Successfully sent destination info to graftcp-local");
                Ok(())
            }
            Err(e) => {
                warn!("Failed to send destination info via FIFO: {}", e);
                // Don't fail the whole operation if FIFO communication fails
                // The connection can still work without graftcp-local tracking
                Ok(())
            }
        }
    }
    
    /// Write message to FIFO
    fn write_to_fifo(&self, message: &str) -> Result<()> {
        // Check if FIFO exists
        if !Path::new(&self.fifo_path).exists() {
            return Err(graftcp_common::GraftcpError::ProcessError(
                format!("FIFO {} does not exist. Is graftcp-local running?", self.fifo_path)
            ));
        }
        
        // Open FIFO for writing (non-blocking)
        let mut file = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK) // Don't block if no reader
            .open(&self.fifo_path)
            .map_err(|e| graftcp_common::GraftcpError::ProcessError(
                format!("Failed to open FIFO {}: {}", self.fifo_path, e)
            ))?;
        
        // Write the message
        file.write_all(message.as_bytes())
            .map_err(|e| graftcp_common::GraftcpError::ProcessError(
                format!("Failed to write to FIFO: {}", e)
            ))?;
        
        file.flush()
            .map_err(|e| graftcp_common::GraftcpError::ProcessError(
                format!("Failed to flush FIFO: {}", e)
            ))?;
        
        Ok(())
    }
}