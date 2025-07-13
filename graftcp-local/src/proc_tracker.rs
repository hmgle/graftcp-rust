use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::fs;
use tracing::{debug, warn};
use graftcp_common::Result;

/// Tracks process ID to destination address mappings
pub struct ProcessTracker {
    pid_to_addr: HashMap<String, SocketAddr>,
}

impl ProcessTracker {
    pub fn new() -> Self {
        Self {
            pid_to_addr: HashMap::new(),
        }
    }
    
    /// Store a PID -> destination address mapping from FIFO data
    pub fn store_pid_addr(&mut self, pid: String, dest_addr: SocketAddr) {
        debug!("Storing PID {} -> {}", pid, dest_addr);
        self.pid_to_addr.insert(pid, dest_addr);
    }
    
    /// Get and remove the destination address for a PID
    pub fn get_and_remove_dest_addr(&mut self, pid: &str) -> Option<SocketAddr> {
        self.pid_to_addr.remove(pid)
    }
    
    /// Find PID and destination address by connection information
    pub fn find_pid_and_dest_by_connection(
        &mut self, 
        local_addr: &SocketAddr,
        remote_addr: &SocketAddr
    ) -> Option<(String, SocketAddr)> {
        // Get inode for this connection from /proc/net/tcp
        let inode = match get_inode_by_addrs(local_addr, remote_addr) {
            Ok(inode) => inode,
            Err(e) => {
                warn!("Failed to get inode for {}→{}: {}", remote_addr, local_addr, e);
                return None;
            }
        };
        
        if inode.is_empty() {
            debug!("No inode found for connection {}→{}", remote_addr, local_addr);
            return None;
        }
        
        // Find PID that has this inode and get its destination
        for (pid, dest_addr) in &self.pid_to_addr {
            debug!("Checking PID {} for inode {}", pid, inode);
            if has_inode_in_pid(pid, &inode) {
                let result = (pid.clone(), *dest_addr);
                debug!("Found matching PID {} for inode {}", pid, inode);
                return Some(result);
            }
        }
        
        // Debug: Print all pid_to_addr mappings when no match is found
        warn!("No matching PID found for inode {} ({}→{})", inode, remote_addr, local_addr);
        warn!("Current pid_to_addr mappings ({} entries):", self.pid_to_addr.len());
        if self.pid_to_addr.is_empty() {
            warn!("  [No mappings stored]");
        } else {
            for (pid, dest) in &self.pid_to_addr {
                warn!("  PID {} → {}", pid, dest);
            }
        }
        
        None
    }
}

/// Get inode for a connection from /proc/net/tcp or /proc/net/tcp6
fn get_inode_by_addrs(local_addr: &SocketAddr, remote_addr: &SocketAddr) -> Result<String> {
    let is_ipv6 = matches!(local_addr.ip(), IpAddr::V6(_));
    let proc_path = if is_ipv6 { "/proc/net/tcp6" } else { "/proc/net/tcp" };
    
    let local_hex = addr_to_hex(local_addr);
    let remote_hex = addr_to_hex(remote_addr);
    
    debug!("Looking for connection {} -> {} in {}", remote_hex, local_hex, proc_path);
    
    let content = fs::read_to_string(proc_path)
        .map_err(|e| graftcp_common::GraftcpError::ProcessError(
            format!("Failed to read {}: {}", proc_path, e)
        ))?;
    
    for line in content.lines().skip(1) { // Skip header
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        
        let line_local = fields[1];
        let line_remote = fields[2];
        let line_inode = fields[9];
        
        // Debug: Show what we're comparing
        debug!("Comparing: target local={}, line local={}, target remote={}, line remote={}", 
               local_hex, line_local, remote_hex, line_remote);
        
        // Match both local and remote addresses
        if line_local == local_hex && line_remote == remote_hex {
            debug!("Found matching connection: {} -> {} with inode {}", 
                   line_remote, line_local, line_inode);
            return Ok(line_inode.to_string());
        }
    }
    
    // Debug: Print the entire proc file content when no match is found
    warn!("No inode found for connection {} -> {} in {}", remote_hex, local_hex, proc_path);
    warn!("Complete {} content:", proc_path);
    warn!("  Target: local={}, remote={}", local_hex, remote_hex);
    for (line_num, line) in content.lines().enumerate() {
        warn!("  Line {}: {}", line_num, line);
    }
    
    Ok(String::new())
}

/// Convert socket address to hex format used in /proc/net/tcp
fn addr_to_hex(addr: &SocketAddr) -> String {
    match addr.ip() {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            let ip_hex = format!("{:02X}{:02X}{:02X}{:02X}", 
                                octets[3], octets[2], octets[1], octets[0]);
            let port_hex = format!("{:04X}", addr.port());
            format!("{}:{}", ip_hex, port_hex)
        }
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            let mut ip_hex = String::new();
            // IPv6 addresses are stored in a specific format in /proc/net/tcp6
            for i in (0..8).rev() {
                ip_hex.push_str(&format!("{:04X}", segments[i]));
            }
            let port_hex = format!("{:04X}", addr.port());
            format!("{}:{}", ip_hex, port_hex)
        }
    }
}

/// Check if a PID has a file descriptor pointing to the given inode
fn has_inode_in_pid(pid: &str, inode: &str) -> bool {
    let fd_pattern = format!("/proc/{}/fd", pid);
    debug!("Checking for inode {} in {}", inode, fd_pattern);
    
    let fd_dir = match fs::read_dir(&fd_pattern) {
        Ok(dir) => dir,
        Err(e) => {
            debug!("Failed to read {}: {}, trying task subdirectories", fd_pattern, e);
            // Try task subdirectories if main PID dir fails
            return check_task_fds(pid, inode);
        }
    };
    
    for entry in fd_dir.flatten() {
        if let Ok(link) = fs::read_link(entry.path()) {
            if let Some(link_str) = link.to_str() {
                debug!("Checking fd {} -> {}", entry.file_name().to_string_lossy(), link_str);
                if link_str.contains(&format!("socket:[{}]", inode)) {
                    debug!("Found inode {} in PID {} fd {}", inode, pid, entry.file_name().to_string_lossy());
                    return true;
                }
            }
        }
    }
    
    debug!("Inode {} not found in PID {} fds", inode, pid);
    false
}

/// Check task subdirectories for the inode (for threads)
fn check_task_fds(pid: &str, inode: &str) -> bool {
    let tasks_pattern = format!("/proc/*/task/{}/fd", pid);
    let tasks_glob = match glob::glob(&tasks_pattern) {
        Ok(paths) => paths,
        Err(e) => {
            debug!("Failed to glob tasks for PID {}: {}", pid, e);
            return false;
        }
    };
    
    for task_fd_path in tasks_glob.flatten() {
        if let Ok(fd_dir) = fs::read_dir(&task_fd_path) {
            for entry in fd_dir.flatten() {
                if let Ok(link) = fs::read_link(entry.path()) {
                    if let Some(link_str) = link.to_str() {
                        if link_str.contains(&format!("socket:[{}]", inode)) {
                            debug!("Found inode {} in task fd {}", inode, entry.path().display());
                            return true;
                        }
                    }
                }
            }
        }
    }
    
    false
}
