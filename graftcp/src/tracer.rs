use crate::ptrace::PtraceManager;
use crate::fifo::FifoManager;
use graftcp_common::{Result, ProcessInfo, SocketInfo};
use nix::sys::wait::WaitStatus;
use nix::unistd::{fork, ForkResult, Pid};
use nix::sys::ptrace;
use std::collections::HashMap;
use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr, IpAddr};
use std::os::raw::c_int;
use std::ffi::CString;
use tracing::{debug, info, error, warn};

/// Socket domain constants
const AF_INET: c_int = 2;
const AF_INET6: c_int = 10;

/// Socket type constants  
const SOCK_STREAM: c_int = 1;

/// Main tracer that manages process execution and syscall interception
pub struct Tracer {
    process_info: HashMap<u32, ProcessInfo>,
    socket_info: HashMap<u64, SocketInfo>,
    local_addr: String,
    local_port: u16,
    ignore_local: bool,
    fifo_manager: FifoManager,
}

impl Tracer {
    pub fn new(local_addr: String, local_port: u16, ignore_local: bool, fifo_path: String) -> Self {
        Self {
            process_info: HashMap::new(),
            socket_info: HashMap::new(),
            local_addr,
            local_port,
            ignore_local,
            fifo_manager: FifoManager::new(fifo_path),
        }
    }
    
    /// Start tracing a program with given arguments
    pub fn start_trace(&mut self, program: &str, args: &[String]) -> Result<()> {
        info!("Starting to trace program: {} with args: {:?}", program, args);
        
        // Fork to create child process
        match unsafe { fork() }? {
            ForkResult::Parent { child } => {
                info!("Parent process: tracing child PID {}", child);
                self.trace_child(child)
            }
            ForkResult::Child => {
                // Child process: enable tracing and exec
                debug!("Child process: enabling ptrace and executing program");
                
                // Allow parent to trace this process
                ptrace::traceme()?;
                
                // Induce a ptrace stop like the C version does
                // This ensures the parent can set up tracing before we exec
                let pid = nix::unistd::getpid();
                nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGSTOP)?;
                
                // Execute the target program using execvp (searches PATH)
                let program_cstring = CString::new(program)
                    .map_err(|e| graftcp_common::GraftcpError::ProcessError(
                        format!("Invalid program name: {}", e)
                    ))?;
                
                // Build args array with program name as first argument (Unix convention)
                let mut all_args = vec![program.to_string()];
                all_args.extend_from_slice(args);
                
                let args_cstrings: Result<Vec<CString>> = all_args.iter()
                    .map(|arg| CString::new(arg.as_str())
                        .map_err(|e| graftcp_common::GraftcpError::ProcessError(
                            format!("Invalid argument: {}", e)
                        )))
                    .collect();
                
                let args_cstrings = args_cstrings?;
                
                // Use execvp to search PATH for the program
                nix::unistd::execvp(&program_cstring, &args_cstrings)
                    .map_err(|e| graftcp_common::GraftcpError::ProcessError(
                        format!("Failed to execute program: {}", e)
                    ))?;
                
                unreachable!("execv should not return");
            }
        }
    }
    
    /// Main tracing loop for child process
    fn trace_child(&mut self, child_pid: Pid) -> Result<()> {
        // Wait for initial stop and set up tracing
        match nix::sys::wait::waitpid(child_pid, None)? {
            WaitStatus::Stopped(_, _) => {
                debug!("Child process {} stopped initially", child_pid);
                
                // Set ptrace options
                ptrace::setoptions(
                    child_pid,
                    ptrace::Options::PTRACE_O_TRACECLONE
                        | ptrace::Options::PTRACE_O_TRACEEXEC
                        | ptrace::Options::PTRACE_O_TRACEFORK
                        | ptrace::Options::PTRACE_O_TRACEVFORK
                        | ptrace::Options::PTRACE_O_TRACESYSGOOD,
                )?;
                
                // Start syscall tracing
                ptrace::syscall(child_pid, None)?;
            }
            status => {
                error!("Unexpected initial status: {:?}", status);
                return Err(graftcp_common::GraftcpError::PtraceError(
                    format!("Unexpected initial wait status: {:?}", status)
                ));
            }
        }
        
        // Add process to tracking
        self.process_info.insert(child_pid.as_raw() as u32, ProcessInfo {
            pid: child_pid.as_raw() as u32,
            flags: 0,
            current_syscall_number: 0,
            current_writing_socket: None,
        });
        
        // Main tracing loop
        loop {
            match nix::sys::wait::waitpid(child_pid, None)? {
                WaitStatus::Exited(pid, exit_code) => {
                    info!("Process {} exited with code {}", pid, exit_code);
                    self.handle_process_exit(pid.as_raw() as u32)?;
                    break;
                }
                WaitStatus::Signaled(pid, signal, _) => {
                    info!("Process {} was killed by signal {:?}", pid, signal);
                    self.handle_process_exit(pid.as_raw() as u32)?;
                    break;
                }
                WaitStatus::Stopped(pid, signal) => {
                    debug!("Process {} stopped with signal {:?}", pid, signal);
                    
                    // Check if this is a syscall stop (SIGTRAP | 0x80)
                    if signal == nix::sys::signal::Signal::SIGTRAP {
                        // Handle syscall entry/exit
                        let ptrace_mgr = PtraceManager::new(pid);
                        self.handle_syscall(&ptrace_mgr, pid.as_raw() as u32)?;
                    }
                    
                    // Continue execution
                    ptrace::syscall(pid, None)?;
                }
                WaitStatus::PtraceEvent(pid, _, event) => {
                    debug!("Process {} ptrace event: {}", pid, event);
                    // Handle clone, fork, exec events
                    ptrace::syscall(pid, None)?;
                }
                WaitStatus::PtraceSyscall(pid) => {
                    debug!("Process {} syscall stop", pid);
                    let ptrace_mgr = PtraceManager::new(pid);
                    self.handle_syscall(&ptrace_mgr, pid.as_raw() as u32)?;
                    ptrace::syscall(pid, None)?;
                }
                status => {
                    debug!("Unhandled wait status: {:?}", status);
                    ptrace::syscall(child_pid, None)?;
                }
            }
        }
        
        Ok(())
    }
    
    /// Handle system call entry/exit
    fn handle_syscall(&mut self, ptrace_mgr: &PtraceManager, pid: u32) -> Result<()> {
        let process_info = self.process_info.get_mut(&pid);
        if process_info.is_none() {
            debug!("Process {} not found in tracking", pid);
            return Ok(());
        }
        
        // Determine if this is syscall entry or exit
        let is_syscall_entry = process_info.unwrap().flags & 0x1 == 0;
        
        if is_syscall_entry {
            // Syscall entry - check if we need to intercept
            
            // Try to get syscall number, but don't fail if we can't
            match ptrace_mgr.get_syscall_number() {
                Ok(syscall_num) => {
                    // Only log network-related syscalls to reduce spam
                    if syscall_num == 41 || syscall_num == 42 || syscall_num == 3 { // socket, connect, close
                        debug!("Syscall entry: {}", syscall_num);
                    }
                    
                    // Check specific syscalls
                    if ptrace_mgr.is_connect_syscall().unwrap_or(false) {
                        debug!("Intercepting connect() syscall for PID {}", pid);
                        if let Err(e) = self.handle_connect_syscall(ptrace_mgr, pid) {
                            warn!("Failed to handle connect syscall: {}", e);
                        }
                    } else if ptrace_mgr.is_socket_syscall().unwrap_or(false) {
                        debug!("Tracking socket() syscall for PID {}", pid);
                        if let Err(e) = self.handle_socket_syscall(ptrace_mgr, pid) {
                            warn!("Failed to handle socket syscall: {}", e);
                        }
                    } else if ptrace_mgr.is_close_syscall().unwrap_or(false) {
                        debug!("Tracking close() syscall for PID {}", pid);
                        if let Err(e) = self.handle_close_syscall(ptrace_mgr, pid) {
                            warn!("Failed to handle close syscall: {}", e);
                        }
                    }
                }
                Err(_) => {
                    // Don't spam the logs with syscall read errors
                    // Most syscalls will fail to read due to timing/permissions
                }
            }
            
            // Update flags to indicate we're in syscall
            if let Some(proc_info) = self.process_info.get_mut(&pid) {
                proc_info.flags |= 0x1;
            }
        } else {
            // Syscall exit - handle socket() return value
            match ptrace_mgr.get_syscall_number() {
                Ok(_) => {
                    if ptrace_mgr.is_socket_syscall().unwrap_or(false) {
                        if let Err(e) = self.handle_socket_syscall_exit(ptrace_mgr, pid) {
                            warn!("Failed to handle socket syscall exit: {}", e);
                        }
                    }
                }
                Err(_) => {
                    // Ignore errors reading syscall number on exit
                }
            }
            
            // Reset flags
            if let Some(proc_info) = self.process_info.get_mut(&pid) {
                proc_info.flags &= !0x1;
            }
        }
        
        Ok(())
    }
    
    /// Handle connect() system call
    fn handle_connect_syscall(&mut self, ptrace_mgr: &PtraceManager, pid: u32) -> Result<()> {
        // Get connect() arguments: connect(sockfd, addr, addrlen)
        let sockfd = ptrace_mgr.get_syscall_arg(0)? as c_int;
        let addr_ptr = ptrace_mgr.get_syscall_arg(1)?;
        let addrlen = ptrace_mgr.get_syscall_arg(2)? as u32;
        
        debug!("connect() called: sockfd={}, addr_ptr=0x{:x}, addrlen={}", 
               sockfd, addr_ptr, addrlen);
        
        // Check if this socket was tracked as a TCP socket
        let socket_key = ((sockfd as u64) << 31) + (pid as u64);
        if !self.socket_info.contains_key(&socket_key) {
            debug!("Socket fd {} not tracked as TCP socket, ignoring connect", sockfd);
            return Ok(());
        }
        
        // Read the socket address from traced process memory
        let addr_data = ptrace_mgr.read_data(addr_ptr, addrlen as usize)?;
        
        if addr_data.len() < 2 {
            warn!("Invalid socket address data length: {}", addr_data.len());
            return Ok(());
        }
        
        // Parse socket address family
        let family = u16::from_ne_bytes([addr_data[0], addr_data[1]]) as c_int;
        
        let dest_addr = match family {
            AF_INET => {
                if addr_data.len() < 8 {
                    warn!("Invalid IPv4 socket address length: {}", addr_data.len());
                    return Ok(());
                }
                
                // Parse sockaddr_in structure
                let port = u16::from_be_bytes([addr_data[2], addr_data[3]]);
                let ip_bytes = [addr_data[4], addr_data[5], addr_data[6], addr_data[7]];
                let ip = Ipv4Addr::from(ip_bytes);
                
                SocketAddr::new(ip.into(), port)
            }
            AF_INET6 => {
                if addr_data.len() < 28 {
                    warn!("Invalid IPv6 socket address length: {}", addr_data.len());
                    return Ok(());
                }
                
                // Parse sockaddr_in6 structure
                let port = u16::from_be_bytes([addr_data[2], addr_data[3]]);
                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&addr_data[8..24]);
                let ip = Ipv6Addr::from(ip_bytes);
                
                SocketAddr::new(ip.into(), port)
            }
            _ => {
                debug!("Unsupported address family: {}", family);
                return Ok(());
            }
        };
        
        info!("Original destination: {}", dest_addr);
        
        // Check if we should ignore this connection
        if self.should_ignore_connection(&dest_addr) {
            debug!("Ignoring connection to {}", dest_addr);
            return Ok(());
        }
        
        // Use fake IP approach instead of FIFO communication
        use graftcp_common::{allocate_fake_ip, is_fake_ip};
        use std::net::{IpAddr, Ipv4Addr};
        
        // Allocate a fake IP for this destination
        let fake_ip = match allocate_fake_ip(dest_addr) {
            Ok(ip) => ip,
            Err(e) => {
                error!("Failed to allocate fake IP for {}: {}", dest_addr, e);
                return Ok(());
            }
        };
        
        info!("Allocated fake IP {} for real destination {}", fake_ip, dest_addr);
        
        // Send fake IP info to graftcp-local via FIFO 
        // This tells the server: "when you see a connection with this fake IP, resolve it"
        if let Err(e) = self.fifo_manager.send_destination_info(&SocketAddr::new(IpAddr::V4(fake_ip), dest_addr.port()), pid) {
            warn!("Failed to send fake IP info to graftcp-local: {}", e);
            // Continue anyway - we still have the global mapping
        }
        
        // Create new socket address pointing to our local proxy 
        let proxy_addr = self.create_proxy_socket_addr(family)?;
        
        // Modify the connect() arguments to redirect to our proxy
        if let Err(e) = self.redirect_connect_to_proxy(ptrace_mgr, addr_ptr, &proxy_addr, family) {
            error!("Failed to redirect connection: {}", e);
            return Ok(()); // Don't fail the whole process
        }
        
        info!("Redirected {} to fake IP {} via {}:{}", dest_addr, fake_ip, self.local_addr, self.local_port);
        
        Ok(())
    }
    
    /// Create socket address for the local proxy
    fn create_proxy_socket_addr(&self, family: c_int) -> Result<SocketAddr> {
        let proxy_ip: IpAddr = match family {
            AF_INET => {
                // Parse IPv4 address
                let addr = self.local_addr.parse::<Ipv4Addr>()
                    .or_else(|_| {
                        // Try to resolve hostname
                        std::net::ToSocketAddrs::to_socket_addrs(&format!("{}:0", self.local_addr))
                            .map_err(|e| graftcp_common::GraftcpError::NetworkError(
                                format!("Failed to resolve hostname {}: {}", self.local_addr, e)
                            ))?
                            .find(|addr| addr.is_ipv4())
                            .map(|addr| match addr.ip() {
                                IpAddr::V4(ipv4) => ipv4,
                                _ => unreachable!(),
                            })
                            .ok_or_else(|| graftcp_common::GraftcpError::NetworkError(
                                format!("No IPv4 address found for {}", self.local_addr)
                            ))
                    })?;
                IpAddr::V4(addr)
            }
            AF_INET6 => {
                // For IPv6, try to parse as IPv6 address or resolve
                let addr = self.local_addr.parse::<Ipv6Addr>()
                    .or_else(|_| {
                        // Try to resolve hostname for IPv6
                        std::net::ToSocketAddrs::to_socket_addrs(&format!("{}:0", self.local_addr))
                            .map_err(|e| graftcp_common::GraftcpError::NetworkError(
                                format!("Failed to resolve hostname {}: {}", self.local_addr, e)
                            ))?
                            .find(|addr| addr.is_ipv6())
                            .map(|addr| match addr.ip() {
                                IpAddr::V6(ipv6) => ipv6,
                                _ => unreachable!(),
                            })
                            .ok_or_else(|| graftcp_common::GraftcpError::NetworkError(
                                format!("No IPv6 address found for {}", self.local_addr)
                            ))
                    })?;
                IpAddr::V6(addr)
            }
            _ => {
                return Err(graftcp_common::GraftcpError::NetworkError(
                    format!("Unsupported address family: {}", family)
                ));
            }
        };
        
        Ok(SocketAddr::new(proxy_ip, self.local_port))
    }
    
    /// Modify connect() arguments to redirect to proxy
    fn redirect_connect_to_proxy(
        &self,
        ptrace_mgr: &PtraceManager,
        addr_ptr: u64,
        proxy_addr: &SocketAddr,
        family: c_int,
    ) -> Result<()> {
        match family {
            AF_INET => {
                // Create sockaddr_in structure for IPv4
                let mut sockaddr_in = vec![0u8; 16]; // sizeof(struct sockaddr_in)
                
                // Fill in the structure
                sockaddr_in[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
                
                if let IpAddr::V4(ipv4) = proxy_addr.ip() {
                    sockaddr_in[2..4].copy_from_slice(&proxy_addr.port().to_be_bytes());
                    sockaddr_in[4..8].copy_from_slice(&ipv4.octets());
                    // Rest is already zeroed
                } else {
                    return Err(graftcp_common::GraftcpError::NetworkError(
                        "IPv4 address expected but got IPv6".to_string()
                    ));
                }
                
                // Write the modified address structure back to process memory
                ptrace_mgr.write_data(addr_ptr, &sockaddr_in)?;
            }
            AF_INET6 => {
                // Create sockaddr_in6 structure for IPv6
                let mut sockaddr_in6 = vec![0u8; 28]; // sizeof(struct sockaddr_in6)
                
                // Fill in the structure
                sockaddr_in6[0..2].copy_from_slice(&(AF_INET6 as u16).to_ne_bytes());
                
                if let IpAddr::V6(ipv6) = proxy_addr.ip() {
                    sockaddr_in6[2..4].copy_from_slice(&proxy_addr.port().to_be_bytes());
                    // Skip flowinfo (4 bytes)
                    sockaddr_in6[8..24].copy_from_slice(&ipv6.octets());
                    // Skip scope_id (4 bytes)
                } else {
                    return Err(graftcp_common::GraftcpError::NetworkError(
                        "IPv6 address expected but got IPv4".to_string()
                    ));
                }
                
                // Write the modified address structure back to process memory
                ptrace_mgr.write_data(addr_ptr, &sockaddr_in6)?;
            }
            _ => {
                return Err(graftcp_common::GraftcpError::NetworkError(
                    format!("Unsupported address family: {}", family)
                ));
            }
        }
        
        debug!("Successfully modified connect() target to {}", proxy_addr);
        Ok(())
    }
    
    /// Handle socket() system call to track new sockets
    fn handle_socket_syscall(&mut self, ptrace_mgr: &PtraceManager, pid: u32) -> Result<()> {
        let domain = ptrace_mgr.get_syscall_arg(0)? as c_int;
        let socket_type = ptrace_mgr.get_syscall_arg(1)? as c_int;
        let protocol = ptrace_mgr.get_syscall_arg(2)? as c_int;
        
        debug!("socket() called: domain={}, type={}, protocol={}", 
               domain, socket_type, protocol);
        
        // Only track TCP sockets
        if (domain == AF_INET || domain == AF_INET6) && (socket_type & SOCK_STREAM) != 0 {
            debug!("Tracking TCP socket for PID {}", pid);
            
            // Create socket info with temporary magic_fd, similar to C implementation
            let socket_info = SocketInfo {
                pid,
                fd: -1, // Will be set when socket() returns
                magic_fd: (graftcp_common::MAGIC_FD << 31) + (pid as u64),
                domain,
                socket_type,
                connect_time: std::time::SystemTime::now(),
            };
            
            // Store with magic_fd key for now
            self.socket_info.insert(socket_info.magic_fd, socket_info);
        }
        
        Ok(())
    }
    
    /// Handle socket() system call exit to get the actual file descriptor
    fn handle_socket_syscall_exit(&mut self, ptrace_mgr: &PtraceManager, pid: u32) -> Result<()> {
        // Try to get the return value (file descriptor) using the more reliable getregs method
        match ptrace_mgr.get_retval_via_getregs() {
            Ok(fd) if fd >= 0 => {
                let magic_fd = (graftcp_common::MAGIC_FD << 31) + (pid as u64);
                
                // Find the socket info with the magic_fd
                if let Some(mut socket_info) = self.socket_info.remove(&magic_fd) {
                    debug!("Socket {} returned fd {}, updating tracking", pid, fd);
                    
                    // Update the socket info with actual fd
                    socket_info.fd = fd as i32;
                    let new_key = ((fd as u64) << 31) + (pid as u64);
                    socket_info.magic_fd = new_key;
                    
                    // Re-insert with new key
                    self.socket_info.insert(new_key, socket_info);
                } else {
                    debug!("No pending socket info found for pid {}, fd {}", pid, fd);
                }
            }
            Ok(fd) => {
                debug!("Socket creation failed with return value: {}", fd);
                // Remove the temporary entry since socket creation failed
                let magic_fd = (graftcp_common::MAGIC_FD << 31) + (pid as u64);
                self.socket_info.remove(&magic_fd);
            }
            Err(e) => {
                debug!("Failed to get socket return value: {}", e);
                // Clean up temporary entry - this is normal if the socket wasn't tracked
                let magic_fd = (graftcp_common::MAGIC_FD << 31) + (pid as u64);
                if self.socket_info.remove(&magic_fd).is_some() {
                    debug!("Cleaned up tracked socket due to read error for pid {}", pid);
                }
            }
        }
        
        Ok(())
    }
    
    /// Handle close() system call for cleanup
    fn handle_close_syscall(&mut self, ptrace_mgr: &PtraceManager, pid: u32) -> Result<()> {
        let fd = ptrace_mgr.get_syscall_arg(0)? as c_int;
        debug!("close() called: fd={}", fd);
        
        // Clean up socket tracking for this fd
        let socket_key = ((fd as u64) << 31) + (pid as u64);
        if let Some(_socket_info) = self.socket_info.remove(&socket_key) {
            debug!("Removed socket tracking for fd {} (pid {})", fd, pid);
            
            // Add delay similar to C implementation to prevent premature connection closure
            use std::time::Duration;
            std::thread::sleep(Duration::from_millis(500)); // MIN_CLOSE_MSEC equivalent
        }
        
        Ok(())
    }
    
    /// Handle process exit/cleanup
    fn handle_process_exit(&mut self, pid: u32) -> Result<()> {
        debug!("Cleaning up process {}", pid);
        self.process_info.remove(&pid);
        
        // Clean up associated socket info for this process
        let keys_to_remove: Vec<u64> = self.socket_info
            .iter()
            .filter(|(_, socket_info)| socket_info.pid == pid)
            .map(|(key, _)| *key)
            .collect();
        
        for key in keys_to_remove {
            self.socket_info.remove(&key);
            debug!("Removed socket info for dead process {}", pid);
        }
        
        Ok(())
    }
    
    /// Check if we should ignore this connection
    fn should_ignore_connection(&self, addr: &SocketAddr) -> bool {
        if self.ignore_local {
            // Ignore localhost connections
            match addr.ip() {
                std::net::IpAddr::V4(ipv4) => {
                    if ipv4.is_loopback() {
                        return true;
                    }
                }
                std::net::IpAddr::V6(ipv6) => {
                    if ipv6.is_loopback() {
                        return true;
                    }
                }
            }
        }
        
        // TODO: Check blacklist/whitelist
        
        false
    }
}