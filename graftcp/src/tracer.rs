use crate::ptrace::PtraceManager;

use graftcp_common::{Result, ProcessInfo, SocketInfo};
use graftcp_common::{allocate_loopback_ip, is_loopback_ip};
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
    /// Storage for original connect() arguments during syscall hook
    /// Key: PID, Value: (original_addr_ptr, original_addr_data, allocated_loopback_ip)
    pending_connects: HashMap<u32, (u64, Vec<u8>, Ipv4Addr)>,
    /// Track pending socket fd updates for seccomp events
    pending_socket_for_fd_update: HashMap<u32, bool>,
}

impl Tracer {
    pub fn new(local_addr: String, local_port: u16, ignore_local: bool) -> Self {
        Self {
            process_info: HashMap::new(),
            socket_info: HashMap::new(),
            local_addr,
            local_port,
            ignore_local,
            pending_connects: HashMap::new(),
            pending_socket_for_fd_update: HashMap::new(),
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
                // Child process: install seccomp filter, enable tracing and exec
                debug!("Child process: installing seccomp, enabling ptrace and executing program");
                
                // Install seccomp BPF filter BEFORE enabling ptrace
                // This ensures we only get traced for the syscalls we care about
                if let Err(e) = crate::seccomp::install_seccomp_filter() {
                    error!("Failed to install seccomp filter: {}", e);
                    std::process::exit(1);
                }
                
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
                
                // Set ptrace options - only seccomp tracing for syscalls
                ptrace::setoptions(
                    child_pid,
                    ptrace::Options::PTRACE_O_TRACECLONE
                        | ptrace::Options::PTRACE_O_TRACEEXEC
                        | ptrace::Options::PTRACE_O_TRACEFORK
                        | ptrace::Options::PTRACE_O_TRACEVFORK
                        | ptrace::Options::PTRACE_O_TRACESECCOMP, // Enable seccomp event tracing
                )?;
                
                // Start with PTRACE_CONT instead of PTRACE_SYSCALL when using seccomp
                // The seccomp filter will generate events for the syscalls we care about
                ptrace::cont(child_pid, None)?;
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
        info!("🚀 Starting main ptrace loop for PID {}", child_pid);
        loop {
            debug!("⏳ Waiting for events from PID {}", child_pid);
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
                    
                    // With seccomp filtering, we should rarely get SIGTRAP for syscalls
                    // Most syscalls are handled via PTRACE_EVENT_SECCOMP
                    if signal == nix::sys::signal::Signal::SIGTRAP {
                        debug!("Unexpected SIGTRAP for PID {} - using fallback syscall handling", pid);
                        let ptrace_mgr = PtraceManager::new(pid);
                        self.handle_syscall(&ptrace_mgr, pid.as_raw() as u32)?;
                    } else {
                        debug!("Non-SIGTRAP signal: {:?} for PID {}", signal, pid);
                    }
                    
                    // Continue execution
                    ptrace::cont(pid, None)?;
                }
                WaitStatus::PtraceEvent(pid, _, event) => {
                    debug!("Process {} ptrace event: {} (0x{:x})", pid, event, event);
                    
                    // Check if this is a seccomp event - this is our primary syscall handling path
                    if event == libc::PTRACE_EVENT_SECCOMP {
                        info!("🔥 SECCOMP event for PID {}", pid);
                        if let Some(trace_data) = crate::seccomp::get_seccomp_trace_data(pid) {
                            let syscall_name = crate::seccomp::trace_data_to_syscall_name(trace_data);
                            info!("🎯 Seccomp intercepted {} syscall (trace_data={})", syscall_name, trace_data);
                            
                            let ptrace_mgr = PtraceManager::new(pid);
                            self.handle_seccomp_syscall(&ptrace_mgr, pid.as_raw() as u32, trace_data)?;
                        } else {
                            warn!("⚠️  Seccomp event but failed to get trace data for PID {}", pid);
                        }
                    } else {
                        // Handle process lifecycle events (clone, fork, exec, etc.)
                        debug!("Process lifecycle event: {} (0x{:x}) for pid {}", event, event, pid);
                        
                        match event {
                            libc::PTRACE_EVENT_FORK => debug!("   → PTRACE_EVENT_FORK"),
                            libc::PTRACE_EVENT_VFORK => debug!("   → PTRACE_EVENT_VFORK"),
                            libc::PTRACE_EVENT_CLONE => debug!("   → PTRACE_EVENT_CLONE"),
                            libc::PTRACE_EVENT_EXEC => debug!("   → PTRACE_EVENT_EXEC"),
                            libc::PTRACE_EVENT_VFORK_DONE => debug!("   → PTRACE_EVENT_VFORK_DONE"),
                            libc::PTRACE_EVENT_EXIT => debug!("   → PTRACE_EVENT_EXIT"),
                            _ => debug!("   → Unknown event type: {}", event),
                        }
                    }
                    
                    ptrace::cont(pid, None)?;
                }
                WaitStatus::PtraceSyscall(pid) => {
                    // This should not happen with seccomp filtering enabled
                    warn!("Unexpected PtraceSyscall event for PID {} - seccomp should handle syscalls", pid);
                    ptrace::cont(pid, None)?;
                }
                status => {
                    debug!("Unhandled wait status: {:?}", status);
                    ptrace::cont(child_pid, None)?;
                }
            }
        }
        
        Ok(())
    }
    
    /// Handle seccomp-triggered syscall events
    /// This is called when seccomp BPF filter triggers a SECCOMP_RET_TRACE for specific syscalls
    fn handle_seccomp_syscall(&mut self, ptrace_mgr: &PtraceManager, pid: u32, trace_data: u64) -> Result<()> {
        info!("📋 Handling seccomp syscall for PID {} with trace_data {}", pid, trace_data);
        
        match trace_data {
            1 => {
                // socket() syscall
                info!("🔌 Handling socket() syscall via seccomp for PID {}", pid);
                
                // Log syscall arguments for debugging
                if let Ok(domain) = ptrace_mgr.get_syscall_arg(0) {
                    if let Ok(socket_type) = ptrace_mgr.get_syscall_arg(1) {
                        if let Ok(protocol) = ptrace_mgr.get_syscall_arg(2) {
                            info!("   → socket({}, {}, {}) called by PID {}", domain, socket_type, protocol, pid);
                        }
                    }
                }
                
                // Handle socket syscall entry (tracking) - only for TCP sockets
                if let Err(e) = self.handle_socket_syscall(ptrace_mgr, pid) {
                    warn!("Failed to handle socket syscall: {}", e);
                }
                
                // For seccomp, we need to also handle socket return value
                // We'll use a simple approach: assume socket() succeeds and track the fd
                // when we see the next syscall or event from this process
                self.pending_socket_for_fd_update.insert(pid, true);
            }
            2 => {
                // connect() syscall  
                info!("🌐 Handling connect() syscall via seccomp for PID {}", pid);
                
                // Log syscall arguments for debugging
                if let Ok(sockfd) = ptrace_mgr.get_syscall_arg(0) {
                    if let Ok(addr_ptr) = ptrace_mgr.get_syscall_arg(1) {
                        if let Ok(addrlen) = ptrace_mgr.get_syscall_arg(2) {
                            info!("   → connect({}, 0x{:x}, {}) called by PID {}", sockfd, addr_ptr, addrlen, pid);
                        }
                    }
                }
                
                if let Err(e) = self.handle_connect_syscall(ptrace_mgr, pid) {
                    warn!("Failed to handle connect syscall: {}", e);
                }
            }
            3 => {
                // close() syscall
                info!("❌ Handling close() syscall via seccomp for PID {}", pid);
                
                // Log syscall arguments for debugging
                if let Ok(fd) = ptrace_mgr.get_syscall_arg(0) {
                    info!("   → close({}) called by PID {}", fd, pid);
                }
                
                if let Err(e) = self.handle_close_syscall(ptrace_mgr, pid) {
                    warn!("Failed to handle close syscall: {}", e);
                }
            }
            4 => {
                // clone() syscall (x86_64 only)
                #[cfg(target_arch = "x86_64")]
                {
                    info!("👥 Handling clone() syscall via seccomp for PID {}", pid);
                    
                    // Log syscall arguments for debugging
                    if let Ok(flags) = ptrace_mgr.get_syscall_arg(0) {
                        info!("   → clone(0x{:x}) called by PID {}", flags, pid);
                    }
                    
                    if let Err(e) = self.handle_clone_syscall(ptrace_mgr, pid) {
                        warn!("Failed to handle clone syscall: {}", e);
                    }
                }
            }
            _ => {
                warn!("❓ Unknown seccomp trace data: {}", trace_data);
            }
        }
        
        info!("✅ Completed handling seccomp syscall {} for PID {}", trace_data, pid);
        Ok(())
    }
    
    /// Handle system call entry/exit - simplified for seccomp-only mode
    /// This is only used as a fallback when seccomp filtering fails
    fn handle_syscall(&mut self, ptrace_mgr: &PtraceManager, pid: u32) -> Result<()> {
        // With seccomp filtering, this function is only called as a fallback
        // Most syscalls should be handled by handle_seccomp_syscall instead
        warn!("Fallback syscall handling triggered for PID {} - this should be rare with seccomp", pid);
        
        // Only handle syscall exits for socket() to get return values
        // when seccomp couldn't handle it properly
        let process_info = self.process_info.get_mut(&pid);
        if process_info.is_none() {
            debug!("Process {} not found in tracking", pid);
            return Ok(());
        }
        
        let is_syscall_entry = process_info.unwrap().flags & 0x1 == 0;
        
        if is_syscall_entry {
            // Set flag to indicate we're in syscall
            if let Some(proc_info) = self.process_info.get_mut(&pid) {
                proc_info.flags |= 0x1;
            }
        } else {
            // Syscall exit - only handle socket() return value as fallback
            if let Ok(syscall_num) = ptrace_mgr.get_syscall_number() {
                if syscall_num == 41 { // SYS_SOCKET
                    debug!("Fallback: handling socket() syscall exit for PID {}", pid);
                    if let Err(e) = self.handle_socket_syscall_exit(ptrace_mgr, pid) {
                        warn!("Failed to handle socket syscall exit: {}", e);
                    }
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
        
        // For seccomp, we might have a pending socket that hasn't been properly keyed yet
        if !self.socket_info.contains_key(&socket_key) {
            // Check if this PID has a pending TCP socket that we need to associate with this fd
            if self.pending_socket_for_fd_update.contains_key(&pid) {
                let magic_fd = (graftcp_common::MAGIC_FD << 31) + (pid as u64);
                if let Some(mut socket_info) = self.socket_info.remove(&magic_fd) {
                    debug!("Updating pending TCP socket for PID {} with fd {}", pid, sockfd);
                    socket_info.fd = sockfd;
                    socket_info.magic_fd = socket_key;
                    self.socket_info.insert(socket_key, socket_info);
                    self.pending_socket_for_fd_update.remove(&pid);
                    info!("=== NEW CONNECTION === Successfully associated TCP socket fd {} with PID {}", sockfd, pid);
                } else {
                    debug!("Socket fd {} not tracked as TCP socket, ignoring connect", sockfd);
                    return Ok(());
                }
            } else {
                debug!("Socket fd {} not tracked as TCP socket, ignoring connect", sockfd);
                return Ok(());
            }
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
        
        // Use loopback allocation and double-hook approach
        // This is the correct implementation as specified by the user
        
        // 1. Allocate a unique loopback IP for this target
        let loopback_ip = match allocate_loopback_ip(dest_addr) {
            Ok(ip) => ip,
            Err(e) => {
                error!("Failed to allocate loopback IP for {}: {}", dest_addr, e);
                return Ok(());
            }
        };
        
        info!("Allocated loopback IP {} for target {}", loopback_ip, dest_addr);
        
        // 2. Save original address data for restoration on syscall exit
        let original_addr_data = addr_data.clone();
        self.pending_connects.insert(pid, (addr_ptr, original_addr_data, loopback_ip));
        
        // 3. Create proxy address pointing to server port
        // The challenge: we need to somehow pass the loopback_ip info to the server
        // One approach: use the source IP somehow, or embed in the connection
        let proxy_addr = SocketAddr::new(
            IpAddr::V4(loopback_ip),  // Connect TO the loopback IP  
            self.local_port           // But on the server port
        );
        
        // 4. Modify the connect() arguments to redirect to (loopback_ip:server_port)
        if let Err(e) = self.redirect_connect_to_address(ptrace_mgr, addr_ptr, &proxy_addr, family) {
            error!("Failed to redirect connection: {}", e);
            // Clean up on failure
            self.pending_connects.remove(&pid);
            return Ok(());
        }
        
        info!("Redirected {} to loopback proxy {}:{}", dest_addr, loopback_ip, self.local_port);
        
        Ok(())
    }
    
    /// Handle connect() system call exit - restore original arguments
    fn handle_connect_syscall_exit(&mut self, ptrace_mgr: &PtraceManager, pid: u32) -> Result<()> {
        // Check if we have a pending connect for this PID
        if let Some((addr_ptr, original_addr_data, loopback_ip)) = self.pending_connects.remove(&pid) {
            debug!("Restoring original connect() arguments for PID {}", pid);
            
            // Restore the original address data
            if let Err(e) = ptrace_mgr.write_data(addr_ptr, &original_addr_data) {
                warn!("Failed to restore original connect() arguments for PID {}: {}", pid, e);
            } else {
                info!("Successfully restored original connect() arguments for PID {} (loopback {})", pid, loopback_ip);
            }
        }
        
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
            
            // For seccomp, we can't easily get the return value, so we use a different approach
            // We'll store the socket info and update it when we see connect()
            let socket_info = SocketInfo {
                pid,
                fd: -1, // Will be determined when connect() is called
                magic_fd: (graftcp_common::MAGIC_FD << 31) + (pid as u64),
                domain,
                socket_type,
                connect_time: std::time::SystemTime::now(),
            };
            
            // Store with magic_fd key for now, we'll re-key it in connect()
            self.socket_info.insert(socket_info.magic_fd, socket_info);
            
            // Mark this PID as having a pending TCP socket
            self.pending_socket_for_fd_update.insert(pid, true);
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
    
    /// Handle clone() system call - remove CLONE_UNTRACED flag
    /// This matches the behavior from the C implementation  
    #[cfg(target_arch = "x86_64")]
    fn handle_clone_syscall(&mut self, ptrace_mgr: &PtraceManager, _pid: u32) -> Result<()> {
        // Get clone flags from first argument
        let flags = ptrace_mgr.get_syscall_arg(0)? as u64;
        debug!("clone() called: original flags=0x{:x}", flags);
        
        // Remove CLONE_UNTRACED flag (0x00800000)
        const CLONE_UNTRACED: u64 = 0x00800000;
        let new_flags = flags & !CLONE_UNTRACED;
        
        if flags != new_flags {
            debug!("Removing CLONE_UNTRACED flag: 0x{:x} -> 0x{:x}", flags, new_flags);
            
            // Write back the modified flags to RDI register (first argument)
            // This matches the C implementation: ptrace(PTRACE_POKEUSER, pid, sizeof(long) * RDI, flags)
            ptrace_mgr.set_syscall_arg(0, new_flags)?;
        }
        
        Ok(())
    }
    
    #[cfg(not(target_arch = "x86_64"))]
    fn handle_clone_syscall(&mut self, _ptrace_mgr: &PtraceManager, _pid: u32) -> Result<()> {
        debug!("clone() syscall handling not implemented for this architecture");
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
    
    /// Modify connect() arguments to redirect to specified address
    fn redirect_connect_to_address(
        &self,
        ptrace_mgr: &PtraceManager,
        addr_ptr: u64,
        target_addr: &SocketAddr,
        family: c_int,
    ) -> Result<()> {
        match family {
            AF_INET => {
                // Create sockaddr_in structure for IPv4
                let mut sockaddr_in = vec![0u8; 16]; // sizeof(struct sockaddr_in)
                
                // Fill in the structure
                sockaddr_in[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
                
                if let IpAddr::V4(ipv4) = target_addr.ip() {
                    sockaddr_in[2..4].copy_from_slice(&target_addr.port().to_be_bytes());
                    sockaddr_in[4..8].copy_from_slice(&ipv4.octets());
                    // Rest is already zeroed
                } else {
                    return Err(graftcp_common::GraftcpError::NetworkError(
                        "IPv4 address expected but got IPv6".to_string()
                    ));
                }
                
                // Write the modified address structure back to process memory
                ptrace_mgr.write_data(addr_ptr, &sockaddr_in)?;
                
                debug!("Modified connect() to use target address: {}", target_addr);
            }
            AF_INET6 => {
                // For IPv6, we fallback to standard localhost since our allocation is IPv4-specific
                let mut sockaddr_in6 = vec![0u8; 28]; // sizeof(struct sockaddr_in6)
                
                // Fill in the structure for ::1 (IPv6 localhost)
                sockaddr_in6[0..2].copy_from_slice(&(AF_INET6 as u16).to_ne_bytes());
                sockaddr_in6[2..4].copy_from_slice(&target_addr.port().to_be_bytes());
                // Set ::1 address
                sockaddr_in6[8..24].copy_from_slice(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]);
                
                // Write the modified address structure back to process memory
                ptrace_mgr.write_data(addr_ptr, &sockaddr_in6)?;
                
                debug!("Modified connect() to use IPv6 localhost: ::1:{}", target_addr.port());
            }
            _ => {
                return Err(graftcp_common::GraftcpError::NetworkError(
                    format!("Unsupported address family: {}", family)
                ));
            }
        }
        
        Ok(())
    }
    
    /// Switch to syscall tracing for a specific socket() call to get return value
    fn switch_to_syscall_tracing(&mut self, pid: nix::unistd::Pid) -> Result<()> {
        // Use PTRACE_SYSCALL to catch the syscall exit and get return value
        ptrace::syscall(pid, None)?;
        Ok(())
    }
}