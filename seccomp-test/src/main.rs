/*!
 * Independent test program for ptrace + seccomp BPF integration
 * 
 * This program demonstrates:
 * 1. Setting up seccomp BPF filters to only trap specific syscalls (socket, connect, close)
 * 2. Using ptrace to intercept those filtered syscalls
 * 3. Verifying that seccomp filtering reduces ptrace overhead
 * 
 * Usage: cargo run --example seccomp_test -- <target_program> [args...]
 */

use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use nix::sys::signal::Signal;
use std::collections::HashMap;
use std::ffi::CString;
use std::os::raw::c_int;
use libseccomp::{ScmpFilterContext, ScmpAction, ScmpSyscall};
use tracing::{debug, info, error, warn};
use std::env;

/// Statistics for tracking seccomp effectiveness
#[derive(Default)]
struct TracingStats {
    total_stops: u64,
    seccomp_stops: u64,
    socket_calls: u64,
    connect_calls: u64,
    close_calls: u64,
    other_stops: u64,
}

impl TracingStats {
    fn print_summary(&self) {
        info!("=== Tracing Statistics ===");
        info!("Total stops: {}", self.total_stops);
        info!("Seccomp-triggered stops: {}", self.seccomp_stops);
        info!("  - socket() calls: {}", self.socket_calls);
        info!("  - connect() calls: {}", self.connect_calls);
        info!("  - close() calls: {}", self.close_calls);
        info!("Other stops (signals, etc): {}", self.other_stops);
        if self.total_stops > 0 {
            let seccomp_ratio = (self.seccomp_stops as f64 / self.total_stops as f64) * 100.0;
            info!("Seccomp filtering effectiveness: {:.1}% of stops were for filtered syscalls", seccomp_ratio);
        }
    }
}

/// Main tracer with seccomp integration
struct SeccompTracer {
    stats: TracingStats,
    process_info: HashMap<u32, String>,
}

impl SeccompTracer {
    fn new() -> Self {
        Self {
            stats: TracingStats::default(),
            process_info: HashMap::new(),
        }
    }

    /// Install seccomp BPF filter in child process to only trap specific syscalls
    fn install_seccomp_filter() -> Result<(), Box<dyn std::error::Error>> {
        info!("Installing seccomp BPF filter for syscall filtering");
        
        // Set no_new_privs FIRST - this is required for unprivileged seccomp filter installation
        // Reference: https://www.kernel.org/doc/Documentation/prctl/no_new_privs.txt
        unsafe {
            let result = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            if result != 0 {
                let err = std::io::Error::last_os_error();
                error!("Failed to set PR_SET_NO_NEW_PRIVS: {} (result={})", err, result);
                return Err(format!("Failed to set PR_SET_NO_NEW_PRIVS: {}", err).into());
            }
        }
        info!("Set PR_SET_NO_NEW_PRIVS=1");
        
        // Create seccomp filter context
        let mut ctx = ScmpFilterContext::new(ScmpAction::Allow)?;
        
        // Add rules to trap specific syscalls with SECCOMP_RET_TRACE
        // This will cause ptrace to be notified only for these syscalls
        ctx.add_rule(ScmpAction::Trace(1), ScmpSyscall::from_name("socket")?)?;
        ctx.add_rule(ScmpAction::Trace(2), ScmpSyscall::from_name("connect")?)?; 
        ctx.add_rule(ScmpAction::Trace(3), ScmpSyscall::from_name("close")?)?;
        
        // We still need to allow process management syscalls for ptrace to work
        // But we don't trap them - they run normally
        ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("clone")?)?;
        ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("fork")?)?;
        ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("vfork")?)?;
        ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("execve")?)?;
        
        // Load the filter into the kernel
        ctx.load()?;
        info!("Seccomp BPF filter installed successfully");
        Ok(())
    }

    /// Start tracing a program with seccomp filtering
    fn start_trace(&mut self, program: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting seccomp-enabled trace of: {} {:?}", program, args);

        match unsafe { fork() }? {
            ForkResult::Parent { child } => {
                info!("Parent: tracing child PID {}", child);
                self.trace_child(child)
            }
            ForkResult::Child => {
                info!("Child: setting up seccomp and ptrace");
                
                // Install seccomp filter BEFORE enabling ptrace
                if let Err(e) = Self::install_seccomp_filter() {
                    error!("Failed to install seccomp filter: {}", e);
                    std::process::exit(1);
                }
                
                // Enable ptrace on this process
                ptrace::traceme()?;
                
                // Send SIGSTOP to let parent set up tracing
                let pid = nix::unistd::getpid();
                nix::sys::signal::kill(pid, Signal::SIGSTOP)?;
                
                // Execute target program
                let program_cstring = CString::new(program)?;
                let mut all_args = vec![program.to_string()];
                all_args.extend_from_slice(args);
                
                let args_cstrings: Result<Vec<CString>, _> = all_args.iter()
                    .map(|arg| CString::new(arg.as_str()))
                    .collect();
                
                let args_cstrings = args_cstrings?;
                nix::unistd::execvp(&program_cstring, &args_cstrings)?;
                
                unreachable!("exec should not return");
            }
        }
    }

    /// Main tracing loop with seccomp event handling
    fn trace_child(&mut self, child_pid: Pid) -> Result<(), Box<dyn std::error::Error>> {
        // Wait for initial stop
        match waitpid(child_pid, None)? {
            WaitStatus::Stopped(_, _) => {
                debug!("Child {} stopped initially", child_pid);
                
                // Set ptrace options including seccomp tracing
                ptrace::setoptions(
                    child_pid,
                    ptrace::Options::PTRACE_O_TRACECLONE
                        | ptrace::Options::PTRACE_O_TRACEEXEC
                        | ptrace::Options::PTRACE_O_TRACEFORK
                        | ptrace::Options::PTRACE_O_TRACEVFORK
                        | ptrace::Options::PTRACE_O_TRACESYSGOOD
                        | ptrace::Options::PTRACE_O_TRACESECCOMP, // Enable seccomp tracing
                )?;
                
                // Continue execution
                ptrace::cont(child_pid, None)?;
            }
            status => {
                error!("Unexpected initial status: {:?}", status);
                return Err("Unexpected initial wait status".into());
            }
        }

        self.process_info.insert(child_pid.as_raw() as u32, "main".to_string());

        // Main tracing loop
        loop {
            match waitpid(child_pid, None)? {
                WaitStatus::Exited(pid, exit_code) => {
                    info!("Process {} exited with code {}", pid, exit_code);
                    self.process_info.remove(&(pid.as_raw() as u32));
                    break;
                }
                WaitStatus::Signaled(pid, signal, _) => {
                    info!("Process {} killed by signal {:?}", pid, signal);
                    self.process_info.remove(&(pid.as_raw() as u32));
                    break;
                }
                WaitStatus::Stopped(pid, signal) => {
                    self.stats.total_stops += 1;
                    debug!("Process {} stopped with signal {:?}", pid, signal);
                    
                    // Handle different stop reasons
                    if signal == Signal::SIGTRAP {
                        // This could be a seccomp event or regular syscall
                        if let Err(e) = self.handle_trap_event(pid) {
                            warn!("Error handling trap event: {}", e);
                        }
                    } else {
                        self.stats.other_stops += 1;
                        debug!("Non-trap signal: {:?}", signal);
                    }
                    
                    // Continue execution
                    ptrace::cont(pid, None)?;
                }
                WaitStatus::PtraceEvent(pid, signal, event) => {
                    self.stats.total_stops += 1;
                    debug!("Ptrace event: pid={}, signal={:?}, event={}", pid, signal, event);
                    
                    // Handle ptrace events (seccomp, clone, exec, etc)
                    if let Err(e) = self.handle_ptrace_event(pid, event) {
                        warn!("Error handling ptrace event: {}", e);
                    }
                    
                    ptrace::cont(pid, None)?;
                }
                status => {
                    debug!("Other wait status: {:?}", status);
                    self.stats.other_stops += 1;
                }
            }
        }

        self.stats.print_summary();
        Ok(())
    }

    /// Handle SIGTRAP events (may be seccomp or other)
    fn handle_trap_event(&mut self, pid: Pid) -> Result<(), Box<dyn std::error::Error>> {
        // Try to get ptrace event message
        if let Ok(event_msg) = ptrace::getevent(pid) {
            if event_msg != 0 {
                // This is a ptrace event, handle via handle_ptrace_event
                return self.handle_ptrace_event(pid, event_msg as i32);
            }
        }
        
        // Regular trap - might be syscall entry/exit
        self.stats.other_stops += 1;
        debug!("Regular SIGTRAP (not seccomp) for pid {}", pid);
        Ok(())
    }

    /// Handle ptrace events including seccomp notifications
    fn handle_ptrace_event(&mut self, pid: Pid, event: i32) -> Result<(), Box<dyn std::error::Error>> {
        // Check if this is a seccomp event
        if (event >> 8) == libc::PTRACE_EVENT_SECCOMP {
            self.stats.seccomp_stops += 1;
            
            // Get the seccomp return data (our trace codes 1, 2, 3)
            if let Ok(seccomp_data) = ptrace::getevent(pid) {
                match seccomp_data {
                    1 => {
                        self.stats.socket_calls += 1;
                        info!("Seccomp intercepted socket() call in pid {}", pid);
                        self.handle_socket_syscall(pid)?;
                    }
                    2 => {
                        self.stats.connect_calls += 1;
                        info!("Seccomp intercepted connect() call in pid {}", pid);
                        self.handle_connect_syscall(pid)?;
                    }
                    3 => {
                        self.stats.close_calls += 1;
                        debug!("Seccomp intercepted close() call in pid {}", pid);
                        self.handle_close_syscall(pid)?;
                    }
                    _ => {
                        debug!("Unknown seccomp trace data: {}", seccomp_data);
                    }
                }
            }
        } else {
            // Other ptrace events (clone, exec, etc)
            debug!("Non-seccomp ptrace event: {} for pid {}", event, pid);
        }
        
        Ok(())
    }

    /// Handle socket() syscall
    fn handle_socket_syscall(&self, pid: Pid) -> Result<(), Box<dyn std::error::Error>> {
        // Read syscall arguments
        let regs = ptrace::getregs(pid)?;
        let domain = regs.rdi as c_int;
        let socket_type = regs.rsi as c_int;
        let protocol = regs.rdx as c_int;
        
        info!("  socket({}, {}, {}) called by pid {}", domain, socket_type, protocol, pid);
        
        // In a real implementation, we would track this socket for later connect() calls
        Ok(())
    }

    /// Handle connect() syscall
    fn handle_connect_syscall(&self, pid: Pid) -> Result<(), Box<dyn std::error::Error>> {
        // Read syscall arguments
        let regs = ptrace::getregs(pid)?;
        let sockfd = regs.rdi as c_int;
        let addr_ptr = regs.rsi;
        let addrlen = regs.rdx as c_int;
        
        info!("  connect({}, 0x{:x}, {}) called by pid {}", sockfd, addr_ptr, addrlen, pid);
        
        // In a real implementation, we would:
        // 1. Read the socket address from memory
        // 2. Decide if we need to redirect this connection
        // 3. Modify the arguments to point to our proxy
        
        Ok(())
    }

    /// Handle close() syscall
    fn handle_close_syscall(&self, pid: Pid) -> Result<(), Box<dyn std::error::Error>> {
        let regs = ptrace::getregs(pid)?;
        let fd = regs.rdi as c_int;
        
        debug!("  close({}) called by pid {}", fd, pid);
        
        // In a real implementation, we would clean up socket tracking
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <program> [args...]", args[0]);
        eprintln!("Example: {} /bin/ls -la", args[0]);
        std::process::exit(1);
    }

    let program = &args[1];
    let program_args = &args[2..];

    info!("Starting seccomp+ptrace test with target: {} {:?}", program, program_args);

    let mut tracer = SeccompTracer::new();
    tracer.start_trace(program, program_args)?;

    Ok(())
}