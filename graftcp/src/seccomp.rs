/*!
 * Seccomp BPF integration for graftcp
 * 
 * This module provides seccomp BPF filtering to reduce ptrace overhead
 * by only trapping specific syscalls (socket, connect, close, clone)
 */

use tracing::{debug, info, error};
use libseccomp::{ScmpFilterContext, ScmpAction, ScmpSyscall};
use graftcp_common::Result;

/// Install seccomp BPF filter to only trap network-related syscalls
/// 
/// This significantly improves performance by reducing the number of 
/// ptrace stops to only the syscalls we care about.
pub fn install_seccomp_filter() -> Result<()> {
    info!("Installing seccomp BPF filter for syscall filtering");
    
    // Set no_new_privs FIRST - this is required for unprivileged seccomp filter installation
    // Reference: https://www.kernel.org/doc/Documentation/prctl/no_new_privs.txt
    unsafe {
        let result = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if result != 0 {
            let err = std::io::Error::last_os_error();
            error!("Failed to set PR_SET_NO_NEW_PRIVS: {} (result={})", err, result);
            return Err(graftcp_common::GraftcpError::ProcessError(
                format!("Failed to set PR_SET_NO_NEW_PRIVS: {}", err)
            ));
        }
    }
    debug!("Set PR_SET_NO_NEW_PRIVS=1");
    
    // Create seccomp filter context with default action ALLOW
    let mut ctx = ScmpFilterContext::new(ScmpAction::Allow)
        .map_err(|e| graftcp_common::GraftcpError::ProcessError(
            format!("Failed to create seccomp filter context: {}", e)
        ))?;
    
    // Add rules to trap specific syscalls with SECCOMP_RET_TRACE
    // These syscalls will cause ptrace to be notified
    
    // Socket creation - we need to track TCP sockets
    ctx.add_rule(ScmpAction::Trace(1), ScmpSyscall::from_name("socket")
        .map_err(|e| graftcp_common::GraftcpError::ProcessError(
            format!("Failed to create socket syscall filter: {}", e)
        ))?)
        .map_err(|e| graftcp_common::GraftcpError::ProcessError(
            format!("Failed to add socket rule: {}", e)
        ))?;
    
    // Connect calls - these are what we intercept and redirect
    ctx.add_rule(ScmpAction::Trace(2), ScmpSyscall::from_name("connect")
        .map_err(|e| graftcp_common::GraftcpError::ProcessError(
            format!("Failed to create connect syscall filter: {}", e)
        ))?)
        .map_err(|e| graftcp_common::GraftcpError::ProcessError(
            format!("Failed to add connect rule: {}", e)
        ))?;
    
    // Close calls - we need to cleanup socket tracking  
    ctx.add_rule(ScmpAction::Trace(3), ScmpSyscall::from_name("close")
        .map_err(|e| graftcp_common::GraftcpError::ProcessError(
            format!("Failed to create close syscall filter: {}", e)
        ))?)
        .map_err(|e| graftcp_common::GraftcpError::ProcessError(
            format!("Failed to add close rule: {}", e)
        ))?;
    
    // For x86_64, we also need to handle clone with CLONE_UNTRACED flag
    // This matches the C implementation
    #[cfg(target_arch = "x86_64")]
    {
        ctx.add_rule(ScmpAction::Trace(4), ScmpSyscall::from_name("clone")
            .map_err(|e| graftcp_common::GraftcpError::ProcessError(
                format!("Failed to create clone syscall filter: {}", e)
            ))?)
            .map_err(|e| graftcp_common::GraftcpError::ProcessError(
                format!("Failed to add clone rule: {}", e)
            ))?;
    }
    
    // Load the filter into the kernel
    ctx.load()
        .map_err(|e| graftcp_common::GraftcpError::ProcessError(
            format!("Failed to load seccomp filter: {}", e)
        ))?;
    
    info!("Seccomp BPF filter installed successfully - only socket/connect/close/clone syscalls will be trapped");
    Ok(())
}

/// Check if ptrace event is a seccomp event and return the trace data
pub fn get_seccomp_trace_data(pid: nix::unistd::Pid) -> Option<u64> {
    debug!("🔍 Checking for seccomp trace data for PID {}", pid);
    match nix::sys::ptrace::getevent(pid) {
        Ok(event_msg) => {
            debug!("📨 Got ptrace event message: {} for PID {}", event_msg, pid);
            // Check if this is a seccomp trace event
            // The event_msg contains our trace data (1=socket, 2=connect, 3=close, 4=clone)
            if event_msg > 0 && event_msg <= 4 {
                info!("✨ Valid seccomp trace data: {} for PID {}", event_msg, pid);
                Some(event_msg as u64)
            } else {
                debug!("❌ Event message {} is not a valid seccomp trace code for PID {}", event_msg, pid);
                None
            }
        }
        Err(e) => {
            debug!("⚠️ Failed to get ptrace event for PID {}: {}", pid, e);
            None
        }
    }
}

/// Convert seccomp trace data to human-readable syscall name
pub fn trace_data_to_syscall_name(trace_data: u64) -> &'static str {
    match trace_data {
        1 => "socket",
        2 => "connect", 
        3 => "close",
        4 => "clone",
        _ => "unknown",
    }
}