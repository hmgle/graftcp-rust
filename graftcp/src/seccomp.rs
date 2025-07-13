//! Seccomp BPF filtering for performance optimization
//! 
//! This module implements seccomp-bpf filters to reduce ptrace overhead
//! by only trapping the system calls we need to intercept for graftcp.
//! 
//! Based on the C implementation logic that filters for:
//! - close(...) - most frequent, checked first
//! - socket([AF_INET|AF_INET6], SOCK_STREAM, ...) - TCP sockets only
//! - connect(...) - connection interception
//! - clone([CLONE_UNTRACED], ...) - on x86_64 only

#[cfg(feature = "seccomp")]
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen as ArgLen, SeccompCmpOp::Eq,
    SeccompCondition as Cond, SeccompFilter, SeccompRule, TargetArch,
};
use graftcp_common::Result;
use tracing::debug;
use std::collections::BTreeMap;

/// Socket domain constants
const AF_INET: u64 = 2;
const AF_INET6: u64 = 10;

/// Socket type constants
const SOCK_STREAM: u64 = 1;

/// Clone flag constants
#[cfg(target_arch = "x86_64")]
const CLONE_UNTRACED: u64 = 0x00800000;

/// System call numbers for different architectures
#[cfg(target_arch = "x86_64")]
mod syscalls {
    pub const SYS_SOCKET: i64 = 41;
    pub const SYS_CONNECT: i64 = 42;
    pub const SYS_CLOSE: i64 = 3;
    pub const SYS_CLONE: i64 = 56;
}

#[cfg(target_arch = "aarch64")]
mod syscalls {
    pub const SYS_SOCKET: i64 = 198;
    pub const SYS_CONNECT: i64 = 203;
    pub const SYS_CLOSE: i64 = 57;
    pub const SYS_CLONE: i64 = 220;
}

/// Install seccomp BPF filter to optimize ptrace performance
/// 
/// This function creates and installs a BPF program that:
/// 1. Allows most system calls to execute normally (SECCOMP_RET_ALLOW)
/// 2. Traps only the specific system calls we need to intercept (SECCOMP_RET_TRACE)
/// 
/// The filter logic matches the C implementation for maximum compatibility.
#[cfg(feature = "seccomp")]
pub fn install_seccomp_filter() -> Result<()> {
    debug!("Installing seccomp BPF filter for graftcp");
    
    // Set no_new_privs before installing seccomp filter
    // This is required for unprivileged processes to install seccomp filters
    use nix::sys::prctl;
    prctl::set_no_new_privs()
        .map_err(|e| graftcp_common::GraftcpError::SeccompError(format!("Failed to set no_new_privs: {}", e)))?;
    
    // Create filter rules map
    let mut filter_map: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    
    // Rule 1: close() - always trap (most frequent syscall)
    // Since we can't have empty rules, we'll use a condition that always matches
    // Check that arg0 >= 0 (file descriptors are always >= 0)
    let close_cond = Cond::new(0, ArgLen::Dword, seccompiler::SeccompCmpOp::Ge, 0)
        .map_err(|e| graftcp_common::GraftcpError::SeccompError(format!("Failed to create close condition: {}", e)))?;
    let close_rule = SeccompRule::new(vec![close_cond])
        .map_err(|e| graftcp_common::GraftcpError::SeccompError(format!("Failed to create close rule: {}", e)))?;
    filter_map.insert(syscalls::SYS_CLOSE, vec![close_rule]);
    
    // Rule 2: socket() - only trap TCP sockets (AF_INET/AF_INET6 + SOCK_STREAM)
    let inet_cond = Cond::new(0, ArgLen::Dword, Eq, AF_INET)
        .map_err(|e| graftcp_common::GraftcpError::SeccompError(format!("Failed to create AF_INET condition: {}", e)))?;
    let inet6_cond = Cond::new(0, ArgLen::Dword, Eq, AF_INET6)
        .map_err(|e| graftcp_common::GraftcpError::SeccompError(format!("Failed to create AF_INET6 condition: {}", e)))?;
    let stream_cond = Cond::new(1, ArgLen::Dword, seccompiler::SeccompCmpOp::MaskedEq(SOCK_STREAM), SOCK_STREAM)
        .map_err(|e| graftcp_common::GraftcpError::SeccompError(format!("Failed to create SOCK_STREAM condition: {}", e)))?;
    
    let socket_rule_inet = SeccompRule::new(vec![inet_cond, stream_cond.clone()])
        .map_err(|e| graftcp_common::GraftcpError::SeccompError(format!("Failed to create socket rule for IPv4: {}", e)))?;
    let socket_rule_inet6 = SeccompRule::new(vec![inet6_cond, stream_cond])
        .map_err(|e| graftcp_common::GraftcpError::SeccompError(format!("Failed to create socket rule for IPv6: {}", e)))?;
    
    filter_map.insert(syscalls::SYS_SOCKET, vec![socket_rule_inet, socket_rule_inet6]);
    
    // Rule 3: connect() - always trap
    // Use a condition that always matches: arg0 >= 0 (socket fd is always >= 0)
    let connect_cond = Cond::new(0, ArgLen::Dword, seccompiler::SeccompCmpOp::Ge, 0)
        .map_err(|e| graftcp_common::GraftcpError::SeccompError(format!("Failed to create connect condition: {}", e)))?;
    let connect_rule = SeccompRule::new(vec![connect_cond])
        .map_err(|e| graftcp_common::GraftcpError::SeccompError(format!("Failed to create connect rule: {}", e)))?;
    filter_map.insert(syscalls::SYS_CONNECT, vec![connect_rule]);
    
    // Rule 4: clone() - only on x86_64, and only if CLONE_UNTRACED is set
    #[cfg(target_arch = "x86_64")]
    {
        let clone_cond = Cond::new(0, ArgLen::Dword, seccompiler::SeccompCmpOp::MaskedEq(CLONE_UNTRACED), CLONE_UNTRACED)
            .map_err(|e| graftcp_common::GraftcpError::SeccompError(format!("Failed to create clone condition: {}", e)))?;
        let clone_rule = SeccompRule::new(vec![clone_cond])
            .map_err(|e| graftcp_common::GraftcpError::SeccompError(format!("Failed to create clone rule: {}", e)))?;
        filter_map.insert(syscalls::SYS_CLONE, vec![clone_rule]);
    }
    
    // Determine target architecture
    let target_arch = if cfg!(target_arch = "x86_64") {
        TargetArch::x86_64
    } else if cfg!(target_arch = "aarch64") {
        TargetArch::aarch64
    } else {
        return Err(graftcp_common::GraftcpError::SeccompError(
            "Unsupported architecture for seccomp".to_string()
        ));
    };
    
    // Create the seccomp filter
    let filter = SeccompFilter::new(
        filter_map,
        SeccompAction::Allow, // Default action: allow all other syscalls
        SeccompAction::Trace(0), // Action for trapped syscalls
        target_arch,
    ).map_err(|e| graftcp_common::GraftcpError::SeccompError(format!("Failed to create seccomp filter: {}", e)))?;
    
    // Compile to BPF program
    let bpf_program: BpfProgram = filter.try_into()
        .map_err(|e| graftcp_common::GraftcpError::SeccompError(format!("Failed to compile BPF program: {}", e)))?;
    
    // Apply the filter to current process
    // This will affect the current process and all its children after exec
    seccompiler::apply_filter(&bpf_program)
        .map_err(|e| graftcp_common::GraftcpError::SeccompError(format!("Failed to apply seccomp filter: {}", e)))?;
    
    debug!("Seccomp BPF filter installed successfully");
    debug!("Filter will trap: close, socket(TCP), connect, clone(x86_64)");
    debug!("All other syscalls will execute normally");
    
    Ok(())
}

/// Stub implementation when seccomp feature is disabled
#[cfg(not(feature = "seccomp"))]
pub fn install_seccomp_filter() -> Result<()> {
    debug!("Seccomp support disabled, using pure ptrace mode");
    debug!("Performance will be significantly worse than with seccomp");
    Ok(())
}

/// Check if seccomp is available and enabled
pub fn is_seccomp_enabled() -> bool {
    cfg!(feature = "seccomp")
}

/// Get human-readable description of what syscalls are filtered
pub fn get_filter_description() -> &'static str {
    if cfg!(feature = "seccomp") {
        #[cfg(target_arch = "x86_64")]
        return "seccomp BPF: trapping close, socket(TCP), connect, clone(UNTRACED)";
        
        #[cfg(target_arch = "aarch64")]
        return "seccomp BPF: trapping close, socket(TCP), connect";
        
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        return "seccomp BPF: basic filtering (unsupported architecture)";
    } else {
        "pure ptrace mode (seccomp disabled at compile time)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_seccomp_feature_detection() {
        // This test verifies that the feature flag works correctly
        let enabled = is_seccomp_enabled();
        let description = get_filter_description();
        
        if enabled {
            assert!(description.contains("seccomp BPF"));
        } else {
            assert!(description.contains("pure ptrace"));
        }
    }
    
    #[cfg(feature = "seccomp")]
    #[test]
    fn test_filter_creation() {
        // Test that we can create the filter without panicking
        // We can't actually install it in tests since it would affect the test process
        let mut filter_map: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        
        // Create a simple rule with a condition (syscall number match is implicit)
        // For testing, we'll create a rule that matches syscall arg 0 >= 0
        let test_cond = Cond::new(0, ArgLen::Dword, seccompiler::SeccompCmpOp::Ge, 0).expect("Failed to create test condition");
        let rule = SeccompRule::new(vec![test_cond]);
        assert!(rule.is_ok(), "Failed to create rule: {:?}", rule);
        
        filter_map.insert(syscalls::SYS_CLOSE, vec![rule.unwrap()]);
        
        let target_arch = if cfg!(target_arch = "x86_64") {
            TargetArch::x86_64
        } else {
            TargetArch::aarch64
        };
        
        let filter = SeccompFilter::new(
            filter_map,
            SeccompAction::Allow,
            SeccompAction::Trace(0),
            target_arch,
        );
        assert!(filter.is_ok(), "Failed to create filter: {:?}", filter);
    }
}