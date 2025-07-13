use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use graftcp_common::Result;
use std::os::raw::{c_long, c_int};
use tracing::{debug, error, warn};

/// System call numbers for different architectures
#[cfg(target_arch = "x86_64")]
mod syscalls {
    use std::os::raw::c_long;
    pub const SYS_SOCKET: c_long = 41;
    pub const SYS_CONNECT: c_long = 42;
    pub const SYS_CLOSE: c_long = 3;
    pub const SYS_CLONE: c_long = 56;
    pub const SYS_EXIT: c_long = 60;
    pub const SYS_EXIT_GROUP: c_long = 231;
}

#[cfg(target_arch = "aarch64")]
mod syscalls {
    use std::os::raw::c_long;
    pub const SYS_SOCKET: c_long = 198;
    pub const SYS_CONNECT: c_long = 203;
    pub const SYS_CLOSE: c_long = 57;
    pub const SYS_CLONE: c_long = 220;
    pub const SYS_EXIT: c_long = 93;
    pub const SYS_EXIT_GROUP: c_long = 94;
}

/// Register offsets for x86_64 architecture (based on struct user_regs_struct)
#[cfg(target_arch = "x86_64")]
mod x86_64_regs {
    pub const ORIG_RAX: usize = 120;  // offsetof(struct user_regs_struct, orig_rax)
    pub const RAX: usize = 80;        // offsetof(struct user_regs_struct, rax)  
    pub const RDI: usize = 112;       // offsetof(struct user_regs_struct, rdi)
    pub const RSI: usize = 104;       // offsetof(struct user_regs_struct, rsi)
    pub const RDX: usize = 96;        // offsetof(struct user_regs_struct, rdx)
    pub const R10: usize = 64;        // offsetof(struct user_regs_struct, r10)
    pub const R8: usize = 72;         // offsetof(struct user_regs_struct, r8)
    pub const R9: usize = 68;         // offsetof(struct user_regs_struct, r9)
}

/// Platform-specific ptrace functionality
pub struct PtraceManager {
    target_pid: Pid,
}

impl PtraceManager {
    pub fn new(target_pid: Pid) -> Self {
        Self { target_pid }
    }
    
    /// Attach to a process for tracing
    pub fn attach(&self) -> Result<()> {
        debug!("Attaching to process {}", self.target_pid);
        ptrace::attach(self.target_pid)?;
        
        // Wait for the process to stop
        match waitpid(self.target_pid, None)? {
            WaitStatus::Stopped(_, _) => {
                debug!("Process {} stopped successfully", self.target_pid);
                
                // Set ptrace options for tracing
                ptrace::setoptions(
                    self.target_pid,
                    ptrace::Options::PTRACE_O_TRACECLONE
                        | ptrace::Options::PTRACE_O_TRACEEXEC
                        | ptrace::Options::PTRACE_O_TRACEFORK
                        | ptrace::Options::PTRACE_O_TRACEVFORK
                        | ptrace::Options::PTRACE_O_TRACESYSGOOD,
                )?;
                
                Ok(())
            }
            status => {
                error!("Unexpected status while attaching: {:?}", status);
                Err(graftcp_common::GraftcpError::PtraceError(
                    format!("Unexpected wait status: {:?}", status)
                ))
            }
        }
    }
    
    /// Get system call number from traced process
    pub fn get_syscall_number(&self) -> Result<i64> {
        #[cfg(target_arch = "x86_64")]
        {
            // Use PTRACE_GETREGS approach which is more reliable than PTRACE_PEEKUSER
            match ptrace::getregs(self.target_pid) {
                Ok(regs) => {
                    let syscall_num = regs.orig_rax as i64;
                    debug!("Read syscall number via getregs: {}", syscall_num);
                    Ok(syscall_num)
                }
                Err(e) => {
                    // If GETREGS fails, fall back to PEEKUSER method
                    debug!("GETREGS failed, trying PEEKUSER: {}", e);
                    match ptrace::read(self.target_pid, x86_64_regs::ORIG_RAX as *mut _) {
                        Ok(syscall_num) => {
                            debug!("Read syscall number via peekuser: {}", syscall_num);
                            Ok(syscall_num as i64)
                        }
                        Err(e2) => {
                            // Both methods failed, this is expected in many cases due to timing
                            debug!("Both getregs and peekuser failed: getregs={}, peekuser={}", e, e2);
                            Err(graftcp_common::GraftcpError::PtraceError(
                                format!("Cannot read syscall number: getregs={}, peekuser={}", e, e2)
                            ))
                        }
                    }
                }
            }
        }
        
        #[cfg(target_arch = "aarch64")]
        {
            // For ARM64, we need to use PTRACE_GETREGSET
            // This is more complex and would require additional implementation
            warn!("ARM64 syscall number retrieval not fully implemented yet");
            Ok(0)
        }
        
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            Err(graftcp_common::GraftcpError::PtraceError(
                "Unsupported architecture".to_string()
            ))
        }
    }
    
    /// Get system call arguments
    pub fn get_syscall_args(&self) -> Result<[u64; 6]> {
        #[cfg(target_arch = "x86_64")]
        {
            let args = [
                ptrace::read(self.target_pid, x86_64_regs::RDI as *mut _)? as u64,
                ptrace::read(self.target_pid, x86_64_regs::RSI as *mut _)? as u64,
                ptrace::read(self.target_pid, x86_64_regs::RDX as *mut _)? as u64,
                ptrace::read(self.target_pid, x86_64_regs::R10 as *mut _)? as u64,
                ptrace::read(self.target_pid, x86_64_regs::R8 as *mut _)? as u64,
                ptrace::read(self.target_pid, x86_64_regs::R9 as *mut _)? as u64,
            ];
            Ok(args)
        }
        
        #[cfg(target_arch = "aarch64")]
        {
            error!("ARM64 syscall arguments retrieval not fully implemented yet");
            Ok([0; 6])
        }
        
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            Err(graftcp_common::GraftcpError::PtraceError(
                "Unsupported architecture".to_string()
            ))
        }
    }
    
    /// Get specific system call argument by index (0-5)
    pub fn get_syscall_arg(&self, index: usize) -> Result<u64> {
        if index >= 6 {
            return Err(graftcp_common::GraftcpError::PtraceError(
                "Invalid syscall argument index".to_string()
            ));
        }
        
        #[cfg(target_arch = "x86_64")]
        {
            // Use PTRACE_GETREGS approach first
            match ptrace::getregs(self.target_pid) {
                Ok(regs) => {
                    let value = match index {
                        0 => regs.rdi,
                        1 => regs.rsi,
                        2 => regs.rdx,
                        3 => regs.r10,
                        4 => regs.r8,
                        5 => regs.r9,
                        _ => unreachable!(),
                    };
                    debug!("Read syscall arg[{}] via getregs: {}", index, value);
                    Ok(value)
                }
                Err(e) => {
                    // Fall back to PEEKUSER method
                    debug!("GETREGS failed for arg {}, trying PEEKUSER: {}", index, e);
                    let reg_offset = match index {
                        0 => x86_64_regs::RDI,
                        1 => x86_64_regs::RSI,
                        2 => x86_64_regs::RDX,
                        3 => x86_64_regs::R10,
                        4 => x86_64_regs::R8,
                        5 => x86_64_regs::R9,
                        _ => unreachable!(),
                    };
                    
                    match ptrace::read(self.target_pid, reg_offset as *mut _) {
                        Ok(value) => {
                            debug!("Read syscall arg[{}] via peekuser: {}", index, value);
                            Ok(value as u64)
                        }
                        Err(e2) => {
                            debug!("Both getregs and peekuser failed for arg {}: getregs={}, peekuser={}", index, e, e2);
                            Err(graftcp_common::GraftcpError::PtraceError(
                                format!("Cannot read syscall arg {}: getregs={}, peekuser={}", index, e, e2)
                            ))
                        }
                    }
                }
            }
        }
        
        #[cfg(target_arch = "aarch64")]
        {
            warn!("ARM64 syscall argument retrieval not fully implemented yet");
            Ok(0)
        }
        
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            Err(graftcp_common::GraftcpError::PtraceError(
                "Unsupported architecture".to_string()
            ))
        }
    }
    
    /// Modify system call arguments
    pub fn set_syscall_args(&self, args: &[u64; 6]) -> Result<()> {
        #[cfg(target_arch = "x86_64")]
        {
            let reg_offsets = [
                x86_64_regs::RDI,
                x86_64_regs::RSI,
                x86_64_regs::RDX,
                x86_64_regs::R10,
                x86_64_regs::R8,
                x86_64_regs::R9,
            ];
            
            for (i, &arg) in args.iter().enumerate() {
                unsafe {
                    ptrace::write(
                        self.target_pid,
                        reg_offsets[i] as *mut _,
                        arg as *mut _,
                    )?;
                }
            }
            
            Ok(())
        }
        
        #[cfg(target_arch = "aarch64")]
        {
            error!("ARM64 syscall argument modification not fully implemented yet");
            Ok(())
        }
        
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            Err(graftcp_common::GraftcpError::PtraceError(
                "Unsupported architecture".to_string()
            ))
        }
    }
    
    /// Get return value of system call
    pub fn get_retval(&self) -> Result<i64> {
        #[cfg(target_arch = "x86_64")]
        {
            let retval = ptrace::read(self.target_pid, x86_64_regs::RAX as *mut _)?;
            Ok(retval as i64)
        }
        
        #[cfg(target_arch = "aarch64")]
        {
            error!("ARM64 return value retrieval not fully implemented yet");
            Ok(0)
        }
        
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            Err(graftcp_common::GraftcpError::PtraceError(
                "Unsupported architecture".to_string()
            ))
        }
    }
    
    /// Get return value using getregs (more reliable than peekuser)
    pub fn get_retval_via_getregs(&self) -> Result<i64> {
        #[cfg(target_arch = "x86_64")]
        {
            match ptrace::getregs(self.target_pid) {
                Ok(regs) => {
                    let retval = regs.rax as i64;
                    debug!("Read return value via getregs: {}", retval);
                    Ok(retval)
                }
                Err(e) => {
                    debug!("GETREGS failed for return value, trying PEEKUSER: {}", e);
                    // Fall back to the original method
                    match ptrace::read(self.target_pid, x86_64_regs::RAX as *mut _) {
                        Ok(retval) => {
                            debug!("Read return value via peekuser: {}", retval);
                            Ok(retval as i64)
                        }
                        Err(e2) => {
                            debug!("Both getregs and peekuser failed for return value: getregs={}, peekuser={}", e, e2);
                            Err(graftcp_common::GraftcpError::PtraceError(
                                format!("Cannot read return value: getregs={}, peekuser={}", e, e2)
                            ))
                        }
                    }
                }
            }
        }
        
        #[cfg(target_arch = "aarch64")]
        {
            warn!("ARM64 return value retrieval via getregs not fully implemented yet");
            Ok(0)
        }
        
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            Err(graftcp_common::GraftcpError::PtraceError(
                "Unsupported architecture".to_string()
            ))
        }
    }
    
    /// Set return value of system call
    pub fn set_retval(&self, new_val: i64) -> Result<()> {
        #[cfg(target_arch = "x86_64")]
        {
            unsafe {
                ptrace::write(
                    self.target_pid,
                    x86_64_regs::RAX as *mut _,
                    new_val as *mut _,
                )?;
            }
            Ok(())
        }
        
        #[cfg(target_arch = "aarch64")]
        {
            error!("ARM64 return value modification not fully implemented yet");
            Ok(())
        }
        
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            Err(graftcp_common::GraftcpError::PtraceError(
                "Unsupported architecture".to_string()
            ))
        }
    }
    
    /// Continue execution until next system call
    pub fn continue_syscall(&self) -> Result<WaitStatus> {
        ptrace::syscall(self.target_pid, None)?;
        let status = waitpid(self.target_pid, None)?;
        Ok(status)
    }
    
    /// Continue execution normally
    pub fn continue_execution(&self) -> Result<WaitStatus> {
        ptrace::cont(self.target_pid, None)?;
        let status = waitpid(self.target_pid, None)?;
        Ok(status)
    }
    
    /// Read data from traced process memory
    pub fn read_data(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut data = Vec::with_capacity(len);
        let mut current_addr = addr;
        let mut remaining = len;
        
        while remaining > 0 {
            let word = ptrace::read(self.target_pid, current_addr as *mut _)?;
            let word_bytes = word.to_ne_bytes();
            
            let copy_len = std::cmp::min(remaining, std::mem::size_of::<c_long>());
            data.extend_from_slice(&word_bytes[..copy_len]);
            
            current_addr += std::mem::size_of::<c_long>() as u64;
            remaining -= copy_len;
        }
        
        data.truncate(len);
        Ok(data)
    }
    
    /// Write data to traced process memory
    pub fn write_data(&self, addr: u64, data: &[u8]) -> Result<()> {
        let mut current_addr = addr;
        let mut offset = 0;
        
        while offset < data.len() {
            let remaining = data.len() - offset;
            
            if remaining >= std::mem::size_of::<c_long>() {
                // Write full word
                let mut word_bytes = [0u8; std::mem::size_of::<c_long>()];
                word_bytes.copy_from_slice(&data[offset..offset + std::mem::size_of::<c_long>()]);
                let word = c_long::from_ne_bytes(word_bytes);
                
                unsafe {
                    ptrace::write(self.target_pid, current_addr as *mut _, word as *mut _)?;
                }
                offset += std::mem::size_of::<c_long>();
            } else {
                // Handle partial word write
                let old_word = ptrace::read(self.target_pid, current_addr as *mut _)?;
                let mut word_bytes = old_word.to_ne_bytes();
                word_bytes[..remaining].copy_from_slice(&data[offset..]);
                let new_word = c_long::from_ne_bytes(word_bytes);
                
                unsafe {
                    ptrace::write(self.target_pid, current_addr as *mut _, new_word as *mut _)?;
                }
                offset += remaining;
            }
            
            current_addr += std::mem::size_of::<c_long>() as u64;
        }
        
        Ok(())
    }
    
    /// Check if this is a connect() system call
    pub fn is_connect_syscall(&self) -> Result<bool> {
        let syscall_num = self.get_syscall_number()?;
        Ok(syscall_num == syscalls::SYS_CONNECT)
    }
    
    /// Check if this is a socket() system call
    pub fn is_socket_syscall(&self) -> Result<bool> {
        let syscall_num = self.get_syscall_number()?;
        Ok(syscall_num == syscalls::SYS_SOCKET)
    }
    
    /// Check if this is a close() system call
    pub fn is_close_syscall(&self) -> Result<bool> {
        let syscall_num = self.get_syscall_number()?;
        Ok(syscall_num == syscalls::SYS_CLOSE)
    }
    
    /// Check if this is a clone() system call
    pub fn is_clone_syscall(&self) -> Result<bool> {
        let syscall_num = self.get_syscall_number()?;
        Ok(syscall_num == syscalls::SYS_CLONE)
    }
}