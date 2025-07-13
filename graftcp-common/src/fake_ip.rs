use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use lazy_static::lazy_static;

/// Loopback address generator that produces sequential unique loopback addresses
/// Uses 127.0.0.1 to 127.255.255.254 range, cycling when exhausted
#[derive(Debug)]
pub struct LoopbackGenerator {
    /// Current loopback IP as u32 (starts from 127.0.0.1)
    current_ip: u32,
    /// Mapping from loopback IP to real destination (IP:port)
    loopback_to_target: HashMap<Ipv4Addr, SocketAddr>,
    /// Reverse mapping for cleanup and deduplication
    target_to_loopback: HashMap<SocketAddr, Ipv4Addr>,
}

/// Loopback IP range: 127.0.0.0/8
const LOOPBACK_BASE: u32 = 0x7F000000; // 127.0.0.0
const LOOPBACK_MASK: u32 = 0xFF000000; // /8 mask
const LOOPBACK_START: u32 = 0x7F000001; // 127.0.0.1 (skip 127.0.0.0)
const LOOPBACK_END: u32 = 0x7FFFFFFE;   // 127.255.255.254 (skip 127.255.255.255)

impl LoopbackGenerator {
    pub fn new() -> Self {
        Self {
            current_ip: LOOPBACK_START,
            loopback_to_target: HashMap::new(),
            target_to_loopback: HashMap::new(),
        }
    }

    /// Allocate a unique loopback IP for the given target address
    /// Returns existing loopback IP if target is already mapped
    pub fn allocate_loopback(&mut self, target: SocketAddr) -> Result<Ipv4Addr, String> {
        // Check if we already have a loopback IP for this target
        if let Some(existing_loopback) = self.target_to_loopback.get(&target) {
            return Ok(*existing_loopback);
        }

        // Find next available loopback IP
        let start_ip = self.current_ip;
        loop {
            let loopback_ip = Ipv4Addr::from(self.current_ip);
            
            // Check if this IP is already in use
            if !self.loopback_to_target.contains_key(&loopback_ip) {
                // Found an available IP
                self.loopback_to_target.insert(loopback_ip, target);
                self.target_to_loopback.insert(target, loopback_ip);
                
                // Advance to next IP for future allocations
                self.advance_current_ip();
                
                return Ok(loopback_ip);
            }
            
            // Move to next IP and check for wraparound
            self.advance_current_ip();
            
            // Check if we've cycled through all available IPs
            if self.current_ip == start_ip {
                return Err("All loopback addresses are in use".to_string());
            }
        }
    }

    /// Resolve a loopback IP back to the original target address
    pub fn resolve_loopback(&self, loopback_ip: Ipv4Addr) -> Option<SocketAddr> {
        self.loopback_to_target.get(&loopback_ip).copied()
    }

    /// Check if an IP is in the loopback range (127.0.0.0/8)
    pub fn is_loopback(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                let ip_u32 = u32::from(ipv4);
                (ip_u32 & LOOPBACK_MASK) == LOOPBACK_BASE
            }
            IpAddr::V6(_) => false,
        }
    }

    /// Release a loopback IP mapping (for cleanup)
    pub fn release_loopback(&mut self, loopback_ip: Ipv4Addr) -> bool {
        if let Some(target) = self.loopback_to_target.remove(&loopback_ip) {
            self.target_to_loopback.remove(&target);
            true
        } else {
            false
        }
    }

    /// Get current usage statistics
    pub fn stats(&self) -> (usize, u32) {
        (self.loopback_to_target.len(), self.current_ip - LOOPBACK_START)
    }

    /// Advance current IP to next available address
    fn advance_current_ip(&mut self) {
        self.current_ip += 1;
        if self.current_ip > LOOPBACK_END {
            self.current_ip = LOOPBACK_START; // Wrap around
        }
    }
}

/// Global instance of the loopback generator
lazy_static! {
    pub static ref GLOBAL_LOOPBACK_GENERATOR: Arc<Mutex<LoopbackGenerator>> = 
        Arc::new(Mutex::new(LoopbackGenerator::new()));
}

/// Convenience functions for global access

/// Allocate a loopback IP for a target address
pub fn allocate_loopback_ip(target: SocketAddr) -> Result<Ipv4Addr, String> {
    GLOBAL_LOOPBACK_GENERATOR
        .lock()
        .map_err(|e| format!("Failed to lock loopback generator: {}", e))?
        .allocate_loopback(target)
}

/// Resolve a loopback IP to target address
pub fn resolve_loopback_ip(loopback_ip: Ipv4Addr) -> Option<SocketAddr> {
    GLOBAL_LOOPBACK_GENERATOR
        .lock()
        .ok()?
        .resolve_loopback(loopback_ip)
}

/// Check if an IP is a loopback IP
pub fn is_loopback_ip(ip: IpAddr) -> bool {
    GLOBAL_LOOPBACK_GENERATOR
        .lock()
        .map(|generator| generator.is_loopback(ip))
        .unwrap_or(false)
}

/// Release a loopback IP mapping
pub fn release_loopback_ip(loopback_ip: Ipv4Addr) -> bool {
    GLOBAL_LOOPBACK_GENERATOR
        .lock()
        .map(|mut generator| generator.release_loopback(loopback_ip))
        .unwrap_or(false)
}

/// Get usage statistics
pub fn get_loopback_stats() -> (usize, u32) {
    GLOBAL_LOOPBACK_GENERATOR
        .lock()
        .map(|generator| generator.stats())
        .unwrap_or((0, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loopback_generator_basic() {
        let mut generator = LoopbackGenerator::new();
        
        let target = "93.184.216.34:80".parse().unwrap();
        let loopback_ip = generator.allocate_loopback(target).unwrap();
        
        // Should be in loopback range
        assert!(generator.is_loopback(IpAddr::V4(loopback_ip)));
        
        // Should resolve back to original
        assert_eq!(generator.resolve_loopback(loopback_ip), Some(target));
    }

    #[test]
    fn test_sequential_allocation() {
        let mut generator = LoopbackGenerator::new();
        
        let target1 = "1.2.3.4:80".parse().unwrap();
        let target2 = "5.6.7.8:443".parse().unwrap();
        
        let loopback1 = generator.allocate_loopback(target1).unwrap();
        let loopback2 = generator.allocate_loopback(target2).unwrap();
        
        // Should be different IPs
        assert_ne!(loopback1, loopback2);
        
        // Should resolve correctly
        assert_eq!(generator.resolve_loopback(loopback1), Some(target1));
        assert_eq!(generator.resolve_loopback(loopback2), Some(target2));
        
        // Sequential IPs
        assert_eq!(u32::from(loopback2), u32::from(loopback1) + 1);
    }

    #[test]
    fn test_duplicate_target_reuses_loopback() {
        let mut generator = LoopbackGenerator::new();
        
        let target = "93.184.216.34:80".parse().unwrap();
        let loopback1 = generator.allocate_loopback(target).unwrap();
        let loopback2 = generator.allocate_loopback(target).unwrap();
        
        // Should return the same loopback IP for the same target
        assert_eq!(loopback1, loopback2);
    }

    #[test]
    fn test_loopback_range() {
        let generator = LoopbackGenerator::new();
        
        // Test loopback IP detection
        assert!(generator.is_loopback("127.0.0.1".parse().unwrap()));
        assert!(generator.is_loopback("127.1.2.3".parse().unwrap()));
        assert!(generator.is_loopback("127.255.255.255".parse().unwrap()));
        assert!(!generator.is_loopback("192.168.1.1".parse().unwrap()));
        assert!(!generator.is_loopback("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_release_loopback() {
        let mut generator = LoopbackGenerator::new();
        
        let target = "93.184.216.34:80".parse().unwrap();
        let loopback_ip = generator.allocate_loopback(target).unwrap();
        
        // Should resolve initially
        assert_eq!(generator.resolve_loopback(loopback_ip), Some(target));
        
        // Release the mapping
        assert!(generator.release_loopback(loopback_ip));
        
        // Should no longer resolve
        assert_eq!(generator.resolve_loopback(loopback_ip), None);
        
        // Can't release again
        assert!(!generator.release_loopback(loopback_ip));
    }

    #[test]
    fn test_global_functions() {
        let target = "8.8.8.8:53".parse().unwrap();
        
        // Allocate via global function
        let loopback_ip = allocate_loopback_ip(target).unwrap();
        
        // Should be in loopback range
        assert!(is_loopback_ip(IpAddr::V4(loopback_ip)));
        
        // Should resolve via global function
        assert_eq!(resolve_loopback_ip(loopback_ip), Some(target));
        
        // Check stats
        let (count, _) = get_loopback_stats();
        assert!(count >= 1);
        
        // Release via global function
        assert!(release_loopback_ip(loopback_ip));
        assert_eq!(resolve_loopback_ip(loopback_ip), None);
    }

    #[test]
    fn test_wraparound_behavior() {
        let mut generator = LoopbackGenerator::new();
        
        // Test that current_ip wraps around correctly
        generator.current_ip = LOOPBACK_END;
        generator.advance_current_ip();
        assert_eq!(generator.current_ip, LOOPBACK_START);
    }

    #[test]
    fn test_first_loopback_allocation() {
        let mut generator = LoopbackGenerator::new();
        let target = "1.2.3.4:80".parse().unwrap();
        
        let loopback_ip = generator.allocate_loopback(target).unwrap();
        
        // First allocation should be 127.0.0.1
        assert_eq!(loopback_ip, Ipv4Addr::new(127, 0, 0, 1));
        
        // Next allocation should be 127.0.0.2
        let target2 = "5.6.7.8:80".parse().unwrap();
        let loopback_ip2 = generator.allocate_loopback(target2).unwrap();
        assert_eq!(loopback_ip2, Ipv4Addr::new(127, 0, 0, 2));
    }
}