use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use lazy_static::lazy_static;

/// Fake IP range: 198.19.0.0/16 (RFC 6890 - Test-Net-2)
/// This range is reserved for documentation and testing purposes
const FAKE_IP_BASE: u32 = 0xC6130000; // 198.19.0.0
const FAKE_IP_MASK: u32 = 0xFFFF0000; // /16 mask

/// Global fake IP generator and mapping storage
#[derive(Debug)]
pub struct FakeIpGenerator {
    /// Next available IP address (as u32)
    next_ip: u32,
    /// Mapping from fake IP to real destination address
    fake_to_real: HashMap<Ipv4Addr, SocketAddr>,
    /// Reverse mapping for cleanup (optional)
    real_to_fake: HashMap<SocketAddr, Ipv4Addr>,
}

impl FakeIpGenerator {
    pub fn new() -> Self {
        Self {
            next_ip: FAKE_IP_BASE + 1, // Start from 198.19.0.1
            fake_to_real: HashMap::new(),
            real_to_fake: HashMap::new(),
        }
    }

    /// Generate a new fake IP for the given real destination
    pub fn allocate_fake_ip(&mut self, real_dest: SocketAddr) -> Result<Ipv4Addr, String> {
        // Check if we already have a fake IP for this destination
        if let Some(fake_ip) = self.real_to_fake.get(&real_dest) {
            return Ok(*fake_ip);
        }

        // Check if we've exhausted the IP range
        if (self.next_ip & !FAKE_IP_MASK) >= 0xFFFF {
            return Err("Fake IP range exhausted".to_string());
        }

        let fake_ip = Ipv4Addr::from(self.next_ip);
        
        // Store the mapping
        self.fake_to_real.insert(fake_ip, real_dest);
        self.real_to_fake.insert(real_dest, fake_ip);
        
        // Increment for next allocation
        self.next_ip += 1;
        
        Ok(fake_ip)
    }

    /// Resolve a fake IP back to the real destination
    pub fn resolve_fake_ip(&self, fake_ip: Ipv4Addr) -> Option<SocketAddr> {
        self.fake_to_real.get(&fake_ip).copied()
    }

    /// Check if an IP is in the fake IP range
    pub fn is_fake_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                let ip_u32 = u32::from(ipv4);
                (ip_u32 & FAKE_IP_MASK) == FAKE_IP_BASE
            }
            IpAddr::V6(_) => false, // IPv6 not supported in fake range
        }
    }

    /// Remove mapping for cleanup (optional)
    pub fn deallocate_fake_ip(&mut self, fake_ip: Ipv4Addr) -> bool {
        if let Some(real_dest) = self.fake_to_real.remove(&fake_ip) {
            self.real_to_fake.remove(&real_dest);
            true
        } else {
            false
        }
    }

    /// Get statistics
    pub fn stats(&self) -> (usize, u32) {
        (self.fake_to_real.len(), self.next_ip - FAKE_IP_BASE)
    }
}

/// Global instance of the fake IP generator
lazy_static! {
    pub static ref GLOBAL_FAKE_IP_GENERATOR: Arc<Mutex<FakeIpGenerator>> = 
        Arc::new(Mutex::new(FakeIpGenerator::new()));
}

/// Convenience functions for global access

/// Allocate a fake IP for a real destination
pub fn allocate_fake_ip(real_dest: SocketAddr) -> Result<Ipv4Addr, String> {
    GLOBAL_FAKE_IP_GENERATOR
        .lock()
        .map_err(|e| format!("Failed to lock fake IP generator: {}", e))?
        .allocate_fake_ip(real_dest)
}

/// Resolve a fake IP to real destination
pub fn resolve_fake_ip(fake_ip: Ipv4Addr) -> Option<SocketAddr> {
    GLOBAL_FAKE_IP_GENERATOR
        .lock()
        .ok()?
        .resolve_fake_ip(fake_ip)
}

/// Check if an IP is a fake IP
pub fn is_fake_ip(ip: IpAddr) -> bool {
    GLOBAL_FAKE_IP_GENERATOR
        .lock()
        .map(|generator| generator.is_fake_ip(ip))
        .unwrap_or(false)
}

/// Get mapping statistics
pub fn get_fake_ip_stats() -> (usize, u32) {
    GLOBAL_FAKE_IP_GENERATOR
        .lock()
        .map(|generator| generator.stats())
        .unwrap_or((0, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fake_ip_allocation() {
        let mut generator = FakeIpGenerator::new();
        
        let real_dest = "93.184.216.34:80".parse().unwrap();
        let fake_ip = generator.allocate_fake_ip(real_dest).unwrap();
        
        // Should be in fake range
        assert!(generator.is_fake_ip(IpAddr::V4(fake_ip)));
        
        // Should resolve back to original
        assert_eq!(generator.resolve_fake_ip(fake_ip), Some(real_dest));
    }

    #[test]
    fn test_fake_ip_range() {
        let generator = FakeIpGenerator::new();
        
        // Test fake IP detection
        assert!(generator.is_fake_ip("198.19.0.1".parse().unwrap()));
        assert!(generator.is_fake_ip("198.19.255.255".parse().unwrap()));
        assert!(!generator.is_fake_ip("198.18.0.1".parse().unwrap()));
        assert!(!generator.is_fake_ip("198.20.0.1".parse().unwrap()));
        assert!(!generator.is_fake_ip("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_duplicate_allocation() {
        let mut generator = FakeIpGenerator::new();
        
        let real_dest = "93.184.216.34:80".parse().unwrap();
        let fake_ip1 = generator.allocate_fake_ip(real_dest).unwrap();
        let fake_ip2 = generator.allocate_fake_ip(real_dest).unwrap();
        
        // Should return the same fake IP for the same destination
        assert_eq!(fake_ip1, fake_ip2);
    }
}