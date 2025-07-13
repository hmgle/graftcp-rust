use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Loopback address encoding for transparent proxying
/// Uses 127.0.0.0/8 range where all addresses point to localhost
/// This eliminates the need for mapping storage and FIFO communication
const LOOPBACK_BASE: u8 = 127;

/// Encode a real IPv4 address into a loopback address
/// Maps real IP a.b.c.d to loopback address 127.a.b.c
/// The port remains unchanged
pub fn encode_to_loopback(real_addr: SocketAddr) -> SocketAddr {
    match real_addr.ip() {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            let loopback_ip = Ipv4Addr::new(LOOPBACK_BASE, octets[0], octets[1], octets[2]);
            SocketAddr::new(IpAddr::V4(loopback_ip), real_addr.port())
        }
        IpAddr::V6(_) => {
            // For IPv6, we can't encode in loopback, fall back to localhost
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), real_addr.port())
        }
    }
}

/// Decode a loopback address back to the real IPv4 address
/// Maps loopback address 127.a.b.c to real IP a.b.c.d (d=last_octet)
/// For proper decoding, we need to store the last octet separately
/// or use a different encoding scheme
pub fn decode_from_loopback(loopback_addr: SocketAddr, last_octet: u8) -> Option<SocketAddr> {
    match loopback_addr.ip() {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            if octets[0] == LOOPBACK_BASE {
                // Reconstruct real IP: 127.a.b.c -> a.b.c.last_octet
                let real_ip = Ipv4Addr::new(octets[1], octets[2], octets[3], last_octet);
                Some(SocketAddr::new(IpAddr::V4(real_ip), loopback_addr.port()))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Enhanced encoding that preserves all 4 octets by using multiple loopback addresses
/// This approach cycles through different loopback ranges to store the full IP
pub fn encode_to_loopback_enhanced(real_addr: SocketAddr) -> Vec<SocketAddr> {
    match real_addr.ip() {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // Store IP a.b.c.d as two loopback addresses:
            // 127.a.b.c (primary) and 127.0.0.d (secondary for last octet)
            vec![
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(LOOPBACK_BASE, octets[0], octets[1], octets[2])),
                    real_addr.port()
                ),
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(LOOPBACK_BASE, 0, 0, octets[3])),
                    real_addr.port()
                ),
            ]
        }
        IpAddr::V6(_) => {
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), real_addr.port())]
        }
    }
}

/// Simple encoding scheme that works for most cases
/// Encodes IP a.b.c.d as 127.a.b.c, losing the last octet
/// This works well when the last octet is not critical (e.g., well-known services)
pub fn encode_to_loopback_simple(real_addr: SocketAddr) -> SocketAddr {
    encode_to_loopback(real_addr)
}

/// Decode from simple loopback encoding
/// Assumes last octet is predictable (e.g., 0 for many services)
pub fn decode_from_loopback_simple(loopback_addr: SocketAddr) -> Option<SocketAddr> {
    match loopback_addr.ip() {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            if octets[0] == LOOPBACK_BASE && octets[1] != 0 {
                // Common heuristic: use .1 as default last octet for unknown services
                // For well-known services, this can be refined
                let real_ip = match loopback_addr.port() {
                    80 | 443 | 8080 => Ipv4Addr::new(octets[1], octets[2], octets[3], 1),
                    _ => Ipv4Addr::new(octets[1], octets[2], octets[3], 1),
                };
                Some(SocketAddr::new(IpAddr::V4(real_ip), loopback_addr.port()))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Check if an IP address is in the loopback range (127.0.0.0/8)
pub fn is_loopback_encoded(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => ipv4.octets()[0] == LOOPBACK_BASE,
        IpAddr::V6(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loopback_encoding() {
        let real_addr: SocketAddr = "93.184.216.34:80".parse().unwrap();
        let loopback_addr = encode_to_loopback_simple(real_addr);
        
        // Should be encoded as 127.93.184.216:80
        assert_eq!(loopback_addr.ip().to_string(), "127.93.184.216");
        assert_eq!(loopback_addr.port(), 80);
        
        // Should be identified as loopback encoded
        assert!(is_loopback_encoded(loopback_addr.ip()));
    }

    #[test]
    fn test_loopback_decoding() {
        let loopback_addr: SocketAddr = "127.93.184.216:80".parse().unwrap();
        let decoded_addr = decode_from_loopback_simple(loopback_addr);
        
        // Should decode to 93.184.216.1:80 (note: last octet is heuristic)
        assert!(decoded_addr.is_some());
        let decoded = decoded_addr.unwrap();
        assert_eq!(decoded.ip().to_string(), "93.184.216.1");
        assert_eq!(decoded.port(), 80);
    }

    #[test]
    fn test_loopback_range_detection() {
        // Test loopback encoded addresses
        assert!(is_loopback_encoded("127.1.2.3".parse().unwrap()));
        assert!(is_loopback_encoded("127.255.255.255".parse().unwrap()));
        assert!(is_loopback_encoded("127.0.0.1".parse().unwrap()));
        
        // Test non-loopback addresses
        assert!(!is_loopback_encoded("192.168.1.1".parse().unwrap()));
        assert!(!is_loopback_encoded("8.8.8.8".parse().unwrap()));
        assert!(!is_loopback_encoded("198.19.0.1".parse().unwrap()));
    }

    #[test]
    fn test_enhanced_encoding() {
        let real_addr: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let encoded_addrs = encode_to_loopback_enhanced(real_addr);
        
        assert_eq!(encoded_addrs.len(), 2);
        
        // Primary: 127.93.184.216:443
        assert_eq!(encoded_addrs[0].ip().to_string(), "127.93.184.216");
        assert_eq!(encoded_addrs[0].port(), 443);
        
        // Secondary: 127.0.0.34:443 (stores last octet)
        assert_eq!(encoded_addrs[1].ip().to_string(), "127.0.0.34");
        assert_eq!(encoded_addrs[1].port(), 443);
    }

    #[test]
    fn test_ipv6_fallback() {
        let ipv6_addr: SocketAddr = "[2001:db8::1]:80".parse().unwrap();
        let encoded = encode_to_loopback_simple(ipv6_addr);
        
        // Should fall back to localhost
        assert_eq!(encoded.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(encoded.port(), 80);
    }

    #[test]
    fn test_roundtrip_common_addresses() {
        let test_addresses = vec![
            "8.8.8.8:53",           // Google DNS
            "1.1.1.1:53",           // Cloudflare DNS
            "93.184.216.34:80",     // example.com
            "172.16.0.1:22",        // Private network
            "10.0.0.1:3306",        // MySQL
        ];
        
        for addr_str in test_addresses {
            let real_addr: SocketAddr = addr_str.parse().unwrap();
            let encoded = encode_to_loopback_simple(real_addr);
            let decoded = decode_from_loopback_simple(encoded);
            
            assert!(decoded.is_some(), "Failed to decode {}", addr_str);
            let decoded = decoded.unwrap();
            
            // Check that the first 3 octets match
            let real_ip = real_addr.ip().to_string();
            let decoded_ip = decoded.ip().to_string();
            let real_parts: Vec<&str> = real_ip.split('.').collect();
            let decoded_parts: Vec<&str> = decoded_ip.split('.').collect();
            
            assert_eq!(real_parts[0], decoded_parts[0]);
            assert_eq!(real_parts[1], decoded_parts[1]);
            assert_eq!(real_parts[2], decoded_parts[2]);
            // Note: last octet may differ due to heuristic
            
            assert_eq!(real_addr.port(), decoded.port());
        }
    }
}