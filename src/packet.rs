use std::net::Ipv4Addr;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Icmp,
    Tcp,
    Udp,
    Other(u8),
}

impl From<u8> for IpProtocol {
    fn from(val: u8) -> Self {
        match val {
            1 => IpProtocol::Icmp,
            6 => IpProtocol::Tcp,
            17 => IpProtocol::Udp,
            other => IpProtocol::Other(other),
        }
    }
}

impl std::fmt::Display for IpProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpProtocol::Icmp => write!(f, "ICMP (1)"),
            IpProtocol::Tcp => write!(f, "TCP (6)"),
            IpProtocol::Udp => write!(f, "UDP (17)"),
            IpProtocol::Other(n) => write!(f, "Protocol({})", n),
        }
    }
}

/// Parsed IPv4 packet header info.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4PacketHeader {
    pub version: u8,
    pub ihl_bytes: usize,
    pub total_length: u16,
    pub ttl: u8,
    pub protocol: IpProtocol,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
}

impl Ipv4PacketHeader {
    /// Parse an IPv4 header from raw packet bytes.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 20 {
            return None;
        }

        let version = (buf[0] >> 4) & 0x0F;
        if version != 4 {
            return None;
        }

        let ihl = (buf[0] & 0x0F) as usize;
        let ihl_bytes = ihl * 4;
        if buf.len() < ihl_bytes || ihl_bytes < 20 {
            return None;
        }

        let total_length = u16::from_be_bytes([buf[2], buf[3]]);
        let ttl = buf[8];
        let protocol = IpProtocol::from(buf[9]);

        let src_ip = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
        let dst_ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);

        Some(Ipv4PacketHeader {
            version,
            ihl_bytes,
            total_length,
            ttl,
            protocol,
            src_ip,
            dst_ip,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_echo_request() -> Vec<u8> {
        let mut p = vec![0u8; 84];
        p[0] = 0x45; // version 4, IHL 5 (20 bytes)
        p[2..4].copy_from_slice(&84u16.to_be_bytes());
        p[8] = 64;   // TTL
        p[9] = 1;    // ICMP
        p[12..16].copy_from_slice(&[10, 8, 0, 2]);
        p[16..20].copy_from_slice(&[10, 8, 0, 3]);
        p[20] = 8;   // ICMP echo request
        p
    }

    #[test]
    fn test_parse_ipv4_valid() {
        let pkt = sample_echo_request();
        let header = Ipv4PacketHeader::parse(&pkt).expect("Should parse valid IPv4 packet");
        assert_eq!(header.version, 4);
        assert_eq!(header.ihl_bytes, 20);
        assert_eq!(header.total_length, 84);
        assert_eq!(header.ttl, 64);
        assert_eq!(header.protocol, IpProtocol::Icmp);
        assert_eq!(header.src_ip, Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(header.dst_ip, Ipv4Addr::new(10, 8, 0, 3));
    }

    #[test]
    fn test_parse_ipv4_truncated() {
        assert!(Ipv4PacketHeader::parse(&[0x45; 10]).is_none());
    }

    #[test]
    fn test_parse_non_ipv4() {
        let mut pkt = sample_echo_request();
        pkt[0] = 0x60; // IPv6
        assert!(Ipv4PacketHeader::parse(&pkt).is_none());
    }
}
