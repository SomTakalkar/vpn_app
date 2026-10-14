use std::net::Ipv4Addr;

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
#[derive(Debug, Clone)]
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
