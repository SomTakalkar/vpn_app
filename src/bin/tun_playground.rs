//! Phase 1: bring up a TUN interface and print every IP packet the kernel sends into it.
//!
//! Run as root (or with CAP_NET_ADMIN), e.g. inside the client namespace:
//!   sudo ip netns exec ns-client ./target/debug/tun_playground
//! Then, from another terminal, ping an address in the TUN subnet that is NOT the
//! interface's own address (pings to your own address are answered by the kernel on
//! loopback and never reach the TUN device):
//!   sudo ip netns exec ns-client ping -c 3 10.8.0.3

use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::io::AsyncReadExt;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(about = "Phase 1: TUN playground - prints parsed IPv4 headers")]
struct Args {
    /// Name of the TUN interface to create
    #[arg(long, default_value = "tun0")]
    name: String,
    /// IPv4 address to assign to the interface
    #[arg(long, default_value = "10.8.0.2")]
    addr: Ipv4Addr,
    /// Netmask for the interface subnet
    #[arg(long, default_value = "255.255.255.0")]
    netmask: Ipv4Addr,
    /// MTU of the interface (leave room for UDP + header + AEAD tag later)
    #[arg(long, default_value_t = 1400)]
    mtu: u16,
}

#[derive(Debug, PartialEq)]
struct Ipv4Header {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    total_len: u16,
    header_len: usize,
    ttl: u8,
}

/// Parse the fixed part of an IPv4 header. Returns None if the buffer is not a valid IPv4 packet start.
fn parse_ipv4(pkt: &[u8]) -> Option<Ipv4Header> {
    if pkt.len() < 20 {
        return None;
    }
    let version = pkt[0] >> 4;
    let header_len = ((pkt[0] & 0x0f) as usize) * 4;
    if version != 4 || header_len < 20 || pkt.len() < header_len {
        return None;
    }
    Some(Ipv4Header {
        total_len: u16::from_be_bytes([pkt[2], pkt[3]]),
        ttl: pkt[8],
        protocol: pkt[9],
        src: Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]),
        dst: Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]),
        header_len,
    })
}

fn protocol_name(p: u8) -> String {
    match p {
        1 => "ICMP".to_string(),
        6 => "TCP".to_string(),
        17 => "UDP".to_string(),
        other => format!("proto {other}"),
    }
}

fn describe(pkt: &[u8]) -> String {
    match pkt.first().map(|b| b >> 4) {
        None => "empty read".to_string(),
        Some(4) => match parse_ipv4(pkt) {
            Some(h) => {
                let mut s = format!(
                    "IPv4 {} -> {} {} len={} ttl={}",
                    h.src,
                    h.dst,
                    protocol_name(h.protocol),
                    h.total_len,
                    h.ttl
                );
                // ICMP: show the message type so pings are easy to spot.
                if h.protocol == 1 && pkt.len() > h.header_len {
                    let kind = match pkt[h.header_len] {
                        8 => "echo request".to_string(),
                        0 => "echo reply".to_string(),
                        t => format!("type {t}"),
                    };
                    s.push_str(&format!(" ({kind})"));
                }
                s
            }
            None => format!("malformed IPv4 packet ({} bytes)", pkt.len()),
        },
        Some(6) => format!("IPv6 packet ({} bytes)", pkt.len()),
        Some(v) => format!(
            "unknown IP version {v} ({} bytes) - is the 4-byte packet-info prefix enabled?",
            pkt.len()
        ),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let args = Args::parse();

    let mut config = tun::Configuration::default();
    config
        .name(&args.name)
        .address(args.addr)
        .netmask(args.netmask)
        .mtu(args.mtu as i32)
        .up();
    // Raw IP packets only, without the 4-byte packet-information prefix.
    #[cfg(target_os = "linux")]
    config.platform(|p| {
        p.packet_information(false);
    });

    let mut dev = tun::create_as_async(&config)
        .context("failed to create the TUN device (are you root / do you have CAP_NET_ADMIN?)")?;
    info!(
        "{} is up: {}/{} mtu={} - waiting for packets (Ctrl-C to quit)",
        args.name, args.addr, args.netmask, args.mtu
    );

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            _ = &mut ctrl_c => {
                info!("shutting down");
                break;
            }
            res = dev.read(&mut buf) => {
                let n = res.context("read from TUN failed")?;
                info!("{}", describe(&buf[..n]));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ICMP echo request 10.8.0.2 -> 10.8.0.3, 84 bytes, TTL 64.
    fn sample_echo_request() -> Vec<u8> {
        let mut p = vec![0u8; 84];
        p[0] = 0x45; // version 4, IHL 5
        p[2..4].copy_from_slice(&84u16.to_be_bytes());
        p[8] = 64; // TTL
        p[9] = 1; // ICMP
        p[12..16].copy_from_slice(&[10, 8, 0, 2]);
        p[16..20].copy_from_slice(&[10, 8, 0, 3]);
        p[20] = 8; // echo request
        p
    }

    #[test]
    fn parses_ipv4_header() {
        let h = parse_ipv4(&sample_echo_request()).unwrap();
        assert_eq!(h.src, Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(h.dst, Ipv4Addr::new(10, 8, 0, 3));
        assert_eq!(h.protocol, 1);
        assert_eq!(h.total_len, 84);
        assert_eq!(h.header_len, 20);
        assert_eq!(h.ttl, 64);
    }

    #[test]
    fn rejects_short_or_non_ipv4() {
        assert!(parse_ipv4(&[0x45; 10]).is_none());
        let mut v6 = sample_echo_request();
        v6[0] = 0x60;
        assert!(parse_ipv4(&v6).is_none());
    }

    #[test]
    fn describes_ping() {
        assert!(describe(&sample_echo_request()).contains("echo request"));
    }
}
