//! Phase 2 – VPN Server: plaintext UDP tunnel
//!
//! Creates a TUN device (10.8.0.1/24), listens on a UDP socket, and
//! bidirectionally forwards raw IP packets between the tunnel and
//! connected clients.
//!
//! Run inside the server namespace:
//!   sudo ip netns exec ns-server ./target/debug/server
//!
//! Peer table: when a UDP datagram arrives, the server parses the
//! encapsulated IPv4 source address and records a mapping
//!   tunnel_ip  →  UDP SocketAddr
//! so that return traffic from the TUN can be routed back to the
//! correct client.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{Context, Result};
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

use vpn::wire::{DataHeader, HEADER_LEN};

#[derive(Parser, Debug)]
#[command(about = "Phase 2: VPN server – plaintext UDP tunnel")]
struct Args {
    /// UDP address to bind on
    #[arg(long, default_value = "0.0.0.0:51820")]
    bind: String,

    /// TUN interface name
    #[arg(long, default_value = "tun0")]
    tun_name: String,

    /// IPv4 address for the server's TUN interface
    #[arg(long, default_value = "10.8.0.1")]
    tun_addr: Ipv4Addr,

    /// Netmask for the TUN subnet
    #[arg(long, default_value = "255.255.255.0")]
    netmask: Ipv4Addr,

    /// MTU for the TUN interface
    #[arg(long, default_value_t = 1400)]
    mtu: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let args = Args::parse();

    // ── Create TUN device ──────────────────────────────────────────
    let mut tun_config = tun::Configuration::default();
    tun_config
        .name(&args.tun_name)
        .address(args.tun_addr)
        .netmask(args.netmask)
        .mtu(args.mtu as i32)
        .up();

    #[cfg(target_os = "linux")]
    tun_config.platform(|p| {
        p.packet_information(false);
    });

    let mut tun_dev = tun::create_as_async(&tun_config)
        .context("Failed to create TUN device (need root / CAP_NET_ADMIN)")?;

    info!(
        "TUN '{}' is up: {}/{} mtu={}",
        args.tun_name, args.tun_addr, args.netmask, args.mtu
    );

    // ── Bind UDP socket ────────────────────────────────────────────
    let udp = UdpSocket::bind(&args.bind)
        .await
        .with_context(|| format!("Failed to bind UDP on {}", args.bind))?;
    info!("Listening on UDP {}", args.bind);

    // ── Peer table: tunnel IPv4 → last-known UDP SocketAddr ───────
    let mut peers: HashMap<Ipv4Addr, SocketAddr> = HashMap::new();

    // ── Counters for outgoing frames ──────────────────────────────
    let mut tx_counter: u64 = 0;

    // ── Buffers ───────────────────────────────────────────────────
    let mut tun_buf = vec![0u8; 65535];
    let mut udp_buf = vec![0u8; 65535];

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    info!("Server ready – waiting for clients");

    loop {
        tokio::select! {
            // ── Graceful shutdown ─────────────────────────────────
            _ = &mut ctrl_c => {
                info!("Shutting down");
                break;
            }

            // ── UDP → TUN (client sent us an encapsulated packet) ─
            result = udp.recv_from(&mut udp_buf) => {
                let (n, peer_addr) = result.context("UDP recv_from failed")?;

                if n < HEADER_LEN {
                    warn!("Dropping undersized UDP datagram ({} bytes) from {}", n, peer_addr);
                    continue;
                }

                // Parse our wire header
                let header = match DataHeader::deserialize(&udp_buf[..n]) {
                    Ok(h) => h,
                    Err(e) => {
                        warn!("Bad header from {}: {}", peer_addr, e);
                        continue;
                    }
                };

                let payload = &udp_buf[HEADER_LEN..n];
                if payload.is_empty() {
                    debug!("Empty payload from {} (keepalive?)", peer_addr);
                    continue;
                }

                // Parse inner IPv4 to learn the client's tunnel IP
                if payload.len() >= 20 && (payload[0] >> 4) == 4 {
                    let src_ip = Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]);
                    if peers.get(&src_ip) != Some(&peer_addr) {
                        info!("Peer registered: tunnel {} → UDP {}", src_ip, peer_addr);
                        peers.insert(src_ip, peer_addr);
                    }
                }

                // Write raw IP packet into TUN
                tun_dev.write_all(payload).await.context("TUN write failed")?;
                debug!(
                    "UDP→TUN: {} bytes from {} (counter={})",
                    payload.len(), peer_addr, header.counter
                );
            }

            // ── TUN → UDP (kernel handed us a response packet) ────
            result = tun_dev.read(&mut tun_buf) => {
                let n = result.context("TUN read failed")?;
                if n < 20 {
                    continue;
                }

                // Parse destination IP to find the right peer
                let dst_ip = Ipv4Addr::new(tun_buf[16], tun_buf[17], tun_buf[18], tun_buf[19]);

                let peer_addr = match peers.get(&dst_ip) {
                    Some(addr) => *addr,
                    None => {
                        debug!("No peer known for destination {}, dropping", dst_ip);
                        continue;
                    }
                };

                // Build wire frame: [header][payload]
                tx_counter += 1;
                let header = DataHeader::new(0, tx_counter);
                let hdr_bytes = header.serialize();

                // Assemble into a single send buffer
                let mut send_buf = Vec::with_capacity(HEADER_LEN + n);
                send_buf.extend_from_slice(&hdr_bytes);
                send_buf.extend_from_slice(&tun_buf[..n]);

                udp.send_to(&send_buf, peer_addr).await.context("UDP send_to failed")?;
                debug!(
                    "TUN→UDP: {} bytes → {} (counter={})",
                    n, peer_addr, tx_counter
                );
            }
        }
    }

    Ok(())
}
