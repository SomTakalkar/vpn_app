//! Phase 2 – VPN Client: plaintext UDP tunnel
//!
//! Creates a TUN device (10.8.0.2/24), connects to the server over UDP,
//! and bidirectionally forwards raw IP packets between the local tunnel
//! and the remote server.
//!
//! Run inside the client namespace:
//!   sudo ip netns exec ns-client ./target/debug/client --server 10.0.2.2:51820

use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

use vpn::wire::{DataHeader, HEADER_LEN};

#[derive(Parser, Debug)]
#[command(about = "Phase 2: VPN client – plaintext UDP tunnel")]
struct Args {
    /// Server address (ip:port)
    #[arg(long)]
    server: String,

    /// TUN interface name
    #[arg(long, default_value = "tun0")]
    tun_name: String,

    /// IPv4 address for the client's TUN interface
    #[arg(long, default_value = "10.8.0.2")]
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

    // ── Bind a UDP socket on an ephemeral port ─────────────────────
    let udp = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("Failed to bind UDP socket")?;

    let server_addr: std::net::SocketAddr = args
        .server
        .parse()
        .with_context(|| format!("Invalid server address: {}", args.server))?;

    udp.connect(server_addr)
        .await
        .with_context(|| format!("Failed to connect UDP to {}", server_addr))?;

    info!("UDP connected to server at {}", server_addr);

    // ── Counter for outgoing frames ───────────────────────────────
    let mut tx_counter: u64 = 0;

    // ── Buffers ───────────────────────────────────────────────────
    let mut tun_buf = vec![0u8; 65535];
    let mut udp_buf = vec![0u8; 65535];

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    info!("Client ready – tunnelling to {}", server_addr);

    loop {
        tokio::select! {
            // ── Graceful shutdown ─────────────────────────────────
            _ = &mut ctrl_c => {
                info!("Shutting down");
                break;
            }

            // ── TUN → UDP (intercept outgoing packets, send to server)
            result = tun_dev.read(&mut tun_buf) => {
                let n = result.context("TUN read failed")?;
                if n < 20 {
                    continue;
                }

                // Build wire frame: [header][raw IP payload]
                tx_counter += 1;
                let header = DataHeader::new(0, tx_counter);
                let hdr_bytes = header.serialize();

                let mut send_buf = Vec::with_capacity(HEADER_LEN + n);
                send_buf.extend_from_slice(&hdr_bytes);
                send_buf.extend_from_slice(&tun_buf[..n]);

                udp.send(&send_buf).await.context("UDP send failed")?;
                debug!("TUN→UDP: {} bytes (counter={})", n, tx_counter);
            }

            // ── UDP → TUN (receive from server, inject into tunnel)
            result = udp.recv(&mut udp_buf) => {
                let n = result.context("UDP recv failed")?;

                if n < HEADER_LEN {
                    warn!("Dropping undersized UDP datagram ({} bytes)", n);
                    continue;
                }

                // Parse and validate wire header
                let header = match DataHeader::deserialize(&udp_buf[..n]) {
                    Ok(h) => h,
                    Err(e) => {
                        warn!("Bad header from server: {}", e);
                        continue;
                    }
                };

                let payload = &udp_buf[HEADER_LEN..n];
                if payload.is_empty() {
                    debug!("Empty payload from server (keepalive?)");
                    continue;
                }

                // Write raw IP packet into TUN
                tun_dev.write_all(payload).await.context("TUN write failed")?;
                debug!(
                    "UDP→TUN: {} bytes (counter={})",
                    payload.len(), header.counter
                );
            }
        }
    }

    Ok(())
}
