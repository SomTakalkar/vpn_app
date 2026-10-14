//! Phase 3 – VPN Client: ChaCha20-Poly1305 encrypted UDP tunnel
//!
//! Identical to the Phase 2 client, but every UDP datagram is now
//! authenticated and encrypted with a pre-shared ChaCha20-Poly1305 key.
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

use vpn::crypto::{decrypt_packet, encrypt_packet, make_cipher, PRESHARED_KEY};

#[derive(Parser, Debug)]
#[command(about = "Phase 3: VPN client – encrypted UDP tunnel")]
struct Args {
    /// Server address (ip:port)
    #[arg(long)]
    server: String,

    #[arg(long, default_value = "tun0")]
    tun_name: String,

    #[arg(long, default_value = "10.8.0.2")]
    tun_addr: Ipv4Addr,

    #[arg(long, default_value = "255.255.255.0")]
    netmask: Ipv4Addr,

    #[arg(long, default_value_t = 1400)]
    mtu: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let args = Args::parse();

    // ── Cipher (Phase 3: pre-shared key; replaced by ECDH in Phase 4) ─
    let cipher = make_cipher(&PRESHARED_KEY);
    info!("ChaCha20-Poly1305 cipher initialised (pre-shared key)");

    // ── Create TUN device ──────────────────────────────────────────
    let mut tun_config = tun::Configuration::default();
    tun_config
        .name(&args.tun_name)
        .address(args.tun_addr)
        .netmask(args.netmask)
        .mtu(args.mtu as i32)
        .up();

    #[cfg(target_os = "linux")]
    tun_config.platform(|p| { p.packet_information(false); });

    let mut tun_dev = tun::create_as_async(&tun_config)
        .context("Failed to create TUN device (need root / CAP_NET_ADMIN)")?;

    info!("TUN '{}' is up: {}/{} mtu={}", args.tun_name, args.tun_addr, args.netmask, args.mtu);

    // ── Connect UDP socket to server ───────────────────────────────
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

    let mut tx_counter: u64 = 0;
    let mut tun_buf = vec![0u8; 65535];
    let mut udp_buf = vec![0u8; 65535];

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    info!("Client ready – tunnelling encrypted traffic to {}", server_addr);

    loop {
        tokio::select! {
            _ = &mut ctrl_c => {
                info!("Shutting down");
                break;
            }

            // ── TUN → UDP (encrypt & send to server) ─────────────
            result = tun_dev.read(&mut tun_buf) => {
                let n = result.context("TUN read failed")?;
                if n < 20 { continue; }

                tx_counter += 1;
                let datagram = encrypt_packet(&cipher, 0, tx_counter, &tun_buf[..n])
                    .context("Encryption failed")?;

                udp.send(&datagram).await.context("UDP send failed")?;
                debug!("TUN→UDP: {} bytes encrypted (counter={})", n, tx_counter);
            }

            // ── UDP → TUN (decrypt & inject into TUN) ────────────
            result = udp.recv(&mut udp_buf) => {
                let n = result.context("UDP recv failed")?;

                let (header, plaintext) = match decrypt_packet(&cipher, &udp_buf[..n]) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("Rejected datagram from server: {}", e);
                        continue;
                    }
                };

                if plaintext.is_empty() {
                    debug!("Keepalive from server");
                    continue;
                }

                tun_dev.write_all(&plaintext).await.context("TUN write failed")?;
                debug!("UDP→TUN: {} plaintext bytes (counter={})",
                    plaintext.len(), header.counter);
            }
        }
    }

    Ok(())
}
