//! Phase 3 – VPN Server: ChaCha20-Poly1305 encrypted UDP tunnel
//!
//! Identical to the Phase 2 server, but every UDP datagram is now
//! authenticated and encrypted with a pre-shared ChaCha20-Poly1305 key.
//!
//! Run inside the server namespace:
//!   sudo ip netns exec ns-server ./target/debug/server

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{Context, Result};
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

use vpn::crypto::{decrypt_packet, encrypt_packet, make_cipher, PRESHARED_KEY};

#[derive(Parser, Debug)]
#[command(about = "Phase 3: VPN server – encrypted UDP tunnel")]
struct Args {
    #[arg(long, default_value = "0.0.0.0:51820")]
    bind: String,

    #[arg(long, default_value = "tun0")]
    tun_name: String,

    #[arg(long, default_value = "10.8.0.1")]
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

    // ── Bind UDP socket ────────────────────────────────────────────
    let udp = UdpSocket::bind(&args.bind)
        .await
        .with_context(|| format!("Failed to bind UDP on {}", args.bind))?;
    info!("Listening on UDP {}", args.bind);

    // ── Peer table: tunnel IPv4 → last-known UDP SocketAddr ───────
    let mut peers: HashMap<Ipv4Addr, SocketAddr> = HashMap::new();
    let mut tx_counter: u64 = 0;

    let mut tun_buf = vec![0u8; 65535];
    let mut udp_buf = vec![0u8; 65535];

    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    info!("Server ready – waiting for encrypted client packets");

    loop {
        tokio::select! {
            _ = &mut ctrl_c => {
                info!("Shutting down");
                break;
            }

            // ── UDP → TUN ─────────────────────────────────────────
            result = udp.recv_from(&mut udp_buf) => {
                let (n, peer_addr) = result.context("UDP recv_from failed")?;

                // Decrypt & authenticate
                let (header, plaintext) = match decrypt_packet(&cipher, &udp_buf[..n]) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("Rejected datagram from {}: {}", peer_addr, e);
                        continue;
                    }
                };

                if plaintext.is_empty() {
                    debug!("Keepalive from {}", peer_addr);
                    continue;
                }

                // Register peer by inner source IP
                if plaintext.len() >= 20 && (plaintext[0] >> 4) == 4 {
                    let src_ip = Ipv4Addr::new(
                        plaintext[12], plaintext[13], plaintext[14], plaintext[15],
                    );
                    if peers.get(&src_ip) != Some(&peer_addr) {
                        info!("Peer registered: tunnel {} → UDP {} (session {})",
                            src_ip, peer_addr, header.session_id);
                        peers.insert(src_ip, peer_addr);
                    }
                }

                tun_dev.write_all(&plaintext).await.context("TUN write failed")?;
                debug!("UDP→TUN: {} plaintext bytes from {} (counter={})",
                    plaintext.len(), peer_addr, header.counter);
            }

            // ── TUN → UDP ─────────────────────────────────────────
            result = tun_dev.read(&mut tun_buf) => {
                let n = result.context("TUN read failed")?;
                if n < 20 { continue; }

                let dst_ip = Ipv4Addr::new(tun_buf[16], tun_buf[17], tun_buf[18], tun_buf[19]);
                let peer_addr = match peers.get(&dst_ip) {
                    Some(a) => *a,
                    None => {
                        debug!("No peer for destination {}, dropping", dst_ip);
                        continue;
                    }
                };

                tx_counter += 1;
                let datagram = encrypt_packet(&cipher, 0, tx_counter, &tun_buf[..n])
                    .context("Encryption failed")?;

                udp.send_to(&datagram, peer_addr).await.context("UDP send_to failed")?;
                debug!("TUN→UDP: {} bytes → {} (counter={})", n, peer_addr, tx_counter);
            }
        }
    }

    Ok(())
}
