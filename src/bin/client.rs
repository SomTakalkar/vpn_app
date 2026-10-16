//! Phase 4 – VPN Client: Authenticated Noise IK Handshake + Anti-Replay + Keepalives
//!
//! Features:
//!   - Initiates Noise IK handshake with Perfect Forward Secrecy.
//!   - Authenticates against pinned server public key.
//!   - Directional keys (K_c→s for send, K_s→c for receive).
//!   - 128-bit AntiReplayFilter executed ONLY AFTER successful Poly1305 decryption.
//!   - Periodic Keepalive (0x04) heartbeats every 20s to sustain NAT mappings.
//!   - Rekeying triggers on packet counter or elapsed time.
//!
//! Run inside the client namespace:
//!   sudo ip netns exec ns-client ./target/debug/client --server 10.0.2.2:51820

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::interval;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;
use x25519_dalek::{PublicKey, StaticSecret};

use vpn::crypto::{decrypt_packet, encrypt_packet, make_cipher};
use vpn::handshake::{
    create_handshake_init, process_handshake_resp,
    DEMO_CLIENT_PRIVATE_KEY, DEMO_SERVER_PRIVATE_KEY,
};
use vpn::wire::{
    AntiReplayFilter, MessageType, HEADER_LEN, KEEPALIVE_INTERVAL_SECS,
    REJECT_AFTER_MESSAGES, REKEY_AFTER_MESSAGES, REKEY_AFTER_TIME_SECS,
};

#[derive(Parser, Debug)]
#[command(about = "Phase 4: VPN Client with Noise IK Handshake & Anti-Replay")]
struct Args {
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

struct ClientSession {
    session_id: u32,
    send_cipher: chacha20poly1305::ChaCha20Poly1305, // K_c→s
    recv_cipher: chacha20poly1305::ChaCha20Poly1305, // K_s→c
    tx_counter: u64,
    replay_filter: AntiReplayFilter,
    last_sent: Instant,
    last_handshake: Instant,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let args = Args::parse();

    // ── Static Keys ────────────────────────────────────────────────
    let client_static = StaticSecret::from(DEMO_CLIENT_PRIVATE_KEY);
    let client_public = PublicKey::from(&client_static);
    info!("Client Static Public Key: {:02x?}", &client_public.as_bytes()[..8]);

    let server_static = StaticSecret::from(DEMO_SERVER_PRIVATE_KEY);
    let server_public = PublicKey::from(&server_static);
    info!("Pinned Server Public Key: {:02x?}", &server_public.as_bytes()[..8]);

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

    // ── Connect UDP socket ─────────────────────────────────────────
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

    info!("UDP socket connected to server at {}", server_addr);

    // ── Initial Handshake ──────────────────────────────────────────
    let mut session = perform_handshake(&udp, &client_static, &server_public).await?;

    let mut tun_buf = vec![0u8; 65535];
    let mut udp_buf = vec![0u8; 65535];

    let mut ticker = interval(Duration::from_secs(1));
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    info!("Client tunnel established – forwarding encrypted packets");

    loop {
        tokio::select! {
            _ = &mut ctrl_c => {
                info!("Shutting down");
                break;
            }

            // ── Periodic Ticker: Keepalive & Rekey Check ───────────
            _ = ticker.tick() => {
                // 1. Send periodic Keepalive (0x04) if idle for 20s
                if session.last_sent.elapsed() >= Duration::from_secs(KEEPALIVE_INTERVAL_SECS) {
                    session.tx_counter += 1;
                    let counter = session.tx_counter;

                    match encrypt_packet(
                        &session.send_cipher,
                        MessageType::Keepalive,
                        session.session_id,
                        counter,
                        b"",
                    ) {
                        Ok(keepalive_pkt) => {
                            if let Err(e) = udp.send(&keepalive_pkt).await {
                                warn!("Failed to send keepalive: {}", e);
                            } else {
                                session.last_sent = Instant::now();
                                debug!("Sent KEEPALIVE (0x04) to maintain NAT mapping (counter={})", counter);
                            }
                        }
                        Err(e) => warn!("Keepalive encryption failed: {}", e),
                    }
                }

                // 2. Check Rekey limits (packet count or time)
                if session.tx_counter >= REKEY_AFTER_MESSAGES
                    || session.last_handshake.elapsed() >= Duration::from_secs(REKEY_AFTER_TIME_SECS)
                {
                    info!("Rekey threshold reached! Rotating session keys...");
                    match perform_handshake(&udp, &client_static, &server_public).await {
                        Ok(new_session) => {
                            session = new_session;
                            info!("Rekey complete! New session active.");
                        }
                        Err(e) => {
                            warn!("Rekeying attempt failed: {}. Retrying on next tick.", e);
                        }
                    }
                }
            }

            // ── TUN Ingress: Encrypt & Send to Server ───────────────
            result = tun_dev.read(&mut tun_buf) => {
                let n = result.context("TUN read failed")?;
                if n < 20 { continue; }

                if session.tx_counter >= REJECT_AFTER_MESSAGES {
                    error!("Session counter exhausted! Halting send to prevent nonce reuse.");
                    continue;
                }

                session.tx_counter += 1;
                let counter = session.tx_counter;

                let datagram = match encrypt_packet(
                    &session.send_cipher,
                    MessageType::Data,
                    session.session_id,
                    counter,
                    &tun_buf[..n],
                ) {
                    Ok(d) => d,
                    Err(e) => {
                        warn!("Encryption failed: {}", e);
                        continue;
                    }
                };

                if let Err(e) = udp.send(&datagram).await {
                    warn!("UDP send failed: {}", e);
                } else {
                    session.last_sent = Instant::now();
                    debug!("TUN→UDP: {} bytes encrypted (counter={})", n, counter);
                }
            }

            // ── UDP Ingress: Decrypt & Forward to TUN ──────────────
            result = udp.recv(&mut udp_buf) => {
                let n = result.context("UDP recv failed")?;
                if n < HEADER_LEN { continue; }

                // CRITICAL STEP 1: Decrypt FIRST before touching replay filter
                let (hdr, plaintext) = match decrypt_packet(&session.recv_cipher, &udp_buf[..n]) {
                    Ok(res) => res,
                    Err(e) => {
                        warn!("Decryption failed on packet from server: {}", e);
                        continue;
                    }
                };

                // Verify session ID matches
                if hdr.session_id != session.session_id {
                    warn!("Dropped packet with mismatched session ID: 0x{:08x}", hdr.session_id);
                    continue;
                }

                // CRITICAL STEP 2: Check & update AntiReplayFilter ONLY on authenticated packet
                if !session.replay_filter.check_and_update(hdr.counter) {
                    warn!("Replay filter dropped duplicate/stale packet from server: counter {}", hdr.counter);
                    continue;
                }

                match hdr.msg_type {
                    MessageType::Data => {
                        if plaintext.len() >= 20 {
                            tun_dev.write_all(&plaintext).await.context("TUN write failed")?;
                            debug!("UDP→TUN: {} bytes from server (counter={})", plaintext.len(), hdr.counter);
                        }
                    }
                    MessageType::Keepalive => {
                        debug!("Keepalive (0x04) received from server");
                    }
                    MessageType::Rekey => {
                        info!("Server requested rekey! Initiating handshake...");
                        if let Ok(new_session) = perform_handshake(&udp, &client_static, &server_public).await {
                            session = new_session;
                        }
                    }
                    _ => debug!("Unhandled message type {:?}", hdr.msg_type),
                }
            }
        }
    }

    Ok(())
}

/// Perform a full Noise IK handshake with retry logic.
async fn perform_handshake(
    udp: &UdpSocket,
    client_static: &StaticSecret,
    server_public: &PublicKey,
) -> Result<ClientSession> {
    info!("Initiating Noise IK Handshake with server...");

    let mut buf = vec![0u8; 2048];
    let max_retries = 5;

    for attempt in 1..=max_retries {
        let (init_pkt, state) = create_handshake_init(client_static, server_public)
            .context("Failed building HANDSHAKE_INIT")?;

        udp.send(&init_pkt).await.context("Failed sending HANDSHAKE_INIT")?;
        debug!("Sent HANDSHAKE_INIT (attempt {}/{})", attempt, max_retries);

        // Wait for HANDSHAKE_RESP with a 2-second timeout
        let recv_resp = tokio::time::timeout(Duration::from_millis(2000), udp.recv(&mut buf)).await;

        match recv_resp {
            Ok(Ok(n)) => {
                if n > 0 && buf[0] == MessageType::HandshakeResp as u8 {
                    match process_handshake_resp(state, &buf[..n]) {
                        Ok(keys) => {
                            info!(
                                "Noise IK Handshake SUCCESS! Session ID: 0x{:08x}",
                                keys.session_id
                            );
                            return Ok(ClientSession {
                                session_id: keys.session_id,
                                send_cipher: make_cipher(&keys.client_to_server_key),
                                recv_cipher: make_cipher(&keys.server_to_client_key),
                                tx_counter: 0,
                                replay_filter: AntiReplayFilter::new(),
                                last_sent: Instant::now(),
                                last_handshake: Instant::now(),
                            });
                        }
                        Err(e) => {
                            warn!("Failed processing HANDSHAKE_RESP: {}. Retrying...", e);
                        }
                    }
                }
            }
            Ok(Err(e)) => warn!("UDP receive error during handshake: {}", e),
            Err(_) => debug!("Handshake timeout (attempt {}). Retrying...", attempt),
        }
    }

    bail!("Handshake failed after {} attempts", max_retries);
}
