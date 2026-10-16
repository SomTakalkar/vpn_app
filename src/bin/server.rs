//! Phase 4/5 – VPN Server: Authenticated Noise IK Handshake + Server-Side NAT (MASQUERADE)
//!
//! Features:
//!   - Ephemeral-static ECDH (Noise IK) key exchange with Perfect Forward Secrecy.
//!   - Per-peer handshake replay protection using monotonic UTC timestamps.
//!   - Per-session table keyed by session_id with directional keys (K_c→s and K_s→c).
//!   - 128-bit AntiReplayFilter checked ONLY AFTER successful Poly1305 decryption.
//!   - RAII NatGuard enabling net.ipv4.ip_forward=1 and iptables MASQUERADE on egress.
//!   - Resilient TUN writes (daemon never panics/aborts on transient write error).
//!   - Zero-copy IPv4 packet parsing for safe routing.
//!   - Periodic stale session GC (purges sessions inactive > 1 hour).
//!   - Support for Data (0x03) and Keepalive (0x04) message types.
//!
//! Run inside the server namespace:
//!   sudo ip netns exec ns-server ./target/debug/server --nat --egress-iface veth-s

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::Command;
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
    process_handshake_init, Timestamp, DEMO_CLIENT_PRIVATE_KEY, DEMO_SERVER_PRIVATE_KEY,
};
use vpn::wire::{
    AntiReplayFilter, DataHeader, MessageType, HEADER_LEN, REJECT_AFTER_MESSAGES,
};

struct PeerConfig {
    allowed_ip: Ipv4Addr,
    last_timestamp: Option<Timestamp>,
}

#[allow(dead_code)]
struct ActiveSession {
    session_id: u32,
    peer_pub: [u8; 32],
    peer_tun_ip: Ipv4Addr,
    peer_udp_addr: SocketAddr,
    send_cipher: chacha20poly1305::ChaCha20Poly1305, // K_s→c
    recv_cipher: chacha20poly1305::ChaCha20Poly1305, // K_c→s
    tx_counter: u64,
    replay_filter: AntiReplayFilter,
    created_at: Instant,
    last_activity: Instant,
}

struct NatGuard {
    subnet: String,
    egress_iface: String,
    active: bool,
}

impl NatGuard {
    pub fn setup(subnet: &str, egress_iface: &str) -> Result<Self> {
        info!("Enabling Server IP forwarding & NAT (MASQUERADE)...");

        // 1. Enable sysctl net.ipv4.ip_forward
        let status = Command::new("sysctl")
            .args(["-w", "net.ipv4.ip_forward=1"])
            .status()
            .context("Failed enabling net.ipv4.ip_forward")?;
        if !status.success() {
            bail!("Failed setting net.ipv4.ip_forward=1");
        }

        // 2. Add iptables MASQUERADE rule
        let iptables_status = Command::new("iptables")
            .args([
                "-t", "nat",
                "-A", "POSTROUTING",
                "-s", subnet,
                "-o", egress_iface,
                "-j", "MASQUERADE",
            ])
            .status()
            .context("Failed executing iptables MASQUERADE command")?;

        if !iptables_status.success() {
            bail!("iptables returned non-zero exit code while adding NAT rule");
        }

        info!("NAT MASQUERADE active: {} -> {}", subnet, egress_iface);

        Ok(Self {
            subnet: subnet.to_string(),
            egress_iface: egress_iface.to_string(),
            active: true,
        })
    }

    pub fn teardown(&mut self) {
        if !self.active {
            return;
        }
        info!("Cleaning up iptables NAT rule...");
        let _ = Command::new("iptables")
            .args([
                "-t", "nat",
                "-D", "POSTROUTING",
                "-s", &self.subnet,
                "-o", &self.egress_iface,
                "-j", "MASQUERADE",
            ])
            .status();
        self.active = false;
        info!("NAT rule removed.");
    }
}

impl Drop for NatGuard {
    fn drop(&mut self) {
        self.teardown();
    }
}

#[derive(Parser, Debug)]
#[command(about = "Phase 4/5: VPN Server with Noise IK Handshake & NAT")]
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

    #[arg(long, default_value = "veth-s")]
    egress_iface: String,

    #[arg(long, default_value_t = true)]
    nat: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let args = Args::parse();

    // ── Static Keys ────────────────────────────────────────────────
    let server_static = StaticSecret::from(DEMO_SERVER_PRIVATE_KEY);
    let server_public = PublicKey::from(&server_static);
    info!("Server Static Public Key: {:02x?}", &server_public.as_bytes()[..8]);

    // ── Authorized Peers ───────────────────────────────────────────
    let client_static = StaticSecret::from(DEMO_CLIENT_PRIVATE_KEY);
    let client_public = PublicKey::from(&client_static);

    let mut authorized_peers: HashMap<[u8; 32], PeerConfig> = HashMap::new();
    authorized_peers.insert(
        *client_public.as_bytes(),
        PeerConfig {
            allowed_ip: Ipv4Addr::new(10, 8, 0, 2),
            last_timestamp: None,
        },
    );
    info!("Loaded {} authorized peer(s)", authorized_peers.len());

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

    // ── Phase 5: Setup NAT Masquerade on Egress Interface ──────────
    let mut _nat_guard = if args.nat {
        Some(NatGuard::setup("10.8.0.0/24", &args.egress_iface)?)
    } else {
        None
    };

    // ── Bind UDP socket ────────────────────────────────────────────
    let udp = UdpSocket::bind(&args.bind)
        .await
        .with_context(|| format!("Failed to bind UDP on {}", args.bind))?;
    info!("Listening on UDP {}", args.bind);

    // ── Session Tables ─────────────────────────────────────────────
    let mut sessions: HashMap<u32, ActiveSession> = HashMap::new();
    let mut tun_ip_to_session: HashMap<Ipv4Addr, u32> = HashMap::new();

    let mut tun_buf = vec![0u8; 65535];
    let mut udp_buf = vec![0u8; 65535];

    let mut sweep_ticker = interval(Duration::from_secs(60));
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    info!("Server ready – waiting for handshakes and tunnel traffic");

    loop {
        tokio::select! {
            _ = &mut ctrl_c => {
                info!("Shutting down");
                break;
            }

            // ── Stale Session Sweep (Purge inactive > 3600s) ───────
            _ = sweep_ticker.tick() => {
                let before = sessions.len();
                sessions.retain(|_, s| s.last_activity.elapsed() < Duration::from_secs(3600));
                tun_ip_to_session.retain(|_, id| sessions.contains_key(id));
                let purged = before - sessions.len();
                if purged > 0 {
                    info!("Purged {} stale session(s) inactive > 3600s", purged);
                }
            }

            // ── UDP Ingress: Handshake or Encrypted Packet ─────────
            result = udp.recv_from(&mut udp_buf) => {
                let (n, peer_addr) = result.context("UDP recv_from failed")?;
                if n == 0 { continue; }

                let msg_type = udp_buf[0];

                // ── 1. Handshake Initiation (0x01) ─────────────────
                if msg_type == MessageType::HandshakeInit as u8 {
                    debug!("Received HANDSHAKE_INIT from {}", peer_addr);

                    let init_res = process_handshake_init(
                        &server_static,
                        &udp_buf[..n],
                        |client_pub| authorized_peers.contains_key(client_pub),
                        |client_pub| authorized_peers.get(client_pub).and_then(|cfg| cfg.last_timestamp),
                    );

                    match init_res {
                        Ok((session_keys, client_pub, timestamp, resp_packet)) => {
                            let client_pub_bytes = *client_pub.as_bytes();
                            let peer_cfg = authorized_peers.get_mut(&client_pub_bytes).unwrap();
                            peer_cfg.last_timestamp = Some(timestamp);
                            let assigned_ip = peer_cfg.allowed_ip;

                            // Create fresh session with directional keys
                            let session_id = session_keys.session_id;
                            let session = ActiveSession {
                                session_id,
                                peer_pub: client_pub_bytes,
                                peer_tun_ip: assigned_ip,
                                peer_udp_addr: peer_addr,
                                send_cipher: make_cipher(&session_keys.server_to_client_key),
                                recv_cipher: make_cipher(&session_keys.client_to_server_key),
                                tx_counter: 0,
                                replay_filter: AntiReplayFilter::new(),
                                created_at: Instant::now(),
                                last_activity: Instant::now(),
                            };

                            sessions.insert(session_id, session);
                            tun_ip_to_session.insert(assigned_ip, session_id);

                            info!(
                                "Noise IK Handshake complete! Session ID: 0x{:08x} for peer {} (tunnel IP: {})",
                                session_id, peer_addr, assigned_ip
                            );

                            // Send HandshakeResp back to client
                            if let Err(e) = udp.send_to(&resp_packet, peer_addr).await {
                                warn!("Failed to send HANDSHAKE_RESP to {}: {}", peer_addr, e);
                            }
                        }
                        Err(e) => {
                            warn!("Handshake rejected from {}: {}", peer_addr, e);
                        }
                    }
                    continue;
                }

                // ── 2. Data (0x03) or Keepalive (0x04) ────────────
                if n < HEADER_LEN {
                    warn!("Dropping undersized packet ({} bytes) from {}", n, peer_addr);
                    continue;
                }

                let header = match DataHeader::deserialize(&udp_buf[..HEADER_LEN]) {
                    Ok(h) => h,
                    Err(e) => {
                        warn!("Bad header from {}: {}", peer_addr, e);
                        continue;
                    }
                };

                // Fast session lookup
                let session = match sessions.get_mut(&header.session_id) {
                    Some(s) => s,
                    None => {
                        warn!("Unknown session ID 0x{:08x} from {}", header.session_id, peer_addr);
                        continue;
                    }
                };

                // CRITICAL STEP 1: Decrypt FIRST before touching replay filter
                let (hdr, plaintext) = match decrypt_packet(&session.recv_cipher, &udp_buf[..n]) {
                    Ok(res) => res,
                    Err(e) => {
                        warn!("Decryption failed for session 0x{:08x}: {}", header.session_id, e);
                        continue;
                    }
                };

                // CRITICAL STEP 2: Check & update AntiReplayFilter ONLY on authenticated packet
                if !session.replay_filter.check_and_update(hdr.counter) {
                    warn!(
                        "Replay filter dropped duplicate/stale packet: session 0x{:08x}, counter {}",
                        header.session_id, hdr.counter
                    );
                    continue;
                }

                // Roaming support: update peer UDP endpoint and activity timestamp
                session.peer_udp_addr = peer_addr;
                session.last_activity = Instant::now();

                match hdr.msg_type {
                    MessageType::Data => {
                        if plaintext.len() >= 20 {
                            if let Err(e) = tun_dev.write_all(&plaintext).await {
                                warn!("Failed writing decrypted packet to TUN: {}", e);
                            } else {
                                debug!("UDP→TUN: {} bytes from session 0x{:08x}", plaintext.len(), header.session_id);
                            }
                        }
                    }
                    MessageType::Keepalive => {
                        debug!("Keepalive received for session 0x{:08x} from {}", header.session_id, peer_addr);
                    }
                    MessageType::Rekey => {
                        info!("Rekey request from session 0x{:08x}", header.session_id);
                    }
                    _ => {
                        debug!("Unhandled message type {:?}", hdr.msg_type);
                    }
                }
            }

            // ── TUN Ingress: Route Outgoing Packet to Session ─────
            result = tun_dev.read(&mut tun_buf) => {
                let n = result.context("TUN read failed")?;
                if n < 20 { continue; }

                let parsed_header = match vpn::packet::Ipv4PacketHeader::parse(&tun_buf[..n]) {
                    Some(h) => h,
                    None => {
                        debug!("Dropping non-IPv4 or malformed packet from TUN");
                        continue;
                    }
                };

                let dst_ip = parsed_header.dst_ip;
                let session_id = match tun_ip_to_session.get(&dst_ip) {
                    Some(&id) => id,
                    None => {
                        debug!("No active session for destination IP {}, dropping", dst_ip);
                        continue;
                    }
                };

                let session = match sessions.get_mut(&session_id) {
                    Some(s) => s,
                    None => continue,
                };

                // Guard counter wrapping
                if session.tx_counter >= REJECT_AFTER_MESSAGES {
                    error!("Session 0x{:08x} tx_counter exhausted! Dropping packet.", session_id);
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

                if let Err(e) = udp.send_to(&datagram, session.peer_udp_addr).await {
                    warn!("Failed sending to peer {}: {}", session.peer_udp_addr, e);
                } else {
                    debug!("TUN→UDP: {} bytes → {} (counter={})", n, session.peer_udp_addr, counter);
                }
            }
        }
    }

    Ok(())
}
