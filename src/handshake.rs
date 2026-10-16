use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::wire::MessageType;

pub const HANDSHAKE_INIT_LEN: usize = 1 + 32 + 48 + 28; // 109 bytes
pub const HANDSHAKE_RESP_LEN: usize = 1 + 32 + 4 + 16;  // 53 bytes

/// Deterministic demo keys for testing without configuration files
pub const DEMO_SERVER_PRIVATE_KEY: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
];

pub const DEMO_CLIENT_PRIVATE_KEY: [u8; 32] = [
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
    0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
    0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89,
    0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0, 0x01,
];

/// 12-byte UTC timestamp (8 bytes seconds + 4 bytes nanoseconds).
/// Used to prevent handshake replay attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp {
    pub secs: u64,
    pub nanos: u32,
}

impl Timestamp {
    pub fn now() -> Self {
        let dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self {
            secs: dur.as_secs(),
            nanos: dur.subsec_nanos(),
        }
    }

    pub fn to_bytes(&self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0..8].copy_from_slice(&self.secs.to_le_bytes());
        out[8..12].copy_from_slice(&self.nanos.to_le_bytes());
        out
    }

    pub fn from_bytes(buf: &[u8; 12]) -> Self {
        let secs = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let nanos = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        Self { secs, nanos }
    }

    pub fn is_newer_than(&self, other: &Self) -> bool {
        self.secs > other.secs || (self.secs == other.secs && self.nanos > other.nanos)
    }
}

/// Helper to derive keys via HKDF-SHA256.
fn hkdf_derive<const N: usize>(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; N] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; N];
    hk.expand(info, &mut okm)
        .expect("HKDF expansion failed; length within bounds");
    okm
}

/// Client handshake state while waiting for the server's response.
pub struct ClientHandshakeInitiated {
    client_ephemeral: StaticSecret,
    client_static: StaticSecret,
    #[allow(dead_code)]
    server_static_pub: PublicKey,
    dh1: [u8; 32],
    dh2: [u8; 32],
}

/// Derived directional session keys produced by a completed handshake.
pub struct SessionKeys {
    pub session_id: u32,
    pub client_to_server_key: [u8; 32],
    pub server_to_client_key: [u8; 32],
}

// ─────────────────────────────────────────────────────────────────────────────
// Client Handshake Functions
// ─────────────────────────────────────────────────────────────────────────────

/// Build a Noise IK Message 1 (`HANDSHAKE_INIT`).
pub fn create_handshake_init(
    client_static: &StaticSecret,
    server_static_pub: &PublicKey,
) -> Result<(Vec<u8>, ClientHandshakeInitiated)> {
    let mut rng = OsRng;
    let client_ephemeral = StaticSecret::random_from_rng(&mut rng);
    let client_ephemeral_pub = PublicKey::from(&client_ephemeral);
    let client_static_pub = PublicKey::from(client_static);

    // DH1 = e_c · S_s
    let dh1 = *client_ephemeral.diffie_hellman(server_static_pub).as_bytes();
    // Key K1 to encrypt client static pubkey
    let k1 = hkdf_derive::<32>(b"vpn-ik-init-s", &dh1, b"init-static");
    let cipher1 = ChaCha20Poly1305::new(Key::from_slice(&k1));

    let mut aad1 = [0u8; 33];
    aad1[0] = MessageType::HandshakeInit as u8;
    aad1[1..33].copy_from_slice(client_ephemeral_pub.as_bytes());

    let nonce0 = Nonce::from([0u8; 12]);
    let enc_static = cipher1
        .encrypt(
            &nonce0,
            Payload {
                msg: client_static_pub.as_bytes(),
                aad: &aad1,
            },
        )
        .map_err(|_| anyhow::anyhow!("Failed encrypting static key in init"))?;

    // DH2 = s_c · S_s
    let dh2 = *client_static.diffie_hellman(server_static_pub).as_bytes();
    // Key K2 to encrypt timestamp
    let mut dh12 = [0u8; 64];
    dh12[0..32].copy_from_slice(&dh1);
    dh12[32..64].copy_from_slice(&dh2);

    let k2 = hkdf_derive::<32>(b"vpn-ik-init-t", &dh12, b"init-timestamp");
    let cipher2 = ChaCha20Poly1305::new(Key::from_slice(&k2));

    let timestamp = Timestamp::now();
    let ts_bytes = timestamp.to_bytes();

    let mut aad2 = Vec::with_capacity(33 + enc_static.len());
    aad2.extend_from_slice(&aad1);
    aad2.extend_from_slice(&enc_static);

    let enc_timestamp = cipher2
        .encrypt(
            &nonce0,
            Payload {
                msg: &ts_bytes,
                aad: &aad2,
            },
        )
        .map_err(|_| anyhow::anyhow!("Failed encrypting timestamp in init"))?;

    // Assemble final 109-byte datagram
    let mut packet = Vec::with_capacity(HANDSHAKE_INIT_LEN);
    packet.push(MessageType::HandshakeInit as u8);
    packet.extend_from_slice(client_ephemeral_pub.as_bytes());
    packet.extend_from_slice(&enc_static);
    packet.extend_from_slice(&enc_timestamp);

    let state = ClientHandshakeInitiated {
        client_ephemeral,
        client_static: client_static.clone(),
        server_static_pub: *server_static_pub,
        dh1,
        dh2,
    };

    Ok((packet, state))
}

/// Process Noise IK Message 2 (`HANDSHAKE_RESP`) on the client to complete session setup.
pub fn process_handshake_resp(
    state: ClientHandshakeInitiated,
    packet: &[u8],
) -> Result<SessionKeys> {
    if packet.len() != HANDSHAKE_RESP_LEN {
        bail!("Invalid HandshakeResp length: {} (expected {})", packet.len(), HANDSHAKE_RESP_LEN);
    }
    if packet[0] != MessageType::HandshakeResp as u8 {
        bail!("Unexpected message type in handshake response: 0x{:02x}", packet[0]);
    }

    let mut server_ephemeral_bytes = [0u8; 32];
    server_ephemeral_bytes.copy_from_slice(&packet[1..33]);
    let server_ephemeral_pub = PublicKey::from(server_ephemeral_bytes);

    let session_id = u32::from_le_bytes(packet[33..37].try_into().unwrap());
    let auth_tag = &packet[37..53];

    // DH3 = e_c · E_s
    let dh3 = *state.client_ephemeral.diffie_hellman(&server_ephemeral_pub).as_bytes();
    // DH4 = s_c · E_s
    let dh4 = *state.client_static.diffie_hellman(&server_ephemeral_pub).as_bytes();

    // Derive all session keys
    let mut all_dhs = [0u8; 128];
    all_dhs[0..32].copy_from_slice(&state.dh1);
    all_dhs[32..64].copy_from_slice(&state.dh2);
    all_dhs[64..96].copy_from_slice(&dh3);
    all_dhs[96..128].copy_from_slice(&dh4);

    let keys = hkdf_derive::<96>(b"vpn-ik-session-v1", &all_dhs, b"session-keys");
    let mut k_c_to_s = [0u8; 32];
    let mut k_s_to_c = [0u8; 32];
    let mut k_resp = [0u8; 32];
    k_c_to_s.copy_from_slice(&keys[0..32]);
    k_s_to_c.copy_from_slice(&keys[32..64]);
    k_resp.copy_from_slice(&keys[64..96]);

    // Authenticate response
    let cipher_resp = ChaCha20Poly1305::new(Key::from_slice(&k_resp));
    let nonce0 = Nonce::from([0u8; 12]);
    let aad = &packet[0..37]; // Type || E_s || session_id

    cipher_resp
        .decrypt(
            &nonce0,
            Payload {
                msg: auth_tag,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("Server handshake response authentication failed"))?;

    Ok(SessionKeys {
        session_id,
        client_to_server_key: k_c_to_s,
        server_to_client_key: k_s_to_c,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Server Handshake Functions
// ─────────────────────────────────────────────────────────────────────────────

/// Process Noise IK Message 1 (`HANDSHAKE_INIT`) on the server.
/// Authenticates client identity, validates timestamp per-peer, and generates response.
pub fn process_handshake_init<F, T>(
    server_static: &StaticSecret,
    packet: &[u8],
    is_authorized_peer: F,
    get_last_timestamp: T,
) -> Result<(SessionKeys, PublicKey, Timestamp, Vec<u8>)>
where
    F: Fn(&[u8; 32]) -> bool,
    T: Fn(&[u8; 32]) -> Option<Timestamp>,
{
    if packet.len() != HANDSHAKE_INIT_LEN {
        bail!("Invalid HandshakeInit length: {} (expected {})", packet.len(), HANDSHAKE_INIT_LEN);
    }
    if packet[0] != MessageType::HandshakeInit as u8 {
        bail!("Unexpected message type in handshake init: 0x{:02x}", packet[0]);
    }

    let mut client_ephemeral_bytes = [0u8; 32];
    client_ephemeral_bytes.copy_from_slice(&packet[1..33]);
    let client_ephemeral_pub = PublicKey::from(client_ephemeral_bytes);

    let enc_static = &packet[33..81];
    let enc_timestamp = &packet[81..109];

    // DH1 = s_s · E_c
    let dh1 = *server_static.diffie_hellman(&client_ephemeral_pub).as_bytes();
    let k1 = hkdf_derive::<32>(b"vpn-ik-init-s", &dh1, b"init-static");
    let cipher1 = ChaCha20Poly1305::new(Key::from_slice(&k1));

    let mut aad1 = [0u8; 33];
    aad1[0] = MessageType::HandshakeInit as u8;
    aad1[1..33].copy_from_slice(client_ephemeral_pub.as_bytes());

    let nonce0 = Nonce::from([0u8; 12]);
    let client_static_bytes = cipher1
        .decrypt(
            &nonce0,
            Payload {
                msg: enc_static,
                aad: &aad1,
            },
        )
        .map_err(|_| anyhow::anyhow!("Failed decrypting client static key in init"))?;

    let client_static_pub_bytes: [u8; 32] = client_static_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Decrypted static key invalid length"))?;
    let client_static_pub = PublicKey::from(client_static_pub_bytes);

    // ── Authorization Check ───────────────────────────────────────
    if !is_authorized_peer(&client_static_pub_bytes) {
        bail!("Client public key is not authorized");
    }

    // DH2 = s_s · S_c
    let dh2 = *server_static.diffie_hellman(&client_static_pub).as_bytes();
    let mut dh12 = [0u8; 64];
    dh12[0..32].copy_from_slice(&dh1);
    dh12[32..64].copy_from_slice(&dh2);

    let k2 = hkdf_derive::<32>(b"vpn-ik-init-t", &dh12, b"init-timestamp");
    let cipher2 = ChaCha20Poly1305::new(Key::from_slice(&k2));

    let mut aad2 = Vec::with_capacity(33 + enc_static.len());
    aad2.extend_from_slice(&aad1);
    aad2.extend_from_slice(enc_static);

    let ts_bytes = cipher2
        .decrypt(
            &nonce0,
            Payload {
                msg: enc_timestamp,
                aad: &aad2,
            },
        )
        .map_err(|_| anyhow::anyhow!("Failed decrypting timestamp in init"))?;

    let ts_arr: [u8; 12] = ts_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Decrypted timestamp invalid length"))?;
    let timestamp = Timestamp::from_bytes(&ts_arr);

    // ── Handshake Replay Check for THIS peer ─────────────────────
    if let Some(last_ts) = get_last_timestamp(&client_static_pub_bytes) {
        if !timestamp.is_newer_than(&last_ts) {
            bail!(
                "Handshake init replay detected! Timestamp {:?} <= last seen {:?}",
                timestamp,
                last_ts
            );
        }
    }

    // ── Generate Server Ephemeral & Derive Session Keys ────────────
    let mut rng = OsRng;
    let server_ephemeral = StaticSecret::random_from_rng(&mut rng);
    let server_ephemeral_pub = PublicKey::from(&server_ephemeral);

    // DH3 = e_s · E_c
    let dh3 = *server_ephemeral.diffie_hellman(&client_ephemeral_pub).as_bytes();
    // DH4 = e_s · S_c
    let dh4 = *server_ephemeral.diffie_hellman(&client_static_pub).as_bytes();

    let mut all_dhs = [0u8; 128];
    all_dhs[0..32].copy_from_slice(&dh1);
    all_dhs[32..64].copy_from_slice(&dh2);
    all_dhs[64..96].copy_from_slice(&dh3);
    all_dhs[96..128].copy_from_slice(&dh4);

    let keys = hkdf_derive::<96>(b"vpn-ik-session-v1", &all_dhs, b"session-keys");
    let mut k_c_to_s = [0u8; 32];
    let mut k_s_to_c = [0u8; 32];
    let mut k_resp = [0u8; 32];
    k_c_to_s.copy_from_slice(&keys[0..32]);
    k_s_to_c.copy_from_slice(&keys[32..64]);
    k_resp.copy_from_slice(&keys[64..96]);

    // Random non-zero session ID
    let mut session_id: u32 = rand::random();
    if session_id == 0 {
        session_id = 1;
    }

    // ── Build HandshakeResp Packet ────────────────────────────────
    let cipher_resp = ChaCha20Poly1305::new(Key::from_slice(&k_resp));
    let mut resp_aad = Vec::with_capacity(37);
    resp_aad.push(MessageType::HandshakeResp as u8);
    resp_aad.extend_from_slice(server_ephemeral_pub.as_bytes());
    resp_aad.extend_from_slice(&session_id.to_le_bytes());

    let auth_tag = cipher_resp
        .encrypt(
            &nonce0,
            Payload {
                msg: b"",
                aad: &resp_aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("Failed building handshake response auth tag"))?;

    let mut resp_packet = Vec::with_capacity(HANDSHAKE_RESP_LEN);
    resp_packet.extend_from_slice(&resp_aad);
    resp_packet.extend_from_slice(&auth_tag);

    let session_keys = SessionKeys {
        session_id,
        client_to_server_key: k_c_to_s,
        server_to_client_key: k_s_to_c,
    };

    Ok((session_keys, client_static_pub, timestamp, resp_packet))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_roundtrip() {
        let mut rng = OsRng;
        let client_static = StaticSecret::random_from_rng(&mut rng);
        let client_static_pub = PublicKey::from(&client_static);

        let server_static = StaticSecret::random_from_rng(&mut rng);
        let server_static_pub = PublicKey::from(&server_static);

        // 1. Client creates HandshakeInit
        let (init_packet, client_state) =
            create_handshake_init(&client_static, &server_static_pub).unwrap();

        // 2. Server processes HandshakeInit
        let (server_session, peer_pub, _ts, resp_packet) = process_handshake_init(
            &server_static,
            &init_packet,
            |pubkey| *pubkey == *client_static_pub.as_bytes(),
            |_| None,
        )
        .unwrap();

        assert_eq!(peer_pub, client_static_pub);

        // 3. Client processes HandshakeResp
        let client_session = process_handshake_resp(client_state, &resp_packet).unwrap();

        // 4. Verify identical directional keys derived
        assert_eq!(client_session.session_id, server_session.session_id);
        assert_eq!(
            client_session.client_to_server_key,
            server_session.client_to_server_key
        );
        assert_eq!(
            client_session.server_to_client_key,
            server_session.server_to_client_key
        );
    }

    #[test]
    fn test_handshake_replay_rejected() {
        let mut rng = OsRng;
        let client_static = StaticSecret::random_from_rng(&mut rng);
        let client_static_pub = PublicKey::from(&client_static);
        let server_static = StaticSecret::random_from_rng(&mut rng);
        let server_static_pub = PublicKey::from(&server_static);

        let (init_packet, _) =
            create_handshake_init(&client_static, &server_static_pub).unwrap();

        // First acceptance
        let (_s1, _peer, ts1, _resp) = process_handshake_init(
            &server_static,
            &init_packet,
            |_| true,
            |_| None,
        )
        .unwrap();

        // Replay of the SAME init_packet with ts1 as last seen timestamp must FAIL
        let replay_res = process_handshake_init(
            &server_static,
            &init_packet,
            |_| true,
            |_| Some(ts1),
        );

        assert!(replay_res.is_err(), "Replayed HandshakeInit must be rejected");
    }

    #[test]
    fn test_unauthorized_client_rejected() {
        let mut rng = OsRng;
        let client_static = StaticSecret::random_from_rng(&mut rng);
        let server_static = StaticSecret::random_from_rng(&mut rng);
        let server_static_pub = PublicKey::from(&server_static);

        let (init_packet, _) =
            create_handshake_init(&client_static, &server_static_pub).unwrap();

        let res = process_handshake_init(
            &server_static,
            &init_packet,
            |_| false, // reject all clients
            |_| None,
        );

        assert!(res.is_err(), "Unauthorized client must be rejected");
    }
}

