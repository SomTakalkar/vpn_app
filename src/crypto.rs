use anyhow::{bail, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};

use crate::wire::{DataHeader, MessageType, HEADER_LEN, TAG_LEN};

/// Build a 96-bit nonce from an 8-byte counter.
/// Layout: [0x00 × 4 bytes || counter as 8-byte LE]
/// Guarantees nonce uniqueness for up to 2^64 packets under a single key.
pub fn make_nonce(counter: u64) -> Nonce {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..].copy_from_slice(&counter.to_le_bytes());
    Nonce::from(nonce_bytes)
}

/// Encrypt an IP packet or control frame into an on-wire datagram.
///
/// Wire format:
///   [header: 13 bytes][ciphertext: n bytes][Poly1305 tag: 16 bytes]
///
/// The header (Type || Session ID || Counter) is authenticated as AEAD associated data (AAD).
pub fn encrypt_packet(
    cipher: &ChaCha20Poly1305,
    msg_type: MessageType,
    session_id: u32,
    counter: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let header = DataHeader::new_typed(msg_type, session_id, counter);
    let hdr_bytes = header.serialize();
    let nonce = make_nonce(counter);

    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &hdr_bytes,
            },
        )
        .map_err(|_| anyhow::anyhow!("Encryption failed (nonce or key error)"))?;

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(&hdr_bytes);
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

/// Decrypt an on-wire datagram back to a raw IP packet or control payload.
///
/// Validates the Poly1305 tag over both header (AAD) and ciphertext.
/// Returns an error if the tag is invalid (tampered, wrong key, or corrupt).
///
/// IMPORTANT: Replay window filter MUST be updated by the caller ONLY IF this returns Ok!
pub fn decrypt_packet(cipher: &ChaCha20Poly1305, datagram: &[u8]) -> Result<(DataHeader, Vec<u8>)> {
    if datagram.len() < HEADER_LEN + TAG_LEN {
        bail!(
            "Datagram too short to decrypt: {} bytes (min {})",
            datagram.len(),
            HEADER_LEN + TAG_LEN
        );
    }

    let header = DataHeader::deserialize(&datagram[..HEADER_LEN])?;
    let ciphertext = &datagram[HEADER_LEN..];
    let nonce = make_nonce(header.counter);
    let hdr_bytes = header.serialize();

    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &hdr_bytes,
            },
        )
        .map_err(|_| anyhow::anyhow!(
            "Decryption/authentication failed – packet is tampered, wrong key, or corrupt"
        ))?;

    Ok((header, plaintext))
}

/// Construct a ChaCha20-Poly1305 cipher from a raw 32-byte key.
pub fn make_cipher(key_bytes: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(Key::from_slice(key_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: [u8; 32] = [0x42; 32];

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let cipher = make_cipher(&TEST_KEY);
        let plaintext = b"Hello, encrypted directional tunnel!";

        let datagram = encrypt_packet(&cipher, MessageType::Data, 0xAABBCCDD, 1, plaintext)
            .expect("Encryption should succeed");

        let (header, recovered) = decrypt_packet(&cipher, &datagram)
            .expect("Decryption should succeed");

        assert_eq!(recovered, plaintext);
        assert_eq!(header.msg_type, MessageType::Data);
        assert_eq!(header.session_id, 0xAABBCCDD);
        assert_eq!(header.counter, 1);
    }

    #[test]
    fn test_keepalive_packet_encryption() {
        let cipher = make_cipher(&TEST_KEY);
        // Keepalive has empty payload
        let datagram = encrypt_packet(&cipher, MessageType::Keepalive, 0x12345678, 5, b"")
            .expect("Keepalive encrypt should succeed");

        let (header, payload) = decrypt_packet(&cipher, &datagram)
            .expect("Keepalive decrypt should succeed");

        assert_eq!(header.msg_type, MessageType::Keepalive);
        assert_eq!(header.session_id, 0x12345678);
        assert_eq!(header.counter, 5);
        assert!(payload.is_empty());
    }

    #[test]
    fn test_tampered_header_rejected() {
        let cipher = make_cipher(&TEST_KEY);
        let mut datagram = encrypt_packet(&cipher, MessageType::Data, 1, 1, b"secret")
            .expect("Encrypt should succeed");

        // Tamper with session ID in header (bytes 1..5)
        datagram[1] ^= 0xFF;

        assert!(
            decrypt_packet(&cipher, &datagram).is_err(),
            "Tampered AAD in header must fail Poly1305 auth"
        );
    }
}
