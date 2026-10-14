use anyhow::{bail, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};

use crate::wire::{DataHeader, HEADER_LEN, TAG_LEN};

/// A pre-shared 256-bit key used for Phase 3.
/// Both client and server must use the same constant.
/// This is replaced by ECDH-derived keys in Phase 4.
pub const PRESHARED_KEY: [u8; 32] = [
    0x4a, 0x6f, 0x75, 0x72, 0x6e, 0x65, 0x79, 0x54,
    0x6f, 0x50, 0x68, 0x61, 0x73, 0x65, 0x46, 0x6f,
    0x75, 0x72, 0x49, 0x73, 0x45, 0x43, 0x44, 0x48,
    0x61, 0x6e, 0x64, 0x52, 0x65, 0x6b, 0x65, 0x79,
];

/// Build a 96-bit nonce from an 8-byte counter.
/// Layout: [0x00 × 4 bytes || counter as 8-byte LE]
/// This guarantees uniqueness for up to 2^64 packets per session key.
fn make_nonce(counter: u64) -> Nonce {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..].copy_from_slice(&counter.to_le_bytes());
    Nonce::from(nonce_bytes)
}

/// Encrypt a raw IP packet into an on-wire datagram.
///
/// Wire format:
///   [header: 13 bytes][ciphertext: n bytes][Poly1305 tag: 16 bytes]
///
/// The header is used as AEAD associated data (authenticated but not encrypted).
pub fn encrypt_packet(
    cipher: &ChaCha20Poly1305,
    session_id: u32,
    counter: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let header = DataHeader::new(session_id, counter);
    let hdr_bytes = header.serialize();
    let nonce = make_nonce(counter);

    // Encrypt with the 13-byte wire header as AAD
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &hdr_bytes,
            },
        )
        .map_err(|_| anyhow::anyhow!("Encryption failed (nonce reuse or key error)"))?;

    // Assemble final datagram
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(&hdr_bytes);
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

/// Decrypt an on-wire datagram back to a raw IP packet.
///
/// Validates the Poly1305 tag over both header (AAD) and ciphertext.
/// Returns an error if the tag is invalid (tampered or replayed packet).
pub fn decrypt_packet(cipher: &ChaCha20Poly1305, datagram: &[u8]) -> Result<(DataHeader, Vec<u8>)> {
    // Minimum size: header (13) + empty ciphertext + tag (16)
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
            "Decryption failed – packet is tampered, replayed, or uses wrong key"
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

    fn test_cipher() -> ChaCha20Poly1305 {
        make_cipher(&PRESHARED_KEY)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let cipher = test_cipher();
        let plaintext = b"Hello, encrypted tunnel!";

        let datagram = encrypt_packet(&cipher, 0xAABBCCDD, 1, plaintext)
            .expect("Encryption should succeed");

        let (header, recovered) = decrypt_packet(&cipher, &datagram)
            .expect("Decryption should succeed");

        assert_eq!(recovered, plaintext);
        assert_eq!(header.session_id, 0xAABBCCDD);
        assert_eq!(header.counter, 1);
    }

    #[test]
    fn test_tampered_ciphertext_rejected() {
        let cipher = test_cipher();
        let plaintext = b"secret data";

        let mut datagram = encrypt_packet(&cipher, 1, 1, plaintext)
            .expect("Encryption should succeed");

        // Flip a bit in the ciphertext
        let last = datagram.len() - 1;
        datagram[last] ^= 0xFF;

        assert!(
            decrypt_packet(&cipher, &datagram).is_err(),
            "Tampered packet must be rejected"
        );
    }

    #[test]
    fn test_wrong_key_rejected() {
        let cipher_a = test_cipher();
        let cipher_b = make_cipher(&[0u8; 32]);
        let plaintext = b"classified";

        let datagram = encrypt_packet(&cipher_a, 1, 1, plaintext)
            .expect("Encryption should succeed");

        assert!(
            decrypt_packet(&cipher_b, &datagram).is_err(),
            "Packet encrypted with different key must be rejected"
        );
    }

    #[test]
    fn test_different_counters_produce_different_ciphertexts() {
        let cipher = test_cipher();
        let plaintext = b"same plaintext";

        let d1 = encrypt_packet(&cipher, 1, 1, plaintext).unwrap();
        let d2 = encrypt_packet(&cipher, 1, 2, plaintext).unwrap();

        // Ciphertexts must differ even for identical plaintexts
        assert_ne!(
            &d1[HEADER_LEN..],
            &d2[HEADER_LEN..],
            "Different counters must produce different ciphertexts"
        );
    }
}
