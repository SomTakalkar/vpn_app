use anyhow::{bail, Result};

#[allow(dead_code)]
pub const HEADER_LEN: usize = 13; // 1 (type) + 4 (session_id) + 8 (counter)
#[allow(dead_code)]
pub const TAG_LEN: usize = 16;    // Poly1305 MAC tag
#[allow(dead_code)]
pub const OVERHEAD: usize = HEADER_LEN + TAG_LEN; // 29 bytes

#[allow(dead_code)]
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    HandshakeInit = 0x01,
    HandshakeResp = 0x02,
    Data          = 0x03,
    Keepalive     = 0x04,
    Rekey         = 0x05,
}

impl TryFrom<u8> for MessageType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(MessageType::HandshakeInit),
            0x02 => Ok(MessageType::HandshakeResp),
            0x03 => Ok(MessageType::Data),
            0x04 => Ok(MessageType::Keepalive),
            0x05 => Ok(MessageType::Rekey),
            other => bail!("Unknown wire message type: 0x{:02x}", other),
        }
    }
}

/// Header for encapsulated data datagrams.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataHeader {
    pub msg_type: MessageType,
    pub session_id: u32,
    pub counter: u64,
}

#[allow(dead_code)]
impl DataHeader {
    pub fn new(session_id: u32, counter: u64) -> Self {
        Self {
            msg_type: MessageType::Data,
            session_id,
            counter,
        }
    }

    /// Serialize header to a 13-byte array.
    pub fn serialize(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0] = self.msg_type as u8;
        out[1..5].copy_from_slice(&self.session_id.to_le_bytes());
        out[5..13].copy_from_slice(&self.counter.to_le_bytes());
        out
    }

    /// Parse header from slice (must be at least 13 bytes).
    pub fn deserialize(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_LEN {
            bail!("Buffer too short for data header: {} bytes", buf.len());
        }

        let msg_type = MessageType::try_from(buf[0])?;
        let session_id = u32::from_le_bytes(buf[1..5].try_into()?);
        let counter = u64::from_le_bytes(buf[5..13].try_into()?);

        Ok(Self {
            msg_type,
            session_id,
            counter,
        })
    }
}

/// 128-bit Anti-Replay Sliding Window.
#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct AntiReplayFilter {
    max_counter: u64,
    bitmap: u128,
}

#[allow(dead_code)]
impl AntiReplayFilter {
    pub const WINDOW_SIZE: u64 = 128;

    pub fn new() -> Self {
        Self {
            max_counter: 0,
            bitmap: 0,
        }
    }

    /// Check if a counter is acceptable and not a duplicate/out-of-window replay.
    /// If valid, updates the window state and returns true.
    pub fn check_and_update(&mut self, counter: u64) -> bool {
        if counter == 0 {
            return false;
        }

        if counter > self.max_counter {
            let diff = counter - self.max_counter;
            if diff < Self::WINDOW_SIZE {
                self.bitmap <<= diff;
                self.bitmap |= 1;
            } else {
                self.bitmap = 1;
            }
            self.max_counter = counter;
            true
        } else {
            let diff = self.max_counter - counter;
            if diff >= Self::WINDOW_SIZE {
                // Too old, dropped
                return false;
            }

            let bit = 1u128 << diff;
            if (self.bitmap & bit) != 0 {
                // Already seen
                return false;
            }

            self.bitmap |= bit;
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_header_roundtrip() {
        let original = DataHeader::new(0xDEADBEEF, 42);
        let bytes = original.serialize();
        let parsed = DataHeader::deserialize(&bytes).expect("Should deserialize");
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_replay_window_in_order() {
        let mut filter = AntiReplayFilter::new();
        assert!(filter.check_and_update(1));
        assert!(filter.check_and_update(2));
        assert!(filter.check_and_update(3));
        // Duplicates rejected
        assert!(!filter.check_and_update(2));
        assert!(!filter.check_and_update(3));
    }

    #[test]
    fn test_replay_window_out_of_order() {
        let mut filter = AntiReplayFilter::new();
        assert!(filter.check_and_update(10));
        assert!(filter.check_and_update(5));
        assert!(filter.check_and_update(8));
        // Repeat rejected
        assert!(!filter.check_and_update(5));
        assert!(!filter.check_and_update(10));
    }

    #[test]
    fn test_replay_window_old_dropped() {
        let mut filter = AntiReplayFilter::new();
        assert!(filter.check_and_update(200));
        // Counter < 200 - 128 = 72 should be dropped
        assert!(!filter.check_and_update(70));
        // Counter within window accepted
        assert!(filter.check_and_update(150));
    }
}
