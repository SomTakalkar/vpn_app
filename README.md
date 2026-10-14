# Custom Layer 3/4 VPN Daemon (`vpn_app`)

A custom, memory-safe, high-performance Layer 3/4 encrypted VPN daemon written in Rust for Linux.

Instead of relying on OpenVPN or WireGuard, this project intercepts raw IP packets via a virtual network interface (`/dev/net/tun`), encrypts them using **ChaCha20-Poly1305 AEAD**, and tunnels them over **UDP** with authenticated **ECDH key exchange** and **anti-replay sliding window filters**.

---

## 🚀 Architecture Overview

```
[ Client Traffic ] ---> (TUN Device: tun0) ---> [ Client Daemon ]
                                                       |
                                          (ChaCha20-Poly1305 Encrypted UDP)
                                                       v
[ Internet / Target ] <--- (NAT / Forwarding) <--- [ Server Daemon ]
```

### Key Components
- **TUN Device Interception**: Direct async read/write of raw IP packets from `/dev/net/tun`.
- **Wire Protocol**: Custom UDP framing `[Type: 1B][Session ID: 4B][Counter: 8B][Ciphertext + 16B Tag]`.
- **Cryptography**: Modern AEAD (`ChaCha20-Poly1305`) with 96-bit nonces derived from a monotonically increasing 64-bit counter. Wire header bytes serve as Authenticated Associated Data (AAD).
- **Anti-Replay Protection**: 128-bit sliding window bitmap dropping duplicate and out-of-order stale packets.
- **NAT & Subnet Forwarding** *(Phase 5)*: Server-side `nftables` masquerade and automated client routing table override.

---

## 📦 Project Structure

```
├── Cargo.toml                  # Dependencies (tokio, tun 0.6, chacha20poly1305, x25519-dalek, etc.)
├── setup-namespaces.sh         # 3-node network namespace testbed (ns-client ↔ ns-router ↔ ns-server)
├── README.md
├── .gitignore
└── src/
    ├── lib.rs                  # Library root (exports crypto, packet, wire modules)
    ├── main.rs                 # Unified CLI entry point
    ├── crypto.rs               # ChaCha20-Poly1305 encrypt/decrypt with AAD and nonce construction
    ├── packet.rs               # Zero-copy IPv4 packet header parser
    ├── wire.rs                 # Wire protocol framing and 128-bit sliding window replay filter
    └── bin/
        ├── tun_playground.rs   # Phase 1: standalone TUN packet sniffer with unit tests
        ├── client.rs           # VPN client daemon (TUN → encrypted UDP → server)
        └── server.rs           # VPN server daemon (encrypted UDP → TUN, peer table, NAT-ready)
```

---

## 🛠️ Getting Started

### Prerequisites (Linux VM / VirtualBox)
```bash
sudo apt update && sudo apt install -y build-essential curl git iproute2 iptables nftables tcpdump
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

### Clone & Build
```bash
git clone https://github.com/SomTakalkar/vpn_app.git
cd vpn_app
cargo build
cargo test --all-targets
```

---

## 🧪 Testing with Network Namespaces

All testing runs on a single Linux machine using isolated network namespaces:

```
ns-client (10.0.1.2) ←─ veth ─→ ns-router (forwarding) ←─ veth ─→ ns-server (10.0.2.2)
```

### 1. Create the Testbed
```bash
chmod +x setup-namespaces.sh
sudo ./setup-namespaces.sh up

# Verify underlay connectivity
sudo ip netns exec ns-client ping -c 2 10.0.2.2
```

### 2. Phase 1 — TUN Playground (Packet Sniffing)
**Terminal 1:**
```bash
sudo ip netns exec ns-client ./target/debug/tun_playground
```
**Terminal 2:**
```bash
sudo ip netns exec ns-client ping -c 3 10.8.0.3
```
Observe the daemon intercepting and parsing raw IPv4/ICMP headers in real time.

### 3. Phase 2 & 3 — Encrypted UDP Tunnel (End-to-End Ping)
**Terminal 1 – Server:**
```bash
sudo ip netns exec ns-server ./target/debug/server
```
**Terminal 2 – Client:**
```bash
sudo ip netns exec ns-client ./target/debug/client --server 10.0.2.2:51820
```
**Terminal 3 – Ping through the tunnel:**
```bash
sudo ip netns exec ns-client ping -c 3 10.8.0.1
```
Expected: **0% packet loss**, ~1 ms RTT.

### 4. Verify Encryption with tcpdump
While the tunnel is active, inspect the wire in a **fourth terminal**:
```bash
sudo ip netns exec ns-router tcpdump -i veth-rc -X udp port 51820 -c 5
```
All UDP payloads should be **opaque ciphertext** — no recognisable IP headers (`0x45`), ICMP types, or patterns.

### 5. Tear Down
```bash
sudo ./setup-namespaces.sh down
```

---

## 🔐 Wire Protocol

### Data Packet Format (`0x03`)
```
[Type: 1 byte][Session ID: 4 bytes LE][Counter: 8 bytes LE][Encrypted Payload][Poly1305 Tag: 16 bytes]
 ← ─ ─ ─ ─ ─ ─ ─ Header (13 bytes, used as AAD) ─ ─ ─ → ← ─ ─ ─ ChaCha20-Poly1305 AEAD ─ ─ ─ →
```

- **Nonce**: `[0x00 × 4 || Counter as 8-byte LE]` → 96-bit, unique per packet.
- **AAD**: The 13-byte header is authenticated but not encrypted, allowing the receiver to parse the counter before decryption.
- **Tamper detection**: Any modification to the header, ciphertext, or tag causes decryption to fail immediately.

### Message Types
| Byte | Type | Description |
|------|------|-------------|
| `0x01` | `HANDSHAKE_INIT` | Client → Server ECDH initiation |
| `0x02` | `HANDSHAKE_RESP` | Server → Client ECDH response |
| `0x03` | `DATA` | Encrypted tunnel payload |
| `0x04` | `KEEPALIVE` | NAT binding heartbeat |
| `0x05` | `REKEY` | Session key rotation trigger |

---

## 🛣️ Roadmap

- [x] **M1: TUN Playground** — Async TUN creation, IP assignment, raw packet parsing.
- [x] **M2: Plaintext UDP Tunnel** — Bidirectional forwarding across network namespaces.
- [x] **M3: ChaCha20-Poly1305** — AEAD encryption verified opaque under `tcpdump`.
- [ ] **M4: Noise IK Handshake** — Authenticated ephemeral-static ECDH, replay window, keepalives, rekeying.
- [ ] **M5: Routing & NAT Automation** — Server-side `nftables` MASQUERADE, client default route override.
- [ ] **M6: Hardening & Deployment** — Privilege drop to `CAP_NET_ADMIN`, DNS leak prevention, fuzzing, OCI cloud deployment.
