# Custom Layer 3/4 VPN Daemon (`vpn_app`)

A custom, memory-safe, high-performance Layer 3/4 encrypted VPN daemon written in Rust for Linux.

Instead of relying on OpenVPN or WireGuard, this project intercepts raw IP packets via a virtual network interface (`/dev/net/tun`), encrypts them using **ChaCha20-Poly1305 AEAD**, and tunnels them over **UDP** with authenticated **ECDH key exchange (Noise IK)**, **directional keys**, **handshake timestamp replay protection**, and **anti-replay sliding window filters**.

---

## 🚀 Architecture Overview

```
[ Client Traffic ] ---> (TUN Device: tun0) ---> [ Client Daemon ]
                                                       |
                                          (Noise IK Authenticated UDP)
                                          - Directional Keys (K_c→s, K_s→c)
                                          - 128-bit Post-Decrypt Replay Filter
                                          - Periodic Keepalives (0x04)
                                                       v
[ Internet / Target ] <--- (NAT / Forwarding) <--- [ Server Daemon ]
```

### Key Components
- **TUN Device Interception**: Direct async read/write of raw IP packets from `/dev/net/tun`.
- **Wire Protocol**: Custom UDP framing `[Type: 1B][Session ID: 4B][Counter: 8B][Ciphertext + 16B Tag]`.
- **Authenticated Handshake (Noise IK)**: Ephemeral-Static Curve25519 Diffie-Hellman (`x25519-dalek`) with mutual authentication and Perfect Forward Secrecy.
- **Handshake Replay Protection**: WireGuard-style encrypted monotonic UTC timestamps; server drops any `HANDSHAKE_INIT` with a timestamp $\le$ last seen for that peer.
- **Directional Nonce Collision Immunity**: Distinct $K_{c \to s}$ and $K_{s \to c}$ derived via `HKDF-SHA256`; prevents nonce collisions and reflection attacks.
- **Post-Decryption Replay Filter**: 128-bit sliding window bitmap; executes **only after** Poly1305 authentication succeeds to prevent unauthenticated window manipulation.
- **NAT Keepalives**: Periodic `0x04` heartbeats sent every 20s during idle periods to sustain NAT state.
- **NAT & Subnet Forwarding** *(Phase 5)*: Server-side `nftables` masquerade and client routing table override.

---

## 📦 Project Structure

```
├── Cargo.toml                  # Dependencies (tokio, tun 0.6, chacha20poly1305, x25519-dalek, hkdf, rand)
├── setup-namespaces.sh         # 3-node network namespace testbed (ns-client ↔ ns-router ↔ ns-server)
├── README.md
├── .gitignore
└── src/
    ├── lib.rs                  # Library root (exports crypto, handshake, packet, wire)
    ├── main.rs                 # Unified CLI entry point
    ├── crypto.rs               # ChaCha20-Poly1305 AEAD with nonce construction & AAD framing
    ├── handshake.rs            # Noise IK handshake, timestamp replay defense & key derivation
    ├── packet.rs               # Zero-copy IPv4 packet header parser
    ├── wire.rs                 # Wire protocol definitions & 128-bit anti-replay filter
    └── bin/
        ├── tun_playground.rs   # Phase 1: standalone TUN packet sniffer with unit tests
        ├── client.rs           # Phase 4 client: handshake, directional encryption, keepalives
        └── server.rs           # Phase 4 server: handshake auth, session table, anti-replay
```

---

## 🛠️ Getting Started

### Prerequisites (Linux VM / VirtualBox)
```bash
sudo apt update && sudo apt install -y build-essential curl git iproute2 iptables nftables tcpdump
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

### Clone, Build & Test
```bash
git clone https://github.com/SomTakalkar/vpn_app.git
cd vpn_app
cargo test --all-targets
cargo build
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

### 2. Phase 4 — Authenticated Noise IK VPN
**Terminal 1 – Server:**
```bash
sudo ip netns exec ns-server ./target/debug/server
```

**Terminal 2 – Client:**
```bash
sudo ip netns exec ns-client ./target/debug/client --server 10.0.2.2:51820
```

Notice the logs in Terminal 1 and 2:
```
INFO client: Initiating Noise IK Handshake with server...
INFO server: Noise IK Handshake complete! Session ID: 0x... for peer 10.0.1.2:... (tunnel IP: 10.8.0.2)
INFO client: Noise IK Handshake SUCCESS! Session ID: 0x...
INFO client: Client tunnel established – forwarding encrypted packets
```

**Terminal 3 – Ping through the tunnel:**
```bash
sudo ip netns exec ns-client ping -c 3 10.8.0.1
```
Expected: **0% packet loss**, authenticated bidirectional encrypted transit!

### 3. Verify Wire Secrecy with tcpdump
**Terminal 4:**
```bash
sudo ip netns exec ns-router tcpdump -i veth-rc -X udp port 51820 -c 10
```
- Handshake init (`0x01`): Ephemeral key + ciphertext.
- Handshake response (`0x02`): Ephemeral key + session ID + auth tag.
- Data (`0x03`): Completely encrypted with directional keys; headers authenticated as AAD.
- Keepalive (`0x04`): Emitted every 20s if no ping traffic is flowing.

### 4. Tear Down
```bash
sudo ./setup-namespaces.sh down
```

---

## 🔐 Wire Protocol Details

### Packet Headers & Types
| Byte | Type | Description |
|------|------|-------------|
| `0x01` | `HANDSHAKE_INIT` | Noise IK Message 1 (Ephemeral pubkey + encrypted static identity + timestamp) |
| `0x02` | `HANDSHAKE_RESP` | Noise IK Message 2 (Ephemeral pubkey + session ID + authentication tag) |
| `0x03` | `DATA` | Encrypted IP packet payload |
| `0x04` | `KEEPALIVE` | Authenticated empty frame to maintain stateful NAT bindings |
| `0x05` | `REKEY` | Rekey trigger before counter exhaustion ($2^{64}-2^{16}$) |

### Data Wire Frame (`0x03` & `0x04`)
```
[Type: 1B][Session ID: 4B LE][Counter: 8B LE][Encrypted Payload][Poly1305 Tag: 16B]
 ← ─ ─ ─ ─ ─ ─ ─ Header (13 bytes, AAD) ─ ─ ─ ─ ─ ─ ─ → ← ─ ─ ChaCha20-Poly1305 ─ ─ ─ →
```

---

## 🛣️ Roadmap

- [x] **M1: TUN Playground** — Async TUN creation, IP assignment, raw packet parsing.
- [x] **M2: Plaintext UDP Tunnel** — Bidirectional forwarding across network namespaces.
- [x] **M3: ChaCha20-Poly1305** — Static key AEAD encryption verified under `tcpdump`.
- [x] **M4: Noise IK Handshake** — Ephemeral-static ECDH, directional keys, timestamp replay defense, per-session table, post-decrypt sliding window, keepalives.
- [ ] **M5: Routing & NAT Automation** — Server-side `nftables` MASQUERADE, client default route override.
- [ ] **M6: Hardening & Cloud Deployment** — Privilege drop to `CAP_NET_ADMIN`, DNS leak prevention, fuzzing, OCI deployment.
