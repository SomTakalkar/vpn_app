# Custom Layer 3/4 VPN Daemon (`vpn_app`)

An educational, memory-safe, high-performance Layer 3/4 encrypted VPN daemon written in Rust for Linux.

Instead of relying on OpenVPN or WireGuard, this project intercepts raw IP packets via a virtual network interface (`/dev/net/tun`), encrypts them using **ChaCha20-Poly1305 AEAD**, and tunnels them over **UDP** with authenticated **ECDH key exchange** and **anti-replay sliding window filters**.

---

## 🚀 Architecture Overview

```
[ Client Traffic ] ---> (TUN Device: tun0) ---> [ Client Daemon ]
                                                       |
                                            (Encrypted UDP Tunnel)
                                                       v
[ Internet / Target ] <--- (NAT / Forwarding) <--- [ Server Daemon ]
```

### Key Components
- **TUN Device Interception**: Direct async read/write of raw IP packets from `/dev/net/tun`.
- **Wire Protocol**: Custom UDP framing `[Type: 1B][Session ID: 4B][Counter: 8B][Ciphertext + 16B Tag]`.
- **Cryptography**: Modern AEAD (`ChaCha20-Poly1305`) with 96-bit nonces (monotonically increasing 64-bit sequence counter) and Diffie-Hellman (`X25519` + `HKDF-SHA256`).
- **Anti-Replay Protection**: 128-bit sliding window bitmap dropping duplicate and out-of-order stale packets.
- **NAT & Subnet Forwarding**: Server-side `nftables` masquerade and automated client routing table override.

---

## 📦 Project Structure

```
├── Cargo.toml                  # Crates & async dependencies (tokio, tun, chacha20poly1305, etc.)
├── scripts/
│   └── setup-testbed.sh        # Linux network namespaces (ip netns) automated testbed
├── src/
│   ├── main.rs                 # CLI binary entry point (tun-playground, client, server)
│   ├── packet.rs               # Zero-copy IPv4 packet header parser
│   └── wire.rs                 # Wire protocol framing and 128-bit sliding window replay filter
└── README.md
```

---

## 🛠️ Getting Started (Local Development)

### 1. Prerequisites (Inside Linux VM / VirtualBox)
```bash
sudo apt update && sudo apt install -y build-essential curl git iproute2 iptables nftables tcpdump
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### 2. Phase 1: TUN Playground
Run the daemon to create the virtual `tun0` interface:
```bash
sudo $(which cargo) run -- tun-playground --name tun0 --ip 10.8.0.2
```

In a second terminal, send test ICMP packets through the virtual interface:
```bash
ping -c 3 10.8.0.2
```
Observe the real-time intercepted IPv4 packet headers, lengths, and protocols parsed directly from raw kernel memory.

### 3. Local Multi-Node Testing with Network Namespaces
To test client and server on one machine without cloud VMs:
```bash
# Set up isolated network namespaces (netns-client and netns-server)
chmod +x scripts/setup-testbed.sh
./scripts/setup-testbed.sh setup

# Test underlay ping between the namespaces
sudo ip netns exec netns-client ping -c 3 192.168.100.1

# Clean up namespaces when done
./scripts/setup-testbed.sh clean
```

---

## 🛣️ Roadmap & Milestones
- [x] **M1: TUN Playground**: Async TUN creation, IP assignment, and raw packet parsing.
- [ ] **M2: Plaintext UDP Tunnel**: Forwarding raw IP packets between client and server namespaces.
- [ ] **M3: ChaCha20-Poly1305**: AEAD encryption with pre-shared key.
- [ ] **M4: Noise IK Handshake**: Authenticated ephemeral-static ECDH, replay window, and keepalives.
- [ ] **M5: Routing & NAT Automation**: Server-side `nftables` MASQUERADE and client default route override.
- [ ] **M6: Hardening & Cloud Deployment**: Dropping root to `CAP_NET_ADMIN`, OCI deployment.
