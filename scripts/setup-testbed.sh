#!/usr/bin/env bash
# scripts/setup-testbed.sh: Sets up isolated network namespaces for local VPN testing
set -euo pipefail

ACTION="${1:-setup}"

if [ "$ACTION" == "setup" ]; then
    echo "[-] Setting up test network namespaces: netns-client and netns-server..."
    
    # 1. Create namespaces
    sudo ip netns add netns-client
    sudo ip netns add netns-server

    # 2. Bring up loopback
    sudo ip netns exec netns-client ip link set lo up
    sudo ip netns exec netns-server ip link set lo up

    # 3. Create veth peer cable
    sudo ip link add veth-client type veth peer name veth-server

    # 4. Move veth endpoints into their respective namespaces
    sudo ip link set veth-client netns netns-client
    sudo ip link set veth-server netns netns-server

    # 5. Assign underlay IP addresses (Simulated local LAN / Internet)
    sudo ip netns exec netns-client ip addr add 192.168.100.2/24 dev veth-client
    sudo ip netns exec netns-server ip addr add 192.168.100.1/24 dev veth-server

    # 6. Bring up interfaces
    sudo ip netns exec netns-client ip link set veth-client up
    sudo ip netns exec netns-server ip link set veth-server up

    echo "[+] Underlay network configured!"
    echo "    netns-client: 192.168.100.2"
    echo "    netns-server: 192.168.100.1"
    echo ""
    echo "To test connectivity:"
    echo "    sudo ip netns exec netns-client ping -c 3 192.168.100.1"
    echo ""
    echo "To run the TUN playground in client namespace:"
    echo "    sudo ip netns exec netns-client cargo run -- tun-playground"

elif [ "$ACTION" == "clean" ]; then
    echo "[-] Tearing down test network namespaces..."
    sudo ip netns del netns-client 2>/dev/null || true
    sudo ip netns del netns-server 2>/dev/null || true
    echo "[+] Cleaned up!"
else
    echo "Usage: $0 [setup|clean]"
    exit 1
fi
