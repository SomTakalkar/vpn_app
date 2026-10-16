#!/usr/bin/env bash
#
# setup-namespaces.sh: 3-Node Network Namespace Testbed for VPN Development
# Architecture:
#   ns-client (10.0.1.2/24) <---> (10.0.1.1/24) ns-router (10.0.2.1/24) <---> (10.0.2.2/24) ns-server
#

set -euo pipefail

red()   { echo -e "\033[1;31m$*\033[0m"; }
green() { echo -e "\033[1;32m$*\033[0m"; }
bold()  { echo -e "\033[1m$*\033[0m"; }

if [[ $EUID -ne 0 ]]; then
   red "This script must be run as root (or with sudo)."
   exit 1
fi

setup_testbed() {
    bold "==> Creating network namespaces..."
    ip netns add ns-client
    ip netns add ns-router
    ip netns add ns-server

    bold "==> Bringing up loopback interfaces..."
    ip netns exec ns-client ip link set lo up
    ip netns exec ns-router ip link set lo up
    ip netns exec ns-server ip link set lo up

    bold "==> Creating veth pairs..."
    # Client <-> Router link
    ip link add veth-c type veth peer name veth-rc
    ip link set veth-c netns ns-client
    ip link set veth-rc netns ns-router

    # Router <-> Server link
    ip link add veth-s type veth peer name veth-rs
    ip link set veth-s netns ns-server
    ip link set veth-rs netns ns-router

    bold "==> Configuring IP addresses and MTUs..."
    # ns-client configuration
    ip netns exec ns-client ip addr add 10.0.1.2/24 dev veth-c
    ip netns exec ns-client ip link set veth-c mtu 1500 up
    ip netns exec ns-client ip route add default via 10.0.1.1

    # ns-router configuration
    ip netns exec ns-router ip addr add 10.0.1.1/24 dev veth-rc
    ip netns exec ns-router ip link set veth-rc mtu 1500 up
    ip netns exec ns-router ip addr add 10.0.2.1/24 dev veth-rs
    ip netns exec ns-router ip link set veth-rs mtu 1500 up
    ip netns exec ns-router sysctl -w net.ipv4.ip_forward=1 >/dev/null

    # ns-server configuration
    ip netns exec ns-server ip addr add 10.0.2.2/24 dev veth-s
    ip netns exec ns-server ip link set veth-s mtu 1500 up
    ip netns exec ns-server ip route add default via 10.0.2.1
    ip netns exec ns-server sysctl -w net.ipv4.ip_forward=1 >/dev/null

    green "==> Testbed is UP!"
    echo "Verifying underlay ping (ns-client -> ns-server 10.0.2.2):"
    if ip netns exec ns-client ping -c 2 -W 1 10.0.2.2 >/dev/null 2>&1; then
        green "✓ Underlay transit verified successfully (0% packet loss)."
    else
        red "✗ Underlay ping failed. Check sysctl net.ipv4.ip_forward."
    fi
}

teardown_testbed() {
    bold "==> Tearing down network namespaces..."
    ip netns del ns-client 2>/dev/null || true
    ip netns del ns-router 2>/dev/null || true
    ip netns del ns-server 2>/dev/null || true
    ip link del veth-c 2>/dev/null || true
    ip link del veth-s 2>/dev/null || true
    green "==> Testbed cleaned up."
}

case "${1:-}" in
    up)
        teardown_testbed
        setup_testbed
        ;;
    down)
        teardown_testbed
        ;;
    status)
        echo "Active Network Namespaces:"
        ip netns list
        ;;
    *)
        echo "Usage: $0 {up|down|status}"
        exit 1
        ;;
esac
