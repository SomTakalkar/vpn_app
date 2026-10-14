#!/usr/bin/env bash
# Simulated network inside one Linux VM:
#
#   ns-client  <--veth-->  ns-router ("the internet")  <--veth-->  ns-server
#   10.0.1.2/24            10.0.1.1 | 10.0.2.1                      10.0.2.2/24
#
# Usage:
#   sudo ./setup-namespaces.sh up        # create the testbed
#   sudo ./setup-namespaces.sh status    # show addresses and test connectivity
#   sudo ./setup-namespaces.sh down      # tear everything down
#
# Optional link impairment on the router (applied by `up`):
#   sudo DELAY=40ms LOSS=2% ./setup-namespaces.sh up
set -euo pipefail

CLIENT=ns-client
ROUTER=ns-router
SERVER=ns-server
DELAY="${DELAY:-}"
LOSS="${LOSS:-}"

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Please run as root: sudo $0 ${1:-up}" >&2
    exit 1
  fi
}

cleanup() {
  for ns in "$CLIENT" "$ROUTER" "$SERVER"; do
    ip netns del "$ns" 2>/dev/null || true
  done
  ip link del veth-c 2>/dev/null || true
  ip link del veth-s 2>/dev/null || true
}

# connect <ns-a> <dev-a> <addr-a> <ns-b> <dev-b> <addr-b>
connect() {
  local ns_a=$1 dev_a=$2 addr_a=$3 ns_b=$4 dev_b=$5 addr_b=$6
  ip link add "$dev_a" type veth peer name "$dev_b"
  ip link set "$dev_a" netns "$ns_a"
  ip link set "$dev_b" netns "$ns_b"
  ip -n "$ns_a" addr add "$addr_a" dev "$dev_a"
  ip -n "$ns_b" addr add "$addr_b" dev "$dev_b"
  ip -n "$ns_a" link set "$dev_a" up
  ip -n "$ns_b" link set "$dev_b" up
}

up() {
  cleanup
  for ns in "$CLIENT" "$ROUTER" "$SERVER"; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
  done

  connect "$CLIENT" veth-c  10.0.1.2/24 "$ROUTER" veth-rc 10.0.1.1/24
  connect "$SERVER" veth-s  10.0.2.2/24 "$ROUTER" veth-rs 10.0.2.1/24

  ip -n "$CLIENT" route add default via 10.0.1.1
  ip -n "$SERVER" route add default via 10.0.2.1
  ip netns exec "$ROUTER" sysctl -qw net.ipv4.ip_forward=1

  if [[ -n "$DELAY" || -n "$LOSS" ]]; then
    local netem=()
    if [[ -n "$DELAY" ]]; then netem+=(delay "$DELAY"); fi
    if [[ -n "$LOSS" ]]; then netem+=(loss "$LOSS"); fi
    for dev in veth-rc veth-rs; do
      ip netns exec "$ROUTER" tc qdisc add dev "$dev" root netem "${netem[@]}"
    done
    echo "Router impairment: ${netem[*]}"
  fi

  echo "Testbed is up. Try:"
  echo "  sudo ip netns exec $CLIENT ping -c 2 10.0.2.2"
}

status() {
  for ns in "$CLIENT" "$ROUTER" "$SERVER"; do
    echo "== $ns =="
    ip -n "$ns" -brief addr
    ip -n "$ns" route
  done
  echo "== client -> server ping =="
  ip netns exec "$CLIENT" ping -c 1 -W 1 10.0.2.2
}

case "${1:-}" in
  up)     require_root "$@"; up ;;
  down)   require_root "$@"; cleanup; echo "Testbed removed." ;;
  status) require_root "$@"; status ;;
  *)      echo "Usage: sudo $0 {up|down|status}" >&2; exit 1 ;;
esac
