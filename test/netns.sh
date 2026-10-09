#!/bin/bash
# Integration test: real Linux routing/firewall in a disposable network namespace.
set -eu
if [ "${1:-}" != inside ]; then
    exec sudo unshare --net --mount-proc bash "$0" inside
fi
ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/src/network.sh"
H=$(mktemp -d)
trap 'rm -rf "$H"' EXIT
printf 'br0\n198.51.100.1\n' > "$H/settings"
ip link set lo up
ip link add br0 type dummy
ip addr add 192.0.2.1/24 dev br0
ip link set br0 up
ip link add ovpnc0 type dummy
ip addr add 10.99.0.2/24 dev ovpnc0
ip link set ovpnc0 up
ip link add wg0 type dummy
ip link set wg0 up
ip route add default dev wg0 table 101
ip rule add pref 100 fwmark 2 table 101

# A foreign owner must never be flushed or silently overwritten.
ip route add unreachable default table 18100
if preflight_network; then echo 'ERROR: accepted occupied table'; exit 1; fi
ip route flush table 18100
guard_network
if ip route get 203.0.113.5 from 192.0.2.2 iif br0 mark 2 2>/dev/null; then echo 'ERROR: leaked before connect'; exit 1; fi
dev=ovpnc0 connect_network
ip route get 203.0.113.5 from 192.0.2.2 iif br0 mark 2 | grep 'dev ovpnc0'
iptables -t nat -C PREROUTING -i br0 -j OC2_DNS
iptables -t nat -C OC2_DNS -p udp --dport 53 -j DNAT --to-destination 198.51.100.1
ip6tables -C FORWARD -j OC2_V6
ip6tables -C OC2_V6 -i br0 -j REJECT
# Reapply is idempotent, and disconnect retains the guard over the WG fallback.
guard_network
dev=ovpnc0 connect_network
test "$(ip rule show | grep -c '^70:')" = 1
disconnect_network
if ip route get 203.0.113.5 from 192.0.2.2 iif br0 mark 2 2>/dev/null; then echo 'ERROR: leaked after disconnect'; exit 1; fi
release_network
! ip rule show | grep -q '^70:'
! iptables -S OC2_FWD 2>/dev/null
! ip6tables -S OC2_V6 2>/dev/null
ip rule show | grep '^100:.*fwmark 0x2.*lookup 101'
ip route show table 101 | grep 'default dev wg0'
echo 'PASS: real policy priority, IPv4 guard, DNS, IPv6 guard, idempotence and scoped cleanup'
