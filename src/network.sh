#!/system/bin/sh
# Sourced by the supervisor and OpenVPN hooks. Never touch another VPN's chains.
H=/data/kano_openvpn/client-v2
TABLE=18100
PREF=70
TUN=ovpnc0
read_settings() {
    [ -r "$H/settings" ] || { echo '请先保存热点接口和家庭 DNS'; return 1; }
    LAN=$(sed -n '1p' "$H/settings")
    DNS=$(sed -n '2p' "$H/settings")
    case "$LAN" in ''|*[!a-zA-Z0-9_.-]*|lo|tun*|wg*|sipa*|rmnet*|ccmni*) return 1;; esac
    case "$DNS" in ''|*[!0-9.]*) return 1;; esac
    ip link show "$LAN" >/dev/null || return 1
    LAN_NET=$(ip -4 route show dev "$LAN" scope link | awk '$1 ~ /^[0-9]+\./ && $1 ~ /\// {print $1; exit}')
    [ -n "$LAN_NET" ] || { echo '热点接口没有 IPv4 子网'; return 1; }
}
owned() { [ -f "$H/network.owned" ]; }
preflight_network() {
    read_settings || return 1
    if ip -4 route get "$DNS" | grep -q '^local '; then echo '家庭 DNS 不能是本设备地址'; return 1; fi
    if ! owned; then
        [ -z "$(ip -4 route show table "$TABLE" 2>/dev/null)" ] || { echo '路由表 18100 已占用'; return 1; }
        ! ip -4 rule show | grep -q '^70:' || { echo '策略优先级 70 已占用'; return 1; }
        for chain in OC2_FWD OC2_NAT OC2_DNS; do
            if iptables -t filter -S "$chain" >/dev/null 2>&1 || iptables -t nat -S "$chain" >/dev/null 2>&1; then echo '同名防火墙链已存在'; return 1; fi
        done
        ! ip6tables -S OC2_V6 >/dev/null 2>&1 || return 1
        ! ip6tables -S OC2_IN6 >/dev/null 2>&1 || return 1
    fi
    # Fail closed if IPv6 cannot be blocked on an IPv6-enabled kernel.
    if [ -e /proc/net/if_inet6 ]; then ip6tables -S FORWARD >/dev/null || return 1; fi
}
guard_network() {
    preflight_network || return 1
    touch "$H/network.owned"
    # Install forwarding guards before policy routing, including DNS-via-local-router bypass.
    iptables -N OC2_FWD 2>/dev/null || :
    if ! iptables -C OC2_FWD -i "$LAN" -j REJECT 2>/dev/null; then iptables -A OC2_FWD -i "$LAN" -j REJECT || return 1; fi
    iptables -C FORWARD -j OC2_FWD 2>/dev/null || iptables -I FORWARD 1 -j OC2_FWD || return 1
    if [ -e /proc/net/if_inet6 ]; then
        ip6tables -N OC2_V6 2>/dev/null || :
        ip6tables -C OC2_V6 -i "$LAN" -j REJECT 2>/dev/null || ip6tables -A OC2_V6 -i "$LAN" -j REJECT || return 1
        ip6tables -C FORWARD -j OC2_V6 2>/dev/null || ip6tables -I FORWARD 1 -j OC2_V6 || return 1
        # Block the LAN's IPv6 DNS proxy as well as forwarded IPv6.
        ip6tables -N OC2_IN6 2>/dev/null || :
        for proto in udp tcp; do
            ip6tables -C OC2_IN6 -i "$LAN" -p "$proto" --dport 53 -j REJECT 2>/dev/null || ip6tables -A OC2_IN6 -i "$LAN" -p "$proto" --dport 53 -j REJECT || return 1
        done
        ip6tables -C INPUT -j OC2_IN6 2>/dev/null || ip6tables -I INPUT 1 -j OC2_IN6 || return 1
    fi
    ip -4 route replace unreachable default metric 32760 table "$TABLE" || return 1
    ip -4 route replace "$LAN_NET" dev "$LAN" table "$TABLE" || return 1
    ip -4 rule show | grep -q '^70:.*iif '"$LAN"'.*lookup 18100' || ip -4 rule add pref "$PREF" iif "$LAN" lookup "$TABLE" || return 1
    iptables -t nat -N OC2_DNS 2>/dev/null || :
    for proto in udp tcp; do
        iptables -t nat -C OC2_DNS -p "$proto" --dport 53 -j DNAT --to-destination "$DNS" 2>/dev/null || iptables -t nat -A OC2_DNS -p "$proto" --dport 53 -j DNAT --to-destination "$DNS" || return 1
    done
    iptables -t nat -C PREROUTING -i "$LAN" -j OC2_DNS 2>/dev/null || iptables -t nat -I PREROUTING 1 -i "$LAN" -j OC2_DNS || return 1
    printf '1\n' > /proc/sys/net/ipv4/ip_forward || return 1
}
connect_network() {
    read_settings || return 1
    owned || return 1
    [ "${dev:-}" = "$TUN" ] || return 1
    ip -4 route replace default dev "$TUN" metric 10 table "$TABLE" || return 1
    iptables -t nat -N OC2_NAT 2>/dev/null || :
    iptables -t nat -C OC2_NAT -o "$TUN" -j MASQUERADE 2>/dev/null || iptables -t nat -A OC2_NAT -o "$TUN" -j MASQUERADE || return 1
    iptables -t nat -C POSTROUTING -j OC2_NAT 2>/dev/null || iptables -t nat -I POSTROUTING 1 -j OC2_NAT || return 1
    iptables -C OC2_FWD -i "$LAN" -o "$TUN" -j ACCEPT 2>/dev/null || iptables -I OC2_FWD 1 -i "$LAN" -o "$TUN" -j ACCEPT || return 1
    iptables -C OC2_FWD -i "$TUN" -o "$LAN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -I OC2_FWD 1 -i "$TUN" -o "$LAN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || return 1
    ip -4 route flush cache 2>/dev/null || :
}
disconnect_network() {
    rm -f "$H/connected"
    owned || return 0
    ip -4 route del default dev "$TUN" metric 10 table "$TABLE" 2>/dev/null || :
    # The terminal unreachable route, DNS redirection and IPv6 guard intentionally remain.
}
release_network() {
    owned || return 0
    # Cleanup also works after the hotspot interface has disappeared.
    LAN=$(sed -n '1p' "$H/settings")
    case "$LAN" in ''|*[!a-zA-Z0-9_.-]*) return 1;; esac
    disconnect_network
    ip -4 rule del pref "$PREF" iif "$LAN" lookup "$TABLE" 2>/dev/null || :
    ip -4 route flush table "$TABLE" || return 1
    iptables -D FORWARD -j OC2_FWD 2>/dev/null || :
    iptables -F OC2_FWD 2>/dev/null || :
    iptables -X OC2_FWD 2>/dev/null || :
    iptables -t nat -D PREROUTING -i "$LAN" -j OC2_DNS 2>/dev/null || :
    iptables -t nat -F OC2_DNS 2>/dev/null || :
    iptables -t nat -X OC2_DNS 2>/dev/null || :
    iptables -t nat -D POSTROUTING -j OC2_NAT 2>/dev/null || :
    iptables -t nat -F OC2_NAT 2>/dev/null || :
    iptables -t nat -X OC2_NAT 2>/dev/null || :
    if [ -e /proc/net/if_inet6 ]; then
        ip6tables -D FORWARD -j OC2_V6 2>/dev/null || :
        ip6tables -F OC2_V6 2>/dev/null || :
        ip6tables -X OC2_V6 2>/dev/null || :
        ip6tables -D INPUT -j OC2_IN6 2>/dev/null || :
        ip6tables -F OC2_IN6 2>/dev/null || :
        ip6tables -X OC2_IN6 2>/dev/null || :
    fi
    rm -f "$H/network.owned"
}
