#!/system/bin/sh
H=/data/kano_openvpn/client-v2
. "$H/network.sh"
if connect_network; then
    umask 077
    rm -f "$H/error"
    printf '%s\n' "${ifconfig_local:-unknown}" > "$H/connected"
else
    disconnect_network
    echo 'OpenVPN: 热点路由配置失败，保留断线保护' >&2
    exit 1
fi
