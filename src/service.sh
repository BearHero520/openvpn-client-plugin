#!/system/bin/sh
umask 077
H=/data/kano_openvpn/client-v2
D=/data/kano_openvpn
PATH=/system/bin:/system/xbin:/vendor/bin:$PATH
export PATH
# Musl library paths must not leak into bionic shell children.
unset LD_LIBRARY_PATH LD_PRELOAD
. "$H/network.sh"
vpn_alive() {
    PID=$(cat "$H/openvpn.pid" 2>/dev/null)
    case "$PID" in ''|*[!0-9]*) return 1;; esac
    kill -0 "$PID" 2>/dev/null || return 1
    tr '\000' '\n' < "/proc/$PID/cmdline" | grep -qxF "$D/openvpn" || return 1
    tr '\000' '\n' < "/proc/$PID/cmdline" | grep -qxF "$H/runtime.ovpn"
}
monitor_alive() {
    MPID=$(cat "$H/monitor.pid" 2>/dev/null)
    case "$MPID" in ''|*[!0-9]*) return 1;; esac
    kill -0 "$MPID" 2>/dev/null || return 1
    tr '\000' '\n' < "/proc/$MPID/cmdline" | grep -qxF "$H/service.sh" || return 1
    tr '\000' '\n' < "/proc/$MPID/cmdline" | grep -qxF monitor
}
preflight() {
    [ "$(id -u)" = 0 ] || { echo '需要 root'; return 1; }
    [ -x "$D/openvpn" ] && [ -x "$D/ld-musl-aarch64.so.1" ] || { echo '未找到原版 ARM64 OpenVPN 二进制，请先安装原版二进制包'; return 1; }
    [ -s "$H/profile.ovpn" ] || { echo '请导入并保存 .ovpn 配置'; return 1; }
    [ -c /dev/net/tun ] || { echo '/dev/net/tun 不可用'; return 1; }
    [ ! -e "$D/.watchdog_enabled" ] || { echo '请先在旧插件关闭看门狗'; return 1; }
    if [ -f "$D/openvpn.pid" ]; then
        old=$(cat "$D/openvpn.pid")
        case "$old" in ''|*[!0-9]*) ;; *) if kill -0 "$old" 2>/dev/null; then echo '请先在旧插件停止 OpenVPN'; return 1; fi;; esac
    fi
    if grep -q '^auth-user-pass ' "$H/profile.ovpn"; then [ -s "$H/pass.txt" ] || { echo '请先保存 VPN 账号密码'; return 1; }; fi
    preflight_network
}
stop_client() {
    rm -f "$H/wanted"
    n=0
    while [ "$n" -lt 25 ]; do
        # Also catches a child launched just as the user pressed stop.
        if vpn_alive; then kill "$PID" || return 1; fi
        if ! monitor_alive && ! vpn_alive; then break; fi
        sleep 1; n=$((n+1))
    done
    if monitor_alive || vpn_alive; then echo '服务尚未退出，请稍后重试停止；断线保护仍保留'; return 1; fi
    release_network || return 1
    rm -f "$H/openvpn.pid" "$H/monitor.pid" "$H/connected"
    echo STOPPED
}
case "${1:-status}" in
    start)
        monitor_alive && { echo 'ALREADY_RUNNING'; exit 0; }
        vpn_alive && { echo '检测到本插件残留进程，请先停止再启动'; exit 1; }
        preflight || exit 1
        # A power loss may leave the empty lock directory on persistent /data.
        [ ! -d "$H/monitor.lock" ] || rmdir "$H/monitor.lock" || exit 1
        rm -f "$H/error"
        guard_network || { echo '防火墙/路由初始化失败；请停止以清理'; exit 1; }
        touch "$H/wanted"
        nohup /system/bin/sh "$H/service.sh" monitor </dev/null >>"$H/supervisor.log" 2>&1 &
        sleep 1
        monitor_alive || { echo '守护进程启动失败'; exit 1; }
        echo CONNECTING
        ;;
    boot)
        # Android may run the boot script before tethering has an address.
        n=0
        while [ "$n" -lt 60 ]; do
            if preflight >/dev/null 2>&1; then "$H/service.sh" start; exit $?; fi
            sleep 5; n=$((n+1))
        done
        echo '开机等待热点/配置超时' > "$H/error"
        exit 1
        ;;
    monitor)
        # Only one detached monitor may own the runtime files.
        mkdir "$H/monitor.lock" 2>/dev/null || exit 1
        echo $$ > "$H/monitor.pid"
        trap 'rm -f "$H/monitor.pid"; rmdir "$H/monitor.lock" 2>/dev/null' EXIT
        while [ -f "$H/wanted" ]; do
            disconnect_network
            # Keep one previous connection log, including authentication failures.
            [ ! -f "$H/openvpn.log" ] || mv -f "$H/openvpn.log" "$H/previous.log"
            if awk -f "$H/resolve.awk" "$H/profile.ovpn" > "$H/runtime.tmp"; then
                mv -f "$H/runtime.tmp" "$H/runtime.ovpn"
                [ -f "$H/wanted" ] || break
                "$D/ld-musl-aarch64.so.1" --library-path "$D/lib" "$D/openvpn" --cd "$H" --config "$H/runtime.ovpn" --writepid "$H/openvpn.pid" --log "$H/openvpn.log" &
                CHILD=$!
                echo "$CHILD" > "$H/openvpn.pid"
                wait "$CHILD"
                disconnect_network
                rm -f "$H/openvpn.pid"
                if grep -q 'AUTH_FAILED\|Options error\|VERIFY ERROR' "$H/openvpn.log"; then
                    echo '认证/配置/证书错误，修复后请停止再启动。' > "$H/error"
                    break
                fi
            else
                echo '系统 DNS 解析失败，10 秒后重试' > "$H/error"
                rm -f "$H/runtime.tmp"
            fi
            sleep 10
        done
        ;;
    stop) stop_client || exit 1 ;;
    restart) stop_client && "$H/service.sh" start ;;
    status)
        if vpn_alive; then
            if [ -s "$H/connected" ] && ip -4 addr show dev ovpnc0 | grep -q 'inet ' && ip -4 route show table "$TABLE" | grep -q 'default dev ovpnc0'; then
                printf 'CONNECTED\nIP=%s\nPID=%s\n' "$(cat "$H/connected")" "$PID"
            else echo CONNECTING; fi
        elif monitor_alive; then echo RETRYING
        elif [ -f "$H/wanted" ]; then echo ERROR
        else echo STOPPED; fi
        [ ! -f "$H/network.owned" ] || echo 'GUARD=ON'
        [ ! -s "$H/error" ] || cat "$H/error"
        ;;
    diagnose)
        "$H/service.sh" status
        echo '--- IPv4 policy ---'; ip -4 rule show
        echo '--- VPN table ---'; ip -4 route show table "$TABLE"
        echo '--- Tunnel ---'; ip -4 addr show dev ovpnc0 2>/dev/null
        echo '--- Forward counters ---'; iptables -nvL OC2_FWD 2>/dev/null
        echo '--- DNS counters ---'; iptables -t nat -nvL OC2_DNS 2>/dev/null
        echo '--- IPv6 guard ---'; ip6tables -nvL OC2_V6 2>/dev/null
        ;;
    *) echo '用法: service.sh start|stop|restart|status|diagnose'; exit 2 ;;
esac
