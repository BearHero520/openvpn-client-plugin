//<script>
// OpenVPN客户端插件 v2.0.0 | https://github.com/BearHero520/openvpn-client-plugin
(async () => {
'use strict';
const DIR = '/data/kano_openvpn';
const HOME = `${DIR}/client-v2`;
function quote(value) { return "'" + String(value).replaceAll("'", "'\\''") + "'"; }
function ipv4(value) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(value) && value.split('.').every(x => Number(x) <= 255);
}
function settings(input) {
  const lan = input.lan.trim(), dns = input.dns.trim();
  if (!/^[a-zA-Z][\w.-]{0,14}$/.test(lan) || /^(lo|tun\d*|wg\d*|rmnet.*|sipa.*|ccmni.*)$/.test(lan)) throw Error('请选择热点 LAN 接口（通常 br0），不能选择蜂窝或 VPN 接口');
  if (!ipv4(dns) || /^(0\.|127\.|224\.|255\.)/.test(dns)) throw Error('填写家庭网络可达的 IPv4 DNS，例如家庭路由器 LAN 地址');
  return {lan, dns};
}
const allowed = new Set(('client tls-client proto remote remote-random nobind float resolv-retry connect-retry connect-retry-max connect-timeout server-poll-timeout sndbuf rcvbuf tun-mtu mssfix fragment auth cipher data-ciphers data-ciphers-fallback remote-cert-tls verify-x509-name peer-fingerprint tls-version-min tls-version-max tls-cipher tls-ciphersuites key-direction reneg-sec reneg-bytes reneg-pkts auth-nocache auth-retry explicit-exit-notify fast-io mute mute-replay-warnings ping ping-restart ping-exit keepalive route route-ipv6 route-metric route-delay route-gateway dhcp-option hand-window tran-window allow-compression compress comp-lzo').split(' '));
const managed = new Set(('dev dev-type persist-tun persist-key script-security route-noexec route-nopull redirect-gateway redirect-private verb block-outside-dns register-dns windows-driver ignore-unknown-option').split(' '));
const blocks = new Set(['ca', 'cert', 'key', 'tls-auth', 'tls-crypt', 'tls-crypt-v2', 'peer-fingerprint']);
// Strict tokenizer: no shell evaluation; quoted CN values remain valid OpenVPN syntax.
function tokens(line) {
  const result = []; let token = '', quoteChar = '', active = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '\\') { if (++i >= line.length) throw Error('不支持续行或末尾反斜杠'); token += line[i]; active = true; }
    else if (quoteChar) { if (c === quoteChar) quoteChar = ''; else token += c; }
    else if (c === '"' || c === "'") { quoteChar = c; active = true; }
    else if (/\s/.test(c)) { if (active) { result.push(token); token = ''; active = false; } }
    else if ((c === '#' || c === ';') && !active) break;
    else { token += c; active = true; }
  }
  if (quoteChar) throw Error('配置中的引号未闭合');
  if (active) result.push(token);
  return result;
}
function parseProfile(raw) {
  if (typeof raw !== 'string' || new TextEncoder().encode(raw).length > 1024 * 1024) throw Error('配置必须是 1 MiB 以内的文本');
  const text = raw.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n');
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(text) || /^\s*[\[{]/.test(text)) throw Error('这不是有效的 OpenVPN 文本配置');
  const out = [], remotes = [], warnings = [], found = new Set();
  let block = '', body = [], auth = false, serverCheck = false, trust = false;
  for (const [index, line] of text.split('\n').entries()) {
    const trim = line.trim();
    if (block) {
      if (trim === `</${block}>`) {
        if (!body.some(x => x.trim())) throw Error(`${block} 内容为空`);
        if (block === 'key' && body.some(x => /ENCRYPTED/.test(x))) throw Error('暂不支持加密私钥，请导出用于无人值守连接的配置');
        out.push(`<${block}>`, ...body, `</${block}>`); found.add(block); if (block === 'peer-fingerprint') { trust = true; serverCheck = true; }
        block = ''; body = [];
      } else { if (/^<\/?[\w-]+>/.test(trim)) throw Error('内嵌证书标签不匹配'); body.push(line); }
      continue;
    }
    if (!trim || /^[#;]/.test(trim)) { out.push(line); continue; }
    const tag = trim.match(/^<([\w-]+)>$/);
    if (tag) { if (!blocks.has(tag[1]) || found.has(tag[1])) throw Error(`不支持或重复的内嵌区块：${tag[1]}`); block = tag[1]; continue; }
    const parts = tokens(trim), option = parts[0]?.replace(/^--/, ''), args = parts.slice(1);
    if (!option) continue;
    if (blocks.has(option) && option !== 'peer-fingerprint') {
      if (args[0] !== '[inline]' || args.length > 2 || (args[1] && !['0', '1'].includes(args[1]))) throw Error(`${option} 需要内嵌证书，不能引用外部文件`);
      if (args[1]) out.push(`key-direction ${args[1]}`);
      continue;
    }
    if (option === 'auth-user-pass') { auth = true; out.push(`auth-user-pass ${HOME}/pass.txt`); continue; }
    if (managed.has(option)) {
      if (option === 'dev' && !/^tun\d*$/.test(args[0] || '')) throw Error('仅支持 TUN 配置');
      if (option === 'dev-type' && args[0] !== 'tun') throw Error('仅支持 TUN 配置');
      if (!['dev', 'verb', 'persist-key', 'persist-tun'].includes(option)) warnings.push(`${option} 由插件接管`);
      continue;
    }
    if (!allowed.has(option)) throw Error(`第 ${index + 1} 行不支持 ${option}；外部脚本、插件、文件引用及管理端口不会执行`);
    if (option === 'remote') {
      if (!/^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$/.test(args[0] || '') || args.length > 3) throw Error('remote 只支持 IPv4 地址或域名');
      const port = args[1] || '1194';
      if (!/^\d+$/.test(port) || +port < 1 || +port > 65535) throw Error('remote 端口无效');
      if (args[2] && !['udp', 'udp4', 'tcp-client', 'tcp4-client', 'tcp'].includes(args[2])) throw Error('remote 仅支持 IPv4 TCP/UDP');
      remotes.push({host: args[0], port: +port});
      out.push(`remote ${args[0]} ${port}${args[2] ? ' ' + args[2] : ''}`); continue;
    }
    if (option === 'proto' && !['udp', 'udp4', 'tcp-client', 'tcp4-client'].includes(args[0])) throw Error('仅支持 IPv4 UDP 或 TCP 客户端协议');
    if (option === 'remote-cert-tls' && args[0] === 'server') serverCheck = true;
    if (option === 'peer-fingerprint') { trust = true; serverCheck = true; }
    if (option === 'compress' || option === 'comp-lzo') {
      if (option === 'comp-lzo' && args[0] === 'no') { warnings.push('移除旧版 comp-lzo no；禁用压缩'); continue; }
      throw Error('请在服务器关闭压缩后重新导出配置');
    }
    if (option === 'allow-compression' && args[0] !== 'no') throw Error('请禁用压缩');
    out.push(trim.replace(/^--/, ''));
  }
  if (block) throw Error(`缺少 </${block}>`);
  if (!remotes.length) throw Error('缺少 remote 服务器地址');
  if (!found.has('ca') && !trust) throw Error('缺少内嵌 CA 或服务器指纹');
  if (!serverCheck) { out.push('remote-cert-tls server'); warnings.push('补充服务器证书用途校验'); }
  if (found.has('cert') !== found.has('key')) throw Error('客户端 cert 与 key 必须配对');
  out.push('client', 'dev ovpnc0', 'dev-type tun', 'nobind', 'verb 3', 'route-noexec', 'script-security 2', 'allow-compression no', 'remap-usr1 SIGTERM', 'connect-retry-max 2', 'resolv-retry 5', 'ping 10', 'ping-restart 60', 'pull-filter ignore "block-outside-dns"', 'pull-filter ignore "redirect-gateway"', 'pull-filter ignore "route-ipv6"', 'pull-filter ignore "ifconfig-ipv6"', `route-up ${HOME}/route.sh`, `route-pre-down ${HOME}/down.sh`, `down ${HOME}/down.sh`, 'down-pre');
  return {text: out.join('\n').trim() + '\n', remotes, auth, warnings: [...new Set(warnings)]};
}
function unwrap(result) {
  if (!result || result.success === false) throw Error('设备命令失败，请检查高级功能和 root 权限');
  let content = result.content;
  // Some UFI-TOOLS releases wrap command results once more as JSON.
  if (typeof content === 'string' && /^\s*\{/.test(content)) {
    try { const inner = JSON.parse(content); if ('content' in inner || 'success' in inner) return unwrap(inner); } catch (e) { if (!(e instanceof SyntaxError)) throw e; }
  }
  if (typeof content !== 'string') throw Error('设备返回了非文本结果');
  return content;
}

const ASSETS = {"service.sh":"#!/system/bin/sh\numask 077\nH=/data/kano_openvpn/client-v2\nD=/data/kano_openvpn\nPATH=/system/bin:/system/xbin:/vendor/bin:$PATH\nexport PATH\n# Musl library paths must not leak into bionic shell children.\nunset LD_LIBRARY_PATH LD_PRELOAD\n. \"$H/network.sh\"\nvpn_alive() {\n    PID=$(cat \"$H/openvpn.pid\" 2>/dev/null)\n    case \"$PID\" in ''|*[!0-9]*) return 1;; esac\n    kill -0 \"$PID\" 2>/dev/null || return 1\n    tr '\\000' '\\n' < \"/proc/$PID/cmdline\" | grep -qxF \"$D/openvpn\" || return 1\n    tr '\\000' '\\n' < \"/proc/$PID/cmdline\" | grep -qxF \"$H/runtime.ovpn\"\n}\nmonitor_alive() {\n    MPID=$(cat \"$H/monitor.pid\" 2>/dev/null)\n    case \"$MPID\" in ''|*[!0-9]*) return 1;; esac\n    kill -0 \"$MPID\" 2>/dev/null || return 1\n    tr '\\000' '\\n' < \"/proc/$MPID/cmdline\" | grep -qxF \"$H/service.sh\" || return 1\n    tr '\\000' '\\n' < \"/proc/$MPID/cmdline\" | grep -qxF monitor\n}\npreflight() {\n    [ \"$(id -u)\" = 0 ] || { echo '需要 root'; return 1; }\n    [ -x \"$D/openvpn\" ] && [ -x \"$D/ld-musl-aarch64.so.1\" ] || { echo '未找到原版 ARM64 OpenVPN 二进制，请先安装原版二进制包'; return 1; }\n    [ -s \"$H/profile.ovpn\" ] || { echo '请导入并保存 .ovpn 配置'; return 1; }\n    [ -c /dev/net/tun ] || { echo '/dev/net/tun 不可用'; return 1; }\n    [ ! -e \"$D/.watchdog_enabled\" ] || { echo '请先在旧插件关闭看门狗'; return 1; }\n    if [ -f \"$D/openvpn.pid\" ]; then\n        old=$(cat \"$D/openvpn.pid\")\n        case \"$old\" in ''|*[!0-9]*) ;; *) if kill -0 \"$old\" 2>/dev/null; then echo '请先在旧插件停止 OpenVPN'; return 1; fi;; esac\n    fi\n    if grep -q '^auth-user-pass ' \"$H/profile.ovpn\"; then [ -s \"$H/pass.txt\" ] || { echo '请先保存 VPN 账号密码'; return 1; }; fi\n    preflight_network\n}\nstop_client() {\n    rm -f \"$H/wanted\"\n    n=0\n    while [ \"$n\" -lt 25 ]; do\n        # Also catches a child launched just as the user pressed stop.\n        if vpn_alive; then kill \"$PID\" || return 1; fi\n        if ! monitor_alive && ! vpn_alive; then break; fi\n        sleep 1; n=$((n+1))\n    done\n    if monitor_alive || vpn_alive; then echo '服务尚未退出，请稍后重试停止；断线保护仍保留'; return 1; fi\n    release_network || return 1\n    rm -f \"$H/openvpn.pid\" \"$H/monitor.pid\" \"$H/connected\"\n    echo STOPPED\n}\ncase \"${1:-status}\" in\n    start)\n        monitor_alive && { echo 'ALREADY_RUNNING'; exit 0; }\n        vpn_alive && { echo '检测到本插件残留进程，请先停止再启动'; exit 1; }\n        preflight || exit 1\n        # A power loss may leave the empty lock directory on persistent /data.\n        [ ! -d \"$H/monitor.lock\" ] || rmdir \"$H/monitor.lock\" || exit 1\n        rm -f \"$H/error\"\n        guard_network || { echo '防火墙/路由初始化失败；请停止以清理'; exit 1; }\n        touch \"$H/wanted\"\n        nohup /system/bin/sh \"$H/service.sh\" monitor </dev/null >>\"$H/supervisor.log\" 2>&1 &\n        sleep 1\n        monitor_alive || { echo '守护进程启动失败'; exit 1; }\n        echo CONNECTING\n        ;;\n    boot)\n        # Android may run the boot script before tethering has an address.\n        n=0\n        while [ \"$n\" -lt 60 ]; do\n            if preflight >/dev/null 2>&1; then \"$H/service.sh\" start; exit $?; fi\n            sleep 5; n=$((n+1))\n        done\n        echo '开机等待热点/配置超时' > \"$H/error\"\n        exit 1\n        ;;\n    monitor)\n        # Only one detached monitor may own the runtime files.\n        mkdir \"$H/monitor.lock\" 2>/dev/null || exit 1\n        echo $$ > \"$H/monitor.pid\"\n        trap 'rm -f \"$H/monitor.pid\"; rmdir \"$H/monitor.lock\" 2>/dev/null' EXIT\n        while [ -f \"$H/wanted\" ]; do\n            disconnect_network\n            # Keep one previous connection log, including authentication failures.\n            [ ! -f \"$H/openvpn.log\" ] || mv -f \"$H/openvpn.log\" \"$H/previous.log\"\n            if awk -f \"$H/resolve.awk\" \"$H/profile.ovpn\" > \"$H/runtime.tmp\"; then\n                mv -f \"$H/runtime.tmp\" \"$H/runtime.ovpn\"\n                [ -f \"$H/wanted\" ] || break\n                \"$D/ld-musl-aarch64.so.1\" --library-path \"$D/lib\" \"$D/openvpn\" --cd \"$H\" --config \"$H/runtime.ovpn\" --writepid \"$H/openvpn.pid\" --log \"$H/openvpn.log\" &\n                CHILD=$!\n                echo \"$CHILD\" > \"$H/openvpn.pid\"\n                wait \"$CHILD\"\n                disconnect_network\n                rm -f \"$H/openvpn.pid\"\n                if grep -q 'AUTH_FAILED\\|Options error\\|VERIFY ERROR' \"$H/openvpn.log\"; then\n                    echo '认证/配置/证书错误，修复后请停止再启动。' > \"$H/error\"\n                    break\n                fi\n            else\n                echo '系统 DNS 解析失败，10 秒后重试' > \"$H/error\"\n                rm -f \"$H/runtime.tmp\"\n            fi\n            sleep 10\n        done\n        ;;\n    stop) stop_client || exit 1 ;;\n    restart) stop_client && \"$H/service.sh\" start ;;\n    status)\n        if vpn_alive; then\n            if [ -s \"$H/connected\" ] && ip -4 addr show dev ovpnc0 | grep -q 'inet ' && ip -4 route show table \"$TABLE\" | grep -q 'default dev ovpnc0'; then\n                printf 'CONNECTED\\nIP=%s\\nPID=%s\\n' \"$(cat \"$H/connected\")\" \"$PID\"\n            else echo CONNECTING; fi\n        elif monitor_alive; then echo RETRYING\n        elif [ -f \"$H/wanted\" ]; then echo ERROR\n        else echo STOPPED; fi\n        [ ! -f \"$H/network.owned\" ] || echo 'GUARD=ON'\n        [ ! -s \"$H/error\" ] || cat \"$H/error\"\n        ;;\n    diagnose)\n        \"$H/service.sh\" status\n        echo '--- IPv4 policy ---'; ip -4 rule show\n        echo '--- VPN table ---'; ip -4 route show table \"$TABLE\"\n        echo '--- Tunnel ---'; ip -4 addr show dev ovpnc0 2>/dev/null\n        echo '--- Forward counters ---'; iptables -nvL OC2_FWD 2>/dev/null\n        echo '--- DNS counters ---'; iptables -t nat -nvL OC2_DNS 2>/dev/null\n        echo '--- IPv6 guard ---'; ip6tables -nvL OC2_V6 2>/dev/null\n        ;;\n    *) echo '用法: service.sh start|stop|restart|status|diagnose'; exit 2 ;;\nesac\n","network.sh":"#!/system/bin/sh\n# Sourced by the supervisor and OpenVPN hooks. Never touch another VPN's chains.\nH=/data/kano_openvpn/client-v2\nTABLE=18100\nPREF=70\nTUN=ovpnc0\nread_settings() {\n    [ -r \"$H/settings\" ] || { echo '请先保存热点接口和家庭 DNS'; return 1; }\n    LAN=$(sed -n '1p' \"$H/settings\")\n    DNS=$(sed -n '2p' \"$H/settings\")\n    case \"$LAN\" in ''|*[!a-zA-Z0-9_.-]*|lo|tun*|wg*|sipa*|rmnet*|ccmni*) return 1;; esac\n    case \"$DNS\" in ''|*[!0-9.]*) return 1;; esac\n    ip link show \"$LAN\" >/dev/null || return 1\n    LAN_NET=$(ip -4 route show dev \"$LAN\" scope link | awk '$1 ~ /^[0-9]+\\./ && $1 ~ /\\// {print $1; exit}')\n    [ -n \"$LAN_NET\" ] || { echo '热点接口没有 IPv4 子网'; return 1; }\n}\nowned() { [ -f \"$H/network.owned\" ]; }\npreflight_network() {\n    read_settings || return 1\n    if ip -4 route get \"$DNS\" | grep -q '^local '; then echo '家庭 DNS 不能是本设备地址'; return 1; fi\n    if ! owned; then\n        [ -z \"$(ip -4 route show table \"$TABLE\" 2>/dev/null)\" ] || { echo '路由表 18100 已占用'; return 1; }\n        ! ip -4 rule show | grep -q '^70:' || { echo '策略优先级 70 已占用'; return 1; }\n        for chain in OC2_FWD OC2_NAT OC2_DNS; do\n            if iptables -t filter -S \"$chain\" >/dev/null 2>&1 || iptables -t nat -S \"$chain\" >/dev/null 2>&1; then echo '同名防火墙链已存在'; return 1; fi\n        done\n        ! ip6tables -S OC2_V6 >/dev/null 2>&1 || return 1\n        ! ip6tables -S OC2_IN6 >/dev/null 2>&1 || return 1\n    fi\n    # Fail closed if IPv6 cannot be blocked on an IPv6-enabled kernel.\n    if [ -e /proc/net/if_inet6 ]; then ip6tables -S FORWARD >/dev/null || return 1; fi\n}\nguard_network() {\n    preflight_network || return 1\n    touch \"$H/network.owned\"\n    # Install forwarding guards before policy routing, including DNS-via-local-router bypass.\n    iptables -N OC2_FWD 2>/dev/null || :\n    if ! iptables -C OC2_FWD -i \"$LAN\" -j REJECT 2>/dev/null; then iptables -A OC2_FWD -i \"$LAN\" -j REJECT || return 1; fi\n    iptables -C FORWARD -j OC2_FWD 2>/dev/null || iptables -I FORWARD 1 -j OC2_FWD || return 1\n    if [ -e /proc/net/if_inet6 ]; then\n        ip6tables -N OC2_V6 2>/dev/null || :\n        ip6tables -C OC2_V6 -i \"$LAN\" -j REJECT 2>/dev/null || ip6tables -A OC2_V6 -i \"$LAN\" -j REJECT || return 1\n        ip6tables -C FORWARD -j OC2_V6 2>/dev/null || ip6tables -I FORWARD 1 -j OC2_V6 || return 1\n        # Block the LAN's IPv6 DNS proxy as well as forwarded IPv6.\n        ip6tables -N OC2_IN6 2>/dev/null || :\n        for proto in udp tcp; do\n            ip6tables -C OC2_IN6 -i \"$LAN\" -p \"$proto\" --dport 53 -j REJECT 2>/dev/null || ip6tables -A OC2_IN6 -i \"$LAN\" -p \"$proto\" --dport 53 -j REJECT || return 1\n        done\n        ip6tables -C INPUT -j OC2_IN6 2>/dev/null || ip6tables -I INPUT 1 -j OC2_IN6 || return 1\n    fi\n    ip -4 route replace unreachable default metric 32760 table \"$TABLE\" || return 1\n    ip -4 route replace \"$LAN_NET\" dev \"$LAN\" table \"$TABLE\" || return 1\n    ip -4 rule show | grep -q '^70:.*iif '\"$LAN\"'.*lookup 18100' || ip -4 rule add pref \"$PREF\" iif \"$LAN\" lookup \"$TABLE\" || return 1\n    iptables -t nat -N OC2_DNS 2>/dev/null || :\n    for proto in udp tcp; do\n        iptables -t nat -C OC2_DNS -p \"$proto\" --dport 53 -j DNAT --to-destination \"$DNS\" 2>/dev/null || iptables -t nat -A OC2_DNS -p \"$proto\" --dport 53 -j DNAT --to-destination \"$DNS\" || return 1\n    done\n    iptables -t nat -C PREROUTING -i \"$LAN\" -j OC2_DNS 2>/dev/null || iptables -t nat -I PREROUTING 1 -i \"$LAN\" -j OC2_DNS || return 1\n    printf '1\\n' > /proc/sys/net/ipv4/ip_forward || return 1\n}\nconnect_network() {\n    read_settings || return 1\n    owned || return 1\n    [ \"${dev:-}\" = \"$TUN\" ] || return 1\n    ip -4 route replace default dev \"$TUN\" metric 10 table \"$TABLE\" || return 1\n    iptables -t nat -N OC2_NAT 2>/dev/null || :\n    iptables -t nat -C OC2_NAT -o \"$TUN\" -j MASQUERADE 2>/dev/null || iptables -t nat -A OC2_NAT -o \"$TUN\" -j MASQUERADE || return 1\n    iptables -t nat -C POSTROUTING -j OC2_NAT 2>/dev/null || iptables -t nat -I POSTROUTING 1 -j OC2_NAT || return 1\n    iptables -C OC2_FWD -i \"$LAN\" -o \"$TUN\" -j ACCEPT 2>/dev/null || iptables -I OC2_FWD 1 -i \"$LAN\" -o \"$TUN\" -j ACCEPT || return 1\n    iptables -C OC2_FWD -i \"$TUN\" -o \"$LAN\" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -I OC2_FWD 1 -i \"$TUN\" -o \"$LAN\" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || return 1\n    ip -4 route flush cache 2>/dev/null || :\n}\ndisconnect_network() {\n    rm -f \"$H/connected\"\n    owned || return 0\n    ip -4 route del default dev \"$TUN\" metric 10 table \"$TABLE\" 2>/dev/null || :\n    # The terminal unreachable route, DNS redirection and IPv6 guard intentionally remain.\n}\nrelease_network() {\n    owned || return 0\n    # Cleanup also works after the hotspot interface has disappeared.\n    LAN=$(sed -n '1p' \"$H/settings\")\n    case \"$LAN\" in ''|*[!a-zA-Z0-9_.-]*) return 1;; esac\n    disconnect_network\n    ip -4 rule del pref \"$PREF\" iif \"$LAN\" lookup \"$TABLE\" 2>/dev/null || :\n    ip -4 route flush table \"$TABLE\" || return 1\n    iptables -D FORWARD -j OC2_FWD 2>/dev/null || :\n    iptables -F OC2_FWD 2>/dev/null || :\n    iptables -X OC2_FWD 2>/dev/null || :\n    iptables -t nat -D PREROUTING -i \"$LAN\" -j OC2_DNS 2>/dev/null || :\n    iptables -t nat -F OC2_DNS 2>/dev/null || :\n    iptables -t nat -X OC2_DNS 2>/dev/null || :\n    iptables -t nat -D POSTROUTING -j OC2_NAT 2>/dev/null || :\n    iptables -t nat -F OC2_NAT 2>/dev/null || :\n    iptables -t nat -X OC2_NAT 2>/dev/null || :\n    if [ -e /proc/net/if_inet6 ]; then\n        ip6tables -D FORWARD -j OC2_V6 2>/dev/null || :\n        ip6tables -F OC2_V6 2>/dev/null || :\n        ip6tables -X OC2_V6 2>/dev/null || :\n        ip6tables -D INPUT -j OC2_IN6 2>/dev/null || :\n        ip6tables -F OC2_IN6 2>/dev/null || :\n        ip6tables -X OC2_IN6 2>/dev/null || :\n    fi\n    rm -f \"$H/network.owned\"\n}\n","route.sh":"#!/system/bin/sh\nH=/data/kano_openvpn/client-v2\n. \"$H/network.sh\"\nif connect_network; then\n    umask 077\n    rm -f \"$H/error\"\n    printf '%s\\n' \"${ifconfig_local:-unknown}\" > \"$H/connected\"\nelse\n    disconnect_network\n    echo 'OpenVPN: 热点路由配置失败，保留断线保护' >&2\n    exit 1\nfi\n","down.sh":"#!/system/bin/sh\n. /data/kano_openvpn/client-v2/network.sh\ndisconnect_network\n","resolve.awk":"# Source profile was validated in JavaScript. Only native Android ping does DNS.\nBEGIN { block = \"\"; failed = 0; count = 0 }\n/^<[a-z-]+>$/ { block = $0 }\n!block && $1 == \"remote\" {\n    host = $2\n    if (host !~ /^[A-Za-z0-9][A-Za-z0-9.-]*$/) { failed = 1; next }\n    if (host !~ /^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$/) {\n        command = \"/system/bin/ping -c 1 -W 1 \" host \" 2>/dev/null\"\n        address = \"\"\n        while ((command | getline answer) > 0) {\n            if (answer ~ /^PING / && match(answer, /\\([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\\)/)) {\n                address = substr(answer, RSTART + 1, RLENGTH - 2)\n            }\n        }\n        close(command)\n        if (!address) { failed = 1; next }\n        $2 = address\n    }\n    count++\n}\n{ print }\n/^<\\/[a-z-]+>$/ { block = \"\" }\nEND { if (failed || count == 0) exit 1 }\n"};
if (typeof runShellWithRoot !== 'function') throw Error('请在 UFI-TOOLS 的插件管理中运行此文件');
if (document.getElementById('openvpn-client-v2')) return;
const anchor = document.querySelector('.functions-container');
if (!anchor) throw Error('没有找到 UFI-TOOLS 插件容器');
const panel = document.createElement('section');
panel.id = 'openvpn-client-v2';
panel.innerHTML = `
<style>
#openvpn-client-v2 {margin:14px 0;padding:16px;border:1px solid #8885;border-radius:12px;color:inherit}
#openvpn-client-v2 h3 {margin:0 0 12px} #openvpn-client-v2 .oc-row {display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:12px 0}
#openvpn-client-v2 label {display:flex;gap:6px;align-items:center;flex-wrap:wrap}
#openvpn-client-v2 input:not([type=file]) {padding:8px;max-width:220px;color:inherit;background:transparent;border:1px solid #8888;border-radius:5px}
#openvpn-client-v2 button {padding:7px 12px;cursor:pointer} #openvpn-client-v2 button:disabled {opacity:.5;cursor:wait}
#openvpn-client-v2 textarea {box-sizing:border-box;width:100%;min-height:220px;background:transparent;color:inherit;border:1px solid #8888;border-radius:6px;padding:10px;font:12px/1.6 monospace}
#openvpn-client-v2 .oc-grid {display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,300px),1fr));gap:14px}
#openvpn-client-v2 .oc-note {font-size:13px;line-height:1.7;opacity:.85} #openvpn-client-v2 output {white-space:pre-wrap;overflow-wrap:anywhere;display:block}
</style>
<h3>OpenVPN 客户端插件 <small>v2.0.0</small></h3>
<output data-id="status" role="status">正在检查设备…</output>
<div class="oc-row"><button data-action="install">安装 / 更新连接组件</button><button data-action="start">启动</button><button data-action="stop">停止并恢复直连</button><button data-action="restart">重连</button><button data-action="diagnose">诊断</button><button data-action="boot">切换开机自启</button></div>
<p class="oc-note">适用于已安装 OpenVPN ARM64 二进制包的 UFI-TOOLS。先关闭旧插件的看门狗、自启并停止旧连接，再安装组件。本模式接管所选热点的全部外网 IPv4 流量，IPv6 外网被阻断；设备自身的 Android 应用保持原有网络。断线保护持续到点击“停止并恢复直连”。</p>
<div class="oc-row"><label>热点接口 <input data-id="lan" value="br0" spellcheck="false" aria-label="热点接口"></label><label>家庭 DNS <input data-id="dns" placeholder="如 192.168.50.2" spellcheck="false" aria-label="家庭 DNS"></label><button data-action="saveSettings">保存网络设置</button></div>
<div class="oc-row"><label>VPN 用户名 <input data-id="username" autocomplete="off"></label><label>VPN 密码 <input data-id="password" type="password" autocomplete="new-password"></label><button data-action="saveAuth">保存账号密码</button></div>
<div class="oc-grid"><div><div class="oc-row"><strong>配置导入</strong><button data-action="import">导入 .ovpn</button><button data-action="read">读取已保存配置</button><button data-action="save">校验并保存</button></div>
<input data-id="file" type="file" accept=".ovpn,.conf,text/plain" hidden>
<textarea data-id="profile" spellcheck="false" aria-label="OpenVPN 配置" placeholder="导入家庭路由器导出的 .ovpn（含内嵌证书），或粘贴配置。"></textarea>
<output data-id="preview" class="oc-note">导入后先显示检查结果，点击“校验并保存”写入设备。</output></div>
<div><div class="oc-row"><strong>连接日志</strong><button data-action="logs">刷新日志</button></div><textarea data-id="logs" readonly aria-label="连接日志"></textarea><p class="oc-note">“隧道已建立”表示本插件的 VPN 进程、接口和路由均存在，不代表已验证公网出口；连接后请用热点终端检查家庭出口。</p></div></div>
<output data-id="message" role="status" class="oc-note"></output>`;
anchor.after(panel);
const el = name => panel.querySelector(`[data-id="${name}"]`);
let busy = false, poll;
function message(text, error = false) {
  el('message').textContent = text;
  el('message').style.color = error ? '#e85c5c' : 'inherit';
  if (typeof createToast === 'function') createToast(text, error ? 'red' : 'green');
}
async function shell(command, timeout = 30000) {
  const marker = 'OC2_' + crypto.getRandomValues(new Uint32Array(2)).join('_');
  const result = unwrap(await runShellWithRoot(`( ${command}\n)\noc2_rc=$?\nprintf '\\n${marker}:%s\\n' "$oc2_rc"`, timeout));
  const match = result.match(new RegExp(`\\n${marker}:(\\d+)\\s*$`));
  if (!match) throw Error('未收到命令完成标记，请检查设备连接；不要把返回结果粘贴为配置');
  const body = result.slice(0, match.index).trim();
  if (match[1] !== '0') throw Error(body || `设备命令退出码 ${match[1]}`);
  return body;
}
async function putFile(name, content, mode = '600') {
  if (!/^[\w.-]+$/.test(name)) throw Error('无效文件名');
  if (typeof KANO_baseURL === 'undefined' || typeof common_headers === 'undefined') throw Error('当前 UFI-TOOLS 版本缺少文件上传接口');
  const form = new FormData();
  form.append('file', new File([content], name, {type:'text/plain'}));
  const response = await fetch(`${KANO_baseURL}/upload_img`, {method:'POST', headers:common_headers, body:form});
  if (!response.ok) throw Error(`上传失败 HTTP ${response.status}`);
  const result = await response.json();
  if (typeof result.url !== 'string' || !/^\/[\w./-]+$/.test(result.url) || result.url.split('/').includes('..')) throw Error('上传接口返回了无效文件路径');
  const source = '/data/data/com.minikano.f50_sms/files' + result.url;
  const destination = `${HOME}/${name}`;
  await shell(`umask 077\nmkdir -p ${quote(HOME)} && chmod 700 ${quote(HOME)} && cp ${quote(source)} ${quote(destination + '.tmp')} && chmod ${mode} ${quote(destination + '.tmp')} && mv -f ${quote(destination + '.tmp')} ${quote(destination)} && rm -f ${quote(source)}`);
}
async function stopped() {
  const result = await shell(`[ ! -f ${quote(HOME + '/wanted')} ] && [ ! -f ${quote(HOME + '/network.owned')} ] && echo STOPPED`);
  if (result !== 'STOPPED') throw Error('先停止连接，再更改配置');
}
async function installed() { await shell(`test -x ${quote(HOME + '/service.sh')}`); }
async function refresh() {
  const output = await shell(`if [ -x ${quote(HOME + '/service.sh')} ]; then ${quote(HOME + '/service.sh')} status; else echo NOT_INSTALLED; fi`);
  const labels = {CONNECTED:'隧道已建立', CONNECTING:'正在建立隧道', RETRYING:'正在连接 / 自动重试', ERROR:'连接失败，请查看日志并修复后重启', STOPPED:'已停止', NOT_INSTALLED:'连接组件尚未安装'};
  const [first, ...rest] = output.split('\n');
  el('status').textContent = (labels[first] || first) + (rest.length ? '\n' + rest.join('\n').replace('GUARD=ON','热点断线保护已开启') : '');
}
async function logs() {
  el('logs').value = await shell(`for f in error openvpn.log; do if [ -f ${quote(HOME)}/"$f" ]; then tail -n 65 ${quote(HOME)}/"$f"; fi; done`);
}
function preview() {
  const parsed = parseProfile(el('profile').value);
  el('preview').textContent = `服务器：${parsed.remotes.map(x=>x.host+':'+x.port).join('、')}\n账号密码：${parsed.auth?'需要另行保存':'配置未要求'}\n${parsed.warnings.join('；')}`;
  return parsed;
}
const actions = {
  async install() {
    await stopped();
    await shell(`[ "$(id -u)" = 0 ] && test -f ${quote(DIR+'/openvpn')} && test -f ${quote(DIR+'/ld-musl-aarch64.so.1')}`);
    // Isolated v2 directory: original service, certificates and wrapper stay intact.
    for (const [name, text] of Object.entries(ASSETS)) await putFile(name, text, name.endsWith('.sh')?'700':'600');
    await shell(`chmod 700 ${quote(DIR+'/openvpn')} ${quote(DIR+'/ld-musl-aarch64.so.1')}\nfor f in ${quote(HOME)}/*.sh; do /system/bin/sh -n "$f" || exit 1; done`);
    message('连接组件已安装。请保存网络设置，导入配置和账号，然后启动。');
  },
  async saveSettings() {
    await stopped();
    const value = settings({lan:el('lan').value,dns:el('dns').value});
    await putFile('settings',`${value.lan}\n${value.dns}\n`);
    message('网络设置已保存');
  },
  async saveAuth() {
    await stopped();
    const username = el('username').value, password = el('password').value;
    if (!username || !password || /[\r\n\0]/.test(username + password)) throw Error('用户名和密码不能为空，且不能包含换行');
    await putFile('pass.txt',`${username}\n${password}\n`);
    el('password').value = '';
    message('账号密码已保存（权限 600），密码输入框已清空');
  },
  import() { el('file').click(); },
  async read() { el('profile').value = await shell(`cat ${quote(HOME+'/source.ovpn')}`); preview(); message('已读取配置；内容含证书，请勿公开分享'); },
  async save() {
    const parsed = preview();
    await stopped();
    await shell(`if [ -f ${quote(HOME+'/profile.ovpn')} ]; then cp -p ${quote(HOME+'/profile.ovpn')} ${quote(HOME+'/profile.previous.ovpn')} || exit 1; fi`);
    await putFile('source.ovpn',el('profile').value);
    await putFile('profile.ovpn',parsed.text);
    message('配置校验通过并保存。服务器域名会在每次重连时通过 Android 系统重新解析。');
  },
  async start() { await installed(); const out = await shell(`${quote(HOME+'/service.sh')} start`); message(out === 'ALREADY_RUNNING'?'连接服务已经运行':'连接请求已提交，等待证书验证和隧道建立'); },
  async stop() { await installed(); await shell(`${quote(HOME+'/service.sh')} stop`,60000); message('已停止并撤销本插件的网络规则，热点恢复原有网络'); },
  async restart() { await installed(); await shell(`${quote(HOME+'/service.sh')} restart`,60000); message('已请求重新连接'); },
  async diagnose() { await installed(); el('logs').value = await shell(`${quote(HOME+'/service.sh')} diagnose`); message('诊断已显示；分享前请隐藏地址等个人信息'); },
  logs,
  async boot() {
    await installed();
    const boot = '/sdcard/ufi_tools_boot.sh', line = `${HOME}/service.sh boot &`;
    const out = await shell(`umask 077\nif [ -f ${quote(boot)} ]; then cp -p ${quote(boot)} ${quote(HOME+'/boot.previous.sh')} || exit 1; else printf '#!/system/bin/sh\\n' > ${quote(boot)}; fi\nif grep -qxF ${quote(line)} ${quote(boot)}; then awk -v line=${quote(line)} '$0 != line' ${quote(boot)} > ${quote(boot+'.oc2.tmp')} && cat ${quote(boot+'.oc2.tmp')} > ${quote(boot)} && rm -f ${quote(boot+'.oc2.tmp')} && echo OFF; else printf '\\n%s\\n' ${quote(line)} >> ${quote(boot)} && echo ON; fi`);
    message(out === 'ON'?'开机自启已开启':'开机自启已关闭');
  }
};
async function run(action) {
  if (busy) return;
  busy = true;
  panel.querySelectorAll('button').forEach(b=>b.disabled=true);
  try { await action(); await refresh(); }
  catch (error) { message(error.message, true); }
  finally { busy=false; panel.querySelectorAll('button').forEach(b=>b.disabled=false); }
}
panel.querySelectorAll('[data-action]').forEach(button=>button.addEventListener('click',()=>run(actions[button.dataset.action])));
el('file').addEventListener('change',()=>run(async()=>{
  const file = el('file').files[0]; el('file').value='';
  if (!file) return;
  if (!/\.(ovpn|conf)$/i.test(file.name) || file.size > 1024*1024) throw Error('请选择 1 MiB 以内的 .ovpn 或 .conf 文件');
  const text = await file.text();
  parseProfile(text); el('profile').value=text; preview(); message('已导入并通过检查；点击“校验并保存”写入设备');
}));
try {
  const stored = await shell(`if [ -f ${quote(HOME+'/settings')} ]; then cat ${quote(HOME+'/settings')}; fi`);
  if (stored) { const [lan,dns] = stored.split('\n'); const parsed = settings({lan,dns}); el('lan').value=parsed.lan; el('dns').value=parsed.dns; }
  await refresh();
} catch (error) { message(error.message,true); }
poll = setInterval(async()=>{
  if (!panel.isConnected) { clearInterval(poll); return; }
  if (busy || document.hidden) return;
  busy=true;
  try { await refresh(); } catch (error) { el('status').textContent='状态读取失败：'+error.message; }
  finally { busy=false; }
},5000);

})().catch(error => { console.error('[OpenVPN]', error.message); if (typeof createToast === 'function') createToast(error.message, 'red'); });
//</script>
