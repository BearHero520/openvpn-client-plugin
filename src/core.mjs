export const DIR = '/data/kano_openvpn';
export const HOME = `${DIR}/client-v2`;
export function quote(value) { return "'" + String(value).replaceAll("'", "'\\''") + "'"; }
export function ipv4(value) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(value) && value.split('.').every(x => Number(x) <= 255);
}
export function settings(input) {
  const lan = input.lan.trim(), dns = input.dns.trim();
  if (!/^[a-zA-Z][\w.-]{0,14}$/.test(lan) || /^(lo|tun\d*|wg\d*|rmnet.*|sipa.*|ccmni.*)$/.test(lan)) throw Error('请选择热点 LAN 接口（通常 br0），不能选择蜂窝或 VPN 接口');
  if (!ipv4(dns) || /^(0\.|127\.|224\.|255\.)/.test(dns)) throw Error('填写家庭网络可达的 IPv4 DNS，例如家庭路由器 LAN 地址');
  return {lan, dns};
}
const allowed = new Set(('client tls-client proto remote remote-random nobind float resolv-retry connect-retry connect-retry-max connect-timeout server-poll-timeout sndbuf rcvbuf tun-mtu mssfix fragment auth cipher data-ciphers data-ciphers-fallback remote-cert-tls verify-x509-name peer-fingerprint tls-version-min tls-version-max tls-cipher tls-ciphersuites key-direction reneg-sec reneg-bytes reneg-pkts auth-nocache auth-retry explicit-exit-notify fast-io mute mute-replay-warnings ping ping-restart ping-exit keepalive route route-ipv6 route-metric route-delay route-gateway dhcp-option hand-window tran-window allow-compression compress comp-lzo').split(' '));
const managed = new Set(('dev dev-type persist-tun persist-key script-security route-noexec route-nopull redirect-gateway redirect-private verb block-outside-dns register-dns windows-driver ignore-unknown-option').split(' '));
const blocks = new Set(['ca', 'cert', 'key', 'tls-auth', 'tls-crypt', 'tls-crypt-v2', 'peer-fingerprint']);
// Strict tokenizer: no shell evaluation; quoted CN values remain valid OpenVPN syntax.
export function tokens(line) {
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
export function parseProfile(raw) {
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
export function unwrap(result) {
  if (!result || result.success === false) throw Error('设备命令失败，请检查高级功能和 root 权限');
  let content = result.content;
  // Some UFI-TOOLS releases wrap command results once more as JSON.
  if (typeof content === 'string' && /^\s*\{/.test(content)) {
    try { const inner = JSON.parse(content); if ('content' in inner || 'success' in inner) return unwrap(inner); } catch (e) { if (!(e instanceof SyntaxError)) throw e; }
  }
  if (typeof content !== 'string') throw Error('设备返回了非文本结果');
  return content;
}
