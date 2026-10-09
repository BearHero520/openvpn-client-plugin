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
