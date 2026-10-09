import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {JSDOM} from 'jsdom';
const code=readFileSync('dist/OpenVPN客户端插件.js','utf8');
const fixture='client\ndev tun\nremote vpn.example.invalid 1194\n<ca>\nTEST-ONLY\n</ca>\n';
const tick=()=>new Promise(resolve=>setTimeout(resolve,30));
async function setup({failSave=false}={}) {
  const dom=new JSDOM('<main class="functions-container"></main>',{runScripts:'outside-only',url:'http://device.example.invalid/'});
  const w=dom.window, uploads=[], commands=[];
  w.TextEncoder=TextEncoder;
  w.KANO_baseURL='http://device.example.invalid'; w.common_headers={}; w.createToast=()=>{};
  w.runShellWithRoot=async command=>{
    commands.push(command);
    const marker=command.match(/OC2_\d+_\d+/)[0];
    const body=command.includes('service.sh\x27 status')?'STOPPED':command.includes('echo STOPPED')?'STOPPED':'';
    const rc=failSave && command.includes('mv -f') ? 1 : 0;
    return {success:true,content:JSON.stringify({success:true,content:`${body}\n${marker}:${rc}\n`})};
  };
  w.fetch=async(url,options)=>{
    const file=options.body.get('file'); uploads.push(file);
    return {ok:true,json:async()=>({url:'/uploads/'+file.name})};
  };
  w.eval(code); await tick();
  const el=name=>w.document.querySelector(`[data-id="${name}"]`);
  const click=async name=>{w.document.querySelector(`[data-action="${name}"]`).click();await tick();};
  return {dom,w,el,click,uploads,commands};
}
test('file import previews without writing; save writes original plus managed config',async()=>{
  const x=await setup();
  try {
    Object.defineProperty(x.el('file'),'files',{value:[{name:'home.ovpn',size:fixture.length,text:async()=>fixture}]});
    x.el('file').dispatchEvent(new x.w.Event('change')); await tick();
    assert.equal(x.el('profile').value,fixture);
    assert.match(x.el('preview').textContent,/vpn.example.invalid:1194/);
    assert.equal(x.uploads.length,0);
    await x.click('save');
    assert.deepEqual(x.uploads.map(f=>f.name),['source.ovpn','profile.ovpn']);
    assert.match(x.el('message').textContent,/配置校验通过并保存/);
    assert.ok(x.commands.some(c=>c.includes('chmod 600')));
  } finally { x.dom.window.close(); }
});
test('invalid import preserves current editor and never uploads',async()=>{
  const x=await setup();
  try {
    x.el('profile').value=fixture;
    Object.defineProperty(x.el('file'),'files',{value:[{name:'bad.ovpn',size:5,text:async()=>'bad data'}]});
    x.el('file').dispatchEvent(new x.w.Event('change')); await tick();
    assert.equal(x.el('profile').value,fixture); assert.equal(x.uploads.length,0);
    assert.match(x.el('message').textContent,/不支持/);
  } finally { x.dom.window.close(); }
});
test('backend file failure cannot display successful save',async()=>{
  const x=await setup({failSave:true});
  try {
    x.el('profile').value=fixture; await x.click('save');
    assert.match(x.el('message').textContent,/退出码 1/);
    assert.equal(x.uploads.length,1);
  } finally { x.dom.window.close(); }
});
test('credentials never load automatically; saving clears password',async()=>{
  const x=await setup();
  try {
    assert.ok(!x.commands.some(c=>c.includes('pass.txt')));
    x.el('username').value='test-user';x.el('password').value="synthetic'$(literal)";
    await x.click('saveAuth');
    assert.equal(x.el('password').value,'');
    assert.deepEqual(x.uploads.map(f=>f.name),['pass.txt']);
  } finally { x.dom.window.close(); }
});
