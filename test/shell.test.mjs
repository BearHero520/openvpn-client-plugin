import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, mkdtempSync, writeFileSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
const bash = process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : 'bash';
for (const name of ['network','route','down','service']) test(`${name}.sh POSIX shell syntax`,()=>{
  const result=spawnSync(bash,['-n',`src/${name}.sh`],{encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);
});
test('native DNS leaves literal IPv4 and inline blocks untouched',()=>{
  const config='remote 203.0.113.10 1194\n<key>\nremote secret.example 443\n</key>\n';
  const result=spawnSync(bash,['-c','awk -f src/resolve.awk'],{input:config,encoding:'utf8'});
  assert.equal(result.status,0,result.stderr); assert.equal(result.stdout,config);
});
test('native DNS resolves every host; failed lookup invalidates runtime',()=>{
  const dir=mkdtempSync(join(tmpdir(),'oc2-'));
  try {
    const resolver=readFileSync('src/resolve.awk','utf8').replace('/system/bin/ping','printf');
    // printf arguments emulate Android ping's first line, even with no ICMP reply.
    const mocked=resolver.replace(' -c 1 -W 1 ', " 'PING %s (203.0.113.8) 56 bytes\\n' ");
    writeFileSync(join(dir,'resolve.awk'),mocked);
    const path=join(dir,'resolve.awk').replaceAll('\\','/');
    const result=spawnSync(bash,['-c',`awk -f '${path}'`],{input:'remote home.example 443 tcp-client\nremote other.example 1194\n',encoding:'utf8'});
    assert.equal(result.status,0,result.stderr);
    assert.equal(result.stdout,'remote 203.0.113.8 443 tcp-client\nremote 203.0.113.8 1194\n');
    const fail=spawnSync(bash,['-c','awk -f src/resolve.awk'],{input:'remote missing.example.invalid 1194\n',encoding:'utf8'});
    assert.equal(fail.status,1);
  } finally { rmSync(dir,{recursive:true,force:true}); }
});
test('service scripts never parse PUSH_REPLY or match every musl process',()=>{
  const text=readFileSync('src/service.sh','utf8')+readFileSync('src/network.sh','utf8');
  assert.doesNotMatch(text,/PUSH_REPLY|killall|pkill|iptables -F\s*(\n|$)/);
  assert.match(text,/grep -qxF "\$D\/openvpn"/);
  assert.match(text,/grep -qxF "\$H\/runtime.ovpn"/);
});
