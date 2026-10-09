import test from 'node:test';
import assert from 'node:assert/strict';
import {parseProfile, settings, quote, unwrap, tokens, HOME} from '../src/core.mjs';
export const fixture = 'client\ndev tun\nproto udp\nremote vpn.example.invalid 1194\nremote-cert-tls server\n<ca>\nSYNTHETIC-TEST-CA-NOT-A-CERTIFICATE\n</ca>\n';
test('ASUS inline profile, BOM/CRLF, auth and full-tunnel management',()=>{
  const profile = parseProfile('\uFEFF'+(fixture+'auth-user-pass\nredirect-gateway def1\nblock-outside-dns\n').replaceAll('\n','\r\n'));
  assert.equal(profile.auth,true);
  assert.deepEqual(profile.remotes,[{host:'vpn.example.invalid',port:1194}]);
  assert.match(profile.text,new RegExp(`auth-user-pass ${HOME}/pass.txt`));
  assert.match(profile.text,/dev ovpnc0/);
  assert.match(profile.text,/route-up .*\/route.sh/);
  assert.doesNotMatch(profile.text,/^redirect-gateway|^block-outside-dns|\r/gm);
  assert.equal(profile.warnings.length,2);
});
test('multiple remotes preserved and normalized for native DNS',()=>{
  const p = parseProfile(fixture+'--remote "backup.example.invalid" 443 tcp-client\n');
  assert.equal(p.remotes.length,2);
  assert.match(p.text,/remote backup.example.invalid 443 tcp-client/);
});
test('inline key content is preserved without treating it as options',()=>{
  const p=parseProfile(fixture+'<cert>\nfake-cert\n</cert>\n<key>\nremote PRIVATE-KEY-CONTENT\n</key>\n');
  assert.match(p.text,/<key>\nremote PRIVATE-KEY-CONTENT\n<\/key>/);
  assert.equal(p.remotes.length,1);
});
for (const bad of ['up /tmp/pwn.sh','plugin evil.so','config /etc/private','management 0.0.0.0 1234','iproute /tmp/cmd','log /tmp/overwrite','setenv PATH /tmp','tls-verify /tmp/pwn','ca /tmp/ca.pem','remote evil;touch 1194','remote bad.example 65536','proto udp6','dev tap','allow-compression yes','compress lz4','auth-user-pass-verify /tmp/pwn via-env']) {
  test(`reject unsafe or unsupported directive: ${bad}`,()=>assert.throws(()=>parseProfile(fixture+bad+'\n')));
}
test('malformed data and backend responses never become profiles',()=>{
  for (const value of ['{"success":true,"content":"client"}',fixture+'\0','remote x 1',fixture+'<key>\nx',fixture+'<ca>\nx\n</ca>',fixture+'<connection>\nremote x\n</connection>', 'x'.repeat(1024*1024+1)]) assert.throws(()=>parseProfile(value));
});
test('cert pair and encrypted key require clear import error',()=>{
  assert.throws(()=>parseProfile(fixture+'<cert>\nx\n</cert>'));
  assert.throws(()=>parseProfile(fixture+'<cert>\nx\n</cert>\n<key>\nENCRYPTED PRIVATE KEY\n</key>'));
});
test('missing server purpose check is added',()=>assert.match(parseProfile(fixture.replace('remote-cert-tls server\n','')).text,/remote-cert-tls server/));
test('settings reject shell injection and cellular/VPN interfaces',()=>{
  assert.deepEqual(settings({lan:'br0',dns:'192.168.50.2'}),{lan:'br0',dns:'192.168.50.2'});
  for (const lan of ['br0; reboot','wg0','sipa_eth8','rmnet_data0','tun0']) assert.throws(()=>settings({lan,dns:'1.1.1.1'}));
  for (const dns of ['999.1.1.1','1.1.1.1;id','example.com','127.0.0.1']) assert.throws(()=>settings({lan:'br0',dns}));
});
test('shell quoting preserves literal apostrophes and command substitutions',()=>assert.equal(quote("a'$(id)"),"'a'\\''$(id)'"));
test('JSON envelope unwrap and failure handling',()=>{
  assert.equal(unwrap({success:true,content:JSON.stringify({success:true,content:'CONNECTED'})}),'CONNECTED');
  assert.throws(()=>unwrap({success:true,content:'{"success":false,"content":"error"}'}));
  assert.throws(()=>unwrap({success:true,content:{data:1}}));
});
test('tokenizer handles quoted names, comments and rejects unclosed quotes',()=>{
  assert.deepEqual(tokens('verify-x509-name "Home VPN" name # note'),['verify-x509-name','Home VPN','name']);
  assert.throws(()=>tokens('remote "oops'));
});
