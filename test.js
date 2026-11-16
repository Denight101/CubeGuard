'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const {once} = require('node:events');
const {createGuard, publicIPv4, matches, parseTarget, validatePolicy} = require('./cube');
const original = require('./policy.json');
const token = 'test-only-secret-'.repeat(3);
const auth = Buffer.from('cube:' + token).toString('base64');

async function fixture(t, overrides = {}, options = {}) {
  const events = [];
  const guard = createGuard({...original, ...overrides}, token, {
    resolve: async () => ['93.184.215.14'], audit: e => events.push(e), ...options
  });
  guard.server.listen(0, '127.0.0.1');
  await once(guard.server, 'listening');
  t.after(() => guard.close());
  return {port: guard.server.address().port, events};
}
function request(port, target = 'example.com:443', credential = auth, head = '') {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1');
    const chunks = [];
    socket.setTimeout(3000, () => socket.destroy(Error('test timeout')));
    socket.on('error', reject);
    socket.on('data', x => chunks.push(x));
    socket.on('end', () => resolve(Buffer.concat(chunks).toString()));
    socket.on('close', () => resolve(Buffer.concat(chunks).toString()));
    socket.on('connect', () => socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\nProxy-Authorization: Basic ${credential}\r\n\r\n${head}`));
  });
}
test('address containment rejects private/reserved/IPv6 addresses', () => {
  for (const ip of ['127.0.0.1', '10.2.3.4', '172.20.1.1', '192.168.1.1', '169.254.169.254',
    '100.64.0.1', '198.18.0.1', '192.0.0.9', '192.0.2.1', '198.51.100.1', '203.0.113.1', '224.0.0.1', '::1']) {
    assert.equal(publicIPv4(ip), false, ip);
  }
  assert.equal(publicIPv4('8.8.8.8'), true);
});
test('wildcards respect label boundaries and targets are strict', () => {
  assert.equal(matches('a.example.com', '*.example.com'), true);
  assert.equal(matches('evilexample.com', '*.example.com'), false);
  assert.equal(matches('example.com', '*.example.com'), false);
  for (const x of ['example.com:0', 'example.com:65536', 'user@example.com:443', '[::1]:443', 'example.com:443/path']) {
    assert.throws(() => parseTarget(x));
  }
  assert.throws(() => validatePolicy({...original, maxConcurrent: 0}));
});
test('authentication required and credentials are absent from logs', async t => {
  const f = await fixture(t);
  assert.match(await request(f.port, undefined, 'wrong'), /^HTTP\/1.1 407/);
  assert.equal(JSON.stringify(f.events).includes(token), false);
});
test('review reports an allowed destination but never connects', async t => {
  const f = await fixture(t, {}, {connect: () => { throw Error('must not connect'); }});
  assert.match(await request(f.port), /^HTTP\/1.1 503/);
  assert.equal(f.events[0].decision, 'would_allow');
});
test('domain, port and explicit block rules deny', async t => {
  const f = await fixture(t, {blockedDomains: ['blocked.example.com']});
  for (const x of ['evil.com:443', 'example.com:80', 'blocked.example.com:443']) {
    assert.match(await request(f.port, x), /^HTTP\/1.1 403/);
  }
});
test('mixed DNS answers fail closed before connection', async t => {
  const f = await fixture(t, {mode: 'enforce'}, {
    resolve: async () => ['8.8.8.8', '127.0.0.1'], connect: () => { throw Error('must not connect'); }
  });
  assert.match(await request(f.port), /^HTTP\/1.1 403/);
  assert.equal(f.events[0].face, 'containment');
});
test('rate budget applies to repeated attempts', async t => {
  const f = await fixture(t, {maxConnectionsPerMinute: 1});
  assert.match(await request(f.port), /^HTTP\/1.1 503/);
  assert.match(await request(f.port), /^HTTP\/1.1 429/);
});
test('DNS failure returns a closed failure', async t => {
  const f = await fixture(t, {}, {resolve: async () => { throw Error('DNS failed'); }});
  assert.match(await request(f.port), /^HTTP\/1.1 502/);
});
test('enforcement pins DNS and relays data without forwarding credentials', async t => {
  let received = '';
  const echo = net.createServer(s => s.on('data', x => { received += x; s.end('world'); }));
  echo.listen(0, '127.0.0.1');
  await once(echo, 'listening');
  t.after(() => echo.close());
  let pinned;
  const f = await fixture(t, {mode: 'enforce'}, {connect: target => {
    pinned = target; return net.connect(echo.address().port, '127.0.0.1');
  }});
  const response = await request(f.port, undefined, auth, 'hello');
  assert.match(response, /^HTTP\/1.1 200/);
  assert.match(response, /world/);
  assert.deepEqual(pinned, {host: '93.184.215.14', port: 443});
  assert.equal(received, 'hello');
});
test('over-budget initial data is never forwarded', async t => {
  let received = '';
  const echo = net.createServer(s => s.on('data', x => { received += x; }));
  echo.listen(0, '127.0.0.1');
  await once(echo, 'listening');
  t.after(() => echo.close());
  const f = await fixture(t, {mode: 'enforce', maxBytesPerSession: 4}, {
    connect: () => net.connect(echo.address().port, '127.0.0.1')
  });
  await request(f.port, undefined, auth, 'too much data');
  assert.equal(received, '');
  assert.ok(f.events.some(x => x.reason === 'data_limit'));
});
test('later payload chunks cannot cross the session data budget', async t => {
  let received = '';
  const echo = net.createServer(s => s.on('data', x => { received += x; }));
  echo.listen(0, '127.0.0.1');
  await once(echo, 'listening');
  t.after(() => echo.close());
  const f = await fixture(t, {mode: 'enforce', maxBytesPerSession: 4}, {
    connect: () => net.connect(echo.address().port, '127.0.0.1')
  });
  const client = net.connect(f.port, '127.0.0.1');
  client.on('error', () => {});
  client.setTimeout(3000, () => client.destroy());
  await once(client, 'connect');
  client.write(`CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic ${auth}\r\n\r\n`);
  const [headers] = await once(client, 'data');
  assert.match(headers.toString(), /^HTTP\/1.1 200/);
  client.write('exceeds budget');
  await once(client, 'close');
  assert.equal(received, '');
  assert.ok(f.events.some(x => x.reason === 'data_limit'));
});
test('pending DNS holds a concurrency slot and releases it on failure', async t => {
  let rejectDNS;
  const f = await fixture(t, {maxConcurrent: 1}, {
    resolve: () => new Promise((_, reject) => { rejectDNS = reject; })
  });
  const first = request(f.port);
  // Wait for the first request to reach its injected DNS resolver.
  while (!rejectDNS) await new Promise(resolve => setImmediate(resolve));
  assert.match(await request(f.port), /^HTTP\/1.1 429/);
  rejectDNS(Error('test failure'));
  assert.match(await first, /^HTTP\/1.1 502/);
});
