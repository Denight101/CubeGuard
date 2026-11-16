'use strict';
// No dependencies. This is an explicit CONNECT proxy, not a WFP driver.
const http = require('node:http');
const net = require('node:net');
const dns = require('node:dns').promises;
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const {Transform} = require('node:stream');

function matches(host, pattern) {
  return pattern.startsWith('*.')
    ? host.endsWith(pattern.slice(1)) && host !== pattern.slice(2)
    : host === pattern;
}

// IPv4-only by design. Deny local, reserved, multicast, and transition ranges.
function publicIPv4(ip) {
  if (net.isIP(ip) !== 4) return false;
  const [a, b, c] = ip.split('.').map(Number);
  return !(a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && (b === 168 || b === 0 || (b === 88 && c === 99) || (b === 2 && c === 0))) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
    (a === 203 && b === 0 && c === 113));
}

function validatePolicy(p) {
  if (!p || !['review', 'enforce'].includes(p.mode)) throw Error('mode must be review or enforce');
  for (const key of ['listenPort', 'maxConcurrent', 'maxConnectionsPerMinute',
    'maxSessionSeconds', 'idleTimeoutSeconds', 'maxBytesPerSession', 'maxHeaderBytes', 'maxAuditBytes']) {
    if (!Number.isSafeInteger(p[key]) || p[key] < 1) throw Error('Invalid ' + key);
  }
  if (p.listenPort > 65535 || p.maxHeaderBytes > 65536) throw Error('Invalid port or header size');
  for (const key of ['allowedDomains', 'blockedDomains']) {
    if (!Array.isArray(p[key]) || p[key].some(x => typeof x !== 'string' ||
      x !== x.toLowerCase() || !/^(\*\.)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(x))) {
      throw Error('Invalid ' + key);
    }
  }
  if (!Array.isArray(p.allowedPorts) || p.allowedPorts.some(x => !Number.isInteger(x) || x < 1 || x > 65535)) {
    throw Error('Invalid allowedPorts');
  }
  return p;
}

function authorized(header, token) {
  if (typeof header !== 'string' || !header.startsWith('Basic ')) return false;
  const expected = Buffer.from('cube:' + token);
  const supplied = Buffer.from(header.slice(6), 'base64');
  return expected.length === supplied.length && crypto.timingSafeEqual(expected, supplied);
}

function parseTarget(value) {
  // No IPv6 literals, paths, userinfo, percent escapes, or ambiguous ports.
  const m = /^([a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?):([0-9]{1,5})$/.exec(value || '');
  if (!m || +m[2] < 1 || +m[2] > 65535) throw Error('invalid_target');
  const host = m[1].toLowerCase();
  if (host.length > 253 || host.split('.').some(x => !x || x.length > 63 || x.startsWith('-') || x.endsWith('-'))) {
    throw Error('invalid_target');
  }
  return {host, port: +m[2]};
}

function createGuard(policy, token, options = {}) {
  validatePolicy(policy);
  if (typeof token !== 'string' || Buffer.byteLength(token) < 32 || /[:\r\n]/.test(token)) {
    throw Error('CUBE_TOKEN must contain at least 32 bytes and no colon/newlines');
  }
  const resolve = options.resolve || (host => dns.resolve4(host));
  const connect = options.connect || (target => net.connect(target));
  const audit = options.audit || (() => {});
  const now = options.now || Date.now;
  let active = 0;
  let attempts = [];
  const sockets = new Set();
  function log(event) { audit({time: new Date().toISOString(), ...event}); }
  function reply(socket, code, reason, auth = false) {
    if (socket.destroyed) return;
    socket.end(`HTTP/1.1 ${code} ${reason}\r\nConnection: close\r\n${auth ? 'Proxy-Authenticate: Basic realm="CubeGuard"\r\n' : ''}Content-Length: 0\r\n\r\n`);
  }
  const server = http.createServer({maxHeaderSize: policy.maxHeaderBytes}, (req, res) => {
    res.writeHead(405, {'Connection': 'close'}).end('CONNECT only\n');
  });
  server.headersTimeout = 10000;
  server.requestTimeout = 10000;
  server.maxConnections = policy.maxConcurrent + 8;
  server.on('connection', socket => {
    sockets.add(socket);
    socket.setTimeout(10000, () => socket.destroy());
    socket.on('error', () => {});
    socket.on('close', () => sockets.delete(socket));
  });
  server.on('clientError', (_err, socket) => reply(socket, 400, 'Bad Request'));
  server.on('connect', async (req, client, head) => {
    const id = crypto.randomUUID();
    let target;
    try {
      // Face 1: local endpoint boundary (not hardware device attestation).
      if (client.remoteAddress !== '127.0.0.1') {
        log({id, decision: 'deny', face: 'device', reason: 'non_loopback'});
        return reply(client, 403, 'Forbidden');
      }
      // Face 2: connection behavior. Global budget also bounds bad-token attempts.
      const timestamp = now();
      attempts = attempts.filter(t => timestamp - t < 60000);
      if (attempts.length >= policy.maxConnectionsPerMinute) {
        log({id, decision: 'deny', face: 'behavior', reason: 'rate_limit'});
        return reply(client, 429, 'Too Many Requests');
      }
      attempts.push(timestamp);
      // Face 3: identity. Credentials never enter the audit log or upstream tunnel.
      if (!authorized(req.headers['proxy-authorization'], token)) {
        log({id, decision: 'deny', face: 'identity', reason: 'invalid_credentials'});
        return reply(client, 407, 'Proxy Authentication Required', true);
      }
      target = parseTarget(req.url);
      const base = {id, ...target};
      // Face 4: traffic rules; blocks always override allows.
      if (!policy.allowedPorts.includes(target.port) ||
        policy.blockedDomains.some(p => matches(target.host, p)) ||
        !policy.allowedDomains.some(p => matches(target.host, p))) {
        log({...base, decision: 'deny', face: 'traffic', reason: 'destination_policy'});
        return reply(client, 403, 'Forbidden');
      }
      if (active >= policy.maxConcurrent) {
        log({...base, decision: 'deny', face: 'behavior', reason: 'concurrency_limit'});
        return reply(client, 429, 'Too Many Requests');
      }
      active++;
      let released = false;
      function release() { if (!released) { active--; released = true; } }
      client.once('close', release);
      let upstream;
      let timer;
      try {
        // Face 5: containment. Resolve once, validate ALL answers, then pin one.
        // This prevents a second DNS lookup from changing the address at connect.
        let dnsTimer;
        let addresses;
        try {
          addresses = await Promise.race([resolve(target.host), new Promise((_, reject) => {
            dnsTimer = setTimeout(() => reject(Error('dns_timeout')), 5000);
          })]);
        } finally { clearTimeout(dnsTimer); }
        if (client.destroyed) return;
        if (!addresses.length || !addresses.every(publicIPv4)) {
          log({...base, decision: 'deny', face: 'containment', reason: 'non_public_address'});
          return reply(client, 403, 'Forbidden');
        }
        if (policy.mode === 'review') {
          log({...base, decision: 'would_allow', reason: 'review_no_forwarding'});
          return reply(client, 503, 'Review Mode - No Forwarding');
        }
        upstream = connect({host: addresses[0], port: target.port});
        let connected = false;
        let bytes = 0;
        let finished = false;
        function finish(reason, status) {
          if (finished) return;
          finished = true;
          clearTimeout(timer);
          if (status) reply(client, status, 'Bad Gateway');
          else client.destroy();
          upstream.destroy();
          release();
          log({...base, decision: 'closed', reason, bytes});
        }
        // Face 6: data budget, bidirectional; includes CONNECT's initial bytes.
        // Encrypted content is not decrypted or scanned.
        function count(chunk) {
          bytes += chunk.length;
          if (bytes > policy.maxBytesPerSession) { finish('data_limit'); return false; }
          return true;
        }
        upstream.setTimeout(5000, () => finish(connected ? 'idle_timeout' : 'connect_timeout'));
        client.setTimeout(policy.idleTimeoutSeconds * 1000, () => finish('idle_timeout'));
        timer = setTimeout(() => finish('session_timeout'), policy.maxSessionSeconds * 1000);
        client.once('close', () => finish('client_closed'));
        upstream.once('close', () => finish('upstream_closed'));
        upstream.once('error', () => {
          finish('upstream_error', connected ? undefined : 502);
        });
        upstream.once('connect', () => {
          if (client.destroyed) return finish('client_closed');
          connected = true;
          upstream.setTimeout(policy.idleTimeoutSeconds * 1000);
          if (!count(head)) return;
          log({...base, decision: 'allow', ip: addresses[0]});
          client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
          if (head.length) upstream.write(head);
          // A chunk over budget never enters the opposite socket.
          function meter() {
            return new Transform({transform(chunk, _encoding, callback) {
              callback(null, count(chunk) ? chunk : undefined);
            }});
          }
          client.pipe(meter()).pipe(upstream);
          upstream.pipe(meter()).pipe(client);
        });
      } catch (_err) {
        log({...base, decision: 'deny', face: 'containment', reason: 'resolution_or_connection_failed'});
        reply(client, 502, 'Bad Gateway');
      } finally {
        // Live tunnels own their slot until close; all preflight paths release.
        if (!upstream) release();
      }
    } catch (_err) {
      log({id, decision: 'deny', face: 'traffic', reason: 'invalid_request'});
      reply(client, 400, 'Bad Request');
    }
  });
  return {server, close() { for (const s of sockets) s.destroy(); server.close(); }};
}

function fileAudit(filename, maxBytes) {
  let size = fs.existsSync(filename) ? fs.statSync(filename).size : 0;
  return event => {
    const line = JSON.stringify(event) + '\n';
    if (size + Buffer.byteLength(line) > maxBytes) {
      const backup = filename + '.1';
      if (fs.existsSync(backup)) fs.unlinkSync(backup);
      if (fs.existsSync(filename)) fs.renameSync(filename, backup);
      size = 0;
    }
    fs.appendFileSync(filename, line, {mode: 0o600});
    size += Buffer.byteLength(line);
  };
}

if (require.main === module) {
  try {
    const policy = validatePolicy(JSON.parse(fs.readFileSync(path.join(__dirname, 'policy.json'), 'utf8')));
    const audit = fileAudit(path.join(__dirname, 'audit.jsonl'), policy.maxAuditBytes);
    const guard = createGuard(policy, process.env.CUBE_TOKEN, {audit});
    guard.server.on('error', err => { console.error(err.message); process.exitCode = 1; });
    guard.server.listen(policy.listenPort, '127.0.0.1', () => {
      console.log(`CubeGuard: 127.0.0.1:${policy.listenPort}, mode=${policy.mode}`);
      console.log('Only explicitly proxied CONNECT traffic is covered. Ctrl+C stops the proxy.');
    });
    process.on('SIGINT', () => guard.close());
    process.on('SIGTERM', () => guard.close());
  } catch (err) { console.error(err.message); process.exitCode = 1; }
}
module.exports = {createGuard, matches, publicIPv4, authorized, parseTarget, validatePolicy};
