import assert from 'node:assert/strict';
import { test } from 'node:test';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import { readFileSync, statSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import tls from 'node:tls';
import { setTimeout as delay } from 'node:timers/promises';
import Ajv2020 from 'ajv/dist/2020.js';
import { fixture, hostCertificate, encryptedEcho } from './helpers.mjs';

const require = createRequire(import.meta.url);
const schema = JSON.parse(readFileSync(require.resolve('@cowork/protocol/relay/control')));
const validate = new Ajv2020({ strict: true }).compile(schema);
const waitClosed = socket => new Promise(resolve => { if (socket.destroyed) resolve(); else socket.once('close', resolve); });

test('vendored contract bytes match the pinned upstream package', () => {
  assert.deepEqual(readFileSync('vendor/relay/control.schema.json'), readFileSync(require.resolve('@cowork/protocol/relay/control')));
  for (const [path, digest] of Object.entries(JSON.parse(readFileSync('vendor/digests.json')))) {
    assert.equal(createHash('sha256').update(readFileSync(path)).digest('hex'), digest);
  }
});

test('verified outer TLS, strict routing and private administration', { timeout: 40_000 }, async t => {
  const f = await fixture(); t.after(f.cleanup);
  assert.equal(statSync(join(f.state, 'admin.sock')).mode & 0o777, 0o600);
  assert.equal(statSync(join(f.state, 'ca-key.pem')).mode & 0o777, 0o600);
  await assert.rejects(f.connect({ ca: undefined }));
  await assert.rejects(f.connect({ servername: 'wrong.invalid' }));
  await assert.rejects(f.connect({ minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' }));
  for (const text of [
    `GET /health/live HTTP/1.1\r\nHost: wrong.invalid\r\n\r\n`,
    `GET /health/live HTTP/1.1\r\nHost: 127.0.0.1:${f.port}\r\nOrigin: https://evil.invalid\r\n\r\n`,
    `GET /admin/devices HTTP/1.1\r\nHost: 127.0.0.1:${f.port}\r\n\r\n`,
    `GET /health/live?token=forbidden HTTP/1.1\r\nHost: 127.0.0.1:${f.port}\r\n\r\n`,
    `CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n`,
    `CONNECT 127.0.0.1:22 HTTP/1.1\r\nHost: 127.0.0.1:22\r\n\r\n`,
    `GET /health/live HTTP/1.1\r\nHost: 127.0.0.1:${f.port}\r\nContent-Length: 1\r\n\r\nx`,
  ]) {
    const response = await f.request(text); assert.notEqual(response.status, 200); response.socket.destroy();
  }
  assert.equal(f.cli('status').protocol, 'cowork.relay/1');
  assert.match(f.human('--lang', 'en', 'status'), /^Operation completed\n/);
  assert.match(f.human('--lang', 'zh-CN', 'status'), /^操作完成\n/);
  const duplicate = await f.request(`GET /health/live HTTP/1.1\r\nHost: 127.0.0.1:${f.port}\r\nHost: wrong.invalid\r\n\r\n`);
  assert.notEqual(duplicate.status, 200); duplicate.socket.destroy();
});

test('several computers and phones retain independent authenticated end-to-end TLS', { timeout: 60_000 }, async t => {
  const f = await fixture(); t.after(f.cleanup);
  const a = f.enroll('host', 'a'); const b = f.enroll('host', 'b');
  const c = f.enroll('client', 'a', a.device.id); const d = f.enroll('client', 'a', a.device.id);
  const e = f.enroll('client', 'b', b.device.id);
  const controlA = await f.control(a); const controlB = await f.control(b);
  assert.equal(validate(controlA.ready), true, JSON.stringify(validate.errors));
  assert.equal(validate(controlB.ready), true);
  const nameA = `${a.device.id}.cowork.invalid`; const nameB = `${b.device.id}.cowork.invalid`;
  const identityA = hostCertificate(f.root, nameA); const identityB = hostCertificate(f.root, nameB);
  const echoA = await encryptedEcho(f, a, controlA, identityA); t.after(echoA.close);
  const echoB = await encryptedEcho(f, b, controlB, identityB); t.after(echoB.close);
  const sessions = [];
  for (const [client, name, identity] of [[c, nameA, identityA], [d, nameA, identityA], [e, nameB, identityB]]) {
    const tunnel = await f.tunnel(client); assert.equal(tunnel.status, 200);
    const socket = tls.connect({ socket: tunnel.socket, servername: name, ca: identity.cert, minVersion: 'TLSv1.3' });
    socket.on('error', () => {}); t.after(() => socket.destroy());
    await once(socket, 'secureConnect');
    const response = once(socket, 'data');
    socket.write(`private-message-${client.device.id}`);
    assert.equal((await response)[0].toString(), `private-message-${client.device.id}`);
    sessions.push(socket);
  }
  const captured = Buffer.concat([...echoA.observed, ...echoB.observed]);
  assert.equal(captured.includes(Buffer.from('private-message-')), false);
  const untrustedTunnel = await f.tunnel(c);
  const untrusted = tls.connect({ socket: untrustedTunnel.socket, servername: nameA, ca: identityB.cert, minVersion: 'TLSv1.3' });
  untrusted.on('error', () => {}); t.after(() => untrusted.destroy());
  await assert.rejects(once(untrusted, 'secureConnect'));
  const registry = readFileSync(join(f.state, 'devices.json'), 'utf8');
  for (const registration of [a,b,c,d,e]) { assert.equal(registry.includes(registration.secret), false); assert.equal(f.logs().includes(registration.secret), false); }
  const denied = await f.tunnel(c, b.device.id); assert.equal(denied.status, 403); denied.socket.destroy();
  assert.equal(f.cli('connections').length, 3);
  f.cli('devices', 'kick', c.device.id);
  await waitClosed(sessions[0]);
  assert.equal(sessions[1].destroyed, false); assert.equal(sessions[2].destroyed, false);
  const retry = await f.tunnel(c); assert.equal(retry.status, 200); retry.socket.destroy();
  const closed = waitClosed(sessions[1]);
  f.cli('devices', 'disable', a.device.id);
  await closed;
  assert.equal(sessions[2].destroyed, false);
  const disabled = await f.tunnel(d); assert.equal(disabled.status, 403); disabled.socket.destroy();
  await f.stop(); await f.start();
  assert.equal(f.cli('devices', 'inspect', a.device.id).device.enabled, false);
  const restarted = await f.tunnel(c); assert.equal(restarted.status, 403); restarted.socket.destroy();
});

test('tickets cannot be stolen, replayed or used after disabling their client', { timeout: 40_000 }, async t => {
  const f = await fixture(); t.after(f.cleanup);
  const a = f.enroll('host', 'g'); const b = f.enroll('host', 'g'); const c = f.enroll('client', 'g', a.device.id);
  const control = await f.control(a);
  const opened = once(control.ws, 'message');
  const pending = f.tunnel(c);
  const message = JSON.parse((await opened)[0]);
  assert.equal(validate(message), true, JSON.stringify(validate.errors));
  const wrong = f.websocket(b, `/relay/v1/data/${message.connectionId}`, { 'x-cowork-ticket': message.ticket });
  await assert.rejects(once(wrong, 'open'));
  f.cli('devices', 'disable', c.device.id);
  const rejected = await pending; assert.notEqual(rejected.status, 200); rejected.socket.destroy();
  const stale = f.websocket(a, `/relay/v1/data/${message.connectionId}`, { 'x-cowork-ticket': message.ticket });
  await assert.rejects(once(stale, 'open'));
  f.cli('devices', 'enable', c.device.id);
  const next = once(control.ws, 'message'); const nextPending = f.tunnel(c);
  const current = JSON.parse((await next)[0]);
  const attached = f.websocket(a, `/relay/v1/data/${current.connectionId}`, { 'x-cowork-ticket': current.ticket });
  await once(attached, 'open');
  const live = await nextPending; assert.equal(live.status, 200);
  const replay = f.websocket(a, `/relay/v1/data/${current.connectionId}`, { 'x-cowork-ticket': current.ticket });
  await assert.rejects(once(replay, 'open'));
  const replacement = await f.control(a);
  assert.notEqual(replacement.ready.epoch, control.ready.epoch);
  live.socket.resume(); await waitClosed(live.socket);
});

test('resource caps reject excess streams and closing a client releases its slot', { timeout: 40_000 }, async t => {
  const f = await fixture(); t.after(f.cleanup);
  const host = f.enroll('host', 'g'); const client = f.enroll('client', 'g', host.device.id);
  const control = await f.control(host);
  control.ws.on('message', bytes => {
    const message = JSON.parse(bytes);
    if (message.type === 'open') f.websocket(host, `/relay/v1/data/${message.connectionId}`, { 'x-cowork-ticket': message.ticket });
  });
  const active = [];
  for (let index = 0; index < 8; index++) { const tunnel = await f.tunnel(client); assert.equal(tunnel.status, 200); active.push(tunnel.socket); }
  const denied = await f.tunnel(client); assert.equal(denied.status, 403); denied.socket.destroy();
  active[0].destroy();
  for (let retry = 0; retry < 30 && f.cli('connections').length >= 8; retry++) await delay(30);
  const admitted = await f.tunnel(client); assert.equal(admitted.status, 200); admitted.socket.destroy();
});

test('oversized frames close only their stream; invalid control frames close the host epoch', { timeout: 30_000 }, async t => {
  const f = await fixture(); t.after(f.cleanup);
  const host = f.enroll('host', 'g'); const client = f.enroll('client', 'g', host.device.id);
  const control = await f.control(host);
  const opened = once(control.ws, 'message'); const pending = f.tunnel(client);
  const message = JSON.parse((await opened)[0]);
  const data = f.websocket(host, `/relay/v1/data/${message.connectionId}`, { 'x-cowork-ticket': message.ticket });
  await once(data, 'open');
  const tunnel = await pending; assert.equal(tunnel.status, 200);
  tunnel.socket.resume(); const closed = waitClosed(tunnel.socket);
  data.send(Buffer.alloc(65_537));
  await closed;
  assert.equal(f.cli('devices', 'inspect', host.device.id).online, true);
  const hostClosed = once(control.ws, 'close');
  control.ws.send('unexpected-control-message');
  await hostClosed;
  assert.equal(f.cli('devices', 'inspect', host.device.id).online, false);
});

test('expiry disconnects an already authenticated host and renew-ip keeps imported trust', { timeout: 30_000 }, async t => {
  const f = await fixture(); t.after(f.cleanup);
  const host = f.enroll('host', 'g');
  await f.stop();
  const path = join(f.state, 'devices.json'); const state = JSON.parse(readFileSync(path));
  state.devices[0].device.createdAt = Math.floor(Date.now() / 1000) - 10;
  state.devices[0].device.expiresAt = Math.floor(Date.now() / 1000) + 3;
  writeFileSync(path, JSON.stringify(state), { mode: 0o600 });
  const before = readFileSync(join(f.state, 'ca.pem'));
  f.cli('renew-ip');
  assert.deepEqual(readFileSync(join(f.state, 'ca.pem')), before);
  await f.start();
  const control = await f.control(host);
  await once(control.ws, 'close');
  assert.equal(f.cli('devices', 'inspect', host.device.id).online, false);
  await assert.rejects(f.control(host));
});
