import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { once } from 'node:events';
import net from 'node:net';
import tls from 'node:tls';
import { setTimeout as delay } from 'node:timers/promises';
import WebSocket, { createWebSocketStream } from 'ws';

const binary = resolve(process.env.COWORK_RELAY_BINARY ?? 'target/release/cowork-relay');
export async function availablePort() {
  const listener = net.createServer();
  listener.listen(0, '127.0.0.1');
  await once(listener, 'listening');
  const port = listener.address().port;
  await new Promise(resolve => listener.close(resolve));
  return port;
}

export async function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'cwr-'));
  const state = join(root, 'state');
  const port = await availablePort();
  let counter = 0;
  let child;
  let logs = '';
  const resources = new Set();
  const cli = (...args) => JSON.parse(execFileSync(binary, ['--data-dir', state, '--json', ...args], { encoding: 'utf8', timeout: 10_000 }));
  const human = (...args) => execFileSync(binary, ['--data-dir', state, ...args], { encoding: 'utf8', timeout: 10_000 });
  try { cli('init-ip', '--ip', '127.0.0.1', '--port', String(port), '--listen', `127.0.0.1:${port}`); }
  catch (error) { rmSync(root, { recursive: true, force: true }); throw error; }
  const ca = readFileSync(join(state, 'ca.pem'));
  const origin = `https://127.0.0.1:${port}`;
  const connect = async (options = {}) => {
    const socket = tls.connect({ host: '127.0.0.1', port, servername: '', ca, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', ...options });
    resources.add(socket);
    socket.on('error', () => {});
    socket.setTimeout(5_000, () => socket.destroy(new Error('TLS test timed out')));
    await once(socket, 'secureConnect');
    socket.setTimeout(0);
    return socket;
  };
  const request = async text => {
    const socket = await connect();
    return readHeaders(socket, text);
  };
  const start = async () => {
    child = spawn(binary, ['--data-dir', state, 'serve'], { stdio: ['ignore', 'ignore', 'pipe'] });
    child.stderr.on('data', bytes => { logs += bytes; });
    for (let attempt = 0; attempt < 100; attempt++) {
      if (child.exitCode !== null) throw new Error(`Relay exited: ${logs}`);
      try {
        const health = await request(`GET /health/live HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\n\r\n`);
        health.socket.destroy();
        if (health.status === 200) return;
      } catch {}
      await delay(30);
    }
    throw new Error(`Relay startup timed out: ${logs}`);
  };
  const stop = async () => {
    if (child && child.exitCode === null && child.signalCode === null) {
      const closed = once(child, 'exit');
      child.kill('SIGTERM');
      await closed;
    }
  };
  const enroll = (role, group, hostId) => {
    const file = join(root, `registration-${++counter}.json`);
    cli('devices', `add-${role}`, '--name', `${role}-${counter}`, '--group', group, '--credential-out', file, ...(hostId ? ['--host', hostId] : []));
    return JSON.parse(readFileSync(file, 'utf8'));
  };
  const websocket = (registration, path, headers = {}) => {
    const ws = new WebSocket(origin.replace('https:', 'wss:') + path, 'cowork.relay.v1', {
      ca, servername: '', minVersion: 'TLSv1.3', perMessageDeflate: false,
      headers: { authorization: `Bearer ${registration.device.id}.${registration.secret}`, ...headers },
      handshakeTimeout: 5_000,
    });
    resources.add(ws);
    ws.on('error', () => {});
    return ws;
  };
  const control = async host => {
    const ws = websocket(host, '/relay/v1/control');
    const [bytes] = await once(ws, 'message');
    return { ws, ready: JSON.parse(bytes) };
  };
  const tunnel = (client, target = client.device.hostId, extra = '') => request(
    `CONNECT ${target}.cowork.invalid:443 HTTP/1.1\r\nHost: ${target}.cowork.invalid:443\r\nProxy-Authorization: Basic ${Buffer.from(`${client.device.id}:${client.secret}`).toString('base64')}\r\n${extra}\r\n`
  );
  const cleanup = async () => {
    for (const resource of resources) {
      if (resource instanceof WebSocket) resource.terminate(); else resource.destroy();
    }
    await stop();
    rmSync(root, { recursive: true, force: true });
  };
  try { await start(); } catch (error) { await cleanup(); throw error; }
  return { root, state, port, ca, origin, cli, human, connect, request, enroll, websocket, control, tunnel, start, stop, cleanup, logs: () => logs };
}

export function readHeaders(socket, request) {
  return new Promise((resolve, reject) => {
    let bytes = Buffer.alloc(0);
    const timer = setTimeout(() => { cleanup(); socket.destroy(); reject(new Error('Response timed out')); }, 15_000);
    const cleanup = () => { clearTimeout(timer); socket.off('data', data); socket.off('error', error); socket.off('end', end); };
    const error = value => { cleanup(); reject(value); };
    const end = () => error(new Error('Connection ended before headers'));
    const data = chunk => {
      bytes = Buffer.concat([bytes, chunk]);
      const index = bytes.indexOf('\r\n\r\n');
      if (index < 0) { if (bytes.length > 16_384) error(new Error('Oversized response')); return; }
      socket.pause(); cleanup();
      if (bytes.length > index + 4) socket.unshift(bytes.subarray(index + 4));
      const headers = bytes.subarray(0, index).toString();
      resolve({ status: Number(headers.split(' ')[1]), headers, socket });
    };
    socket.on('data', data); socket.once('error', error); socket.once('end', end);
    socket.write(request);
  });
}

export function hostCertificate(root, name) {
  const directory = join(root, `tls-${name.slice(0, 8)}`);
  mkdirSync(directory, { mode: 0o700 });
  const config = join(directory, 'openssl.cnf');
  writeFileSync(config, `[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=${name}\n[ext]\nsubjectAltName=DNS:${name}\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n`);
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(directory, 'key.pem'), '-out', join(directory, 'cert.pem'), '-days', '1', '-config', config], { stdio: 'ignore' });
  return { key: readFileSync(join(directory, 'key.pem')), cert: readFileSync(join(directory, 'cert.pem')) };
}

export async function encryptedEcho(f, host, control, identity) {
  const observed = [];
  const sockets = new Set();
  control.ws.on('message', bytes => {
    const message = JSON.parse(bytes);
    if (message.type !== 'open') return;
    const ws = f.websocket(host, `/relay/v1/data/${message.connectionId}`, { 'x-cowork-ticket': message.ticket });
    ws.on('message', (bytes, binary) => { if (binary) observed.push(Buffer.from(bytes)); });
    ws.once('open', () => {
      const stream = createWebSocketStream(ws);
      stream.on('error', () => {});
      const inner = new tls.TLSSocket(stream, { isServer: true, secureContext: tls.createSecureContext(identity), minVersion: 'TLSv1.3' });
      sockets.add(inner);
      inner.on('error', () => {});
      inner.on('data', bytes => inner.write(bytes));
      inner.on('close', () => sockets.delete(inner));
    });
  });
  return { observed, close: () => { for (const socket of sockets) socket.destroy(); } };
}
