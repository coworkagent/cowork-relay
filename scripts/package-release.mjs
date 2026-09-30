import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const targets = {
  'linux-x64': 'x86_64-unknown-linux-musl',
  'linux-arm64': 'aarch64-unknown-linux-musl',
  'darwin-x64': 'x86_64-apple-darwin',
  'darwin-arm64': 'aarch64-apple-darwin',
};
const [platform, target] = process.argv.slice(2);
assert.ok(Object.hasOwn(targets, platform), 'Unsupported platform');
assert.equal(target, targets[platform]);
const version = JSON.parse(readFileSync('package.json')).version;
assert.match(version, /^\d+\.\d+\.\d+$/);
assert.equal(readFileSync('Cargo.toml', 'utf8').match(/^version = "([^"]+)"/m)?.[1], version);
assert.equal(JSON.parse(readFileSync('package-lock.json')).packages[''].version, version);
if (process.env.GITHUB_REF_TYPE === 'tag') assert.equal(process.env.GITHUB_REF_NAME, `v${version}`);
const binary = resolve(`target/${target}/release/cowork-relay`);
assert.equal(execFileSync(binary, ['--version'], { encoding: 'utf8' }).trim(), `cowork-relay ${version}`);
const name = `cowork-relay-${version}-${platform}`;
const staging = mkdtempSync(join(tmpdir(), 'cowork-package-'));
mkdirSync('dist', { recursive: true });
try {
  const directory = join(staging, name);
  mkdirSync(directory);
  cpSync(binary, join(directory, 'cowork-relay'));
  for (const path of ['README.md', 'README.zh-CN.md', 'RELEASE_NOTES.md', 'deploy']) {
    cpSync(path, join(directory, path), { recursive: true });
  }
  const manifest = {
    version, platform, target,
    commit: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
    rustc: execFileSync('rustc', ['--version'], { encoding: 'utf8' }).trim(),
    binarySha256: createHash('sha256').update(readFileSync(binary)).digest('hex'),
    linkage: platform.startsWith('linux-') ? 'static-musl' : 'system',
    ...(platform.startsWith('darwin-') ? { deploymentTarget: process.env.MACOSX_DEPLOYMENT_TARGET } : {}),
  };
  writeFileSync(join(directory, 'BUILD.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  const archive = resolve('dist', `${name}.tar.gz`);
  execFileSync('tar', ['-czf', archive, '-C', staging, name]);
  const digest = createHash('sha256').update(readFileSync(archive)).digest('hex');
  writeFileSync(`${archive}.sha256`, `${digest}  ${name}.tar.gz\n`);
  console.log(`${name}.tar.gz: ${digest}`);
} finally {
  rmSync(staging, { recursive: true, force: true });
}
