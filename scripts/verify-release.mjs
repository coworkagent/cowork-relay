import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';

const version = JSON.parse(readFileSync('package.json')).version;
assert.match(version, /^\d+\.\d+\.\d+$/);
if (process.env.GITHUB_REF_TYPE === 'tag') assert.equal(process.env.GITHUB_REF_NAME, `v${version}`);
const archives = ['darwin-arm64', 'darwin-x64', 'linux-arm64', 'linux-x64']
  .map(platform => `cowork-relay-${version}-${platform}.tar.gz`);
assert.deepEqual(readdirSync('dist').sort(), archives.flatMap(name => [name, `${name}.sha256`]).sort());
const sums = archives.map(name => {
  const digest = createHash('sha256').update(readFileSync(`dist/${name}`)).digest('hex');
  const line = `${digest}  ${name}\n`;
  assert.equal(readFileSync(`dist/${name}.sha256`, 'utf8'), line);
  return line;
}).join('');
writeFileSync('dist/SHA256SUMS', sums);
console.log(sums);
