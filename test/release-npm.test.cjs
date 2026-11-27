const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const { setImmediate: nextTurn } = require('node:timers/promises');
const { waitForNpmVersion } = require('../scripts/wait-for-npm-version.cjs');

const pkg = { name: '@zerotheory-labs/marlowe-ci', version: '0.7.1' };
const ref = 'refs/tags/v0.7.1';
const versionUrl = 'https://registry.npmjs.org/@zerotheory-labs%2Fmarlowe-ci/0.7.1';

test('v0.7.1 release waits through a temporary npm 404 for the exact scoped version', async () => {
  let visible = false;
  const urls = [];
  const request = async url => {
    urls.push(url);
    if (!visible) return new Response('version not found: 0.7.1', { status: 404 });
    return Response.json(pkg);
  };
  const pause = async ms => {
    assert.ok(ms > 0);
    await nextTurn();
    visible = true;
  };

  await waitForNpmVersion(pkg, { ref, request, pause, maxAttempts: 2 });
  assert.deepEqual(urls, [versionUrl, versionUrl]);
});

test('a version that stays absent exhausts the wait and blocks MCP publication', async t => {
  const request = t.mock.fn(async () => new Response(null, { status: 404 }));
  await assert.rejects(waitForNpmVersion(pkg, { ref, request, pause: nextTurn, maxAttempts: 2 }),
    /marlowe-ci@0\.7\.1.*2 attempts.*HTTP 404/);
  assert.equal(request.mock.callCount(), 2);
});

test('a different registry version or a mismatched Git tag cannot pass the wait', async () => {
  const request = async () => Response.json({ ...pkg, version: '0.7.0' });
  await assert.rejects(waitForNpmVersion(pkg, { ref, request }), /expected .*@0\.7\.1.*got .*@0\.7\.0/i);
  await assert.rejects(waitForNpmVersion(pkg, { ref: 'refs/tags/v0.7.2', request }), /tag v0\.7\.2.*0\.7\.1/i);
});

test('release workflows wait for npm before invoking the MCP publisher', () => {
  for (const file of ['release-npm-mcp.yml', 'publish-mcp.yml']) {
    const workflow = readFileSync(path.join(__dirname, '../.github/workflows', file), 'utf8');
    const wait = workflow.indexOf('run: node scripts/wait-for-npm-version.cjs');
    assert.ok(wait >= 0 && wait < workflow.indexOf('./mcp-publisher publish'), file);
    if (file === 'release-npm-mcp.yml') {
      const publish = workflow.indexOf('run: npm publish ');
      assert.ok(publish >= 0 && publish < wait, file);
    }
  }
});
