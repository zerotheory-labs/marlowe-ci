const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { pathToFileURL } = require('node:url');
const { runAction } = require('../src/github-action.cjs');
const pkg = require('../package.json');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '../bin/marlowe-ci.cjs');

test('marlowe-ci init --all is idempotent and preserves existing user settings', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'marlowe-init-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));

  await execFileAsync('git', ['init', '-b', 'main'], { cwd: dir });
  await fs.mkdir(path.join(dir, '.claude'), { recursive: true });
  await fs.writeFile(
    path.join(dir, '.claude', 'settings.json'),
    JSON.stringify({
      customKey: true,
      hooks: {
        PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'echo user-hook' }] }]
      }
    }),
    'utf8'
  );

  // Run init twice to assert strict idempotency
  await execFileAsync(process.execPath, [CLI, 'init', '--all', '--path', dir]);
  await execFileAsync(process.execPath, [CLI, 'init', '--all', '--path', dir]);

  const claudeSettings = JSON.parse(await fs.readFile(path.join(dir, '.claude', 'settings.json'), 'utf8'));
  assert.equal(claudeSettings.customKey, true);
  assert.equal(claudeSettings.hooks.PreToolUse.length, 2);
  assert.equal(claudeSettings.hooks.PostToolUse.length, 1);
  assert.equal(claudeSettings.hooks.Stop.length, 1);

  const mcp = JSON.parse(await fs.readFile(path.join(dir, '.mcp.json'), 'utf8'));
  assert.equal(mcp.mcpServers.marlowe.args.includes('mcp'), true);

  const workflow = await fs.readFile(path.join(dir, '.github', 'workflows', 'marlowe-ci.yml'), 'utf8');
  assert.ok(workflow.includes(`zerotheory-labs/marlowe-ci@v${pkg.version}`));
  assert.ok(workflow.includes('github/codeql-action/upload-sarif@v4'));

  const preCommit = await fs.readFile(path.join(dir, '.git', 'hooks', 'pre-commit'), 'utf8');
  assert.equal(preCommit.match(/marlowe-ci-pre-commit start/g).length, 1);
});

test('GitHub Action runner writes SARIF v2.1.0, GITHUB_OUTPUT, GITHUB_STEP_SUMMARY, and sets exitCode on FAILS', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'marlowe-gha-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));

  await execFileAsync('git', ['init', '-b', 'main'], { cwd: dir });
  await execFileAsync('git', ['config', 'user.email', 'ci@example.com'], { cwd: dir });
  await execFileAsync('git', ['config', 'user.name', 'Marlowe Test'], { cwd: dir });
  await fs.writeFile(path.join(dir, 'ok.js'), 'export const a = 1;\n', 'utf8');
  await execFileAsync('git', ['add', '.'], { cwd: dir });
  await execFileAsync('git', ['commit', '-m', 'base'], { cwd: dir });

  await execFileAsync('git', ['checkout', '-b', 'feat/test'], { cwd: dir });
  const fakeKey = 'AKIA' + 'ABCDEF1234567890';
  await fs.writeFile(path.join(dir, 'secret.js'), `export const k = "${fakeKey}";\n`, 'utf8');
  await execFileAsync('git', ['add', '.'], { cwd: dir });
  await execFileAsync('git', ['commit', '-m', 'add secret'], { cwd: dir });

  const outFile = path.join(dir, 'gh_output.txt');
  const sumFile = path.join(dir, 'gh_summary.md');
  const eventFile = path.join(dir, 'gh_event.json');
  await fs.writeFile(outFile, '', 'utf8');
  await fs.writeFile(sumFile, '', 'utf8');
  await fs.writeFile(eventFile, JSON.stringify({ pull_request: { number: 1 } }), 'utf8');

  const savedEnv = { ...process.env };
  const prevExitCode = process.exitCode;
  t.after(() => {
    process.env = savedEnv;
    process.exitCode = prevExitCode;
  });

  process.env.GITHUB_WORKSPACE = dir;
  process.env.GITHUB_BASE_REF = 'main';
  process.env.GITHUB_EVENT_NAME = 'pull_request';
  process.env.GITHUB_EVENT_PATH = eventFile;
  process.env.GITHUB_REPOSITORY = 'zerotheory-labs/marlowe';
  process.env.GITHUB_OUTPUT = outFile;
  process.env.GITHUB_STEP_SUMMARY = sumFile;
  process.env.INPUT_MODE = 'diff';
  // GitHub Actions runner preserves hyphens in INPUT_* env variable names
  process.env['INPUT_QUERY-OSV'] = 'false';
  process.env['INPUT_SARIF-FILE'] = 'out/marlowe.sarif';
  process.env['INPUT_COMMENT-PR'] = 'true';
  process.env['INPUT_GITHUB-TOKEN'] = 'ghs_test_token';

  const calls = [];
  const fetchImpl = async (url, opts = {}) => {
    calls.push({ url, method: opts.method || 'GET', body: opts.body || '' });
    if (!opts.method || opts.method === 'GET') {
      return { ok: true, status: 200, json: async () => [] };
    }
    return { ok: true, status: 201, json: async () => ({ id: 42 }), text: async () => '' };
  };

  const result = await runAction({ fetchImpl });
  assert.equal(result.verdict, 'fails');
  assert.equal(process.exitCode, 1);
  assert.equal(calls.length, 2);
  assert.equal(calls[1].method, 'POST');
  assert.ok(calls[1].url.endsWith('/repos/zerotheory-labs/marlowe/issues/1/comments'));
  assert.ok(JSON.parse(calls[1].body).body.includes('<!-- marlowe-ci-verdict -->'));

  const outputs = await fs.readFile(outFile, 'utf8');
  assert.ok(outputs.includes('verdict=fails'));
  assert.ok(outputs.includes('findings-count=1'));

  const summary = await fs.readFile(sumFile, 'utf8');
  assert.ok(summary.includes('Marlowe CI Verdict: **FAILS**'));

  const sarif = JSON.parse(await fs.readFile(path.join(dir, 'out', 'marlowe.sarif'), 'utf8'));
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].results.length, 1);
});

async function createPushFixture(t) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'marlowe-push-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const repo = path.join(dir, 'repo');
  await fs.mkdir(repo);
  const git = async (...args) => (await execFileAsync('git', args, { cwd: repo })).stdout.trim();
  await git('init', '-b', 'main');
  await git('config', 'user.email', 'ci@example.com');
  await git('config', 'user.name', 'Marlowe Test');
  async function commit(file, content) {
    await fs.writeFile(path.join(repo, file), content);
    await git('add', file);
    await git('commit', '-m', file);
    return git('rev-parse', 'HEAD');
  }
  // Use the real Action entry point with runner artifacts outside the checkout.
  const eventFile = path.join(dir, 'event.json');
  const sarifFile = path.join(dir, 'result.sarif');
  const outputFile = path.join(dir, 'outputs');
  const summaryFile = path.join(dir, 'summary.md');
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(GITHUB_|INPUT_)/.test(key)));
  async function push(event, inputs = {}) {
    await fs.writeFile(eventFile, JSON.stringify(event));
    const result = await execFileAsync(process.execPath, [path.resolve(__dirname, '../src/github-action.cjs')], {
      cwd: repo,
      env: { ...env, GITHUB_WORKSPACE: repo, GITHUB_EVENT_NAME: 'push', GITHUB_EVENT_PATH: eventFile,
        GITHUB_OUTPUT: outputFile, GITHUB_STEP_SUMMARY: summaryFile,
        INPUT_QUERY_OSV: 'false', INPUT_SARIF_FILE: sarifFile, ...inputs }
    });
    return result.stdout;
  }
  return { git, commit, push, sarifFile, outputFile, summaryFile };
}

test('push action inspects the event range in a clean checkout', async t => {
  const { git, commit, push, sarifFile } = await createPushFixture(t);
  const base = await commit('base.js', 'const base = 1;\n');
  const first = await commit('first.js', 'const first = 1;\n');
  const after = await commit('second.js', 'const second = 2;\n');
  const inspected = n => new RegExp(`HOLDS UP .*\\b${n} file\\(s\\) inspected`);
  assert.match(await push({ before: base, after }), inspected(2));
  assert.match(await push({ before: base, after }, { INPUT_BASE_REF: first }), inspected(1));
  assert.match(await push({ before: '0'.repeat(base.length), after, created: true }), inspected(3));
  assert.match(await push({ before: after, after }), inspected(0)); // genuinely empty range

  // A force push also changes a file whose old-tip edit is absent from the common ancestor.
  await git('checkout', '-b', 'old-tip', base);
  const oldTip = await commit('base.js', 'const base = 2;\n');
  await git('checkout', 'main');
  assert.match(await push({ before: oldTip, after, forced: true }), inspected(3));
  await git('checkout', '--detach', base);
  assert.match(await push({ before: oldTip, after: base, forced: true }), inspected(1));
  await git('checkout', 'main');
  await assert.rejects(push({ before: '1'.repeat(base.length), after }), /push range/i);
  await assert.rejects(push({ after }), /push event/i);
  await assert.rejects(push({ before: base, after: first }), /checkout/i);
  assert.match(await push({ before: after, after: '0'.repeat(base.length), deleted: true }), /deleted ref/i);

  const exampleKey = 'AKIA' + 'ABCDEF1234567890';
  await commit('early.js', `export const key = "${exampleKey}";\n`);
  const final = await commit('guide.md', 'A harmless follow-up.\n');
  await assert.rejects(push({ before: after, after: final }), err => err.code === 1 && /Verdict: FAILS/.test(err.stdout));
  const sarif = JSON.parse(await fs.readFile(sarifFile, 'utf8'));
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'early.js');
});

test('push fails for a secret added in one commit and removed in the next', async t => {
  const { git, commit, push, sarifFile, outputFile, summaryFile } = await createPushFixture(t);
  const safe = 'export const enabled = true;\n';
  const before = await commit('config.js', safe);
  const fixtureKey = 'AKIA' + 'ABCDEF1234567890';
  const exposed = await commit('config.js', safe + `export const key = "${fixtureKey}";\n`);
  const after = await commit('config.js', safe);
  assert.equal(await git('diff', before, after), '');
  const worktrees = await git('worktree', 'list', '--porcelain');

  await assert.rejects(push({ before, after }), err => {
    assert.equal(err.code, 1);
    assert.match(err.stdout, /Verdict: FAILS/);
    assert.match(err.stdout, /across 2 commits/);
    assert.ok(!err.stdout.includes(fixtureKey));
    return true;
  });
  const outputs = await fs.readFile(outputFile, 'utf8');
  assert.match(outputs, /^verdict=fails$/m);
  assert.match(outputs, /^findings-count=1$/m);
  const sarif = await fs.readFile(sarifFile, 'utf8');
  assert.ok(!sarif.includes(fixtureKey));
  const findings = JSON.parse(sarif).runs[0].results;
  assert.equal(findings.length, 1);
  assert.equal(findings[0].properties.category, 'secrets');
  assert.equal(findings[0].properties.commitSha, exposed);
  const { artifactLocation, region } = findings[0].locations[0].physicalLocation;
  assert.equal(artifactLocation.uri, 'config.js');
  assert.equal(region.startLine, 2);
  assert.ok((await fs.readFile(summaryFile, 'utf8')).includes(exposed));
  assert.equal(await git('rev-parse', 'HEAD'), after);
  assert.equal(await git('status', '--porcelain'), '');
  assert.equal(await git('worktree', 'list', '--porcelain'), worktrees);
});

test('push inspects commits on a merged branch even when the event lists only the tip', async t => {
  const { git, commit, push, sarifFile } = await createPushFixture(t);
  const before = await commit('base.js', 'export const value = 1;\n');
  await git('checkout', '-b', 'side');
  const fixtureKey = 'AKIA' + 'ABCDEF1234567890';
  const exposed = await commit('temporary.js', `export const key = "${fixtureKey}";\n`);
  await git('rm', 'temporary.js');
  await git('commit', '-m', 'Delete temporary file');
  await git('checkout', 'main');
  await git('merge', '--no-ff', '-m', 'Merge side', 'side');
  const after = await git('rev-parse', 'HEAD');

  await assert.rejects(push({ before, after, commits: [{ id: after }] }), err => err.code === 1 && /Verdict: FAILS/.test(err.stdout));
  const { results } = JSON.parse(await fs.readFile(sarifFile, 'utf8')).runs[0];
  assert.equal(results.length, 1);
  assert.equal(results[0].properties.commitSha, exposed);
  assert.equal(results[0].locations[0].physicalLocation.artifactLocation.uri, 'temporary.js');
});

test('new refs use the event commit list and fall back to history if it is incomplete', async t => {
  const { commit, push } = await createPushFixture(t);
  const fixtureKey = 'AKIA' + 'ABCDEF1234567890';
  const exposed = await commit('config.js', `export const key = "${fixtureKey}";\n`);
  await commit('config.js', 'export const enabled = true;\n');
  const after = await commit('guide.md', 'Setup instructions.\n');
  const event = { before: '0'.repeat(after.length), after, created: true, commits: [{ id: after }] };
  assert.match(await push(event), /Verdict: HOLDS UP/);
  await assert.rejects(push({ ...event, size: 3 }), err => err.code === 1 && err.stdout.includes(exposed));
});

test('push fails when a shallow checkout has both tips but lacks intermediate history', async t => {
  const { git, commit, push } = await createPushFixture(t);
  const before = await commit('config.js', 'export const value = 1;\n');
  await commit('config.js', 'export const value = 2;\n');
  const after = await commit('config.js', 'export const value = 1;\n');
  const repo = await git('rev-parse', '--show-toplevel');
  const shallow = path.join(path.dirname(repo), 'shallow');
  await execFileAsync('git', ['clone', '--depth=1', pathToFileURL(repo).href, shallow]);
  await execFileAsync('git', ['-C', shallow, 'fetch', '--depth=1', 'origin', before]);
  await assert.rejects(push({ before, after }, { GITHUB_WORKSPACE: shallow }), /fetch-depth: 0/);
});
