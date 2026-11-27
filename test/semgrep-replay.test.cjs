const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { resolveToolBinary } = require('../src/core/cyber-toolchain.cjs');

const exec = promisify(execFile);
const cli = path.resolve(__dirname, '../bin/marlowe-ci.cjs');
const action = path.resolve(__dirname, '../src/github-action.cjs');

test('Semgrep replay checks the same base-owned fixture with the real scanner on both revisions', async t => {
  if (!await resolveToolBinary('semgrep', process.env.PATH)) {
    assert.ok(!process.env.MARLOWE_TEST_REQUIRE_SEMGREP, 'CI must have the Semgrep CLI installed');
    return t.skip('Install the optional Semgrep CLI to exercise the replay integration');
  }
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'marlowe-replay-test-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const repo = path.join(dir, 'repo');
  await fs.mkdir(repo);
  const git = async (...args) => (await exec('git', args, { cwd: repo })).stdout.trim();
  const write = async (file, content) => {
    await fs.mkdir(path.dirname(path.join(repo, file)), { recursive: true });
    await fs.writeFile(path.join(repo, file), content);
  };
  const commit = async message => {
    await git('add', '.');
    await git('commit', '-qm', message);
    return git('rev-parse', 'HEAD');
  };
  await git('init', '-qb', 'main');
  await git('config', 'user.name', 'Marlowe Test');
  await git('config', 'user.email', 'ci@example.com');
  const manifest = '.marlowe/replay.json';
  const spec = {
    config: '.semgrep/rules.yml', rule: 'replay-marker',
    fixture: '.marlowe/example.js', target: 'services/payments/example.js'
  };
  const rule = `  - id: replay-marker
    languages: [javascript]
    message: Harmless fixture
    severity: WARNING
    pattern: console.log(...)
`;
  const rules = `rules:\n${rule}`;
  await write(spec.config, rules);
  await write(manifest, JSON.stringify(spec));
  await write(spec.fixture, 'console.log("Marlowe replay");\n');
  await write('services/payments/index.js', 'export const currency = "USD";\n');
  await write('.semgrepignore', '# Project exclusions\n');
  const base = await commit('Configure replay for payments');
  await git('switch', '-qc', 'feature');
  const localReplay = async (baseRef = base) => {
    // A nonzero exit still carries the normal JSON verdict on stdout.
    const res = await exec(process.execPath, [cli, 'scan', '--base', baseRef, '--semgrep-replay', manifest,
      '--no-osv', '--fail-on-cant-tell', '--json'], { cwd: repo }).catch(err => err);
    return { code: res.code || 0, report: JSON.parse(res.stdout) };
  };

  await t.test('a PR editing the fixture and manifest cannot change the positive control', async () => {
    await write(spec.fixture, 'void 0;\n');
    await write(manifest, '{}');
    const head = await commit('Propose a different fixture');
    const { code, report } = await localReplay();
    assert.equal(code, 0, JSON.stringify(report.cantTellReasons));
    assert.equal(report.verdict, 'holds');
    assert.deepEqual(report.semgrepReplay.base, { commit: base, outcome: 'matched' });
    assert.deepEqual(report.semgrepReplay.head, { commit: head, outcome: 'matched' });
  });

  await t.test('the PR Action flags a previously covered directory excluded by the head config', async () => {
    await write('.semgrepignore', '# Project exclusions\n/services/payments/\n');
    const head = await commit('Change scanner coverage');
    const ordinary = await exec(process.execPath, [cli, 'scan', '--base', base, '--no-osv', '--json'], { cwd: repo });
    assert.equal(JSON.parse(ordinary.stdout).verdict, 'holds');
    // Actions normally checks out a merge ref. Neither its files nor a moving
    // base branch are authoritative for the two SHA values in the PR payload.
    await git('checkout', '-q', '--detach', base);
    await write(spec.config, '# Uncommitted work must survive the replay\n');
    const state = await git('status', '--porcelain');
    const event = path.join(dir, 'event.json');
    const output = path.join(dir, 'output');
    const summary = path.join(dir, 'summary');
    const sarif = path.join(dir, 'report.sarif');
    await fs.writeFile(event, JSON.stringify({ pull_request: { base: { sha: base }, head: { sha: head } } }));
    const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(INPUT_|GITHUB_)/.test(k)));
    const res = await exec(process.execPath, [action], { cwd: repo, env: {
      ...env, GITHUB_WORKSPACE: repo, GITHUB_BASE_REF: 'main', GITHUB_EVENT_NAME: 'pull_request',
      GITHUB_REPOSITORY: 'example/payments', GITHUB_SERVER_URL: 'https://github.example.test',
      GIT_INDEX_FILE: path.join(repo, '.git', 'index'),
      GITHUB_EVENT_PATH: event, GITHUB_OUTPUT: output, GITHUB_STEP_SUMMARY: summary,
      INPUT_SEMGREP_REPLAY: manifest, INPUT_SARIF_FILE: sarif, INPUT_QUERY_OSV: 'false'
    } }).catch(err => err);
    assert.equal(res.code, 1, res.stdout || res.stderr);
    assert.match(await fs.readFile(output, 'utf8'), /^verdict=fails$/m);
    const md = await fs.readFile(summary, 'utf8');
    const repoUrl = 'https://github.example.test/example/payments';
    assert.ok(md.includes(`Base [${base}](${repoUrl}/commit/${base}) — matched`));
    assert.ok(md.includes(`PR [${head}](${repoUrl}/commit/${head}) — not scanned`));
    assert.ok(md.includes(`${repoUrl}/blob/${head}/.semgrepignore#L2`));
    const [finding] = JSON.parse(await fs.readFile(sarif, 'utf8')).runs[0].results;
    assert.equal(finding.ruleId, 'MARLOWE-SEMGREP-REPLAY');
    assert.ok(finding.message.text.includes(spec.rule));
    assert.ok(finding.message.text.includes(spec.target));
    assert.equal(finding.locations[0].physicalLocation.artifactLocation.uri, '.semgrepignore');
    assert.equal(finding.locations[0].physicalLocation.region.startLine, 2);
    assert.equal(await git('rev-parse', 'HEAD'), base);
    assert.equal(await git('status', '--porcelain'), state);
    await git('restore', '--', spec.config);
    await git('switch', '-q', 'feature');
  });

  await t.test('a rule-level path exclusion is flagged even when another rule matches the same fixture', async () => {
    await write('.semgrepignore', '# Project exclusions\n');
    const otherRule = rule.replace('id: replay-marker', 'id: another-rule');
    await write(spec.config, `${rules}    paths:\n      exclude: ["services/payments/**"]\n${otherRule}`);
    await commit('Exclude payments from the expected rule');
    const { code, report } = await localReplay();
    assert.equal(code, 1);
    assert.equal(report.semgrepReplay.head.outcome, 'scanned without a match');
    assert.deepEqual(report.semgrepReplay.changedConfigs, [spec.config]);
    assert.equal(report.failingFindings[0].ruleId, 'MARLOWE-SEMGREP-REPLAY');
  });

  await t.test('an invalid PR config is inconclusive', async () => {
    await write(spec.config, 'rules: [\n');
    await commit('Malformed rules');
    const { code, report } = await localReplay();
    assert.equal(code, 2);
    assert.equal(report.verdict, 'cant-tell');
    assert.equal(report.semgrepReplay.base.outcome, 'matched');
    assert.equal(report.failingFindings.length, 0);
    assert.ok(report.cantTellReasons.some(r => r.code === 'semgrep-replay-inconclusive'));
  });

  await t.test('a base that misses the fixture cannot establish coverage', async () => {
    await write(spec.config, rules);
    await write(manifest, JSON.stringify(spec));
    const noMatch = await commit('Keep an inert example as the base');
    const { code, report } = await localReplay(noMatch);
    assert.equal(code, 2);
    assert.equal(report.semgrepReplay.base.outcome, 'scanned without a match');
    assert.equal(report.semgrepReplay.status, 'inconclusive');
  });

  await t.test('a nested ignore file uses the patterns included by that revision', async () => {
    await write('services/.semgrepignore', ':include scan-exclusions\n');
    await write('services/scan-exclusions', 'payments/\n');
    await commit('Exclude payments using shared ignore patterns');
    const { code, report } = await localReplay();
    assert.equal(code, 1, JSON.stringify(report.cantTellReasons));
    assert.equal(report.semgrepReplay.head.outcome, 'not scanned');
    assert.ok(report.semgrepReplay.changedConfigs.includes('services/scan-exclusions'));
  });
});
