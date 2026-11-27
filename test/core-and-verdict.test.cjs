const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { runAudit } = require('../src/engine/verdict.cjs');

const execFileAsync = promisify(execFile);

async function makeTempGitRepo() {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'marlowe-ci-verdict-'));
  await execFileAsync('git', ['init', '-b', 'main'], { cwd: dir });
  await execFileAsync('git', ['config', 'user.email', 'ci@example.com'], { cwd: dir });
  await execFileAsync('git', ['config', 'user.name', 'Marlowe Test'], { cwd: dir });
  await fs.mkdir(path.join(dir, 'src'), { recursive: true });
  await fs.writeFile(path.join(dir, 'src', 'index.js'), 'export function add(a, b) { return a + b; }\n', 'utf8');
  await execFileAsync('git', ['add', '.'], { cwd: dir });
  await execFileAsync('git', ['commit', '-m', 'init'], { cwd: dir });
  return dir;
}

test('returns HOLDS UP on clean diff with test file', async t => {
  const repo = await makeTempGitRepo();
  t.after(() => fs.rm(repo, { recursive: true, force: true }));

  await fs.writeFile(path.join(repo, 'src', 'math.js'), 'export const mul = (a, b) => a * b;\n', 'utf8');
  const res = await runAudit({ root: repo, mode: 'diff', queryOsv: false });

  assert.equal(res.verdict, 'holds');
  assert.equal(res.verdictLabel, 'HOLDS UP');
  assert.equal(res.findings.length, 0);
  assert.equal(res.cantTellReasons.length, 0);
  assert.equal(res.sarif.version, '2.1.0');
  assert.equal(res.sarif.runs[0].tool.driver.name, 'Marlowe CI');
});

test('returns FAILS and masks hardcoded AWS & GitHub tokens in diff', async t => {
  const repo = await makeTempGitRepo();
  t.after(() => fs.rm(repo, { recursive: true, force: true }));

  const fakeAws = 'AKIA' + '1234567890ABCDEF';
  const fakeGh = 'ghp_' + 'aB3dEf9012'.repeat(3);
  await fs.writeFile(
    path.join(repo, 'src', 'creds.js'),
    `const aws = '${fakeAws}';\nconst gh = '${fakeGh}';\n`,
    'utf8'
  );

  const res = await runAudit({ root: repo, mode: 'diff', queryOsv: false });
  assert.equal(res.verdict, 'fails');
  assert.ok(res.failingFindings.length >= 2);
  for (const f of res.failingFindings) {
    assert.ok(!f.evidence.includes(fakeAws), 'Raw AWS secret leaked into finding evidence');
    assert.ok(!f.evidence.includes(fakeGh), 'Raw GitHub token leaked into finding evidence');
    assert.ok(f.evidence.includes('[REDACTED]'));
  }
  assert.ok(res.sarif.runs[0].results.length >= 2);
});

test('returns FAILS on reachable SQL injection sink in HTTP handler and TLS disable regression', async t => {
  const repo = await makeTempGitRepo();
  t.after(() => fs.rm(repo, { recursive: true, force: true }));

  const tlsBypass = 'rejectUnauth' + 'orized: fal' + 'se';
  const sqli = 'SEL' + 'ECT * FROM accounts WHERE id = ' + "'${req.query.id}'";
  await fs.writeFile(
    path.join(repo, 'src', 'handler.js'),
    [
      'export async function fetchUser(req, res) {',
      `  const q = \`${sqli}\`;`,
      `  const tlsOpts = { ${tlsBypass} };`,
      '  return { q, tlsOpts };',
      '}'
    ].join('\n') + '\n',
    'utf8'
  );

  const res = await runAudit({ root: repo, mode: 'diff', queryOsv: false });
  assert.equal(res.verdict, 'fails');
  assert.ok(res.failingFindings.some(f => f.cwe === 'CWE-89'));
  assert.ok(res.failingFindings.some(f => f.cwe === 'CWE-295'));
});

test('returns CANT TELL on unverified local sink without external entry surface', async t => {
  const repo = await makeTempGitRepo();
  t.after(() => fs.rm(repo, { recursive: true, force: true }));

  const weakHash = 'create' + "Hash('md5')";
  const domSink = 'el.' + 'innerHTML = someLocalVar;';
  // Test dom-xss without HTTP/CLI input in module -> unverified sink -> CAN'T TELL (when failOn is high, and dom-xss is medium)
  await fs.writeFile(
    path.join(repo, 'src', 'render.js'),
    `export function draw(el, label) {\n  ${domSink.replace('someLocalVar', 'label')}\n  return '${weakHash.slice(0, 4)}';\n}\n`,
    'utf8'
  );

  const res = await runAudit({ root: repo, mode: 'diff', queryOsv: false, failOn: 'high' });
  assert.equal(res.verdict, 'cant-tell');
  assert.ok(res.cantTellReasons.some(r => r.code === 'unverified-sink'));
});

test('returns CANT TELL when auth surface changes without tests or suppression comment added', async t => {
  const repo = await makeTempGitRepo();
  t.after(() => fs.rm(repo, { recursive: true, force: true }));

  await fs.mkdir(path.join(repo, 'src', 'auth'), { recursive: true });
  await fs.writeFile(
    path.join(repo, 'src', 'auth', 'session.js'),
    '// ' + 'nosemgrep\nexport function verifySession(id) { return Boolean(id); }\n',
    'utf8'
  );

  const res = await runAudit({ root: repo, mode: 'diff', queryOsv: false });
  assert.equal(res.verdict, 'cant-tell');
  const codes = new Set(res.cantTellReasons.map(r => r.code));
  assert.ok(codes.has('sensitive-surface-untested'));
  assert.ok(codes.has('guardrail-suppression-added'));
});

test('returns CANT TELL when opaque ELF binary is added', async t => {
  const repo = await makeTempGitRepo();
  t.after(() => fs.rm(repo, { recursive: true, force: true }));

  const elfHeader = Buffer.alloc(64);
  elfHeader[0] = 0x7f;
  elfHeader[1] = 0x45;
  elfHeader[2] = 0x4c;
  elfHeader[3] = 0x46;
  elfHeader[4] = 2;
  elfHeader[5] = 1;
  await fs.writeFile(path.join(repo, 'payload.bin'), elfHeader);

  const res = await runAudit({ root: repo, mode: 'diff', queryOsv: false });
  assert.equal(res.verdict, 'cant-tell');
  assert.ok(res.cantTellReasons.some(r => r.code === 'high-entropy-or-binary'));
});

test('returns CANT TELL when requested external scanner is missing', async t => {
  const repo = await makeTempGitRepo();
  t.after(() => fs.rm(repo, { recursive: true, force: true }));

  const res = await runAudit({
    root: repo,
    mode: 'diff',
    queryOsv: false,
    scanners: ['nonexistent-scanner']
  });
  assert.equal(res.verdict, 'cant-tell');
  assert.ok(res.cantTellReasons.some(r => r.code === 'unknown-scanner'));
});

test('cross-file reachability traces 1-hop HTTP route importing helper SQLi -> FAILS', async t => {
  const repo = await makeTempGitRepo();
  t.after(() => fs.rm(repo, { recursive: true, force: true }));

  await fs.mkdir(path.join(repo, 'src', 'routes'), { recursive: true });
  await fs.mkdir(path.join(repo, 'src', 'db'), { recursive: true });
  await fs.writeFile(
    path.join(repo, 'src', 'routes', 'users.js'),
    "import { fetchUser } from '../db/queries.js';\nexport async function getUser(req, res) {\n  return fetchUser(req.query.id);\n}\n",
    'utf8'
  );
  const sqli = 'SEL' + 'ECT * FROM users WHERE id = ' + "'${id}'";
  await fs.writeFile(
    path.join(repo, 'src', 'db', 'queries.js'),
    `export function fetchUser(id) {\n  return db.query(\`${sqli}\`);\n}\nexport function ping() { return 'ok'; }\n`,
    'utf8'
  );

  const res = await runAudit({ root: repo, mode: 'diff', queryOsv: false });
  assert.equal(res.verdict, 'fails');
  const sqliFinding = res.failingFindings.find(f => f.cwe === 'CWE-89');
  assert.ok(sqliFinding, 'Expected reachable CWE-89 finding from 1-hop importer');
  assert.equal(sqliFinding.reachability, 'reachable');
  assert.ok(sqliFinding.remediation.includes('src/routes/users.js'));
});

test('cross-file reachability traces 2-hop route -> service -> helper SQLi -> FAILS', async t => {
  const repo = await makeTempGitRepo();
  t.after(() => fs.rm(repo, { recursive: true, force: true }));

  await fs.mkdir(path.join(repo, 'src', 'routes'), { recursive: true });
  await fs.mkdir(path.join(repo, 'src', 'services'), { recursive: true });
  await fs.mkdir(path.join(repo, 'src', 'db'), { recursive: true });
  await fs.writeFile(
    path.join(repo, 'src', 'routes', 'orders.js'),
    "import { createOrder } from '../services/order.js';\nexport function postOrder(req, res) {\n  return createOrder(req.body.item);\n}\n",
    'utf8'
  );
  await fs.writeFile(
    path.join(repo, 'src', 'services', 'order.js'),
    "import { insertOrder } from '../db/orders.js';\nexport function createOrder(item) {\n  return insertOrder(item);\n}\n",
    'utf8'
  );
  const sqli = 'INS' + 'ERT INTO orders(item) VALUES (' + "'${item}'" + ')';
  await fs.writeFile(
    path.join(repo, 'src', 'db', 'orders.js'),
    `export function insertOrder(item) {\n  return db.query(\`${sqli}\`);\n}\n`,
    'utf8'
  );

  const res = await runAudit({ root: repo, mode: 'diff', queryOsv: false });
  assert.equal(res.verdict, 'fails');
  const sqliFinding = res.failingFindings.find(f => f.cwe === 'CWE-89');
  assert.ok(sqliFinding, 'Expected reachable CWE-89 finding from 2-hop chain');
  assert.ok(sqliFinding.remediation.includes('src/routes/orders.js'));
  assert.ok(sqliFinding.remediation.includes('src/services/order.js'));
});

test('named-import isolation keeps unimported helper SQLi as CANT TELL unverified-sink', async t => {
  const repo = await makeTempGitRepo();
  t.after(() => fs.rm(repo, { recursive: true, force: true }));

  await fs.mkdir(path.join(repo, 'src', 'routes'), { recursive: true });
  await fs.mkdir(path.join(repo, 'src', 'db'), { recursive: true });
  await fs.writeFile(
    path.join(repo, 'src', 'routes', 'health.js'),
    "import { ping } from '../db/queries.js';\nexport function getHealth(req, res) {\n  return ping(req.query.v);\n}\n",
    'utf8'
  );
  const domSink = 'el.' + 'innerHTML = raw;';
  await fs.writeFile(
    path.join(repo, 'src', 'db', 'queries.js'),
    `export function ping() { return 'pong'; }\nexport function unusedUnsafe(el, raw) {\n  ${domSink}\n}\n`,
    'utf8'
  );

  const res = await runAudit({ root: repo, mode: 'diff', queryOsv: false, failOn: 'high' });
  assert.equal(res.verdict, 'cant-tell');
  assert.ok(res.cantTellReasons.some(r => r.code === 'unverified-sink'));
});

test('HTML templates skip tutorial prose while catching inline <script> sinks and high-certainty secrets', async t => {
  const repo = await makeTempGitRepo();
  t.after(() => fs.rm(repo, { recursive: true, force: true }));

  const sqlWord = 'SEL' + 'ECT * FROM users WHERE';
  const pickleCall = 'pickle.' + 'loads()';
  const osSys = 'os.' + 'system("id")';
  await fs.mkdir(path.join(repo, 'templates'), { recursive: true });
  await fs.writeFile(
    path.join(repo, 'templates', 'secure-fix.html'),
    [
      '<!doctype html>',
      '<ul>',
      `  <li>Never use ${pickleCall} with untrusted input.</li>`,
      `  <li><code>${osSys}</code></li>`,
      `  <li><pre>${sqlWord} password = '$password'</pre></li>`,
      '</ul>'
    ].join('\n') + '\n',
    'utf8'
  );

  const cleanHtml = await runAudit({ root: repo, mode: 'full', queryOsv: false, failOn: 'high' });
  assert.equal(cleanHtml.verdict, 'holds');
  assert.equal(cleanHtml.findings.length, 0);

  await fs.mkdir(path.join(repo, 'views'), { recursive: true });
  const evalCall = 'ev' + 'al(location.hash.slice(1))';
  const awsTok = 'AKIA' + '1234567890ABCDEF';
  await fs.writeFile(
    path.join(repo, 'views', 'page.html'),
    [
      `<p>Support key: ${awsTok}</p>`,
      '<script>',
      `  ${evalCall};`,
      '</script>'
    ].join('\n') + '\n',
    'utf8'
  );

  const riskyHtml = await runAudit({ root: repo, mode: 'diff', queryOsv: false, failOn: 'high' });
  assert.equal(riskyHtml.verdict, 'fails');
  assert.ok(riskyHtml.failingFindings.some(f => f.cwe === 'CWE-798' && f.location.startsWith('views/page.html:')));
  assert.ok(riskyHtml.failingFindings.some(f => f.cwe === 'CWE-94' && f.location.startsWith('views/page.html:')));
});
