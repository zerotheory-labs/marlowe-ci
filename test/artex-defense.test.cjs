const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { scanArtexEdgeSurface } = require('../src/core/artex-defense.cjs');
const { analyzeLogs } = require('../src/core/cyber-analyzers.cjs');
const { handlePostToolUse } = require('../src/integrations/claude-hooks.cjs');
const { runPurpleTeamHarness } = require('../benchmarks/run-artex-purple-team.cjs');

async function withTmpDir(fn) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'marlowe-artex-'));
  try {
    return await fn(dir);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}

test('ARTEX-EDGE-001 flags unauthenticated Swagger/GraphQL introspection and sourcemap exposure while honoring dev guards', () => {
  const exposed = scanArtexEdgeSurface('src/server.js', [
    'const apollo = new ApolloServer({ typeDefs, resolvers, introspection: true });',
    'app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(spec));'
  ].join('\n'));
  assert.equal(exposed.findings.filter(f => f.ruleId === 'ARTEX-EDGE-001').length, 2);

  const mapLeak = scanArtexEdgeSurface('public/assets/app.js.map', '{"version":3,"sources":["src/auth.js"]}');
  assert.ok(mapLeak.cantTellReasons.some(r => r.code === 'ARTEX-EDGE-001'));

  const viteMap = scanArtexEdgeSurface('vite.config.js', 'export default { build: { sourcemap: true } };');
  assert.ok(viteMap.cantTellReasons.some(r => r.code === 'ARTEX-EDGE-001'));

  const guarded = scanArtexEdgeSurface('src/server.js', [
    'const isDev = process.env.NODE_ENV !== "production";',
    'const apollo = new ApolloServer({ typeDefs, resolvers, introspection: process.env.NODE_ENV !== "production" });',
    'if (isDev) { app.use("/api-docs", requireAuth, swaggerUi.serve); }'
  ].join('\n'));
  assert.equal(guarded.findings.length, 0);
  assert.equal(guarded.cantTellReasons.length, 0);
});

test('ARTEX-EDGE-002 and ARTEX-EDGE-003 catch OAuth state bypasses, open redirects, credentialed CORS, and unauth admin routes', () => {
  const oauthBad = scanArtexEdgeSurface('src/auth/oauth.js', [
    'passport.use(new OAuth2Strategy({ state: false }, verify));',
    'app.get("/callback", (req, res) => { return res.redirect(req.query.redirect_uri); });',
    'const resetToken = createHash("' + 'sha' + '1").update(String(Date.now())).digest("hex");',
    'app.use(cors({ origin: true, credentials: true }));'
  ].join('\n'));
  const rules = new Set(oauthBad.findings.map(f => f.ruleId));
  assert.ok(rules.has('ARTEX-EDGE-002'));
  assert.equal(oauthBad.findings.filter(f => f.ruleId === 'ARTEX-EDGE-002').length, 4);

  const backupBypass = scanArtexEdgeSurface('src/routes/ops.js', [
    'app.post("/backup/export", { skipAuth: true }, runBackup);'
  ].join('\n'));
  assert.ok(backupBypass.findings.some(f => f.ruleId === 'ARTEX-EDGE-003'));

  const unauthAdmin = scanArtexEdgeSurface('src/routes/admin.js', [
    'app.get("/admin/users", (req, res) => res.json({ users: [] }));'
  ].join('\n'));
  assert.ok(unauthAdmin.cantTellReasons.some(r => r.code === 'ARTEX-EDGE-003'));

  const hardenedAdmin = scanArtexEdgeSurface('src/routes/admin.js', [
    'app.get("/admin/users", requireAuth, (req, res) => res.json({ users: [] }));'
  ].join('\n'));
  assert.equal(hardenedAdmin.findings.length, 0);
  assert.equal(hardenedAdmin.cantTellReasons.length, 0);
});

test('ARTEX-BEHAV-001 detects machine-speed ARTEX attack loop despite rotated IPs and browser UA while ignoring human traffic', async () => {
  await withTmpDir(async dir => {
    const artexTrace = [
      { ts: '2026-11-26T18:00:00.000Z', ip: '198.51.100.11', method: 'GET', path: '/assets/app.js.map', status: 200, ua: 'Mozilla/5.0 Chrome/128.0' },
      { ts: '2026-11-26T18:00:00.450Z', ip: '198.51.100.12', method: 'GET', path: '/openapi.json', status: 200, ua: 'Mozilla/5.0 Chrome/128.0' },
      { ts: '2026-11-26T18:00:00.900Z', ip: '198.51.100.13', method: 'POST', path: '/oauth/token?grant=code', status: 400, ua: 'Mozilla/5.0 Chrome/128.0' },
      { ts: '2026-11-26T18:00:01.350Z', ip: '198.51.100.14', method: 'POST', path: '/oauth/token?grant=client', status: 401, ua: 'Mozilla/5.0 Chrome/128.0' },
      { ts: '2026-11-26T18:00:01.800Z', ip: '198.51.100.15', method: 'POST', path: '/api/v1/auth/reset-password?step=1', status: 422, ua: 'Mozilla/5.0 Chrome/128.0' },
      { ts: '2026-11-26T18:00:02.250Z', ip: '198.51.100.16', method: 'POST', path: '/api/v1/auth/reset-password?step=2', status: 422, ua: 'Mozilla/5.0 Chrome/128.0' },
      { ts: '2026-11-26T18:00:02.700Z', ip: '198.51.100.17', method: 'GET', path: '/api/v1/users/me', status: 403, ua: 'Mozilla/5.0 Chrome/128.0' },
      { ts: '2026-11-26T18:00:03.150Z', ip: '198.51.100.18', method: 'POST', path: '/admin/impersonate', status: 403, ua: 'Mozilla/5.0 Chrome/128.0' },
      { ts: '2026-11-26T18:00:03.600Z', ip: '198.51.100.19', method: 'POST', path: '/oauth/authorize?redirect_uri=https://evil.test', status: 302, ua: 'Mozilla/5.0 Chrome/128.0' }
    ].map(x => JSON.stringify(x)).join('\n');

    const artexPath = path.join(dir, 'artex-access.jsonl');
    await fs.writeFile(artexPath, artexTrace, 'utf8');
    const res = await analyzeLogs(artexPath, 'artex-access.jsonl', {}, new AbortController().signal);
    assert.equal(res.agenticBehavior.detected, true);
    assert.equal(res.agenticBehavior.confidence, 'high');
    assert.ok(res.agenticBehavior.indicators.some(x => x.id === 'recon-to-auth-pivot'));
    assert.ok(res.agenticBehavior.indicators.some(x => x.id === 'error-adaptation-loop' && x.breakthrough === true));
    assert.ok(res.agenticBehavior.indicators.some(x => x.id === 'machine-speed-enumeration'));
    assert.ok(res.alerts.some(a => a.ruleId === 'ARTEX-BEHAV-001'));

    const humanTrace = [
      { ts: '2026-11-26T18:10:00.000Z', ip: '203.0.113.5', method: 'GET', path: '/', status: 200, ua: 'Mozilla/5.0' },
      { ts: '2026-11-26T18:10:00.120Z', ip: '203.0.113.5', method: 'GET', path: '/styles/main.css', status: 200, ua: 'Mozilla/5.0' },
      { ts: '2026-11-26T18:10:00.250Z', ip: '203.0.113.5', method: 'GET', path: '/img/hero.png', status: 200, ua: 'Mozilla/5.0' },
      { ts: '2026-11-26T18:10:08.500Z', ip: '203.0.113.5', method: 'GET', path: '/pricing', status: 200, ua: 'Mozilla/5.0' },
      { ts: '2026-11-26T18:10:19.000Z', ip: '203.0.113.5', method: 'GET', path: '/docs', status: 200, ua: 'Mozilla/5.0' }
    ].map(x => JSON.stringify(x)).join('\n');
    const humanPath = path.join(dir, 'human-access.jsonl');
    await fs.writeFile(humanPath, humanTrace, 'utf8');
    const clean = await analyzeLogs(humanPath, 'human-access.jsonl', {}, new AbortController().signal);
    assert.equal(clean.agenticBehavior.detected, false);
    assert.equal(clean.alerts.length, 0);

    // Noisy React/Next.js SPA dashboard firing 10 rapid 200 OK API requests with 0 static assets (CDN-cached) must NOT false-positive
    const spaLines = Array.from({ length: 10 }, (_, idx) => JSON.stringify({
      ts: new Date(Date.parse('2026-11-26T18:20:00.000Z') + idx * 15).toISOString(),
      ip: '203.0.113.88',
      method: 'GET',
      path: `/api/widgets/panel-${idx}`,
      status: 200,
      ua: 'Mozilla/5.0 Chrome/128.0'
    })).join('\n');
    const spaPath = path.join(dir, 'spa-dashboard.jsonl');
    await fs.writeFile(spaPath, spaLines, 'utf8');
    const spaRes = await analyzeLogs(spaPath, 'spa-dashboard.jsonl', {}, new AbortController().signal);
    assert.equal(spaRes.agenticBehavior.detected, false);
    assert.equal(spaRes.alerts.length, 0);
  });
});

test('PostToolUse reports ARTEX-EDGE exposure findings back to Claude Code', async () => {
  await withTmpDir(async dir => {
    await fs.mkdir(path.join(dir, 'src'), { recursive: true });
    await fs.writeFile(path.join(dir, 'src/graphql.js'), 'export const server = new ApolloServer({ introspection: true });\n', 'utf8');
    const hookOut = await handlePostToolUse({
      cwd: dir,
      tool_name: 'Write',
      tool_input: { file_path: 'src/graphql.js' }
    });
    assert.ok(hookOut);
    assert.match(hookOut.hookSpecificOutput.additionalContext, /ARTEX-EDGE-001/);
  });
});

test('Live 127.0.0.1 purple-team harness records 4->0 compromises before/after hardening while ARTEX-BEHAV-001 detects attack bursts with 0 human FPs', async () => {
  const report = await runPurpleTeamHarness({ saveReport: false });
  assert.equal(report.beforeHardening.preMergeVerdict, 'fails');
  assert.ok(report.beforeHardening.preMergeRuleIds.includes('ARTEX-EDGE-001'));
  assert.ok(report.beforeHardening.preMergeRuleIds.includes('ARTEX-EDGE-002'));
  assert.ok(report.beforeHardening.preMergeRuleIds.includes('ARTEX-EDGE-003'));
  assert.equal(report.beforeHardening.liveAttack.compromisesCount, 4);
  assert.equal(report.beforeHardening.dfirLog.detected, true);
  assert.equal(report.beforeHardening.dfirLog.confidence, 'high');
  assert.equal(report.beforeHardening.dfirLog.scannerUaHits, 0);

  assert.equal(report.afterHardening.preMergeVerdict, 'holds');
  assert.equal(report.afterHardening.liveAttack.compromisesCount, 0);
  assert.equal(report.afterHardening.dfirLog.detected, true);

  assert.equal(report.benignHumanBaseline.detected, false);
  assert.equal(report.benignHumanBaseline.alertsCount, 0);
});
