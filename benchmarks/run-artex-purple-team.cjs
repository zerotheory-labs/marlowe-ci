const fs = require('node:fs/promises');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { performance } = require('node:perf_hooks');
const { runAudit } = require('../src/engine/verdict.cjs');
const { analyzeLogs } = require('../src/core/cyber-analyzers.cjs');

const execFileAsync = promisify(execFile);
const BROWSER_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function git(cwd, args) {
  await execFileAsync('git', args, { cwd });
}

async function createGitRepo(files = {}) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'marlowe-artex-pt-'));
  await git(dir, ['init', '-q']);
  await git(dir, ['config', 'user.email', 'bench@zerotheorylabs.com']);
  await git(dir, ['config', 'user.name', 'Zero Theory Bench']);
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    await fs.mkdir(path.dirname(full), { recursive: true });
    await fs.writeFile(full, content, 'utf8');
  }
  await git(dir, ['add', '.']);
  await git(dir, ['commit', '-q', '-m', 'base', '--allow-empty']);
  return dir;
}

async function applyDiffFiles(dir, files = {}) {
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    await fs.mkdir(path.dirname(full), { recursive: true });
    await fs.writeFile(full, content, 'utf8');
  }
}

function startTargetServer({ hardened, logFile }) {
  const logQueue = [];
  let flushing = false;
  const appendLog = entry => {
    logQueue.push(JSON.stringify(entry) + '\n');
  };

  const flushLogs = async () => {
    if (flushing || !logQueue.length) return;
    flushing = true;
    try {
      const chunk = logQueue.splice(0, logQueue.length).join('');
      await fs.appendFile(logFile, chunk, 'utf8');
    } finally {
      flushing = false;
    }
  };

  const server = http.createServer((req, res) => {
    const urlObj = new URL(req.url || '/', 'http://127.0.0.1');
    const reqPath = urlObj.pathname;
    const xff = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    const clientIp = xff || req.socket.remoteAddress || '127.0.0.1';
    const ua = String(req.headers['user-agent'] || '');

    const send = (status, bodyObjOrStr, extraHeaders = {}) => {
      const isStr = typeof bodyObjOrStr === 'string';
      const body = isStr ? bodyObjOrStr : JSON.stringify(bodyObjOrStr);
      const headers = {
        'Content-Type': isStr ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8',
        ...extraHeaders
      };
      appendLog({
        ts: new Date().toISOString(),
        ip: clientIp,
        method: req.method,
        path: req.url,
        status,
        ua
      });
      res.writeHead(status, headers);
      res.end(body);
    };

    if (reqPath === '/assets/app.js.map') {
      if (hardened) return send(404, { error: 'Not found' });
      return send(200, {
        version: 3,
        sources: ['src/auth/oauth.js', 'src/routes/backup.js'],
        routes: ['/oauth/callback', '/oauth/token', '/api/v1/auth/reset-password', '/backup/export']
      });
    }

    if (reqPath === '/openapi.json' || reqPath === ('/api-' + 'docs')) {
      if (hardened) return send(401, { error: 'Authentication required' });
      return send(200, {
        openapi: '3.1.0',
        paths: {
          '/oauth/callback': { get: { parameters: [{ name: 'redirect_uri', in: 'query' }] } },
          '/oauth/token': { post: {} },
          '/api/v1/auth/reset-password': { post: { parameters: [{ name: 'step', in: 'query' }] } },
          '/backup/export': { post: { parameters: [{ name: 'format', in: 'query' }] } },
          '/admin/users': { get: {} }
        }
      });
    }

    if (reqPath === '/oauth/callback') {
      const redirectUri = urlObj.searchParams.get('redirect_uri') || '';
      const stateParam = urlObj.searchParams.get('state') || '';
      if (hardened) {
        if (!stateParam || !redirectUri.startsWith('/') || redirectUri.startsWith('//')) {
          return send(400, { error: 'Invalid OAuth state or disallowed redirect_uri' });
        }
        return send(302, '', { Location: redirectUri });
      }
      return send(302, '', { Location: redirectUri || '/' });
    }

    if (reqPath === '/oauth/token') {
      const grant = urlObj.searchParams.get('grant') || '';
      return send(grant === 'client' ? 401 : 400, {
        error: 'invalid_request',
        hint: 'Provide valid client assertion'
      });
    }

    if (reqPath === '/api/v1/auth/reset-password') {
      const step = urlObj.searchParams.get('step') || '';
      return send(422, {
        error: 'validation_failed',
        detail: `Invalid reset step "${step}"`
      });
    }

    if (reqPath === '/backup/export') {
      const originHdr = String(req.headers.origin || '');
      if (hardened) {
        const authHdr = String(req.headers.authorization || '');
        const corsHeaders = originHdr === 'https://app.example.com'
          ? { ['Access-Control-' + 'Allow-Origin']: 'https://app.example.com', ['Access-Control-' + 'Allow-Credentials']: 'true' }
          : {};
        if (!authHdr.startsWith('Bearer ')) {
          return send(401, { error: 'Admin authorization required' }, corsHeaders);
        }
        return send(200, { exported: true }, corsHeaders);
      }
      const corsHeaders = originHdr
        ? { ['Access-Control-' + 'Allow-Origin']: originHdr, ['Access-Control-' + 'Allow-Credentials']: 'true' }
        : {};
      if (urlObj.searchParams.get('format') !== 'json') {
        return send(422, { error: 'Missing required query parameter: format=json' }, corsHeaders);
      }
      return send(200, { exported: true, tenants: ['acme-demo'] }, corsHeaders);
    }

    if (reqPath === '/admin/users') {
      if (hardened) return send(401, { error: 'Unauthorized' });
      return send(403, { error: 'Forbidden' });
    }

    if (['/', '/styles/main.css', '/img/logo.svg', '/pricing', '/docs'].includes(reqPath)) {
      return send(200, { ok: true, page: reqPath });
    }

    return send(404, { error: 'Not found' });
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({
        baseUrl: `http://127.0.0.1:${addr.port}`,
        flushLogs,
        async close() {
          await flushLogs();
          await new Promise(r => server.close(() => r()));
        }
      });
    });
  });
}

async function runArtexStyleAttacker(baseUrl) {
  let reqIdx = 0;
  const hit = async (method, reqPath, { headers = {}, redirect = 'follow' } = {}) => {
    reqIdx++;
    const ip = `198.51.100.${10 + (reqIdx % 12)}`;
    const res = await fetch(`${baseUrl}${reqPath}`, {
      method,
      redirect,
      headers: {
        'User-Agent': BROWSER_UA,
        'X-Forwarded-For': ip,
        ...headers
      }
    });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    await sleep(20);
    return { status: res.status, headers: res.headers, text, json };
  };

  // Phase 1: Edge Recon (sourcemap + OpenAPI harvesting)
  const mapRes = await hit('GET', '/assets/app.js.map');
  const specRes = await hit('GET', '/openapi.json');
  const reconHarvested =
    (mapRes.status === 200 && Boolean(mapRes.json?.routes?.length)) ||
    (specRes.status === 200 && Boolean(specRes.json?.paths));

  // Phase 2: Machine-paced 4xx validation/error adaptation loop
  await hit('POST', '/oauth/token?grant=code');
  await hit('POST', '/oauth/token?grant=client');
  await hit('POST', '/api/v1/auth/reset-password?step=1');
  await hit('POST', '/api/v1/auth/reset-password?step=2');
  await hit('GET', '/admin/users');

  // Phase 3: Exploit attempts driven by harvested routes + 422 feedback
  const oauthPath = specRes.json?.paths?.['/oauth/callback'] ? '/oauth/callback' : '/oauth/callback';
  const redirRes = await hit('GET', `${oauthPath}?redirect_uri=https://attacker.invalid/steal`, { redirect: 'manual' });
  const loc = redirRes.headers.get('location') || '';
  const openRedirectHijacked = redirRes.status === 302 && loc.startsWith('https://attacker.invalid');

  const backupPath = specRes.json?.paths?.['/backup/export'] ? '/backup/export' : '/backup/export';
  const attackerOrigin = 'https://attacker.invalid';
  let backupRes = await hit('POST', backupPath, { headers: { Origin: attackerOrigin } });
  const corsOriginReflected =
    backupRes.headers.get('access-control-allow-origin') === attackerOrigin &&
    backupRes.headers.get('access-control-allow-credentials') === 'true';
  if (backupRes.status === 422 && /format=json/.test(backupRes.text)) {
    backupRes = await hit('POST', `${backupPath}?format=json`, { headers: { Origin: attackerOrigin } });
  }
  const unauthBackupExported = backupRes.status === 200 && Boolean(backupRes.json?.exported);

  const compromises = [
    reconHarvested ? 'recon-harvested' : '',
    openRedirectHijacked ? 'oauth-open-redirect' : '',
    corsOriginReflected ? 'credentialed-cors-reflection' : '',
    unauthBackupExported ? 'unauth-backup-export' : ''
  ].filter(Boolean);

  return {
    totalRequests: reqIdx,
    reconHarvested,
    openRedirectHijacked,
    corsOriginReflected,
    unauthBackupExported,
    compromises,
    compromisesCount: compromises.length
  };
}

async function runBenignHumanSession(baseUrl) {
  const paths = ['/', '/styles/main.css', '/img/logo.svg', '/pricing', '/docs'];
  let count = 0;
  for (const p of paths) {
    await fetch(`${baseUrl}${p}`, {
      headers: {
        'User-Agent': BROWSER_UA,
        'X-Forwarded-For': '203.0.113.55'
      }
    });
    count++;
    await sleep(15);
  }
  return { totalRequests: count };
}

function unhardenedFiles() {
  return {
    'public/assets/app.js.map': '{"version":3,"sources":["src/auth/oauth.js","src/routes/backup.js"]}\n',
    'src/server.js': [
      'export function mountApp(app, swaggerUi, spec, runBackup) {',
      '  app.use("/api-' + 'docs", swaggerUi.serve, swaggerUi.setup(spec));',
      '  app.post("/backup/export", { ' + 'skipAuth' + ': true }, runBackup);',
      '}'
    ].join('\n'),
    'src/auth/oauth.js': [
      'export function initOauth(passport) {',
      '  passport.use({ ' + 'state' + ': false });',
      '}',
      'export const corsOpts = { ' + 'origin' + ': true, ' + 'credentials' + ': true };',
      'export function callback(req, res) {',
      '  return res.' + 'redirect(req.query.redirect_uri);',
      '}'
    ].join('\n'),
    'test/server.test.js': 'test("server", () => {});\n'
  };
}

function hardenedFiles() {
  return {
    'src/server.js': [
      'const isDev = process.env.NODE_ENV !== "production";',
      'export function mountApp(app, requireAuth, swaggerUi, spec, runBackup) {',
      '  if (isDev) { app.use("/api-' + 'docs", requireAuth, swaggerUi.serve, swaggerUi.setup(spec)); }',
      '  app.post("/backup/export", requireAuth, runBackup);',
      '}'
    ].join('\n'),
    'src/auth/oauth.js': [
      'const ALLOWED_REDIRECTS = new Set(["/dashboard", "/account"]);',
      'export function initOauth(passport) {',
      '  passport.use({ state: true });',
      '}',
      'export const corsOpts = { origin: ["https://app.example.com"], credentials: true };',
      'export function callback(req, res) {',
      '  const nextUrl = String(req.query.redirect_uri || "/");',
      '  if (!nextUrl.startsWith("/") && !ALLOWED_REDIRECTS.has(nextUrl)) return res.status(400).end();',
      '  return res.' + 'redirect(nextUrl);',
      '}'
    ].join('\n'),
    'test/server.test.js': 'test("server", () => {});\n'
  };
}

async function runPurpleTeamHarness({ saveReport = false } = {}) {
  const workDir = await fs.mkdtemp(path.join(os.tmpdir(), 'marlowe-artex-logs-'));
  const t0 = performance.now();
  let repoBefore = null;
  let repoAfter = null;

  try {
    // Phase A: Before Marlowe Gate (unhardened codebase + live attack)
    repoBefore = await createGitRepo({});
    await applyDiffFiles(repoBefore, unhardenedFiles());
    const auditBefore = await runAudit({ root: repoBefore, mode: 'diff', queryOsv: false, failOn: 'high' });

    const beforeLogPath = path.join(workDir, 'access-before.jsonl');
    const srvBefore = await startTargetServer({ hardened: false, logFile: beforeLogPath });
    let attackBefore;
    try {
      attackBefore = await runArtexStyleAttacker(srvBefore.baseUrl);
    } finally {
      await srvBefore.close();
    }
    const logBefore = await analyzeLogs(beforeLogPath, 'access-before.jsonl', {}, new AbortController().signal);

    // Phase B: After Marlowe Gate Hardening (hardened codebase + identical live attack)
    repoAfter = await createGitRepo({});
    await applyDiffFiles(repoAfter, hardenedFiles());
    const auditAfter = await runAudit({ root: repoAfter, mode: 'diff', queryOsv: false, failOn: 'high' });

    const afterLogPath = path.join(workDir, 'access-after.jsonl');
    const srvAfter = await startTargetServer({ hardened: true, logFile: afterLogPath });
    let attackAfter;
    try {
      attackAfter = await runArtexStyleAttacker(srvAfter.baseUrl);
    } finally {
      await srvAfter.close();
    }
    const logAfter = await analyzeLogs(afterLogPath, 'access-after.jsonl', {}, new AbortController().signal);

    // Phase C: Live Benign Human Session
    const benignLogPath = path.join(workDir, 'access-benign.jsonl');
    const srvBenign = await startTargetServer({ hardened: true, logFile: benignLogPath });
    let benignSession;
    try {
      benignSession = await runBenignHumanSession(srvBenign.baseUrl);
    } finally {
      await srvBenign.close();
    }
    const logBenign = await analyzeLogs(benignLogPath, 'access-benign.jsonl', {}, new AbortController().signal);

    const report = {
      generatedAt: new Date().toISOString(),
      harnessType: 'sealed-loopback-http-purple-team',
      bindHost: '127.0.0.1',
      nodeVersion: process.version,
      durationMs: Math.round((performance.now() - t0) * 100) / 100,
      beforeHardening: {
        preMergeVerdict: auditBefore.verdict,
        preMergeRuleIds: [...new Set([
          ...auditBefore.findings.map(f => f.ruleId).filter(Boolean),
          ...auditBefore.cantTellReasons.map(r => r.code).filter(Boolean)
        ])],
        liveAttack: attackBefore,
        dfirLog: {
          analyzedLines: logBefore.analyzedLines,
          scannerUaHits: logBefore.signatureCounts['scanner-ua'] || 0,
          detected: logBefore.agenticBehavior.detected,
          confidence: logBefore.agenticBehavior.confidence,
          ruleId: logBefore.agenticBehavior.ruleId,
          indicators: logBefore.agenticBehavior.indicators.map(x => x.id),
          burstMetrics: logBefore.agenticBehavior.burstMetrics
        }
      },
      afterHardening: {
        preMergeVerdict: auditAfter.verdict,
        preMergeFindingsCount: auditAfter.findings.length,
        preMergeCantTellCount: auditAfter.cantTellReasons.length,
        liveAttack: attackAfter,
        dfirLog: {
          analyzedLines: logAfter.analyzedLines,
          scannerUaHits: logAfter.signatureCounts['scanner-ua'] || 0,
          detected: logAfter.agenticBehavior.detected,
          confidence: logAfter.agenticBehavior.confidence,
          ruleId: logAfter.agenticBehavior.ruleId,
          indicators: logAfter.agenticBehavior.indicators.map(x => x.id),
          burstMetrics: logAfter.agenticBehavior.burstMetrics
        }
      },
      benignHumanBaseline: {
        totalRequests: benignSession.totalRequests,
        analyzedLines: logBenign.analyzedLines,
        detected: logBenign.agenticBehavior.detected,
        alertsCount: logBenign.alerts.length
      }
    };

    if (saveReport) {
      const outPath = path.join(__dirname, 'artex-purple-team-results.json');
      await fs.writeFile(outPath, JSON.stringify(report, null, 2) + '\n', 'utf8');
    }
    return report;
  } finally {
    await fs.rm(workDir, { recursive: true, force: true });
    if (repoBefore) await fs.rm(repoBefore, { recursive: true, force: true });
    if (repoAfter) await fs.rm(repoAfter, { recursive: true, force: true });
  }
}

if (require.main === module) {
  runPurpleTeamHarness({ saveReport: true })
    .then(report => {
      const b = report.beforeHardening;
      const a = report.afterHardening;
      const h = report.benignHumanBaseline;
      process.stdout.write(
        `\nZero Theory Labs · Live Localhost ARTEX Purple-Team Run (${report.durationMs}ms · 127.0.0.1)\n` +
        `Phase A (Before Marlowe Gate): Pre-merge=${b.preMergeVerdict.toUpperCase()} | Compromises=${b.liveAttack.compromisesCount}/4 (${b.liveAttack.compromises.join(', ')}) | DFIR=${b.dfirLog.ruleId} (${b.dfirLog.confidence}, scannerUaHits=${b.dfirLog.scannerUaHits})\n` +
        `Phase B (After Hardening):     Pre-merge=${a.preMergeVerdict.toUpperCase()} | Compromises=${a.liveAttack.compromisesCount}/4 | DFIR=${a.dfirLog.ruleId} (${a.dfirLog.confidence}, scannerUaHits=${a.dfirLog.scannerUaHits})\n` +
        `Phase C (Human Browser):       Requests=${h.totalRequests} | ARTEX-BEHAV-001=${h.detected} | Alerts=${h.alertsCount}\n` +
        `Saved report to benchmarks/artex-purple-team-results.json\n`
      );
      const ok =
        b.preMergeVerdict === 'fails' &&
        b.liveAttack.compromisesCount === 4 &&
        b.dfirLog.detected === true &&
        a.preMergeVerdict === 'holds' &&
        a.liveAttack.compromisesCount === 0 &&
        a.dfirLog.detected === true &&
        h.detected === false &&
        h.alertsCount === 0;
      if (!ok) process.exitCode = 1;
    })
    .catch(err => {
      process.stderr.write(`${err.stack || err.message}\n`);
      process.exitCode = 1;
    });
}

module.exports = { runPurpleTeamHarness };
