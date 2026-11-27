const fs = require('node:fs/promises');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { performance } = require('node:perf_hooks');
const { runAudit } = require('../src/engine/verdict.cjs');
const { inspectShirudoTarget } = require('../src/core/shirudo.cjs');

const execFileAsync = promisify(execFile);

const CLEAN_REPOS = [
  { slug: 'express', repo: 'expressjs/express', url: 'https://github.com/expressjs/express.git', ecosystem: 'JS', role: 'clean-production' },
  { slug: 'fastify', repo: 'fastify/fastify', url: 'https://github.com/fastify/fastify.git', ecosystem: 'JS', role: 'clean-production' },
  { slug: 'hono', repo: 'honojs/hono', url: 'https://github.com/honojs/hono.git', ecosystem: 'TS', role: 'clean-production' },
  { slug: 'koa', repo: 'koajs/koa', url: 'https://github.com/koajs/koa.git', ecosystem: 'JS', role: 'clean-production' },
  { slug: 'zod', repo: 'colinhacks/zod', url: 'https://github.com/colinhacks/zod.git', ecosystem: 'TS', role: 'clean-production' },
  { slug: 'flask', repo: 'pallets/flask', url: 'https://github.com/pallets/flask.git', ecosystem: 'Python', role: 'clean-production' },
  { slug: 'fastapi', repo: 'fastapi/fastapi', url: 'https://github.com/fastapi/fastapi.git', ecosystem: 'Python', role: 'clean-production' },
  { slug: 'gin', repo: 'gin-gonic/gin', url: 'https://github.com/gin-gonic/gin.git', ecosystem: 'Go', role: 'clean-production' },
  { slug: 'shirudo', repo: 'shirudo-dev/shirudo', url: 'https://github.com/shirudo-dev/shirudo.git', ecosystem: 'eBPF / C / Rust', role: 'clean-production', isShirudo: true }
];

const VULN_REPOS = [
  { slug: 'NodeGoat', repo: 'OWASP/NodeGoat', url: 'https://github.com/OWASP/NodeGoat.git', ecosystem: 'Node.js', role: 'vulnerable-target' },
  { slug: 'juice-shop', repo: 'juice-shop/juice-shop', url: 'https://github.com/juice-shop/juice-shop.git', ecosystem: 'Node.js / TS', role: 'vulnerable-target' },
  { slug: 'pygoat', repo: 'adeyosemanputra/pygoat', url: 'https://github.com/adeyosemanputra/pygoat.git', ecosystem: 'Python / Django', role: 'vulnerable-target', fallbackUrl: 'https://github.com/appsecco/dvna.git', fallbackRepo: 'appsecco/dvna', fallbackEcosystem: 'Node.js' }
];

function parseCliArgs(argv) {
  let corpusDir = '/tmp/marlowe-corpus';
  let outPath = '';
  let prCount = 15;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--dir' && argv[i + 1]) corpusDir = argv[++i];
    else if (argv[i] === '--out' && argv[i + 1]) outPath = argv[++i];
    else if (argv[i] === '--prs' && argv[i + 1]) prCount = Math.max(1, Number(argv[++i]) || 15);
  }
  return { corpusDir, outPath, prCount };
}

function round2(n) {
  return Math.round(n * 100) / 100;
}

function percentile(sortedNums, p) {
  if (!sortedNums.length) return 0;
  const idx = Math.min(sortedNums.length - 1, Math.max(0, Math.ceil((p / 100) * sortedNums.length) - 1));
  return sortedNums[idx];
}

async function runGit(cwd, args, timeout = 120000) {
  return execFileAsync('git', args, {
    cwd,
    timeout,
    maxBuffer: 16 * 1024 * 1024,
    env: { ...process.env, GIT_TERMINAL_PROMPT: '0', LC_ALL: 'C' }
  });
}

async function ensureRepoClone(entry, corpusDir, depth) {
  const targetDir = path.join(corpusDir, entry.slug);
  let activeRepo = entry.repo;
  let activeEcosystem = entry.ecosystem;
  let needsClone = true;

  try {
    await fs.access(path.join(targetDir, '.git'));
    if (depth > 1) {
      const { stdout } = await runGit(targetDir, ['rev-list', '--count', 'HEAD']);
      if (Number(stdout.trim()) >= 20) needsClone = false;
    } else {
      needsClone = false;
    }
  } catch {
    needsClone = true;
  }

  if (needsClone) {
    await fs.rm(targetDir, { recursive: true, force: true });
    await fs.mkdir(corpusDir, { recursive: true });
    try {
      await runGit(corpusDir, ['clone', '--depth', String(depth), '--quiet', entry.url, targetDir]);
    } catch (err) {
      if (!entry.fallbackUrl) throw err;
      await fs.rm(targetDir, { recursive: true, force: true });
      await runGit(corpusDir, ['clone', '--depth', String(depth), '--quiet', entry.fallbackUrl, targetDir]);
      activeRepo = entry.fallbackRepo;
      activeEcosystem = entry.fallbackEcosystem;
    }
  }

  const { stdout: headSha } = await runGit(targetDir, ['rev-parse', 'HEAD']);
  const { stdout: shortSha } = await runGit(targetDir, ['rev-parse', '--short', 'HEAD']);
  return {
    targetDir,
    headSha: headSha.trim(),
    commitSha: shortSha.trim(),
    repo: activeRepo,
    ecosystem: activeEcosystem
  };
}

function summarizeCategories(items, keyFn) {
  const counts = {};
  for (const item of items) {
    const k = keyFn(item);
    counts[k] = (counts[k] || 0) + 1;
  }
  return counts;
}

function summarizeFinding(f) {
  return {
    ruleId: f.ruleId || f.cwe || '',
    severity: f.severity,
    cwe: f.cwe || '',
    category: f.category,
    title: f.title,
    location: f.location,
    evidence: String(f.evidence || '').slice(0, 140)
  };
}

async function runPrDiffReplay(targetDir, headSha, prCount) {
  const { stdout: listOut } = await runGit(targetDir, ['rev-list', '--no-merges', '-n', '22', 'HEAD']);
  const candidates = listOut.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
  const commits = [];
  for (const sha of candidates) {
    if (commits.length >= prCount) break;
    try {
      await runGit(targetDir, ['rev-parse', '--verify', `${sha}^`]);
      commits.push(sha);
    } catch {
      // Skip root commits with no parent.
    }
  }

  const perCommit = [];
  try {
    for (const sha of commits) {
      await runGit(targetDir, ['checkout', '--quiet', '--detach', sha]);
      const shortSha = sha.slice(0, 7);
      const t0 = performance.now();
      const audit = await runAudit({
        root: targetDir,
        mode: 'diff',
        baseRef: `${sha}^`,
        queryOsv: false,
        failOn: 'high'
      });
      const durationMs = round2(performance.now() - t0);
      perCommit.push({
        sha: shortSha,
        verdict: audit.verdict,
        verdictLabel: audit.verdictLabel,
        durationMs,
        changedFiles: audit.changedFiles,
        failingCount: audit.failingFindings.length,
        cantTellCount: audit.cantTellReasons.length,
        topFindings: audit.failingFindings.slice(0, 3).map(summarizeFinding),
        topCantTell: audit.cantTellReasons.slice(0, 3).map(r => ({
          code: r.code,
          path: r.path,
          line: r.line,
          message: r.message
        }))
      });
    }
  } finally {
    await runGit(targetDir, ['checkout', '--quiet', '--detach', headSha]).catch(() => {});
  }

  const durations = perCommit.map(c => c.durationMs).sort((a, b) => a - b);
  return {
    commitsTested: perCommit.length,
    holdsCount: perCommit.filter(c => c.verdict === 'holds').length,
    cantTellCount: perCommit.filter(c => c.verdict === 'cant-tell').length,
    failsCount: perCommit.filter(c => c.verdict === 'fails').length,
    p50Ms: round2(percentile(durations, 50)),
    p95Ms: round2(percentile(durations, 95)),
    durations,
    nonHoldsSamples: perCommit.filter(c => c.verdict !== 'holds')
  };
}

async function main() {
  const { corpusDir, outPath, prCount } = parseCliArgs(process.argv.slice(2));
  const cleanResults = [];
  const vulnerableResults = [];
  const allPrDurations = [];

  for (const entry of CLEAN_REPOS) {
    const info = await ensureRepoClone(entry, corpusDir, 25);
    const prReplayRaw = await runPrDiffReplay(info.targetDir, info.headSha, prCount);
    allPrDurations.push(...prReplayRaw.durations);
    const { durations: _drop, ...prReplay } = prReplayRaw;

    const t0 = performance.now();
    const audit = await runAudit({
      root: info.targetDir,
      mode: 'full',
      queryOsv: false,
      failOn: 'high'
    });
    const elapsedMs = round2(performance.now() - t0);

    let shirudoDirectAudit = null;
    if (entry.isShirudo) {
      const sAudit = await inspectShirudoTarget(info.targetDir, '.');
      shirudoDirectAudit = {
        verdict: sAudit.verdict,
        inspectedCount: sAudit.inspectedCount,
        findingsCount: sAudit.findings.length,
        cantTellCount: sAudit.cantTellReasons.length,
        findings: sAudit.findings.slice(0, 15).map(summarizeFinding),
        cantTellReasons: sAudit.cantTellReasons.slice(0, 15)
      };
    }

    const rec = {
      slug: entry.slug,
      repo: info.repo,
      ecosystem: info.ecosystem,
      commitSha: info.commitSha,
      role: entry.role,
      verdict: audit.verdict,
      verdictLabel: audit.verdictLabel,
      scannedFiles: audit.scannedFiles,
      durationMs: elapsedMs,
      totalFindings: audit.findings.length,
      failingFindings: audit.failingFindings.length,
      cantTellCount: audit.cantTellReasons.length,
      ruleBreakdown: summarizeCategories(audit.findings, f => f.ruleId || f.cwe || f.category || 'unknown'),
      cantTellBreakdown: summarizeCategories(audit.cantTellReasons, r => r.code || 'unknown'),
      sampleFindings: audit.findings.slice(0, 15).map(summarizeFinding),
      sampleCantTell: audit.cantTellReasons.slice(0, 15).map(r => ({
        code: r.code,
        path: r.path,
        line: r.line,
        message: r.message
      })),
      prReplay,
      ...(shirudoDirectAudit ? { shirudoDirectAudit } : {})
    };
    cleanResults.push(rec);

    process.stdout.write(
      `\n=== [CLEAN] ${rec.repo} @ ${rec.commitSha} (${rec.ecosystem}) ===\n` +
      `PR Replay (${prReplay.commitsTested} diffs): HOLDS=${prReplay.holdsCount}, CANT_TELL=${prReplay.cantTellCount}, FAILS=${prReplay.failsCount} | p50=${prReplay.p50Ms}ms, p95=${prReplay.p95Ms}ms\n` +
      `Full Sweep (${rec.scannedFiles} files, ${rec.durationMs}ms): ${rec.verdictLabel} | Findings=${rec.totalFindings} (failing=${rec.failingFindings}) | CantTell=${rec.cantTellCount}\n`
    );
    if (rec.failingFindings > 0) {
      for (const sf of rec.sampleFindings.filter(f => f.severity === 'high' || f.severity === 'critical' || f.category === 'secrets')) {
        process.stdout.write(`  [FAIL ${sf.ruleId}] ${sf.title} @ ${sf.location} :: ${sf.evidence}\n`);
      }
    }
    if (prReplay.failsCount > 0) {
      for (const c of prReplay.nonHoldsSamples.filter(x => x.verdict === 'fails')) {
        process.stdout.write(`  [PR FAIL ${c.sha}] ${JSON.stringify(c.topFindings)}\n`);
      }
    }
    if (rec.shirudoDirectAudit) {
      process.stdout.write(
        `  Shirudo Direct Audit: verdict=${rec.shirudoDirectAudit.verdict}, inspected=${rec.shirudoDirectAudit.inspectedCount}, findings=${rec.shirudoDirectAudit.findingsCount}, cantTell=${rec.shirudoDirectAudit.cantTellCount}\n`
      );
    }
  }

  for (const entry of VULN_REPOS) {
    const info = await ensureRepoClone(entry, corpusDir, 1);
    const t0 = performance.now();
    const audit = await runAudit({
      root: info.targetDir,
      mode: 'full',
      queryOsv: false,
      failOn: 'high'
    });
    const elapsedMs = round2(performance.now() - t0);

    const rec = {
      slug: entry.slug,
      repo: info.repo,
      ecosystem: info.ecosystem,
      commitSha: info.commitSha,
      role: entry.role,
      verdict: audit.verdict,
      verdictLabel: audit.verdictLabel,
      scannedFiles: audit.scannedFiles,
      durationMs: elapsedMs,
      totalFindings: audit.findings.length,
      failingFindings: audit.failingFindings.length,
      cantTellCount: audit.cantTellReasons.length,
      ruleBreakdown: summarizeCategories(audit.findings, f => f.ruleId || f.cwe || f.category || 'unknown'),
      cweBreakdown: summarizeCategories(audit.failingFindings, f => f.cwe || f.ruleId || 'other'),
      sampleFindings: audit.findings.slice(0, 15).map(summarizeFinding)
    };
    vulnerableResults.push(rec);

    process.stdout.write(
      `\n=== [VULN] ${rec.repo} @ ${rec.commitSha} (${rec.ecosystem}) ===\n` +
      `Full Sweep (${rec.scannedFiles} files, ${rec.durationMs}ms): ${rec.verdictLabel} | Findings=${rec.totalFindings} (failing=${rec.failingFindings})\n` +
      `CWE/Rule Failing Breakdown: ${JSON.stringify(rec.cweBreakdown)}\n`
    );
  }

  const allRepos = [...cleanResults, ...vulnerableResults];
  const sortedPr = [...allPrDurations].sort((a, b) => a - b);
  const totalPrDiffs = cleanResults.reduce((s, r) => s + r.prReplay.commitsTested, 0);
  const prHoldsCount = cleanResults.reduce((s, r) => s + r.prReplay.holdsCount, 0);
  const prCantTellCount = cleanResults.reduce((s, r) => s + r.prReplay.cantTellCount, 0);
  const prFailsCount = cleanResults.reduce((s, r) => s + r.prReplay.failsCount, 0);
  const vulnerableCweBreakdown = {};
  for (const r of vulnerableResults) {
    for (const [k, v] of Object.entries(r.cweBreakdown || {})) {
      vulnerableCweBreakdown[k] = (vulnerableCweBreakdown[k] || 0) + v;
    }
  }

  const summary = {
    totalRepos: allRepos.length,
    cleanReposCount: cleanResults.length,
    vulnerableReposCount: vulnerableResults.length,
    totalPrDiffs,
    prHoldsCount,
    prCantTellCount,
    prFailsCount,
    prFalseFailRatePct: totalPrDiffs ? round2((prFailsCount / totalPrDiffs) * 100) : 0,
    prP50Ms: round2(percentile(sortedPr, 50)),
    prP95Ms: round2(percentile(sortedPr, 95)),
    prMeanMs: sortedPr.length ? round2(sortedPr.reduce((a, b) => a + b, 0) / sortedPr.length) : 0,
    cleanFullRepoFailsRepos: cleanResults.filter(r => r.failingFindings > 0).length,
    vulnerableTotalFailing: vulnerableResults.reduce((s, r) => s + r.failingFindings, 0),
    vulnerableReposCaught: vulnerableResults.filter(r => r.verdict === 'fails').length,
    vulnerableCweBreakdown
  };

  const report = {
    generatedAt: new Date().toISOString(),
    nodeVersion: process.version,
    platform: `${process.platform}-${process.arch}`,
    summary,
    repos: allRepos
  };

  process.stdout.write(`\n=== SUMMARY ===\n${JSON.stringify(summary, null, 2)}\n`);

  if (outPath) {
    const absOut = path.resolve(outPath);
    await fs.writeFile(absOut, JSON.stringify(report, null, 2) + '\n', 'utf8');
    process.stdout.write(`Saved corpus audit report to ${outPath}\n`);
  }
}

main().catch(err => {
  process.stderr.write(`${err.stack || err.message}\n`);
  process.exitCode = 1;
});
