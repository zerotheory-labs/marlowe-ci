const fs = require('node:fs/promises');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { performance } = require('node:perf_hooks');
const { runAudit } = require('../src/engine/verdict.cjs');
const { inspectShirudoTarget } = require('../src/core/shirudo.cjs');

const execFileAsync = promisify(execFile);

const CALIBRATION_REPOS = [
  { slug: 'express', repo: 'expressjs/express', url: 'https://github.com/expressjs/express.git', ecosystem: 'JS', cohort: 'calibration' },
  { slug: 'fastify', repo: 'fastify/fastify', url: 'https://github.com/fastify/fastify.git', ecosystem: 'JS', cohort: 'calibration' },
  { slug: 'hono', repo: 'honojs/hono', url: 'https://github.com/honojs/hono.git', ecosystem: 'TS', cohort: 'calibration' },
  { slug: 'koa', repo: 'koajs/koa', url: 'https://github.com/koajs/koa.git', ecosystem: 'JS', cohort: 'calibration' },
  { slug: 'zod', repo: 'colinhacks/zod', url: 'https://github.com/colinhacks/zod.git', ecosystem: 'TS', cohort: 'calibration' },
  { slug: 'flask', repo: 'pallets/flask', url: 'https://github.com/pallets/flask.git', ecosystem: 'Python', cohort: 'calibration' },
  { slug: 'fastapi', repo: 'fastapi/fastapi', url: 'https://github.com/fastapi/fastapi.git', ecosystem: 'Python', cohort: 'calibration' },
  { slug: 'gin', repo: 'gin-gonic/gin', url: 'https://github.com/gin-gonic/gin.git', ecosystem: 'Go', cohort: 'calibration' },
  { slug: 'shirudo', repo: 'shirudo-dev/shirudo', url: 'https://github.com/shirudo-dev/shirudo.git', ecosystem: 'eBPF / C / Rust', cohort: 'calibration', isShirudo: true }
];

// Blind held-out production repos: never inspected or tuned against during rule changes.
const BLIND_HELDOUT_REPOS = [
  { slug: 'axios', repo: 'axios/axios', url: 'https://github.com/axios/axios.git', ecosystem: 'JS', cohort: 'blind-held-out' },
  { slug: 'trpc', repo: 'trpc/trpc', url: 'https://github.com/trpc/trpc.git', ecosystem: 'TS', cohort: 'blind-held-out' },
  { slug: 'click', repo: 'pallets/click', url: 'https://github.com/pallets/click.git', ecosystem: 'Python', cohort: 'blind-held-out' },
  { slug: 'requests', repo: 'psf/requests', url: 'https://github.com/psf/requests.git', ecosystem: 'Python', cohort: 'blind-held-out' },
  { slug: 'fiber', repo: 'gofiber/fiber', url: 'https://github.com/gofiber/fiber.git', ecosystem: 'Go', cohort: 'blind-held-out' },
  { slug: 'axum', repo: 'tokio-rs/axum', url: 'https://github.com/tokio-rs/axum.git', ecosystem: 'Rust', cohort: 'blind-held-out' }
];

const VULN_REPOS = [
  { slug: 'NodeGoat', repo: 'OWASP/NodeGoat', url: 'https://github.com/OWASP/NodeGoat.git', ecosystem: 'Node.js', cohort: 'vulnerable-target' },
  { slug: 'juice-shop', repo: 'juice-shop/juice-shop', url: 'https://github.com/juice-shop/juice-shop.git', ecosystem: 'Node.js / TS', cohort: 'vulnerable-target' },
  { slug: 'pygoat', repo: 'adeyosemanputra/pygoat', url: 'https://github.com/adeyosemanputra/pygoat.git', ecosystem: 'Python / Django', cohort: 'vulnerable-target' }
];

// Verified real public security advisories from GitHub Advisory Database.
const CVE_REPLAYS = [
  {
    cve: 'CVE-2021-21315',
    repo: 'sebhildebrandt/systeminformation',
    url: 'https://github.com/sebhildebrandt/systeminformation.git',
    fixSha: '07daa05fb06f24f96297abaa30c2ace8bfd8b525',
    cwe: 'CWE-78',
    summary: 'Command Injection in service lookup'
  },
  {
    cve: 'CVE-2022-25912',
    repo: 'steveukx/git-js',
    url: 'https://github.com/steveukx/git-js.git',
    fixSha: '774648049eb3e628379e292ea172dccaba610504',
    cwe: 'CWE-78',
    summary: 'simple-git ext transport RCE bypass'
  },
  {
    cve: 'CVE-2021-23337',
    repo: 'lodash/lodash',
    url: 'https://github.com/lodash/lodash.git',
    fixSha: '3469357cff396a26c363f8c1b5a91dde28ba4b1c',
    cwe: 'CWE-94',
    summary: 'Command / template code injection in _.template'
  },
  {
    cve: 'CVE-2020-14343',
    repo: 'yaml/pyyaml',
    url: 'https://github.com/yaml/pyyaml.git',
    fixSha: 'a001f2782501ad2d24986959f0239a354675f9dc',
    cwe: 'CWE-502',
    summary: 'PyYAML FullLoader arbitrary code execution'
  }
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
  let needsClone = true;

  try {
    await fs.access(path.join(targetDir, '.git'));
    if (depth > 1) {
      const { stdout } = await runGit(targetDir, ['rev-list', '--count', 'HEAD']);
      if (Number(stdout.trim()) >= Math.min(depth, 20)) needsClone = false;
    } else {
      needsClone = false;
    }
  } catch {
    needsClone = true;
  }

  if (needsClone) {
    await fs.rm(targetDir, { recursive: true, force: true });
    await fs.mkdir(corpusDir, { recursive: true });
    await runGit(corpusDir, ['clone', '--depth', String(depth), '--quiet', entry.url, targetDir]);
  }

  const { stdout: headSha } = await runGit(targetDir, ['rev-parse', 'HEAD']);
  const { stdout: shortSha } = await runGit(targetDir, ['rev-parse', '--short', 'HEAD']);
  return {
    targetDir,
    headSha: headSha.trim(),
    commitSha: shortSha.trim(),
    repo: entry.repo,
    ecosystem: entry.ecosystem
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
  const { stdout: listOut } = await runGit(targetDir, ['rev-list', '--no-merges', '-n', '35', 'HEAD']);
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

async function auditProductionCohort(entries, corpusDir, prCount, allPrDurations) {
  const out = [];
  for (const entry of entries) {
    const info = await ensureRepoClone(entry, corpusDir, 40);
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
      cohort: entry.cohort,
      role: entry.cohort,
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
    out.push(rec);

    const tag = entry.cohort === 'blind-held-out' ? 'BLIND' : 'CAL';
    process.stdout.write(
      `\n=== [${tag}] ${rec.repo} @ ${rec.commitSha} (${rec.ecosystem}) ===\n` +
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
  return out;
}

async function runCveReplays(corpusDir) {
  const out = [];
  for (const entry of CVE_REPLAYS) {
    const targetDir = path.join(corpusDir, `cve-${entry.cve}`);
    await fs.rm(targetDir, { recursive: true, force: true });
    await fs.mkdir(targetDir, { recursive: true });
    await runGit(targetDir, ['init']);
    await runGit(targetDir, ['remote', 'add', 'origin', entry.url]);
    await runGit(targetDir, ['fetch', '--depth', '2', '--quiet', 'origin', entry.fixSha]);

    const { stdout: parentRaw } = await runGit(targetDir, ['rev-parse', `${entry.fixSha}^`]);
    const parentSha = parentRaw.trim();
    const { stdout: diffFilesOut } = await runGit(targetDir, ['diff-tree', '--no-commit-id', '--name-only', '-r', entry.fixSha]);
    const diffPaths = diffFilesOut.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    const { stdout: parentTreeOut } = await runGit(targetDir, ['ls-tree', '-r', '--name-only', parentSha]);
    const parentFilesSet = new Set(parentTreeOut.split(/\r?\n/).map(s => s.trim()).filter(Boolean));
    const changedSourceFiles = diffPaths.filter(p =>
      parentFilesSet.has(p) &&
      /\.(?:[cm]?[jt]sx?|py|go|rs|sh)$/i.test(p) &&
      !/(?:^|\/)(?:tests?|testing|__tests__|spec|docs?)\//i.test(p) &&
      !/\.(?:test|spec)\./i.test(p)
    );

    // Pre-patch vulnerable state: diff from fixed commit -> vulnerable parent highlights removed/vulnerable logic as '+' lines in --mode diff
    await runGit(targetDir, ['checkout', '--quiet', '--detach', parentSha]);
    const preDiffAudit = await runAudit({
      root: targetDir,
      mode: 'diff',
      baseRef: entry.fixSha,
      queryOsv: false,
      failOn: 'high'
    });
    const preFileAudit = changedSourceFiles.length
      ? await runAudit({ root: targetDir, files: changedSourceFiles, mode: 'full', queryOsv: false, failOn: 'high' })
      : null;

    // Post-patch fixed state
    await runGit(targetDir, ['checkout', '--quiet', '--detach', entry.fixSha]);
    const postDiffAudit = await runAudit({
      root: targetDir,
      mode: 'diff',
      baseRef: parentSha,
      queryOsv: false,
      failOn: 'high'
    });

    const detectedInPrePatch =
      preDiffAudit.verdict === 'fails' ||
      preDiffAudit.verdict === 'cant-tell' ||
      (preFileAudit && (preFileAudit.verdict === 'fails' || preFileAudit.verdict === 'cant-tell'));

    const rec = {
      cve: entry.cve,
      repo: entry.repo,
      fixSha: entry.fixSha.slice(0, 7),
      parentSha: parentSha.slice(0, 7),
      cwe: entry.cwe,
      summary: entry.summary,
      changedSourceFiles: changedSourceFiles.slice(0, 8),
      prePatchDiff: {
        verdict: preDiffAudit.verdict,
        verdictLabel: preDiffAudit.verdictLabel,
        changedFiles: preDiffAudit.changedFiles,
        failingCount: preDiffAudit.failingFindings.length,
        cantTellCount: preDiffAudit.cantTellReasons.length,
        topFindings: preDiffAudit.failingFindings.slice(0, 3).map(summarizeFinding),
        topCantTell: preDiffAudit.cantTellReasons.slice(0, 3)
      },
      prePatchFileAudit: preFileAudit ? {
        verdict: preFileAudit.verdict,
        verdictLabel: preFileAudit.verdictLabel,
        failingCount: preFileAudit.failingFindings.length,
        cantTellCount: preFileAudit.cantTellReasons.length,
        topFindings: preFileAudit.failingFindings.slice(0, 3).map(summarizeFinding)
      } : null,
      postPatchDiff: {
        verdict: postDiffAudit.verdict,
        verdictLabel: postDiffAudit.verdictLabel,
        changedFiles: postDiffAudit.changedFiles,
        failingCount: postDiffAudit.failingFindings.length,
        cantTellCount: postDiffAudit.cantTellReasons.length
      },
      detectedInPrePatch: Boolean(detectedInPrePatch)
    };
    out.push(rec);

    process.stdout.write(
      `\n=== [CVE REPLAY] ${rec.cve} (${rec.repo} ${rec.parentSha} -> ${rec.fixSha}, ${rec.cwe}) ===\n` +
      `Pre-patch diff: ${rec.prePatchDiff.verdictLabel} (failing=${rec.prePatchDiff.failingCount}, cantTell=${rec.prePatchDiff.cantTellCount}) | File-level: ${rec.prePatchFileAudit?.verdictLabel || 'N/A'}\n` +
      `Post-patch diff: ${rec.postPatchDiff.verdictLabel} (failing=${rec.postPatchDiff.failingCount}, cantTell=${rec.postPatchDiff.cantTellCount})\n`
    );
  }
  return out;
}

function summarizePrCohort(results) {
  const totalPrDiffs = results.reduce((s, r) => s + r.prReplay.commitsTested, 0);
  const prHoldsCount = results.reduce((s, r) => s + r.prReplay.holdsCount, 0);
  const prCantTellCount = results.reduce((s, r) => s + r.prReplay.cantTellCount, 0);
  const prFailsCount = results.reduce((s, r) => s + r.prReplay.failsCount, 0);
  return {
    reposCount: results.length,
    totalPrDiffs,
    prHoldsCount,
    prCantTellCount,
    prFailsCount,
    prFalseFailRatePct: totalPrDiffs ? round2((prFailsCount / totalPrDiffs) * 100) : 0,
    fullRepoFailsRepos: results.filter(r => r.failingFindings > 0).length
  };
}

async function main() {
  const { corpusDir, outPath, prCount } = parseCliArgs(process.argv.slice(2));
  const calibrationPrDurations = [];
  const blindPrDurations = [];

  const calibrationResults = await auditProductionCohort(CALIBRATION_REPOS, corpusDir, prCount, calibrationPrDurations);
  const blindResults = await auditProductionCohort(BLIND_HELDOUT_REPOS, corpusDir, prCount, blindPrDurations);

  const vulnerableResults = [];
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
      cohort: entry.cohort,
      role: entry.cohort,
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

  const cveReplays = await runCveReplays(corpusDir);

  const allProd = [...calibrationResults, ...blindResults];
  const allPrDurations = [...calibrationPrDurations, ...blindPrDurations].sort((a, b) => a - b);
  const calSum = summarizePrCohort(calibrationResults);
  const blindSum = summarizePrCohort(blindResults);
  const calSort = [...calibrationPrDurations].sort((a, b) => a - b);
  const blindSort = [...blindPrDurations].sort((a, b) => a - b);

  const vulnerableCweBreakdown = {};
  for (const r of vulnerableResults) {
    for (const [k, v] of Object.entries(r.cweBreakdown || {})) {
      vulnerableCweBreakdown[k] = (vulnerableCweBreakdown[k] || 0) + v;
    }
  }

  const summary = {
    totalRepos: allProd.length + vulnerableResults.length,
    productionReposCount: allProd.length,
    vulnerableReposCount: vulnerableResults.length,
    totalPrDiffs: calSum.totalPrDiffs + blindSum.totalPrDiffs,
    prHoldsCount: calSum.prHoldsCount + blindSum.prHoldsCount,
    prCantTellCount: calSum.prCantTellCount + blindSum.prCantTellCount,
    prFailsCount: calSum.prFailsCount + blindSum.prFailsCount,
    prFalseFailRatePct: (calSum.totalPrDiffs + blindSum.totalPrDiffs)
      ? round2(((calSum.prFailsCount + blindSum.prFailsCount) / (calSum.totalPrDiffs + blindSum.totalPrDiffs)) * 100)
      : 0,
    prP50Ms: round2(percentile(allPrDurations, 50)),
    prP95Ms: round2(percentile(allPrDurations, 95)),
    calibration: { ...calSum, prP50Ms: round2(percentile(calSort, 50)), prP95Ms: round2(percentile(calSort, 95)) },
    blindHeldOut: { ...blindSum, prP50Ms: round2(percentile(blindSort, 50)), prP95Ms: round2(percentile(blindSort, 95)) },
    vulnerableTotalFailing: vulnerableResults.reduce((s, r) => s + r.failingFindings, 0),
    vulnerableReposCaught: vulnerableResults.filter(r => r.verdict === 'fails').length,
    vulnerableCweBreakdown,
    cveReplaysCount: cveReplays.length,
    cveDetectedPrePatch: cveReplays.filter(c => c.detectedInPrePatch).length,
    cveFailsPrePatch: cveReplays.filter(c => c.prePatchDiff.verdict === 'fails').length
  };

  const report = {
    generatedAt: new Date().toISOString(),
    nodeVersion: process.version,
    platform: `${process.platform}-${process.arch}`,
    summary,
    repos: [...blindResults, ...calibrationResults, ...vulnerableResults],
    cveReplays
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
