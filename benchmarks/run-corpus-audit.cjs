const fs = require('node:fs/promises');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { performance } = require('node:perf_hooks');
const { runAudit } = require('../src/engine/verdict.cjs');
const { inspectShirudoTarget } = require('../src/core/shirudo.cjs');

const execFileAsync = promisify(execFile);

const REPOS = [
  { slug: 'express', repo: 'expressjs/express', url: 'https://github.com/expressjs/express.git', role: 'clean-framework' },
  { slug: 'fastify', repo: 'fastify/fastify', url: 'https://github.com/fastify/fastify.git', role: 'clean-framework' },
  { slug: 'hono', repo: 'honojs/hono', url: 'https://github.com/honojs/hono.git', role: 'clean-framework' },
  { slug: 'shirudo', repo: 'shirudo-dev/shirudo', url: 'https://github.com/shirudo-dev/shirudo.git', role: 'upstream-shirudo' },
  { slug: 'NodeGoat', repo: 'OWASP/NodeGoat', url: 'https://github.com/OWASP/NodeGoat.git', role: 'vulnerable-app' },
  { slug: 'juice-shop', repo: 'juice-shop/juice-shop', url: 'https://github.com/juice-shop/juice-shop.git', role: 'vulnerable-app' }
];

function parseCliArgs(argv) {
  let corpusDir = '/tmp/marlowe-corpus';
  let outPath = '';
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--dir' && argv[i + 1]) corpusDir = argv[++i];
    else if (argv[i] === '--out' && argv[i + 1]) outPath = argv[++i];
  }
  return { corpusDir, outPath };
}

async function ensureRepoClone(entry, corpusDir) {
  const targetDir = path.join(corpusDir, entry.slug);
  let exists = false;
  try {
    await fs.access(path.join(targetDir, '.git'));
    exists = true;
  } catch {
    exists = false;
  }
  if (!exists) {
    await fs.mkdir(corpusDir, { recursive: true });
    await execFileAsync('git', ['clone', '--depth', '1', '--quiet', entry.url, targetDir], {
      timeout: 120000
    });
  }
  const { stdout } = await execFileAsync('git', ['rev-parse', '--short', 'HEAD'], { cwd: targetDir });
  return { targetDir, commitSha: stdout.trim() };
}

function summarizeCategories(items, keyFn) {
  const counts = {};
  for (const item of items) {
    const k = keyFn(item);
    counts[k] = (counts[k] || 0) + 1;
  }
  return counts;
}

async function main() {
  const { corpusDir, outPath } = parseCliArgs(process.argv.slice(2));
  const results = [];

  for (const entry of REPOS) {
    const { targetDir, commitSha } = await ensureRepoClone(entry, corpusDir);
    const t0 = performance.now();
    const audit = await runAudit({
      root: targetDir,
      mode: 'full',
      queryOsv: false,
      failOn: 'high'
    });
    const elapsedMs = Math.round((performance.now() - t0) * 100) / 100;

    let shirudoTargetAudit = null;
    if (entry.role === 'upstream-shirudo') {
      shirudoTargetAudit = await inspectShirudoTarget(targetDir, '.');
    }

    const ruleBreakdown = summarizeCategories(audit.findings, f => f.ruleId || f.cwe || f.category || 'unknown');
    const cantTellBreakdown = summarizeCategories(audit.cantTellReasons, r => r.code || 'unknown');

    const detailLimit = entry.role === 'vulnerable-app' ? 15 : 50;
    const sampleFindings = audit.findings.slice(0, detailLimit).map(f => ({
      ruleId: f.ruleId || f.cwe || '',
      severity: f.severity,
      cwe: f.cwe,
      category: f.category,
      title: f.title,
      location: f.location,
      evidence: String(f.evidence || '').slice(0, 140)
    }));
    const sampleCantTell = audit.cantTellReasons.slice(0, 20).map(r => ({
      code: r.code,
      path: r.path,
      line: r.line,
      message: r.message
    }));

    const rec = {
      slug: entry.slug,
      repo: entry.repo,
      commitSha,
      role: entry.role,
      verdict: audit.verdict,
      verdictLabel: audit.verdictLabel,
      scannedFiles: audit.scannedFiles,
      durationMs: elapsedMs,
      totalFindings: audit.findings.length,
      failingFindings: audit.failingFindings.length,
      cantTellCount: audit.cantTellReasons.length,
      ruleBreakdown,
      cantTellBreakdown,
      sampleFindings,
      sampleCantTell,
      ...(shirudoTargetAudit ? {
        shirudoDirectAudit: {
          verdict: shirudoTargetAudit.verdict,
          inspectedCount: shirudoTargetAudit.inspectedCount,
          findingsCount: shirudoTargetAudit.findings.length,
          cantTellCount: shirudoTargetAudit.cantTellReasons.length,
          findings: shirudoTargetAudit.findings.slice(0, 25).map(f => ({
            ruleId: f.ruleId || f.cwe,
            severity: f.severity,
            title: f.title,
            location: f.location
          })),
          cantTellReasons: shirudoTargetAudit.cantTellReasons.slice(0, 25)
        }
      } : {})
    };
    results.push(rec);

    process.stdout.write(
      `\n=== ${entry.repo} @ ${commitSha} (${entry.role}) ===\n` +
      `Verdict: ${rec.verdictLabel} | Files: ${rec.scannedFiles} | Time: ${rec.durationMs}ms | Findings: ${rec.totalFindings} (failing: ${rec.failingFindings}) | Can't Tell: ${rec.cantTellCount}\n` +
      `Rules: ${JSON.stringify(rec.ruleBreakdown)}\n` +
      `CantTell: ${JSON.stringify(rec.cantTellBreakdown)}\n`
    );
    if (sampleFindings.length) {
      for (const sf of sampleFindings.slice(0, entry.role === 'vulnerable-app' ? 8 : 25)) {
        process.stdout.write(`  [${sf.severity.toUpperCase()} ${sf.ruleId}] ${sf.title} @ ${sf.location} :: ${sf.evidence}\n`);
      }
    }
    if (rec.shirudoDirectAudit) {
      process.stdout.write(`  Shirudo Direct Audit: verdict=${rec.shirudoDirectAudit.verdict}, inspected=${rec.shirudoDirectAudit.inspectedCount}, findings=${rec.shirudoDirectAudit.findingsCount}, cantTell=${rec.shirudoDirectAudit.cantTellCount}\n`);
      for (const f of rec.shirudoDirectAudit.findings) {
        process.stdout.write(`    - [${f.ruleId}] ${f.title} @ ${f.location}\n`);
      }
      for (const c of rec.shirudoDirectAudit.cantTellReasons) {
        process.stdout.write(`    ? [${c.code}] ${c.message}\n`);
      }
    }
  }

  const report = {
    generatedAt: new Date().toISOString(),
    nodeVersion: process.version,
    platform: `${process.platform}-${process.arch}`,
    repos: results
  };

  if (outPath) {
    const absOut = path.resolve(outPath);
    await fs.writeFile(absOut, JSON.stringify(report, null, 2) + '\n', 'utf8');
    process.stdout.write(`\nSaved corpus audit report to ${outPath}\n`);
  }
}

main().catch(err => {
  process.stderr.write(`${err.stack || err.message}\n`);
  process.exitCode = 1;
});
