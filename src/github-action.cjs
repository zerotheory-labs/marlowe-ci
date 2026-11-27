const fs = require('node:fs/promises');
const path = require('node:path');
const { version } = require('../package.json');
const { runAudit } = require('./engine/verdict.cjs');
const { formatTerminalReport, formatMarkdownSummary } = require('./engine/format.cjs');
const { runGit } = require('./engine/git-diff.cjs');
const { resolvePushRange, pushSnapshots } = require('./github-push.cjs');

const COMMENT_MARKER = '<!-- marlowe-ci-verdict -->';

function getInput(name, fallback = '') {
  const normalized = String(name || '').trim();
  const hyphenKey = `INPUT_${normalized.replace(/ /g, '_').toUpperCase()}`;
  const underscoreKey = `INPUT_${normalized.replace(/[^a-zA-Z0-9]+/g, '_').toUpperCase()}`;
  const val = process.env[hyphenKey] !== undefined && process.env[hyphenKey] !== ''
    ? process.env[hyphenKey]
    : process.env[underscoreKey];
  return val !== undefined && val !== '' ? val.trim() : fallback;
}

async function resolvePrBaseRef(root, explicitBase) {
  if (explicitBase) return explicitBase;
  const ghBase = (process.env.GITHUB_BASE_REF || '').trim();
  if (!ghBase) return '';
  for (const candidate of [`origin/${ghBase}`, ghBase]) {
    try {
      await runGit(root, ['rev-parse', '--verify', candidate]);
      return candidate;
    } catch {
      // Try next candidate.
    }
  }
  return '';
}

async function setOutputs(outputs) {
  const outputPath = process.env.GITHUB_OUTPUT;
  if (!outputPath) return;
  const lines = Object.entries(outputs).map(([k, v]) => `${k}=${String(v ?? '').replace(/\r?\n/g, ' ')}`);
  await fs.appendFile(outputPath, lines.join('\n') + '\n', 'utf8');
}

async function writeStepSummary(markdown) {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath) return;
  await fs.appendFile(summaryPath, markdown + '\n', 'utf8');
}

async function upsertPrComment({ token, repository, prNumber, body, fetchImpl = fetch }) {
  if (!token || !repository || !prNumber) return false;
  const apiBase = (process.env.GITHUB_API_URL || 'https://api.github.com').replace(/\/$/, '');
  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: 'application/vnd.github+json',
    'User-Agent': `Marlowe-CI/${version}`,
    'X-GitHub-Api-Version': '2022-11-28'
  };

  const listUrl = `${apiBase}/repos/${repository}/issues/${prNumber}/comments?per_page=100`;
  const listRes = await fetchImpl(listUrl, { headers });
  let existingId = null;
  if (listRes.ok) {
    const comments = await listRes.json();
    if (Array.isArray(comments)) {
      const found = comments.find(c => typeof c?.body === 'string' && c.body.includes(COMMENT_MARKER));
      if (found) existingId = found.id;
    }
  } else {
    process.stderr.write(`[marlowe-ci] PR comment lookup failed with HTTP ${listRes.status}\n`);
  }

  const targetUrl = existingId
    ? `${apiBase}/repos/${repository}/issues/comments/${existingId}`
    : `${apiBase}/repos/${repository}/issues/${prNumber}/comments`;
  const method = existingId ? 'PATCH' : 'POST';

  const res = await fetchImpl(targetUrl, {
    method,
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify({ body })
  });
  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    process.stderr.write(`[marlowe-ci] PR comment ${method} failed with HTTP ${res.status}: ${errText.slice(0, 200)}\n`);
  }
  return res.ok;
}

async function extractPrNumberFromEvent() {
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (!eventPath) return null;
  try {
    const raw = JSON.parse(await fs.readFile(eventPath, 'utf8'));
    return raw?.pull_request?.number || raw?.number || null;
  } catch {
    return null;
  }
}

async function runAction({ fetchImpl = fetch } = {}) {
  const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
  const mode = getInput('mode', 'diff');
  const explicitBase = getInput('base-ref', '');
  const failOn = getInput('fail-on', 'high');
  const failOnCantTell = getInput('fail-on-cant-tell', 'false').toLowerCase() === 'true';
  const queryOsv = getInput('query-osv', 'true').toLowerCase() !== 'false';
  const scannersRaw = getInput('scanners', 'none');
  const sarifFile = getInput('sarif-file', 'marlowe.sarif');
  const commentPr = getInput('comment-pr', 'false').toLowerCase() === 'true';
  const token = getInput('github-token', '') || process.env.GITHUB_TOKEN || '';
  const baselineRaw = getInput('baseline-file', '.marlowe-baseline.json');

  let range = {};
  if (mode === 'diff') {
    if (process.env.GITHUB_EVENT_NAME === 'push') {
      const commits = await resolvePushRange(workspace, explicitBase);
      if (!commits) {
        const message = 'Skipped deleted ref. There are no pushed commits to scan.';
        process.stdout.write(message + '\n');
        await writeStepSummary(message);
        await setOutputs({ verdict: 'skipped', 'findings-count': 0, 'baselined-count': 0, 'cant-tell-count': 0, 'sarif-file': '' });
        process.exitCode = 0;
        return { verdict: 'skipped' };
      }
      range = { snapshots: pushSnapshots(workspace, commits) };
    } else {
      range = { baseRef: await resolvePrBaseRef(workspace, explicitBase) };
    }
  }
  const scanners = scannersRaw.split(',').map(s => s.trim()).filter(Boolean);

  const result = await runAudit({
    root: workspace,
    mode,
    ...range,
    failOn,
    queryOsv,
    scanners,
    baselinePath: baselineRaw === '.marlowe-baseline.json' ? '' : baselineRaw,
    useBaseline: baselineRaw !== 'none' && baselineRaw !== 'false'
  });

  process.stdout.write(formatTerminalReport(result));

  let resolvedSarifPath = '';
  if (sarifFile) {
    resolvedSarifPath = path.isAbsolute(sarifFile) ? sarifFile : path.join(workspace, sarifFile);
    await fs.mkdir(path.dirname(resolvedSarifPath), { recursive: true });
    await fs.writeFile(resolvedSarifPath, JSON.stringify(result.sarif, null, 2) + '\n', 'utf8');
  }

  const md = formatMarkdownSummary(result);
  await writeStepSummary(md);
  await setOutputs({
    verdict: result.verdict,
    'findings-count': result.findings.length,
    'baselined-count': result.baselinedCount || 0,
    'cant-tell-count': result.cantTellReasons.length,
    'sarif-file': resolvedSarifPath || sarifFile
  });

  if (commentPr && process.env.GITHUB_EVENT_NAME === 'pull_request' && token) {
    const prNumber = await extractPrNumberFromEvent();
    const repo = process.env.GITHUB_REPOSITORY || '';
    if (prNumber && repo) {
      await upsertPrComment({ token, repository: repo, prNumber, body: md, fetchImpl }).catch(err => {
        process.stderr.write(`[marlowe-ci] Failed to post PR comment: ${err.message}\n`);
      });
    }
  }

  if (result.verdict === 'fails') {
    process.exitCode = 1;
  } else if (result.verdict === 'cant-tell' && failOnCantTell) {
    process.exitCode = 2;
  } else {
    process.exitCode = 0;
  }

  return result;
}

if (require.main === module) {
  runAction().catch(err => {
    process.stderr.write(`[marlowe-ci] Fatal action error: ${err.stack || err.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = {
  resolvePrBaseRef,
  upsertPrComment,
  runAction
};
