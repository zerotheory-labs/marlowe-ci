const fs = require('node:fs/promises');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { version } = require('../../package.json');
const { resolveWithinRoot, readRegularTextFile } = require('../core/fs-safe.cjs');

const DEFAULT_BASELINE_FILE = '.marlowe-baseline.json';

function stripLocationLine(location) {
  const raw = String(location || '').trim().replace(/^\.\//, '');
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) return raw.toLowerCase();
  return raw.replace(/:\d+(?::\d+)?$/, '').toLowerCase();
}

function findingFingerprint(finding) {
  const cat = String(finding?.category || '').toLowerCase();
  const cwe = String(finding?.cwe || '').toUpperCase();
  const fileBase = stripLocationLine(finding?.location);
  const title = String(finding?.title || '').trim().toLowerCase();
  return createHash('sha256').update(`${cat}|${cwe}|${fileBase}|${title}`).digest('hex').slice(0, 16);
}

async function loadBaseline(root, explicitPath = '') {
  const target = explicitPath ? String(explicitPath).trim() : DEFAULT_BASELINE_FILE;
  if (!target) return null;

  let resolved;
  try {
    resolved = await resolveWithinRoot(root, target);
  } catch (err) {
    if (explicitPath) throw new Error(`Invalid baseline path "${explicitPath}": ${err.message}`);
    return null;
  }

  let text;
  try {
    text = await readRegularTextFile(resolved.fullPath, 2 * 1024 * 1024);
  } catch (err) {
    if (err && err.code === 'ENOENT') {
      if (explicitPath) throw new Error(`Baseline file not found: ${resolved.relPath}`);
      return null;
    }
    if (explicitPath) throw new Error(`Unable to read baseline file "${resolved.relPath}": ${err.message}`);
    return null;
  }

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new Error(`Invalid JSON in baseline file "${resolved.relPath}": ${err.message}`);
  }

  const entries = Array.isArray(parsed?.entries) ? parsed.entries : [];
  const fingerprints = new Set();
  for (const entry of entries) {
    if (!entry || typeof entry !== 'object') continue;
    // Security invariant: hardcoded secrets must never be suppressed by a baseline.
    if (String(entry.category || '').toLowerCase() === 'secrets') continue;
    const fp = typeof entry.fingerprint === 'string' && entry.fingerprint.trim()
      ? entry.fingerprint.trim().toLowerCase()
      : findingFingerprint(entry);
    fingerprints.add(fp);
  }

  return {
    path: resolved.relPath,
    fingerprints,
    entries
  };
}

function applyBaseline(findings = [], baseline = null) {
  if (!baseline || !baseline.fingerprints || baseline.fingerprints.size === 0) {
    return { activeFindings: [...findings], baselinedFindings: [] };
  }

  const activeFindings = [];
  const baselinedFindings = [];

  for (const f of findings) {
    // Hardcoded secrets never get silenced by baselines.
    if (String(f.category || '').toLowerCase() === 'secrets') {
      activeFindings.push(f);
      continue;
    }
    const fp = findingFingerprint(f);
    if (baseline.fingerprints.has(fp)) {
      baselinedFindings.push({ ...f, fingerprint: fp });
    } else {
      activeFindings.push(f);
    }
  }

  return { activeFindings, baselinedFindings };
}

async function writeBaseline(root, result, outPath = DEFAULT_BASELINE_FILE) {
  const targetRel = String(outPath || DEFAULT_BASELINE_FILE).trim();
  const resolved = await resolveWithinRoot(root, targetRel);
  const allFindings = [...(result?.findings || []), ...(result?.baselinedFindings || [])];

  const entries = [];
  const seen = new Set();
  let skippedSecrets = 0;

  for (const f of allFindings) {
    if (String(f.category || '').toLowerCase() === 'secrets') {
      skippedSecrets++;
      continue;
    }
    const fingerprint = findingFingerprint(f);
    if (seen.has(fingerprint)) continue;
    seen.add(fingerprint);
    entries.push({
      fingerprint,
      title: f.title,
      severity: f.severity,
      category: f.category,
      cwe: f.cwe || '',
      location: stripLocationLine(f.location)
    });
  }

  const payload = {
    version: 1,
    generator: `marlowe-ci@${version}`,
    generatedAt: new Date().toISOString(),
    note: 'Acknowledged non-secret baseline findings. Secrets (category="secrets") are never baselined.',
    entries
  };

  await fs.mkdir(path.dirname(resolved.fullPath), { recursive: true });
  await fs.writeFile(resolved.fullPath, JSON.stringify(payload, null, 2) + '\n', 'utf8');

  return {
    path: resolved.relPath,
    baselinedCount: entries.length,
    skippedSecrets
  };
}

module.exports = {
  DEFAULT_BASELINE_FILE,
  findingFingerprint,
  loadBaseline,
  applyBaseline,
  writeBaseline
};
