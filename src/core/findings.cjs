const fs = require('node:fs/promises');
const path = require('node:path');
const { createHash, randomUUID } = require('node:crypto');
const { redactSecrets } = require('./cyber-scope.cjs');
const { version: DEFAULT_APP_VERSION } = require('../../package.json');

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const STATUSES = ['open', 'verified', 'mitigated', 'false-positive'];
const CATEGORIES = ['appsec', 'secrets', 'supply-chain', 'network', 'web', 'dfir', 'config'];
const SEVERITY_ORDER = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));
const SARIF_LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
const SARIF_SCORE = { critical: '9.5', high: '7.8', medium: '5.5', low: '3.0', info: '1.0' };

function workspaceId(workspace) {
  return createHash('sha256').update(String(workspace || '')).digest('hex').slice(0, 16);
}

function cleanField(value, max, fallback = '') {
  if (typeof value !== 'string') return fallback;
  return value.replace(/\0/g, '').trim().slice(0, max);
}

function normalizeFinding(input, context = {}) {
  if (!input || typeof input !== 'object') throw new Error('Invalid finding payload.');
  const title = cleanField(input.title, 200);
  if (!title) throw new Error('Finding title is required.');
  const severity = String(input.severity || '').toLowerCase();
  if (!SEVERITIES.includes(severity)) throw new Error(`severity must be one of: ${SEVERITIES.join(', ')}.`);
  const status = input.status ? String(input.status).toLowerCase() : 'open';
  if (!STATUSES.includes(status)) throw new Error(`status must be one of: ${STATUSES.join(', ')}.`);
  const category = input.category ? String(input.category).toLowerCase() : 'appsec';
  if (!CATEGORIES.includes(category)) throw new Error(`category must be one of: ${CATEGORIES.join(', ')}.`);
  const location = cleanField(input.location, 300);
  if (!location) throw new Error('Finding location (file:line or host/URL) is required.');
  const cweRaw = cleanField(input.cwe, 32).toUpperCase();
  const cwe = cweRaw && !/^CWE-\d{1,5}$/.test(cweRaw) ? (/^\d{1,5}$/.test(cweRaw) ? `CWE-${cweRaw}` : '') : cweRaw;
  const mitreRaw = cleanField(input.mitre, 32).toUpperCase();
  const mitre = mitreRaw && /^T\d{4}(?:\.\d{3})?$/.test(mitreRaw) ? mitreRaw : '';
  const ruleId = cleanField(input.ruleId, 64).toUpperCase();
  let cvss = null;
  if (input.cvss !== undefined && input.cvss !== null && input.cvss !== '') {
    const parsed = Number(input.cvss);
    if (!Number.isFinite(parsed) || parsed < 0 || parsed > 10) throw new Error('cvss must be between 0.0 and 10.0.');
    cvss = Math.round(parsed * 10) / 10;
  }
  const evidence = redactSecrets(cleanField(input.evidence, 4000)).text;
  const remediation = cleanField(input.remediation, 2000);
  const now = new Date().toISOString();
  return {
    id: randomUUID(),
    title,
    severity,
    status,
    category,
    ruleId,
    cwe,
    mitre,
    cvss,
    location,
    evidence,
    remediation,
    playbook: cleanField(context.playbook || input.playbook, 32, 'general'),
    runId: cleanField(context.runId || input.runId, 100),
    createdAt: now,
    updatedAt: now
  };
}

function sortFindings(list) {
  return [...list].sort((a, b) => {
    const sev = (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9);
    if (sev !== 0) return sev;
    return (b.updatedAt || '').localeCompare(a.updatedAt || '');
  });
}

function createFindingsStore(baseDir) {
  const filePath = workspace => path.join(baseDir, `${workspaceId(workspace)}.json`);

  async function readWorkspace(workspace) {
    try {
      const raw = JSON.parse(await fs.readFile(filePath(workspace), 'utf8'));
      return Array.isArray(raw.findings) ? sortFindings(raw.findings) : [];
    } catch {
      return [];
    }
  }

  async function writeWorkspace(workspace, findings) {
    await fs.mkdir(baseDir, { recursive: true, mode: 0o700 });
    const target = filePath(workspace), temp = `${target}.${randomUUID()}.tmp`;
    const sorted = sortFindings(findings.slice(0, 500));
    await fs.writeFile(temp, JSON.stringify({ version: 1, workspace, updatedAt: new Date().toISOString(), findings: sorted }, null, 2), { mode: 0o600 });
    await fs.rename(temp, target);
    return sorted;
  }

  return {
    list: workspace => readWorkspace(workspace),
    async record(workspace, input, context = {}) {
      const normalized = normalizeFinding(input, context);
      const current = await readWorkspace(workspace);
      const fileBase = parseLocationUri(normalized.location).uri.toLowerCase();
      const key = `${normalized.title.toLowerCase()}|${fileBase}|${normalized.cwe}`;
      const existingIndex = current.findIndex(f => `${f.title.toLowerCase()}|${parseLocationUri(f.location).uri.toLowerCase()}|${f.cwe || ''}` === key);
      let saved, deduplicated = false;
      if (existingIndex !== -1) {
        const prev = current[existingIndex];
        saved = {
          ...prev,
          severity: normalized.severity,
          category: normalized.category,
          cwe: normalized.cwe || prev.cwe,
          mitre: normalized.mitre || prev.mitre,
          cvss: normalized.cvss ?? prev.cvss,
          evidence: normalized.evidence || prev.evidence,
          remediation: normalized.remediation || prev.remediation,
          playbook: normalized.playbook || prev.playbook,
          runId: normalized.runId || prev.runId,
          updatedAt: normalized.updatedAt
        };
        current[existingIndex] = saved;
        deduplicated = true;
      } else {
        saved = normalized;
        current.push(saved);
      }
      await writeWorkspace(workspace, current);
      return { finding: saved, deduplicated, total: current.length };
    },
    async update(workspace, id, patch) {
      const rawId = String(id || '').trim().replace(/…$/, '');
      if (!/^[a-f0-9-]{8,36}$/i.test(rawId)) throw new Error('Invalid finding ID.');
      const current = await readWorkspace(workspace);
      let index = current.findIndex(f => f.id.toLowerCase() === rawId.toLowerCase());
      if (index === -1 && rawId.length >= 8) {
        const prefixMatches = current.map((f, i) => f.id.toLowerCase().startsWith(rawId.toLowerCase()) ? i : -1).filter(i => i !== -1);
        if (prefixMatches.length === 1) index = prefixMatches[0];
      }
      if (index === -1) throw new Error('Finding not found.');
      const next = { ...current[index], updatedAt: new Date().toISOString() };
      if (patch?.status !== undefined) {
        if (!STATUSES.includes(patch.status)) throw new Error('Invalid finding status.');
        next.status = patch.status;
      }
      if (patch?.severity !== undefined) {
        if (!SEVERITIES.includes(patch.severity)) throw new Error('Invalid finding severity.');
        next.severity = patch.severity;
      }
      current[index] = next;
      return writeWorkspace(workspace, current);
    },
    async remove(workspace, id) {
      if (!/^[a-f0-9-]{36}$/i.test(id || '')) throw new Error('Invalid finding ID.');
      const current = await readWorkspace(workspace);
      return writeWorkspace(workspace, current.filter(f => f.id !== id));
    },
    async clear(workspace) {
      return writeWorkspace(workspace, []);
    }
  };
}

function parseLocationUri(location) {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(location)) return { uri: location, line: null };
  const match = /^(.+?):(\d{1,7})(?::\d{1,7})?$/.exec(location);
  if (match && !match[1].includes('//')) {
    return { uri: match[1].replace(/^\.\//, ''), line: Number(match[2]) };
  }
  return { uri: location.replace(/^\.\//, ''), line: null };
}

function toMarkdownReport({ workspace, scope = {}, findings = [], appVersion = DEFAULT_APP_VERSION, generatedAt = new Date().toISOString() }) {
  const active = findings.filter(f => f.status === 'open' || f.status === 'verified');
  const counts = Object.fromEntries(SEVERITIES.map(s => [s, active.filter(f => f.severity === s).length]));
  const lines = [
    '# Marlowe Security Assessment Report',
    '',
    `- **Generated:** ${generatedAt}`,
    `- **Generator:** Marlowe CI / Guard v${appVersion}`,
    `- **Workspace:** \`${workspace || 'N/A'}\``,
    `- **Authorized Network Scope:** ${(scope.targets && scope.targets.length) ? scope.targets.map(t => `\`${t}\``).join(', ') : 'Workspace only (no external network targets)'}`,
    '',
    '## Executive Summary (Active Findings)',
    '',
    '| Severity | Active Count |',
    '| :--- | ---: |',
    ...SEVERITIES.map(s => `| **${s.toUpperCase()}** | ${counts[s]} |`),
    `| **Total Active** | **${active.length}** |`,
    ''
  ];
  if (!findings.length) {
    lines.push('_No security findings recorded for this workspace._', '');
    return lines.join('\n');
  }
  lines.push('## Detailed Findings', '');
  findings.forEach((f, index) => {
    const tags = [f.severity.toUpperCase(), f.status, f.category, f.cwe, f.mitre, f.cvss !== null ? `CVSS ${f.cvss}` : ''].filter(Boolean).join(' · ');
    lines.push(
      `### ${index + 1}. [${f.severity.toUpperCase()}] ${f.title}`,
      '',
      `- **Metadata:** ${tags}`,
      `- **Location:** \`${f.location}\``,
      ''
    );
    if (f.evidence) lines.push('**Evidence:**', '```text', f.evidence, '```', '');
    if (f.remediation) lines.push('**Recommended Remediation:**', '', f.remediation, '');
    lines.push('---', '');
  });
  return lines.join('\n');
}

function toSarifReport({ workspace, findings = [], appVersion = DEFAULT_APP_VERSION, generatedAt = new Date().toISOString() }) {
  const active = findings.filter(f => f.status !== 'false-positive' && f.status !== 'mitigated');
  const rulesMap = new Map();
  const results = active.map(f => {
    const ruleId = f.ruleId || f.cwe || `MARLOWE-${f.category.toUpperCase()}-${createHash('sha256').update(f.title).digest('hex').slice(0, 6).toUpperCase()}`;
    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId,
        name: f.title.slice(0, 120),
        shortDescription: { text: f.title },
        ...(f.remediation ? { help: { text: f.remediation } } : {}),
        properties: {
          tags: ['security', f.category, ...(f.cwe ? [f.cwe] : []), ...(f.mitre ? [f.mitre] : [])],
          'security-severity': f.cvss !== null ? String(f.cvss) : SARIF_SCORE[f.severity] || '5.0'
        }
      });
    }
    const loc = parseLocationUri(f.location);
    return {
      ruleId,
      level: SARIF_LEVEL[f.severity] || 'warning',
      message: { text: [f.title, f.evidence ? `Evidence: ${f.evidence}` : '', f.remediation ? `Remediation: ${f.remediation}` : ''].filter(Boolean).join('\n\n') },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: loc.uri },
          ...(loc.line ? { region: { startLine: loc.line } } : {})
        }
      }],
      properties: {
        findingId: f.id,
        severity: f.severity,
        status: f.status,
        category: f.category,
        ...(f.mitre ? { mitreAttack: f.mitre } : {}),
        recordedAt: f.updatedAt
      }
    };
  });
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'Marlowe CI',
          version: appVersion,
          informationUri: 'https://github.com/zerotheory-labs/marlowe-ci',
          rules: [...rulesMap.values()]
        }
      },
      invocations: [{ executionSuccessful: true, endTimeUtc: generatedAt, workingDirectory: { uri: workspace || '.' } }],
      results
    }]
  };
}

module.exports = {
  SEVERITIES,
  STATUSES,
  CATEGORIES,
  normalizeFinding,
  createFindingsStore,
  toMarkdownReport,
  toSarifReport
};
