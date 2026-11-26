const { version: PKG_VERSION } = require('../../package.json');

const VERDICT_META = {
  holds: {
    badge: 'HOLDS UP',
    emoji: '🟢',
    summary: 'All inspected changes held up against recorded security checks.'
  },
  fails: {
    badge: 'FAILS',
    emoji: '🔴',
    summary: 'Verified security issues crossed the fail threshold.'
  },
  'cant-tell': {
    badge: "CAN'T TELL",
    emoji: '🟡',
    summary: 'Evidence is incomplete or contains unverified sinks — never rounded to a pass.'
  }
};

function formatTerminalReport(result) {
  const meta = VERDICT_META[result.verdict] || VERDICT_META['cant-tell'];
  const lines = [
    ``,
    `Zero Theory Labs · Marlowe CI / Guard v${PKG_VERSION}`,
    `Verdict: ${meta.badge} (${result.mode} mode · ${result.scannedFiles} file(s) inspected in ${result.durationMs}ms)`,
    `${meta.summary}`,
    ``
  ];

  if (result.baselinedCount > 0) {
    lines.push(`Baselined (acknowledged non-secret findings): ${result.baselinedCount}${result.baselinePath ? ` (${result.baselinePath})` : ''}`, '');
  }

  if (result.findings.length) {
    lines.push(`Findings (${result.findings.length} total, ${result.failingFindings.length} failing >= ${result.failOn}):`);
    for (const f of result.findings.slice(0, 25)) {
      const tag = f.reachability === 'unverified' ? 'UNVERIFIED' : f.severity.toUpperCase();
      const idTag = f.ruleId && f.cwe ? ` [${f.ruleId} · ${f.cwe}]` : (f.ruleId || f.cwe ? ` [${f.ruleId || f.cwe}]` : '');
      lines.push(`  - [${tag}] ${f.title} (${f.location})${idTag}`);
      if (f.evidence) lines.push(`    Evidence: ${f.evidence}`);
    }
    lines.push('');
  }

  if (result.cantTellReasons.length) {
    lines.push(`Can't Tell Reasons (${result.cantTellReasons.length}):`);
    for (const r of result.cantTellReasons.slice(0, 15)) {
      lines.push(`  - [${r.code}] ${r.message}`);
    }
    lines.push('');
  }

  if (result.dependencySummary) {
    lines.push(
      `Supply Chain: ${result.dependencySummary.totalPackages} package(s) across ${result.dependencySummary.manifests.join(', ')} · OSV: ${result.dependencySummary.osvStatus}`
    );
  }
  if (result.scannerRuns.length) {
    lines.push(`Local CLIs: ${result.scannerRuns.map(s => `${s.scanner} (${s.findingsCount})`).join(', ')}`);
  }

  return lines.join('\n').trimEnd() + '\n';
}

function escapeMd(value) {
  return String(value || '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

function formatMarkdownSummary(result) {
  const meta = VERDICT_META[result.verdict] || VERDICT_META['cant-tell'];
  const lines = [
    `<!-- marlowe-ci-verdict -->`,
    `## ${meta.emoji} Marlowe CI Verdict: **${meta.badge}**`,
    ``,
    `> ${meta.summary}`,
    ``,
    `- **Mode:** \`${result.mode}\` · **Files inspected:** \`${result.scannedFiles}\` · **Threshold:** \`${result.failOn}\` · **Duration:** \`${result.durationMs}ms\`${result.baselinedCount > 0 ? ` · **Baselined:** \`${result.baselinedCount}\`` : ''}`,
    ''
  ];

  if (result.findings.length) {
    lines.push(
      `### Findings (${result.findings.length})`,
      '',
      `| Severity | Reachability | Finding | Location | CWE |`,
      `| :--- | :--- | :--- | :--- | :--- |`
    );
    for (const f of result.findings.slice(0, 40)) {
      const idCell = f.ruleId && f.cwe ? `${f.ruleId} (${f.cwe})` : (f.ruleId || f.cwe || '—');
      lines.push(
        `| **${f.severity.toUpperCase()}** | \`${f.reachability || 'reachable'}\` | ${escapeMd(f.title)} | \`${escapeMd(f.location)}\` | ${escapeMd(idCell)} |`
      );
    }
    lines.push('');
  } else {
    lines.push(`_No security findings detected._`, '');
  }

  if (result.cantTellReasons.length) {
    lines.push(`### Can't Tell Items (${result.cantTellReasons.length})`, '');
    for (const r of result.cantTellReasons.slice(0, 20)) {
      lines.push(`- \`${r.code}\` — ${r.message}`);
    }
    lines.push('');
  }

  lines.push(
    `---`,
    `<sub>Verified by **[Marlowe CI / Guard](https://github.com/zerotheory-labs/marlowe-ci)** · [Zero Theory Labs](https://zerotheorylabs.com/marlowe) — Every check returns Holds up, Fails, or Can't tell.</sub>`
  );

  return lines.join('\n');
}

module.exports = {
  VERDICT_META,
  formatTerminalReport,
  formatMarkdownSummary
};
