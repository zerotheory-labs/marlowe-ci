#!/usr/bin/env node

const fs = require('node:fs/promises');
const path = require('node:path');
const { runAudit } = require('../src/engine/verdict.cjs');
const { writeBaseline } = require('../src/engine/baseline.cjs');
const { formatTerminalReport, formatMarkdownSummary } = require('../src/engine/format.cjs');
const { runClaudeHookCli } = require('../src/integrations/claude-hooks.cjs');
const { startMcpServer } = require('../src/integrations/mcp-server.cjs');
const {
  parseCommandPrefix,
  installClaudeHooks,
  installMcpConfig,
  installCursorConfig,
  installVscodeConfig,
  installCodexConfig,
  installWindsurfConfig,
  installGitHubWorkflow,
  installGitPreCommitHook
} = require('../src/integrations/init.cjs');
const { resolveWithinRoot, loadScopeConfig } = require('../src/core/fs-safe.cjs');
const {
  inspectHttpSecurity,
  inspectTls,
  dnsRecon,
  triageArtifact,
  analyzeLogs,
  extractIocs
} = require('../src/core/cyber-analyzers.cjs');
const {
  inspectShirudoTarget,
  verifyShirudoAttestation,
  inspectShirudoStatus
} = require('../src/core/shirudo.cjs');
const { detectSecurityTools } = require('../src/core/cyber-toolchain.cjs');
const { loginPath, DEFAULT_PATH } = require('../src/core/toolchain.cjs');
const pkg = require('../package.json');

const HELP = `Marlowe CI / Guard v${pkg.version} — Zero Theory Labs

Usage:
  marlowe-ci scan [options]             Run diff or full workspace security audit
  marlowe-ci baseline [options]         Record non-secret findings into .marlowe-baseline.json
  marlowe-ci recon <http|tls|dns> <target> [--path <dir>] [--method GET|HEAD] [--json]
                                        Run ScopeGate-enforced HTTP, TLS, or DNS inspection
  marlowe-ci dfir <triage|logs|iocs> <file> [--path <dir>] [--filter <str>] [--json]
                                        Run read-only O_NOFOLLOW forensic triage/log/IOC analysis
  marlowe-ci shirudo <audit|attest|status> [target] [--path <dir>] [--nonce <hex>] [--ak-name <ak>] [--fail-on-cant-tell] [--json]
                                        Audit Shirudo Beefiles/BPF upatches or verify TPM 2.0 attestation
  marlowe-ci claude <pre-tool|post-tool|stop> [--strict-cant-tell]
                                        Run Claude Code hook handler over stdin/stdout JSON
  marlowe-ci mcp [--path <dir>]         Start stdio JSON-RPC 2.0 MCP security server (13 tools)
  marlowe-ci init [--claude|--claude-global|--mcp|--cursor|--vscode|--codex|--windsurf|--all-agents|--github|--git-hook|--all] [--path <dir>] [--cmd <prefix>]
                                        Install idempotent configs into a project
  marlowe-ci doctor [--path <dir>]      Inspect installed local security CLIs (10-CLI posture)

Scan options:
  --path <dir>          Workspace directory (default: .)
  --mode <diff|full>    Audit mode (default: diff)
  --staged              Audit staged git index changes only (for pre-commit)
  --base <ref>          Compare HEAD against git base ref (e.g. origin/main)
  --fail-on <sev>       critical | high | medium | low (default: high)
  --fail-on-cant-tell   Exit 2 when verdict is CAN'T TELL
  --baseline <file>     Baseline file relative to workspace (default: .marlowe-baseline.json)
  --no-baseline         Ignore .marlowe-baseline.json during this scan
  --no-osv              Skip online OSV.dev advisory queries
  --scanners <list>     none | auto | comma-separated CLIs (gitleaks,semgrep,trivy,osv-scanner)
  --semgrep-replay <file> Replay a base-committed fixture manifest against --base and HEAD
  --sarif <file>        Write SARIF v2.1.0 report to file
  --markdown            Print GitHub Markdown summary instead of terminal text
  --json                Print structured JSON verdict output

Exit codes:
  0  HOLDS UP (or CAN'T TELL without --fail-on-cant-tell)
  1  FAILS (verified security issue >= --fail-on or hardcoded secret)
  2  CAN'T TELL (when --fail-on-cant-tell is set)
`;

function parseArgs(argv) {
  const positionals = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (!token.startsWith('--')) {
      positionals.push(token);
      continue;
    }
    const eq = token.indexOf('=');
    if (eq !== -1) {
      flags[token.slice(2, eq)] = token.slice(eq + 1);
      continue;
    }
    const key = token.slice(2);
    if (key.startsWith('no-')) {
      flags[key.slice(3)] = false;
      continue;
    }
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith('--')) {
      flags[key] = next;
      i++;
    } else {
      flags[key] = true;
    }
  }
  return { positionals, flags };
}

async function cmdScan(flags) {
  const root = path.resolve(String(flags.path || '.'));
  const mode = flags.mode === 'full' ? 'full' : 'diff';
  const scannersRaw = typeof flags.scanners === 'string' ? flags.scanners : 'none';
  const scanners = scannersRaw.split(',').map(s => s.trim()).filter(Boolean);
  const manifest = flags['semgrep-replay'];
  if (manifest && (typeof manifest !== 'string' || typeof flags.base !== 'string' || mode !== 'diff' || flags.staged)) {
    throw new Error('--semgrep-replay requires a manifest path and --base <ref> in a committed diff.');
  }

  const result = await runAudit({
    root,
    mode,
    staged: Boolean(flags.staged),
    baseRef: typeof flags.base === 'string' ? flags.base : '',
    failOn: typeof flags['fail-on'] === 'string' ? flags['fail-on'] : 'high',
    queryOsv: flags.osv !== false,
    scanners,
    semgrepReplay: manifest ? { manifest, baseRef: flags.base, headRef: 'HEAD' } : undefined,
    baselinePath: typeof flags.baseline === 'string' ? flags.baseline : '',
    useBaseline: flags.baseline !== false
  });

  if (typeof flags.sarif === 'string' && flags.sarif.trim()) {
    const sarifOut = path.resolve(root, flags.sarif.trim());
    await fs.mkdir(path.dirname(sarifOut), { recursive: true });
    await fs.writeFile(sarifOut, JSON.stringify(result.sarif, null, 2) + '\n', 'utf8');
  }

  if (flags.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else if (flags.markdown) {
    process.stdout.write(formatMarkdownSummary(result) + '\n');
  } else {
    process.stdout.write(formatTerminalReport(result));
  }

  if (result.verdict === 'fails') return 1;
  if (result.verdict === 'cant-tell' && flags['fail-on-cant-tell']) return 2;
  return 0;
}

async function cmdInit(flags) {
  const targetDir = path.resolve(String(flags.path || '.'));
  const commandPrefix = typeof flags.cmd === 'string' && flags.cmd.trim()
    ? flags.cmd.trim()
    : 'npx --yes @zerotheory-labs/marlowe-ci';
  const { command: mcpCommand, baseArgs } = parseCommandPrefix(commandPrefix);
  const mcpArgs = [...baseArgs, 'mcp'];

  const all = Boolean(flags.all);
  const allAgents = Boolean(flags['all-agents']);
  const doClaude = all || allAgents || Boolean(flags.claude);
  const doClaudeGlobal = Boolean(flags['claude-global']);
  const doMcp = all || allAgents || Boolean(flags.mcp);
  const doCursor = allAgents || Boolean(flags.cursor);
  const doVscode = allAgents || Boolean(flags.vscode);
  const doCodex = allAgents || Boolean(flags.codex);
  const doWindsurf = allAgents || Boolean(flags.windsurf);
  const doGithub = all || Boolean(flags.github);
  const doGitHook = all || Boolean(flags['git-hook']);

  const selectedAny = doClaude || doClaudeGlobal || doMcp || doCursor || doVscode || doCodex || doWindsurf || doGithub || doGitHook;
  const actions = [];

  if (doClaude || !selectedAny) {
    actions.push({ label: 'Claude Code hooks (project)', ...(await installClaudeHooks({ targetDir, commandPrefix })) });
  }
  if (doClaudeGlobal) {
    actions.push({ label: 'Claude Code hooks (global)', ...(await installClaudeHooks({ targetDir, global: true, commandPrefix })) });
  }
  if (doMcp || !selectedAny) {
    actions.push({ label: 'MCP server config (.mcp.json)', ...(await installMcpConfig({ targetDir, command: mcpCommand, args: mcpArgs })) });
  }
  if (doCursor) {
    const res = await installCursorConfig({ targetDir, command: mcpCommand, args: mcpArgs });
    actions.push({ label: 'Cursor MCP & rules', path: `${res.path} + ${res.rulePath}` });
  }
  if (doVscode) {
    actions.push({ label: 'VS Code MCP config (.vscode/mcp.json)', ...(await installVscodeConfig({ targetDir, command: mcpCommand, args: mcpArgs })) });
  }
  if (doCodex) {
    actions.push({ label: 'Codex CLI MCP config (.codex/config.toml)', ...(await installCodexConfig({ targetDir, command: mcpCommand, args: mcpArgs })) });
  }
  if (doWindsurf) {
    const res = await installWindsurfConfig({ targetDir, command: mcpCommand, args: mcpArgs });
    actions.push({ label: 'Windsurf MCP & rules', path: `${res.path} + ${res.rulePath}` });
  }
  if (doGithub) {
    actions.push({ label: 'GitHub Actions workflow', ...(await installGitHubWorkflow({ targetDir })) });
  }
  if (doGitHook) {
    actions.push({ label: 'Git pre-commit hook', ...(await installGitPreCommitHook({ targetDir, commandPrefix })) });
  }

  for (const act of actions) {
    process.stdout.write(`✓ Installed ${act.label}: ${act.path}\n`);
  }
  return 0;
}

async function cmdBaseline(flags) {
  const root = path.resolve(String(flags.path || '.'));
  const outPath = typeof flags.out === 'string' && flags.out.trim() ? flags.out.trim() : '.marlowe-baseline.json';
  const result = await runAudit({
    root,
    mode: 'full',
    queryOsv: flags.osv !== false,
    useBaseline: false
  });
  const saved = await writeBaseline(root, result, outPath);
  if (flags.json) {
    process.stdout.write(JSON.stringify(saved, null, 2) + '\n');
  } else {
    process.stdout.write(`✓ Wrote ${saved.baselinedCount} acknowledged non-secret finding(s) to ${saved.path}`);
    if (saved.skippedSecrets > 0) {
      process.stdout.write(` (skipped ${saved.skippedSecrets} secret(s) — secrets are never baselined)`);
    }
    process.stdout.write('\n');
  }
  return saved.skippedSecrets > 0 ? 1 : 0;
}

async function cmdRecon(kind, target, flags) {
  if (!kind || !target) {
    throw new Error('Usage: marlowe-ci recon <http|tls|dns> <target> [--path <dir>] [--method GET|HEAD] [--json]');
  }
  const root = path.resolve(String(flags.path || '.'));
  const scope = await loadScopeConfig(root);
  const signal = new AbortController().signal;
  let out;
  if (kind === 'http') {
    out = await inspectHttpSecurity(target, { method: typeof flags.method === 'string' ? flags.method : 'GET', scope }, signal);
  } else if (kind === 'tls') {
    out = await inspectTls(target, { scope }, signal);
  } else if (kind === 'dns') {
    out = await dnsRecon(target, { scope }, signal);
  } else {
    throw new Error(`Unknown recon subcommand "${kind}". Use http, tls, or dns.`);
  }
  if (flags.json) {
    process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  } else {
    process.stdout.write(`${out.summary}\n`);
    for (const issue of out.issues || []) {
      process.stdout.write(`  - [${String(issue.severity || 'info').toUpperCase()}] ${issue.issue} (${issue.cwe || 'config'})\n`);
    }
  }
  return (out.issues || []).some(i => i.severity === 'high' || i.severity === 'critical') ? 1 : 0;
}

async function cmdDfir(kind, fileArg, flags) {
  if (!kind || !fileArg) {
    throw new Error('Usage: marlowe-ci dfir <triage|logs|iocs> <file> [--path <dir>] [--filter <str>] [--json]');
  }
  const root = path.resolve(String(flags.path || '.'));
  const resolved = await resolveWithinRoot(root, fileArg);
  const signal = new AbortController().signal;
  let out;
  if (kind === 'triage') {
    out = await triageArtifact(resolved.fullPath, resolved.relPath, signal);
  } else if (kind === 'logs') {
    out = await analyzeLogs(resolved.fullPath, resolved.relPath, { filter: typeof flags.filter === 'string' ? flags.filter : '' }, signal);
  } else if (kind === 'iocs') {
    out = await extractIocs(resolved.fullPath, resolved.relPath, signal);
  } else {
    throw new Error(`Unknown dfir subcommand "${kind}". Use triage, logs, or iocs.`);
  }
  if (flags.json) {
    process.stdout.write(JSON.stringify(out, null, 2) + '\n');
  } else {
    process.stdout.write(`${out.summary}\n`);
    for (const alert of (out.alerts || []).slice(0, 15)) {
      process.stdout.write(`  - line ${alert.line} [${alert.type}] ${alert.sample}\n`);
    }
  }
  return 0;
}

async function cmdShirudo(action, arg, flags) {
  const root = path.resolve(String(flags.path || '.'));
  if (!action || action === 'audit') {
    const target = arg || '.';
    const out = await inspectShirudoTarget(root, target);
    if (flags.json) {
      process.stdout.write(JSON.stringify(out, null, 2) + '\n');
    } else {
      process.stdout.write(`${out.summary}\n`);
      for (const f of out.findings) {
        process.stdout.write(`  - [${String(f.severity || 'medium').toUpperCase()}] ${f.title} (${f.location})${f.cwe ? ` [${f.cwe}]` : ''}\n`);
      }
      for (const ct of out.cantTellReasons) {
        process.stdout.write(`  - [${ct.code}] ${ct.message}\n`);
      }
    }
    if (out.verdict === 'fails') return 1;
    if (out.verdict === 'cant-tell' && flags['fail-on-cant-tell']) return 2;
    return 0;
  }

  const commandPath = (await loginPath({ shell: process.env.SHELL || '', root, env: process.env })) || process.env.PATH || DEFAULT_PATH;

  if (action === 'attest') {
    if (!arg) {
      throw new Error('Usage: marlowe-ci shirudo attest <evidence.json> [--nonce <hex>] [--ak-name <ak>] [--path <dir>] [--fail-on-cant-tell] [--json]');
    }
    const out = await verifyShirudoAttestation({
      root,
      evidencePath: arg,
      nonce: typeof flags.nonce === 'string' ? flags.nonce : '',
      akName: typeof flags['ak-name'] === 'string' ? flags['ak-name'] : '',
      commandPath
    });
    if (flags.json) {
      process.stdout.write(JSON.stringify(out, null, 2) + '\n');
    } else {
      process.stdout.write(`Shirudo Attestation (${out.evidencePath}): ${out.verdictLabel}\n`);
      if (out.reason) process.stdout.write(`  ${out.reason}\n`);
      if (out.output) process.stdout.write(`  ${out.output}\n`);
    }
    if (out.verdict === 'fails') return 1;
    if (out.verdict === 'cant-tell' && flags['fail-on-cant-tell']) return 2;
    return 0;
  }

  if (action === 'status') {
    const out = await inspectShirudoStatus({ root, commandPath });
    if (flags.json) {
      process.stdout.write(JSON.stringify(out, null, 2) + '\n');
    } else {
      process.stdout.write(`Shirudo Status: ${out.verdictLabel}\n`);
      if (out.reason) process.stdout.write(`  ${out.reason}\n`);
      if (out.output) process.stdout.write(`${out.output}\n`);
    }
    if (out.verdict === 'fails') return 1;
    if (out.verdict === 'cant-tell' && flags['fail-on-cant-tell']) return 2;
    return 0;
  }

  throw new Error(`Unknown shirudo subcommand "${action}". Use audit, attest, or status.`);
}

async function cmdDoctor(flags) {
  const root = path.resolve(String(flags.path || '.'));
  const commandPath = (await loginPath({ shell: process.env.SHELL || '', root, env: process.env })) || process.env.PATH || DEFAULT_PATH;
  const report = await detectSecurityTools(commandPath, { root });
  if (flags.json) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    return 0;
  }
  process.stdout.write(`Marlowe Toolchain Doctor (${report.availableCount}/${report.totalCount} local CLIs ready)\n\n`);
  for (const tool of report.tools) {
    const status = tool.available ? `READY (${tool.version})` : `missing — ${tool.installHint}`;
    process.stdout.write(`  - ${tool.id.padEnd(13)} ${status}\n`);
  }
  return 0;
}

async function main() {
  const rawArgs = process.argv.slice(2);
  if (rawArgs.includes('--version') || rawArgs.includes('-v')) {
    process.stdout.write(`${pkg.version}\n`);
    return 0;
  }
  if (!rawArgs.length || rawArgs.includes('--help') || rawArgs.includes('-h') || rawArgs[0] === 'help') {
    process.stdout.write(HELP);
    return 0;
  }

  const { positionals, flags } = parseArgs(rawArgs);
  const sub = positionals[0] || 'scan';

  if (sub === 'scan') return cmdScan(flags);
  if (sub === 'baseline') return cmdBaseline(flags);
  if (sub === 'recon') return cmdRecon(positionals[1], positionals[2], flags);
  if (sub === 'dfir') return cmdDfir(positionals[1], positionals[2], flags);
  if (sub === 'shirudo') return cmdShirudo(positionals[1], positionals[2], flags);
  if (sub === 'claude') {
    const hookType = positionals[1] || '';
    return runClaudeHookCli(hookType, { strictCantTell: Boolean(flags['strict-cant-tell']) });
  }
  if (sub === 'mcp') {
    const root = path.resolve(String(flags.path || '.'));
    return startMcpServer({ root });
  }
  if (sub === 'init') return cmdInit(flags);
  if (sub === 'doctor') return cmdDoctor(flags);

  process.stderr.write(`Unknown command "${sub}". Run "marlowe-ci --help" for usage.\n`);
  return 1;
}

main()
  .then(code => {
    process.exitCode = code;
  })
  .catch(err => {
    process.stderr.write(`[marlowe-ci] ${err.message}\n`);
    process.exitCode = 1;
  });
