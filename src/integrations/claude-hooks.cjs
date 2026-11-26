const path = require('node:path');
const net = require('node:net');
const { isPrivateOrReservedIp, parseTargetEndpoint, checkTargetScopeSync } = require('../core/cyber-scope.cjs');
const { isProtectedSegment, resolveWithinRoot, readRegularTextFile, loadScopeConfig } = require('../core/fs-safe.cjs');
const { shannonEntropy } = require('../core/cyber-analyzers.cjs');
const {
  isBeefilePath,
  isBpfSourcePath,
  auditBeefile,
  auditBpfUpatchSource,
  auditShirudoCommands
} = require('../core/shirudo.cjs');
const { hasHiddenUnicodeControls, scanAgentGuard } = require('../core/agent-guard.cjs');
const { scanTextLines, runAudit } = require('../engine/verdict.cjs');

const FILE_READ_TOOLS = new Set(['Read', 'View']);
const FILE_MUTATION_TOOLS = new Set(['Edit', 'Write', 'MultiEdit', 'NotebookEdit']);

const CATASTROPHIC_RM_RE = /\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r|--recursive\s+--force|--force\s+--recursive)\s+(?:\/(?:\s|$|\*)|~\/?(?:\s|$)|\$HOME\b|\$\{HOME\})/i;
const PIPE_TO_SHELL_RE = /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+|env\s+)?(?:sh|bash|zsh|dash|ksh)\b/i;
const METADATA_SSRF_RE = /(?:169\.254\.169\.254|169\.254\.170\.2|metadata\.google\.internal|metadata\.goog)/i;
const SENSITIVE_PATH_IN_CMD_RE = /(?:~\/\.ssh\/id_|\/\.ssh\/id_|~\/\.aws\/credentials|\/\.aws\/credentials|~\/\.gnupg|~\/\.shirudo|\/\.shirudo|shirudo-keys|\/\.npmrc\b|\/\.netrc\b|\b\.env(?:\.(?:local|prod|production|staging))?\b)/i;
const NETWORK_EGRESS_IN_CMD_RE = /\b(?:curl|wget|nc|ncat|netcat|scp|sftp|rsync|ftp|telnet|socat)\b|https?:\/\//i;
const TLS_ENV_BYPASS_RE = /\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0\b/;

const HIGH_IMPACT_ASK_PATTERNS = [
  { re: /\bgit\s+push\b[^\n]*(?:--force(?:-with-lease)?|\s-f(?:\s|$))/, reason: 'Force-pushing git history is a high-impact operation.' },
  { re: /\bgit\s+reset\s+--hard\b/, reason: 'git reset --hard discards uncommitted local work.' },
  { re: /\bchmod\s+(?:-R\s+)?0?777\b/, reason: 'Setting 777 permissions makes files world-writable.' },
  { re: /(?:^|[;&|]\s*)sudo\s+/, reason: 'Command elevates privileges with sudo.' },
  { re: /\b(?:npm|pnpm|yarn)\s+publish\b/, reason: 'Publishing a package affects external registries.' },
  { re: /\bwrangler\s+deploy\b|\bterraform\s+apply\b|\bpulumi\s+up\b/, reason: 'Command modifies live cloud infrastructure or deployments.' },
  { re: /\bdocker\s+run\b[^\n]*--privileged\b/, reason: 'Running a --privileged container disables container isolation.' },
  { re: /\bshirudo\s+upatch\s+(?:load|unload|reconcile)\b/i, reason: 'Loading, unloading, or reconciling live Shirudo kernel/runtime upatches modifies active host enforcement.' },
  { re: /\bshirudo\s+bpm\s+(?:build|push|tree\s+append)\b/i, reason: 'Building, signing, or pushing Shirudo .bee packages or signed upatch trees affects fleet distribution.' },
  { re: /\bshirudo\s+(?:genkey|keys|init|image)\b/i, reason: 'Managing Shirudo ML-DSA-87 signing keys, keyring trust, or initrd images changes trust roots.' }
];

function hasProtectedPathSegment(filePath) {
  if (!filePath || typeof filePath !== 'string') return '';
  const clean = filePath.replace(/\\/g, '/');
  const segments = clean.split('/').filter(Boolean);
  for (const seg of segments) {
    if (isProtectedSegment(seg)) return seg;
  }
  return '';
}

function preToolDecision(decision, reason) {
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: decision,
      permissionDecisionReason: `[Marlowe Guard] ${reason}`
    }
  };
}

function checkUrlSafety(rawUrl, scope) {
  let endpoint;
  try {
    endpoint = parseTargetEndpoint(rawUrl, { requireUrl: true });
  } catch (err) {
    return { allowed: false, reason: err.message };
  }

  const host = endpoint.host;
  const targets = Array.isArray(scope?.targets) ? scope.targets : [];

  if (targets.length > 0) {
    try {
      checkTargetScopeSync(rawUrl, scope, { requireUrl: true });
    } catch (err) {
      return { allowed: false, reason: err.message };
    }
  }

  const isLocalhost = host === 'localhost' || host.endsWith('.localhost');
  const isMetadataHost = host === 'metadata.google.internal' || host === 'metadata.goog' || host === 'metadata';
  const isReservedIp = net.isIP(host) !== 0 && isPrivateOrReservedIp(host);

  if (isMetadataHost) {
    return { allowed: false, reason: `Blocked cloud metadata SSRF target "${host}".` };
  }

  if (isLocalhost || isReservedIp) {
    // Allow only if explicitly listed in .marlowe-scope.json
    let explicitlyScoped = false;
    if (targets.length > 0) {
      try {
        checkTargetScopeSync(rawUrl, scope, { requireUrl: true });
        explicitlyScoped = true;
      } catch {
        explicitlyScoped = false;
      }
    }
    if (!explicitlyScoped) {
      return {
        allowed: false,
        reason: `Blocked private/loopback SSRF target "${host}" (not listed in .marlowe-scope.json).`
      };
    }
  }

  return { allowed: true };
}

async function handlePreToolUse(payload) {
  if (!payload || typeof payload !== 'object') return null;
  const cwd = payload.cwd || process.cwd();
  const toolName = String(payload.tool_name || '');
  const input = payload.tool_input && typeof payload.tool_input === 'object' ? payload.tool_input : {};
  const scope = await loadScopeConfig(cwd);

  if (FILE_READ_TOOLS.has(toolName) || FILE_MUTATION_TOOLS.has(toolName)) {
    const targetPath = String(input.file_path || input.path || '').trim();
    if (!targetPath) return null;

    const protectedSeg = hasProtectedPathSegment(targetPath);
    if (protectedSeg) {
      return preToolDecision('deny', `Access to protected credential/sensitive path "${protectedSeg}" (${targetPath}) is blocked.`);
    }

    if (FILE_MUTATION_TOOLS.has(toolName)) {
      try {
        await resolveWithinRoot(cwd, targetPath);
      } catch (err) {
        return preToolDecision('deny', err.message);
      }
      if (isBeefilePath(targetPath)) {
        const incoming = typeof input.content === 'string'
          ? input.content
          : (typeof input.new_string === 'string' ? input.new_string : '');
        if (incoming) {
          const probe = /\[\[upatches\.rodata\]\]/i.test(incoming)
            ? incoming
            : `[package]\nname = "draft"\n[[upatches.rodata]]\n${incoming}`;
          const bfPre = await auditBeefile(targetPath, probe, {});
          const beeExec = bfPre.findings.find(f => f.ruleId === 'SHIRUDO-BEE-002');
          if (beeExec) {
            return preToolDecision('deny', `[${beeExec.ruleId}] ${beeExec.title}: ${beeExec.evidence}`);
          }
        }
      }
    }
    return null;
  }

  if (toolName === 'WebFetch') {
    const rawUrl = String(input.url || '').trim();
    if (!rawUrl) return null;
    const verdict = checkUrlSafety(rawUrl, scope);
    if (!verdict.allowed) {
      return preToolDecision('deny', verdict.reason);
    }
    return null;
  }

  if (toolName === 'Bash') {
    const cmd = String(input.command || '');
    if (!cmd.trim()) return null;

    if (CATASTROPHIC_RM_RE.test(cmd)) {
      return preToolDecision('deny', 'Catastrophic recursive delete targeting /, ~, or $HOME is blocked.');
    }
    if (hasHiddenUnicodeControls(cmd)) {
      return preToolDecision('deny', 'Hidden bidirectional/tag/zero-width Unicode control characters (Trojan Source) in shell command are blocked.');
    }
    if (PIPE_TO_SHELL_RE.test(cmd)) {
      return preToolDecision('deny', 'Piping remote curl/wget output directly into a shell is blocked.');
    }
    if (METADATA_SSRF_RE.test(cmd)) {
      return preToolDecision('deny', 'Access to cloud instance metadata endpoints (169.254.169.254 / metadata.google.internal) is blocked.');
    }
    if (TLS_ENV_BYPASS_RE.test(cmd)) {
      return preToolDecision('deny', 'Disabling Node TLS certificate verification via environment override is blocked.');
    }
    if (SENSITIVE_PATH_IN_CMD_RE.test(cmd) && NETWORK_EGRESS_IN_CMD_RE.test(cmd)) {
      return preToolDecision('deny', 'Potential credential exfiltration: command combines sensitive credential files with network egress.');
    }

    const shirudoCmdAudit = auditShirudoCommands('bash', cmd, { isShellCommand: true });
    const tpmFail = shirudoCmdAudit.findings.find(f => f.ruleId === 'SHIRUDO-TPM-001' || f.ruleId === 'SHIRUDO-TPM-003');
    if (tpmFail) {
      return preToolDecision('deny', `[${tpmFail.ruleId}] ${tpmFail.title}`);
    }

    for (const rule of HIGH_IMPACT_ASK_PATTERNS) {
      if (rule.re.test(cmd)) {
        return preToolDecision('ask', rule.reason);
      }
    }
  }

  return null;
}

async function handlePostToolUse(payload) {
  if (!payload || typeof payload !== 'object') return null;
  const toolName = String(payload.tool_name || '');
  if (!FILE_MUTATION_TOOLS.has(toolName)) return null;

  const cwd = payload.cwd || process.cwd();
  const input = payload.tool_input && typeof payload.tool_input === 'object' ? payload.tool_input : {};
  const targetPath = String(input.file_path || input.path || '').trim();
  if (!targetPath) return null;

  let resolved;
  try {
    resolved = await resolveWithinRoot(cwd, targetPath);
  } catch {
    return null;
  }

  let text;
  try {
    text = await readRegularTextFile(resolved.fullPath);
  } catch {
    return null;
  }

  const { secretHits, codeHits } = scanTextLines(resolved.relPath, text);
  const warnings = [];

  for (const s of secretHits.slice(0, 5)) {
    warnings.push(`• [SECRET ${s.severity.toUpperCase()}] ${s.title} at ${s.location}: ${s.evidence}`);
  }
  for (const c of codeHits.slice(0, 5)) {
    warnings.push(`• [${c.cwe} ${c.severity.toUpperCase()}] ${c.title} at ${c.path}:${c.line}: ${c.snippet}`);
  }

  const entropy = shannonEntropy(Buffer.from(text, 'utf8').subarray(0, 65536));
  if (text.length > 512 && entropy >= 7.2) {
    warnings.push(`• [HIGH ENTROPY ${entropy.toFixed(2)}/8.00] File contains high-entropy content; verify no packed or obfuscated payload was written.`);
  }

  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];
    if (!/^(?:const|let|var)\s+[A-Z0-9_]+_RE\s*=/.test(ln.trim()) && /\b(?:nosemgrep|gitleaks:allow|trivy:ignore|bandit:\s*skip|@ts-nocheck)\b|\/\/\s*nolint\b|eslint-disable(?:-next-line)?\s+security\b/i.test(ln)) {
      warnings.push(`• [SUPPRESSION] Security suppression directive detected at ${resolved.relPath}:${i + 1}; verify justification.`);
      break;
    }
  }

  if (isBeefilePath(resolved.relPath)) {
    const shirudoRes = await auditBeefile(resolved.relPath, text, { root: resolved.rootReal });
    for (const f of shirudoRes.findings.slice(0, 5)) {
      warnings.push(`• [SHIRUDO ${f.severity.toUpperCase()}] ${f.title} at ${f.location}: ${f.evidence}`);
    }
    for (const ct of shirudoRes.cantTellReasons.slice(0, 3)) {
      warnings.push(`• [SHIRUDO CAN'T TELL · ${ct.code}] ${ct.message}`);
    }
  } else if (isBpfSourcePath(resolved.relPath)) {
    const bpfRes = auditBpfUpatchSource(resolved.relPath, text);
    for (const f of bpfRes.findings.slice(0, 5)) {
      warnings.push(`• [SHIRUDO ${f.cwe} ${f.severity.toUpperCase()}] ${f.title} at ${f.location}: ${f.evidence}`);
    }
    for (const ct of bpfRes.cantTellReasons.slice(0, 3)) {
      warnings.push(`• [SHIRUDO CAN'T TELL · ${ct.code}] ${ct.message}`);
    }
  } else if (/\.(?:sh|bash|zsh|ya?ml)$/i.test(resolved.relPath)) {
    const cmdPost = auditShirudoCommands(resolved.relPath, text);
    for (const f of cmdPost.findings.slice(0, 5)) {
      warnings.push(`• [SHIRUDO ${f.ruleId || f.cwe} ${f.severity.toUpperCase()}] ${f.title} at ${f.location}: ${f.evidence}`);
    }
    for (const ct of cmdPost.cantTellReasons.slice(0, 3)) {
      warnings.push(`• [SHIRUDO CAN'T TELL · ${ct.code}] ${ct.message}`);
    }
  }

  const agentGuardRes = scanAgentGuard(resolved.relPath, text);
  for (const f of agentGuardRes.findings.slice(0, 5)) {
    warnings.push(`• [AGENT-GUARD ${f.cwe || f.category.toUpperCase()} ${f.severity.toUpperCase()}] ${f.title} at ${f.location}: ${f.evidence}`);
  }
  for (const ct of agentGuardRes.cantTellReasons.slice(0, 3)) {
    warnings.push(`• [AGENT-GUARD CAN'T TELL · ${ct.code}] ${ct.message}`);
  }

  if (!warnings.length) return null;

  return {
    hookSpecificOutput: {
      hookEventName: 'PostToolUse',
      additionalContext: `[Marlowe Guard] Detected potential security issues after modifying ${resolved.relPath} (all secrets masked). Fix before finishing:\n${warnings.join('\n')}`
    }
  };
}

async function handleStop(payload, { strictCantTell = false } = {}) {
  if (!payload || typeof payload !== 'object') return null;
  // Critical infinite-loop prevention per Claude Code Stop hook contract.
  if (payload.stop_hook_active === true) return null;

  const cwd = payload.cwd || process.cwd();
  const result = await runAudit({
    root: cwd,
    mode: 'diff',
    queryOsv: false,
    failOn: 'high'
  });

  if (result.verdict === 'fails') {
    const details = result.failingFindings
      .slice(0, 5)
      .map(f => `${f.location}: [${f.severity.toUpperCase()}] ${f.title}`)
      .join('; ');
    return {
      decision: 'block',
      reason: `[Marlowe Guard · FAILS] Diff audit found ${result.failingFindings.length} blocking issue(s): ${details}. Resolve them before completing.`
    };
  }

  if (strictCantTell && result.verdict === 'cant-tell' && result.cantTellReasons.length) {
    const details = result.cantTellReasons.slice(0, 3).map(r => r.message).join('; ');
    return {
      decision: 'block',
      reason: `[Marlowe Guard · CAN'T TELL] Diff requires verification before completion: ${details}`
    };
  }

  return null;
}

function readStdinText() {
  return new Promise(resolve => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', chunk => {
      if (data.length < 2 * 1024 * 1024) data += chunk;
    });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', () => resolve(''));
  });
}

async function runClaudeHookCli(hookType, options = {}) {
  const raw = await readStdinText();
  if (!raw || !raw.trim()) return 0;

  let payload;
  try {
    payload = JSON.parse(raw);
  } catch (err) {
    process.stderr.write(`[marlowe-ci claude] Ignoring malformed stdin JSON: ${err.message}\n`);
    return 0;
  }

  let output = null;
  if (hookType === 'pre-tool') {
    output = await handlePreToolUse(payload);
  } else if (hookType === 'post-tool') {
    output = await handlePostToolUse(payload);
  } else if (hookType === 'stop') {
    output = await handleStop(payload, options);
  } else {
    throw new Error(`Unknown Claude hook "${hookType}". Use pre-tool, post-tool, or stop.`);
  }

  if (output) {
    process.stdout.write(JSON.stringify(output) + '\n');
  }
  return 0;
}

module.exports = {
  checkUrlSafety,
  handlePreToolUse,
  handlePostToolUse,
  handleStop,
  runClaudeHookCli
};
