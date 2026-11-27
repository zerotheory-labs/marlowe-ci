const path = require('node:path');

const BIDI_CONTROL_RE = /[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/;
const ZERO_WIDTH_RE = /[\u200B\u200C\u200D]/g;
const RULE_DEF_LINE_RE = /^(?:const|let|var)\s+[A-Z0-9_]+_RE\s*=/;

const AGENT_INSTRUCTION_BASENAMES = new Set([
  'claude.md',
  'agents.md',
  'gemini.md',
  'skill.md',
  'soul.md',
  '.cursorrules',
  '.windsurfrules',
  '.clinerules',
  'copilot-instructions.md'
]);

const AGENT_INSTRUCTION_PATH_RE = /(?:^|\/)(?:\.cursor\/rules\/|\.windsurf\/rules\/|\.github\/ISSUE_TEMPLATE\/|\.github\/copilot-instructions\.md$)/i;

const PROMPT_OVERRIDE_RE = /\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|system|safety)\s+(?:instructions|prompts?|rules|guardrails)\b|\byou\s+are\s+now\s+in\s+(?:unrestricted|developer|jailbreak)\s+mode\b/i;
const COVERT_EXFIL_RE = /\b(?:silently|secretly|without\s+(?:telling|informing|asking)\s+the\s+user|do\s+not\s+(?:tell|inform|mention\s+to)\s+the\s+user|hide\s+this\s+from\s+the\s+user)\b[^\n]{0,160}\b(?:\.env|\.ssh|secret|token|key|password|credential|curl|wget|bash|shell|exfiltrat|http:\/\/|https:\/\/|mcp)\b/i;
const HIDDEN_HTML_DIRECTIVE_RE = /<!--[\s\S]{0,600}?\b(?:ignore\s+(?:all\s+)?(?:previous|prior)|system\s+prompt|exfiltrate|read\s+\.env|curl\s+https?:\/\/|run\s+bash|override\s+safety|without\s+(?:telling|informing)\s+the\s+user)\b[\s\S]{0,200}?-->/i;

const LIFECYCLE_HOOKS = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish', 'preuninstall', 'postuninstall'];
const RUGPULL_SCRIPT_RE = /\b(?:curl|wget)\b[^\n]*(?:\|\s*(?:sh|bash|zsh|dash)|-o\b|-O\b)|\bpowershell\b[^\n]*-enc\b|\bbase64\s+(?:-d|--decode)\b|\bnode\s+-e\b[^\n]*(?:fetch|http|https|child_process|process\.env)|\bpython3?\s+-c\b[^\n]*(?:urllib|requests|socket)|\/dev\/tcp\/|\b(?:nc|ncat|netcat)\s+/i;

const MCP_CONFIG_BASENAMES = new Set(['.mcp.json', 'mcp.json']);
const MCP_PIPE_SHELL_RE = /\b(?:curl|wget)\b[^\n]*(?:\|\s*(?:sh|bash|zsh|dash))/i;

function isAgentInstructionPath(relPath) {
  const norm = String(relPath || '').replace(/\\/g, '/').replace(/^\.\//, '');
  const base = path.posix.basename(norm).toLowerCase();
  return AGENT_INSTRUCTION_BASENAMES.has(base) || AGENT_INSTRUCTION_PATH_RE.test(norm);
}

function isMcpConfigPath(relPath) {
  const norm = String(relPath || '').replace(/\\/g, '/').replace(/^\.\//, '');
  const base = path.posix.basename(norm).toLowerCase();
  if (base === '.mcp.json') return true;
  if (MCP_CONFIG_BASENAMES.has(base) && /(?:^|\/)\.(?:cursor|vscode|windsurf)\/mcp\.json$/i.test(norm)) {
    return true;
  }
  return false;
}

function extractUnicodeControlSummary(str, { allowDirectionalMarks = false } = {}) {
  const s = String(str || '');
  const codePoints = [];
  let zeroWidthCount = 0;
  let tagCount = 0;
  let bidiCount = 0;

  const chars = Array.from(s);
  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i];
    const cp = ch.codePointAt(0);
    if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069)) {
      bidiCount++;
      codePoints.push(`U+${cp.toString(16).toUpperCase().padStart(4, '0')}`);
    } else if (!allowDirectionalMarks && (cp === 0x200e || cp === 0x200f || cp === 0x061c)) {
      bidiCount++;
      codePoints.push(`U+${cp.toString(16).toUpperCase().padStart(4, '0')}`);
    } else if (cp >= 0xe0001 && cp <= 0xe007f) {
      tagCount++;
      codePoints.push(`U+${cp.toString(16).toUpperCase().padStart(5, '0')}`);
    } else if (cp === 0x200b || cp === 0x200c || cp === 0x200d || (cp === 0xfeff && i > 0)) {
      if (cp === 0x200d) {
        const prev = i > 0 ? chars[i - 1] : '';
        const next = i + 1 < chars.length ? chars[i + 1] : '';
        const isEmojiZwj = Boolean(
          prev &&
          next &&
          (/\p{Extended_Pictographic}/u.test(prev) ||
            prev.codePointAt(0) === 0xfe0f ||
            /\p{Extended_Pictographic}/u.test(next))
        );
        if (isEmojiZwj) continue;
      }
      zeroWidthCount++;
      codePoints.push(`U+${cp.toString(16).toUpperCase().padStart(4, '0')}`);
    }
  }

  return {
    bidiCount,
    tagCount,
    zeroWidthCount,
    hasHazard: bidiCount > 0 || tagCount > 0 || zeroWidthCount >= 3,
    codes: [...new Set(codePoints)].slice(0, 6)
  };
}

function hasHiddenUnicodeControls(str) {
  return extractUnicodeControlSummary(str).hasHazard;
}

function escapeInvisibleForEvidence(line) {
  let out = '';
  let idx = 0;
  for (const ch of String(line || '')) {
    const cp = ch.codePointAt(0);
    if (
      (cp >= 0x202a && cp <= 0x202e) ||
      (cp >= 0x2066 && cp <= 0x2069) ||
      cp === 0x200e ||
      cp === 0x200f ||
      cp === 0x061c ||
      (cp >= 0xe0001 && cp <= 0xe007f) ||
      cp === 0x200b ||
      cp === 0x200c ||
      cp === 0x200d ||
      (cp === 0xfeff && idx > 0)
    ) {
      out += `[U+${cp.toString(16).toUpperCase().padStart(4, '0')}]`;
    } else {
      out += ch;
    }
    idx++;
  }
  return out.trim().slice(0, 220);
}

function findJsonKeyLine(lines, keyName, startAt = 0) {
  const escaped = keyName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`"${escaped}"\\s*:`);
  for (let i = startAt; i < lines.length; i++) {
    if (re.test(lines[i])) return i + 1;
  }
  return 1;
}

function scanPackageLifecycleScripts(relPath, text, lines, { allowedLines = null, addedLines = null } = {}) {
  const findings = [];
  const cantTellReasons = [];
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { findings, cantTellReasons };
  }
  const scripts = parsed && typeof parsed === 'object' && parsed.scripts && typeof parsed.scripts === 'object'
    ? parsed.scripts
    : null;
  if (!scripts) return { findings, cantTellReasons };

  const addedLineSet = Array.isArray(addedLines) && addedLines.length
    ? new Set(addedLines.map(l => l.line))
    : null;
  const scriptsStart = findJsonKeyLine(lines, 'scripts', 0) - 1;

  for (const hook of LIFECYCLE_HOOKS) {
    if (typeof scripts[hook] !== 'string') continue;
    const cmd = scripts[hook];
    const lineNum = findJsonKeyLine(lines, hook, Math.max(0, scriptsStart));
    if (allowedLines && !allowedLines.has(lineNum)) continue;

    if (RUGPULL_SCRIPT_RE.test(cmd)) {
      findings.push({
        title: `Malicious package lifecycle script (${hook})`,
        severity: 'high',
        category: 'supply-chain',
        cwe: 'CWE-506',
        reachability: 'reachable',
        location: `${relPath}:${lineNum}`,
        evidence: `"${hook}": "${cmd}"`.slice(0, 220),
        remediation: `Remove remote shell execution or encoded payload logic from "${hook}" in package.json before installing.`
      });
    } else if (addedLineSet && addedLineSet.has(lineNum) && (hook === 'preinstall' || hook === 'postinstall')) {
      cantTellReasons.push({
        code: 'lifecycle-script-added',
        path: relPath,
        line: lineNum,
        message: `New package lifecycle hook "${hook}" added at ${relPath}:${lineNum}; verify install-time behavior manually.`
      });
    }
  }

  return { findings, cantTellReasons };
}

function scanMcpConfigEntries(relPath, text, lines, { allowedLines = null } = {}) {
  const findings = [];
  const cantTellReasons = [];
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { findings, cantTellReasons };
  }
  if (!parsed || typeof parsed !== 'object') return { findings, cantTellReasons };

  const registries = [parsed.mcpServers, parsed.servers].filter(obj => obj && typeof obj === 'object' && !Array.isArray(obj));
  for (const reg of registries) {
    for (const [serverName, cfg] of Object.entries(reg)) {
      if (!cfg || typeof cfg !== 'object') continue;
      const keyLine = findJsonKeyLine(lines, serverName, 0);
      if (allowedLines) {
        let blockTouched = allowedLines.has(keyLine);
        if (!blockTouched) {
          for (let ln = keyLine; ln <= Math.min(lines.length, keyLine + 16); ln++) {
            if (allowedLines.has(ln)) {
              blockTouched = true;
              break;
            }
          }
        }
        if (!blockTouched) continue;
      }

      const cmd = typeof cfg.command === 'string' ? cfg.command : '';
      const argsList = Array.isArray(cfg.args) ? cfg.args.map(a => String(a)) : [];
      const fullCmd = [cmd, ...argsList].join(' ').trim();
      const env = cfg.env && typeof cfg.env === 'object' ? cfg.env : {};

      if (MCP_PIPE_SHELL_RE.test(fullCmd) || RUGPULL_SCRIPT_RE.test(fullCmd)) {
        findings.push({
          title: `Untrusted MCP server shell pipeline (${serverName})`,
          severity: 'high',
          category: 'appsec',
          cwe: 'CWE-78',
          reachability: 'reachable',
          location: `${relPath}:${keyLine}`,
          evidence: fullCmd.slice(0, 220),
          remediation: 'Pin MCP servers to verified npm packages or local signed binaries rather than piping remote URLs into a shell.'
        });
      }

      if (String(env.NODE_TLS_REJECT_UNAUTHORIZED || '').trim() === '0' || String(env.NODE_TLS_REJECT_UNAUTHORIZED || '').trim().toLowerCase() === 'false') {
        const tlsLine = findJsonKeyLine(lines, 'NODE_TLS_REJECT_UNAUTHORIZED', Math.max(0, keyLine - 1));
        findings.push({
          title: `MCP server disables TLS certificate verification (${serverName})`,
          severity: 'high',
          category: 'crypto',
          cwe: 'CWE-295',
          reachability: 'reachable',
          location: `${relPath}:${tlsLine}`,
          evidence: 'NODE_TLS_REJECT_UNAUTHORIZED: "0"',
          remediation: 'Remove NODE_TLS_REJECT_UNAUTHORIZED override from MCP server env configuration.'
        });
      }

      if (typeof cfg.url === 'string' && /^http:\/\//i.test(cfg.url.trim())) {
        const rawUrl = cfg.url.trim();
        let isLoopback = false;
        try {
          const u = new URL(rawUrl);
          isLoopback = u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '[::1]';
        } catch {
          isLoopback = false;
        }
        if (!isLoopback) {
          const urlLine = findJsonKeyLine(lines, 'url', Math.max(0, keyLine - 1));
          cantTellReasons.push({
            code: 'mcp-insecure-transport',
            path: relPath,
            line: urlLine,
            message: `MCP server "${serverName}" uses unencrypted non-loopback http:// transport at ${relPath}:${urlLine}; verify TLS or network boundary.`
          });
        }
      }
    }
  }

  return { findings, cantTellReasons };
}

function scanAgentGuard(relPath, text, { allowedLines = null, addedLines = null } = {}) {
  const findings = [];
  const cantTellReasons = [];
  if (typeof text !== 'string' || !text.length) return { findings, cantTellReasons };

  const lines = text.split('\n');
  const isAgentDoc = isAgentInstructionPath(relPath);
  const isI18nOrDocData = !isAgentDoc && /\.(?:md|mdx|rst|txt|ya?ml|json|po|xlf)$/i.test(String(relPath || ''));
  const baseName = path.posix.basename(String(relPath || '').replace(/\\/g, '/'));

  for (let i = 0; i < lines.length; i++) {
    const lineNum = i + 1;
    if (allowedLines && !allowedLines.has(lineNum)) continue;
    const raw = lines[i].replace(/\r$/, '');
    if (!raw || raw.length > 4000) continue;

    const uni = extractUnicodeControlSummary(raw, { allowDirectionalMarks: isI18nOrDocData });
    if (uni.hasHazard) {
      const kind = uni.bidiCount > 0 ? 'Trojan Source bidirectional Unicode control' : 'Hidden Unicode tag/zero-width smuggling';
      findings.push({
        title: `${kind} (${uni.codes.join(', ')})`,
        severity: 'high',
        category: 'appsec',
        cwe: 'CWE-116',
        reachability: 'reachable',
        location: `${relPath}:${lineNum}`,
        evidence: escapeInvisibleForEvidence(raw),
        remediation: 'Strip bidirectional override, tag-block, and hidden zero-width Unicode control characters from tracked files.'
      });
    }

    const trimmed = raw.trim();
    if (isAgentDoc && !RULE_DEF_LINE_RE.test(trimmed)) {
      if (PROMPT_OVERRIDE_RE.test(raw) || COVERT_EXFIL_RE.test(raw)) {
        findings.push({
          title: 'Indirect prompt injection directive in agent context file',
          severity: 'high',
          category: 'appsec',
          cwe: 'CWE-74',
          reachability: 'reachable',
          location: `${relPath}:${lineNum}`,
          evidence: trimmed.slice(0, 220),
          remediation: 'Remove instruction-override or covert exfiltration directives from agent instruction files before loading into an AI session.'
        });
      }
    }
  }

  // Detect covert prompt-injection instructions hidden inside HTML/Markdown comments anywhere in docs/code
  if (text.includes('<!--')) {
    const commentRe = new RegExp('<' + '!--[\\s\\S]{0,800}?--' + '>', 'g');
    let m;
    while ((m = commentRe.exec(text)) !== null) {
      const snippet = m[0];
      const before = text.slice(0, m.index);
      const lineNum = before.split('\n').length;
      const lineText = (lines[lineNum - 1] || '').trim();
      if (RULE_DEF_LINE_RE.test(lineText)) continue;
      const lineSpan = snippet.split('\n').length;
      if (allowedLines) {
        let touchesAllowed = false;
        for (let ln = lineNum; ln < lineNum + lineSpan; ln++) {
          if (allowedLines.has(ln)) {
            touchesAllowed = true;
            break;
          }
        }
        if (!touchesAllowed) continue;
      }
      if (HIDDEN_HTML_DIRECTIVE_RE.test(snippet) || PROMPT_OVERRIDE_RE.test(snippet) || COVERT_EXFIL_RE.test(snippet)) {
        findings.push({
          title: 'Hidden prompt-injection directive inside HTML comment',
          severity: 'high',
          category: 'appsec',
          cwe: 'CWE-74',
          reachability: 'reachable',
          location: `${relPath}:${lineNum}`,
          evidence: snippet.replace(/\s+/g, ' ').trim().slice(0, 220),
          remediation: 'Remove hidden prompt-injection instructions from Markdown or HTML comments.'
        });
      }
    }
  }

  if (baseName === 'package.json') {
    const pkgRes = scanPackageLifecycleScripts(relPath, text, lines, { allowedLines, addedLines });
    findings.push(...pkgRes.findings);
    cantTellReasons.push(...pkgRes.cantTellReasons);
  }

  if (isMcpConfigPath(relPath)) {
    const mcpRes = scanMcpConfigEntries(relPath, text, lines, { allowedLines });
    findings.push(...mcpRes.findings);
    cantTellReasons.push(...mcpRes.cantTellReasons);
  }

  return { findings, cantTellReasons };
}

module.exports = {
  BIDI_CONTROL_RE,
  ZERO_WIDTH_RE,
  isAgentInstructionPath,
  isMcpConfigPath,
  hasHiddenUnicodeControls,
  scanAgentGuard
};
