const fs = require('node:fs/promises');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { redactSecrets } = require('./cyber-scope.cjs');
const { triageArtifact } = require('./cyber-analyzers.cjs');
const { resolveToolBinary, safeSearchDirs } = require('./cyber-toolchain.cjs');
const { DEFAULT_PATH } = require('./toolchain.cjs');
const {
  resolveWithinRoot,
  readRegularTextFile,
  walkWorkspace
} = require('./fs-safe.cjs');

const execFileAsync = promisify(execFile);

const BEEFILE_NAME_RE = /(?:^|\/)(?:Beefile|[^/]+\.beefile)$/i;
const BPF_SOURCE_NAME_RE = /\.(?:bpf|upatch)\.c$/i;
const SHIRUDO_ARTIFACT_RE = /(?:^|\/)(?:Beefile|[^/]+\.beefile|[^/]+\.(?:bpf|upatch)\.c|[^/]+\.(?:bee|upatch))$/i;
const SHIRUDO_DRAFT_PATH_RE = /(?:^|\/)(?:Beefile|[^/]+\.beefile|[^/]+\.(?:bpf|upatch)\.c)$/i;

const HEX_NONCE_RE = /^[0-9a-fA-F]{8,128}$/;
const AK_NAME_RE = /^[0-9a-zA-Z:._-]{4,128}$/;
const ZERO_HEX_64_RE = /^(?:0x)?0{64}$/i;
const ZERO_HEX_SHORT_RE = /^(?:0x)?0{8,}$/i;

const FMOD_RET_TAG_RE = /^fmod_ret(\.s)?\/([^\s/]+)$/;
const SAFE_FMOD_SYM_RE = /^(?:__x64_sys_|__arm64_sys_|security_)/;
const LSM_COVERED_FMOD_SYM_RE = /^(?:vfs_open|vfs_read|vfs_write|vfs_unlink|vfs_rename|vfs_mkdir|vfs_rmdir|vfs_create|vfs_mknod|vfs_symlink|vfs_link|vfs_chmod|vfs_chown|do_filp_open|do_execve|do_execveat_common|bprm_execve|__sock_create|sock_create|sock_create_kern|inet_create|tcp_v4_connect|udp_sendmsg|security_file_open|security_bprm_check|security_socket_create|security_socket_connect|security_socket_sendmsg)$/;

const BAD_FMOD_ERRNO_RE = /^-\s*(?:EAGAIN|EWOULDBLOCK|EMSGSIZE|EINPROGRESS|ERESTARTSYS|ERESTARTNOINTR|ERESTARTNOHAND|ERESTART_RESTARTBLOCK|ENOIOCTLCMD)\b/;
const BAD_FMOD_POS_INT_RE = /^\+?[1-9]\d*[uUlL]*$/;
const BAD_FMOD_NEG_INT_RE = /^-\s*(\d+)[uUlL]*$/;

const RO_DANGER_EXEC_RE = /^(?:sh|bash|zsh|dash|ksh|cmd|cmd\.exe|powershell|pwsh|curl|wget|nc|ncat|netcat|socat)$/i;
const RO_PIPE_FETCH_RE = /\b(?:curl|wget)\b[^\n]*(?:\|\s*(?:sh|bash|zsh|dash)|-o\b|-O\b)|\/dev\/tcp\//i;
const LOAD_TARGET_RE = /^upatches\/[^/]+$/;
const CTRL_ESCAPE_RE = /\\(?:n|r|t|0)|[\x00-\x1f\x7f]/;
const SHIRUDO_CI_WORKFLOW_RE = /(?:^|\/)\.github\/workflows\/.*\.ya?ml$/i;

function isBeefilePath(relPath) {
  return BEEFILE_NAME_RE.test(String(relPath || '').replace(/\\/g, '/'));
}

function isBpfSourcePath(relPath) {
  return BPF_SOURCE_NAME_RE.test(String(relPath || '').replace(/\\/g, '/'));
}

function isShirudoArtifactPath(relPath) {
  return SHIRUDO_ARTIFACT_RE.test(String(relPath || '').replace(/\\/g, '/'));
}

function isShirudoDraftPath(relPath) {
  return SHIRUDO_DRAFT_PATH_RE.test(String(relPath || '').replace(/\\/g, '/'));
}

function stripTomlComment(line) {
  let inSingle = false;
  let inDouble = false;
  let escaped = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (inDouble && ch === '\\') {
      escaped = true;
      continue;
    }
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      continue;
    }
    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      continue;
    }
    if (ch === '#' && !inSingle && !inDouble) {
      return line.slice(0, i);
    }
  }
  return line;
}

function parseTomlValue(rawVal) {
  const s = String(rawVal || '').trim();
  if (!s) return '';
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    return s.slice(1, -1);
  }
  if (s === 'true') return true;
  if (s === 'false') return false;
  if (/^-?\d+$/.test(s)) return Number(s);
  if (s.startsWith('[') && s.endsWith(']')) {
    const inner = s.slice(1, -1).trim();
    if (!inner) return [];
    const items = [];
    let cur = '';
    let inSingle = false;
    let inDouble = false;
    let escaped = false;
    for (let i = 0; i < inner.length; i++) {
      const ch = inner[i];
      if (escaped) {
        cur += ch;
        escaped = false;
        continue;
      }
      if (inDouble && ch === '\\') {
        cur += ch;
        escaped = true;
        continue;
      }
      if (ch === "'" && !inDouble) inSingle = !inSingle;
      else if (ch === '"' && !inSingle) inDouble = !inDouble;
      if (ch === ',' && !inSingle && !inDouble) {
        items.push(parseTomlValue(cur));
        cur = '';
        continue;
      }
      cur += ch;
    }
    if (cur.trim()) items.push(parseTomlValue(cur));
    return items;
  }
  return s;
}

function parseBeefile(text) {
  const pkg = {};
  const files = [];
  const upatches = [];
  const selectors = [];
  const rawKeys = [];
  const parseWarnings = [];
  const unsupportedConstructs = [];
  const duplicateKeys = [];

  let section = '';
  let currentFile = null;
  let currentUpatch = null;
  let currentRodata = null;
  let currentPolicy = null;
  const selectorSeenKeys = new WeakMap();

  const lines = String(text || '').split(/\r?\n/);

  const ensureUpatch = lineNum => {
    if (!currentUpatch) {
      currentUpatch = {
        line: lineNum,
        source: '',
        type: '',
        unload: '',
        id: '',
        load_target: '',
        unload_target: '',
        treeId: '',
        treeLine: null,
        fixes: [],
        hasTreeSection: false,
        hasSelectorSection: false,
        selectorFields: {},
        kconfigFields: {},
        selectorLabels: {},
        rodata: [],
        policies: []
      };
      upatches.push(currentUpatch);
    }
    return currentUpatch;
  };

  const trackUniqueKey = (bucketObj, key, lineNum) => {
    if (Object.prototype.hasOwnProperty.call(bucketObj, key)) {
      duplicateKeys.push({ section, key, line: lineNum });
    }
  };

  for (let i = 0; i < lines.length; i++) {
    const lineNum = i + 1;
    const rawLine = lines[i];
    const clean = stripTomlComment(rawLine);
    const trimmed = clean.trim();
    if (!trimmed) continue;

    if (trimmed.startsWith('[[')) {
      const m = /^\[\[([^\]]+)\]\]$/.exec(trimmed);
      if (!m) {
        parseWarnings.push({ line: lineNum, message: `Malformed TOML array table header: ${trimmed.slice(0, 80)}` });
        continue;
      }
      section = m[1].trim();
      if (section === 'files') {
        currentFile = { line: lineNum, source: '', target: '' };
        files.push(currentFile);
      } else if (section === 'upatches') {
        currentUpatch = null;
        ensureUpatch(lineNum);
      } else if (section === 'upatches.rodata') {
        const up = ensureUpatch(lineNum);
        currentRodata = {
          line: lineNum,
          commentAbove: i > 0 ? String(lines[i - 1] || '') : '',
          symbol: '',
          generator: null,
          update: null
        };
        up.rodata.push(currentRodata);
      } else if (section === 'upatches.policy') {
        const up = ensureUpatch(lineNum);
        currentPolicy = { line: lineNum, id: '', bit: '', paths: [] };
        up.policies.push(currentPolicy);
      }
      continue;
    }

    if (trimmed.startsWith('[')) {
      const m = /^\[([^\]]+)\]$/.exec(trimmed);
      if (!m) {
        parseWarnings.push({ line: lineNum, message: `Malformed TOML section header: ${trimmed.slice(0, 80)}` });
        continue;
      }
      section = m[1].trim();
      if (section === 'upatches.tree') {
        const up = ensureUpatch(lineNum);
        up.hasTreeSection = true;
        if (!up.treeLine) up.treeLine = lineNum;
      } else if (
        section === 'upatches.tree.selector' ||
        section === 'upatches.tree.selector.kconfig' ||
        section === 'upatches.tree.selector.labels' ||
        section === 'upatches.selector.labels'
      ) {
        const up = ensureUpatch(lineNum);
        up.hasSelectorSection = true;
      }
      continue;
    }

    const eq = trimmed.indexOf('=');
    if (eq === -1) {
      parseWarnings.push({ line: lineNum, message: `Unexpected TOML line without "=" at line ${lineNum}` });
      continue;
    }

    const rawVal = trimmed.slice(eq + 1).trim();
    const key = trimmed.slice(0, eq).trim().replace(/^["']|["']$/g, '');

    if (/^(?:true|false)$/i.test(rawVal)) {
      unsupportedConstructs.push({ kind: 'boolean', line: lineNum, raw: trimmed.slice(0, 120) });
    } else if (rawVal.startsWith('{')) {
      unsupportedConstructs.push({ kind: 'inline-table', line: lineNum, raw: trimmed.slice(0, 120) });
    } else if (rawVal.startsWith('[') && !rawVal.endsWith(']')) {
      unsupportedConstructs.push({ kind: 'multiline-array', line: lineNum, raw: trimmed.slice(0, 120) });
    }

    const value = parseTomlValue(rawVal);
    rawKeys.push({ section, key, value, rawVal, line: lineNum });

    if (section === 'package') {
      pkg[key] = value;
    } else if (section === 'files' && currentFile) {
      if (key === 'source' || key === 'target') {
        currentFile[key] = typeof value === 'string' ? value : String(value || '');
      }
    } else if (section === 'upatches' && currentUpatch) {
      if (['source', 'type', 'unload', 'id', 'load_target', 'unload_target'].includes(key)) {
        currentUpatch[key] = typeof value === 'string' ? value : String(value || '');
      }
    } else if (section === 'upatches.rodata' && currentRodata) {
      if (key === 'symbol') currentRodata.symbol = typeof value === 'string' ? value : String(value || '');
      if (key === 'generator') {
        currentRodata.generator = Array.isArray(value) ? value.map(String) : [String(value || '')];
      }
      if (key === 'update') {
        currentRodata.update = Array.isArray(value) ? value.map(String) : [String(value || '')];
      }
    } else if (section === 'upatches.policy' && currentPolicy) {
      if (key === 'id' || key === 'bit') {
        currentPolicy[key] = typeof value === 'string' ? value : String(value || '');
      } else if (key === 'paths') {
        currentPolicy.paths = Array.isArray(value) ? value.map(String) : [String(value || '')];
      }
    } else if (section === 'upatches.tree' && currentUpatch) {
      if (key === 'id') currentUpatch.treeId = typeof value === 'string' ? value : String(value || '');
      if (key === 'fixes') {
        currentUpatch.fixes = Array.isArray(value) ? value.map(String) : [String(value || '')];
      }
    } else if (section === 'upatches.tree.selector' && currentUpatch) {
      trackUniqueKey(currentUpatch.selectorFields, key, lineNum);
      const vals = Array.isArray(value) ? value.map(v => String(v)) : (rawVal === '[]' ? [] : [String(value)]);
      currentUpatch.selectorFields[key] = vals;
      selectors.push({ upatchLine: currentUpatch.line, section, key, values: vals, rawVal, line: lineNum });
    } else if (section === 'upatches.tree.selector.kconfig' && currentUpatch) {
      trackUniqueKey(currentUpatch.kconfigFields, key, lineNum);
      const vals = Array.isArray(value) ? value.map(v => String(v)) : (rawVal === '[]' ? [] : [String(value)]);
      currentUpatch.kconfigFields[key] = vals;
      selectors.push({ upatchLine: currentUpatch.line, section, key, values: vals, rawVal, line: lineNum });
    } else if (
      (section === 'upatches.tree.selector.labels' || section === 'upatches.selector.labels') &&
      currentUpatch
    ) {
      trackUniqueKey(currentUpatch.selectorLabels, key, lineNum);
      const vals = Array.isArray(value) ? value.map(v => String(v)) : (rawVal === '[]' ? [] : [String(value)]);
      currentUpatch.selectorLabels[key] = vals;
      selectors.push({ upatchLine: currentUpatch.line, section, key, values: vals, rawVal, line: lineNum });
    }
    void selectorSeenKeys;
  }

  return {
    package: pkg,
    files,
    upatches,
    selectors,
    rawKeys,
    parseWarnings,
    unsupportedConstructs,
    duplicateKeys
  };
}

function stripCCommentsAndStrings(src) {
  let out = '';
  let inLine = false;
  let inBlock = false;
  let inStr = '';
  let esc = false;
  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    const next = src[i + 1];
    if (inLine) {
      if (ch === '\n') {
        inLine = false;
        out += '\n';
      } else {
        out += ' ';
      }
      continue;
    }
    if (inBlock) {
      if (ch === '*' && next === '/') {
        inBlock = false;
        out += '  ';
        i++;
      } else {
        out += ch === '\n' ? '\n' : ' ';
      }
      continue;
    }
    if (inStr) {
      out += ch === '\n' ? '\n' : ' ';
      if (esc) {
        esc = false;
      } else if (ch === '\\') {
        esc = true;
      } else if (ch === inStr) {
        inStr = '';
      }
      continue;
    }
    if (ch === '/' && next === '/') {
      inLine = true;
      out += '  ';
      i++;
      continue;
    }
    if (ch === '/' && next === '*') {
      inBlock = true;
      out += '  ';
      i++;
      continue;
    }
    if (ch === '"' || ch === "'") {
      inStr = ch;
      out += ' ';
      continue;
    }
    out += ch;
  }
  return out;
}

function extractSecPrograms(src) {
  const programs = [];
  const secRe = /\bSEC\s*\(\s*["']([^"']+)["']\s*\)/g;
  const cleanSrc = stripCCommentsAndStrings(src);
  let m;
  while ((m = secRe.exec(src)) !== null) {
    const secTag = m[1].trim();
    const secLine = src.slice(0, m.index).split('\n').length;
    if (/^(?:license|\.rodata|\.maps|maps)$/i.test(secTag)) continue;

    // Locate first '{' after SEC(...) outside comments/strings
    let openIdx = -1;
    for (let i = m.index + m[0].length; i < cleanSrc.length; i++) {
      if (cleanSrc[i] === '{') {
        openIdx = i;
        break;
      }
      if (cleanSrc[i] === ';') {
        // Variable declaration rather than function body
        break;
      }
    }
    if (openIdx === -1) {
      programs.push({ secTag, secLine, bodyStartLine: secLine, body: '', cleanBody: '' });
      continue;
    }
    let depth = 0;
    let closeIdx = cleanSrc.length - 1;
    for (let i = openIdx; i < cleanSrc.length; i++) {
      if (cleanSrc[i] === '{') depth++;
      else if (cleanSrc[i] === '}') {
        depth--;
        if (depth === 0) {
          closeIdx = i;
          break;
        }
      }
    }
    const bodyStartLine = src.slice(0, openIdx).split('\n').length;
    programs.push({
      secTag,
      secLine,
      bodyStartLine,
      body: src.slice(openIdx, closeIdx + 1),
      cleanBody: cleanSrc.slice(openIdx, closeIdx + 1)
    });
  }
  return programs;
}

function isOneHot64BitHex(hexStr) {
  const s = String(hexStr || '').trim();
  if (!/^0x[0-9a-fA-F]+$/.test(s)) return false;
  try {
    const val = BigInt(s);
    return val > 0n && val < (1n << 64n) && (val & (val - 1n)) === 0n;
  } catch {
    return false;
  }
}

function strippedUpatchBasename(sourceRel) {
  const base = path.posix.basename(String(sourceRel || '').trim().replace(/\\/g, '/'));
  return base
    .replace(/\.upatch\.c$/i, '')
    .replace(/\.bpf\.c$/i, '')
    .replace(/\.bpf\.o$/i, '')
    .replace(/\.(?:o|jar)$/i, '');
}

async function auditBeefile(relPath, text, { root = '' } = {}) {
  const parsed = parseBeefile(text);
  const findings = [];
  const cantTellReasons = [];
  const lines = String(text || '').split(/\r?\n/);

  // 1. Embedded private key material or operator key pointers
  const pemRe = new RegExp('-----BEGIN ' + '(?:[A-Z0-9 ]* )?PRIVATE KEY-----', 'i');
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];
    if (pemRe.test(ln)) {
      findings.push({
        ruleId: 'SHIRUDO-KEY-001',
        title: 'Private signing key embedded inside Shirudo Beefile',
        severity: 'critical',
        category: 'secrets',
        cwe: 'CWE-798',
        reachability: 'reachable',
        location: `${relPath}:${i + 1}`,
        evidence: redactSecrets(ln.trim().slice(0, 180)).text,
        remediation: 'Remove signing key material from Beefile; keep ML-DSA-87 operator keys strictly in an external keys directory outside version control.'
      });
    }
  }

  for (const entry of parsed.rawKeys) {
    const valStr = Array.isArray(entry.value) ? entry.value.join(',') : String(entry.value || '');
    if (
      /^(?:keys_dir|private_key|signing_key|key_path|ml_dsa_key)$/i.test(entry.key) ||
      (/\.(?:pem|key)(?:$|\b)/i.test(valStr) && !/\.pub\.pem$/i.test(valStr))
    ) {
      findings.push({
        ruleId: 'SHIRUDO-KEY-002',
        title: `Shirudo operator signing key reference in Beefile (${entry.key})`,
        severity: 'critical',
        category: 'secrets',
        cwe: 'CWE-798',
        reachability: 'reachable',
        location: `${relPath}:${entry.line}`,
        evidence: redactSecrets(`${entry.key} = ${JSON.stringify(entry.value)}`).text,
        remediation: 'Pass --keys-dir only via operator CLI invocation outside the repository; never commit private key paths or key material inside Beefile.'
      });
    }

    // Plaintext http:// OCI/registry URL or embedded credentials
    if (typeof entry.value === 'string') {
      if (/\bhttp:\/\//i.test(entry.value) && !/^http:\/\/(?:127\.0\.0\.1|localhost)(?::|\/|$)/i.test(entry.value)) {
        findings.push({
          ruleId: 'SHIRUDO-REG-001',
          title: 'Plaintext http:// registry or artifact URL in Shirudo Beefile',
          severity: 'high',
          category: 'config',
          cwe: 'CWE-319',
          reachability: 'reachable',
          location: `${relPath}:${entry.line}`,
          evidence: redactSecrets(`${entry.key} = "${entry.value}"`).text,
          remediation: 'Use TLS-protected oci:// or https:// endpoints so signed .bee upatch artifacts cannot be downgraded or tampered in transit.'
        });
      }
      if (/(?:oci|https?):\/\/[^/\s:@]+:[^@\s/'"]+@/i.test(entry.value)) {
        findings.push({
          ruleId: 'SHIRUDO-REG-002',
          title: 'Embedded registry credentials in Shirudo Beefile URL',
          severity: 'high',
          category: 'secrets',
          cwe: 'CWE-798',
          reachability: 'reachable',
          location: `${relPath}:${entry.line}`,
          evidence: redactSecrets(`${entry.key} = "${entry.value}"`).text,
          remediation: 'Remove embedded credentials from Beefile registry URLs and authenticate out-of-band via OCI credential helpers.'
        });
      }
    }
  }

  // SHIRUDO-BEE-003 (4): Unsupported Beefile TOML constructs (booleans, inline tables, multiline arrays)
  for (const uc of parsed.unsupportedConstructs) {
    findings.push({
      ruleId: 'SHIRUDO-BEE-003',
      title: `Unsupported Beefile TOML construct (${uc.kind})`,
      severity: 'high',
      category: 'config',
      cwe: 'CWE-20',
      reachability: 'reachable',
      location: `${relPath}:${uc.line}`,
      evidence: uc.raw,
      remediation: 'Use Shirudo\'s strict line-by-line TOML subset: string/integer/single-line array values without unquoted booleans, inline tables, or multiline arrays.'
    });
  }

  // SHIRUDO-BEE-001: Duplicate selector / kconfig / labels keys
  for (const dup of parsed.duplicateKeys) {
    findings.push({
      ruleId: 'SHIRUDO-BEE-001',
      title: `Duplicate Beefile key "${dup.key}" in [${dup.section}]`,
      severity: 'high',
      category: 'config',
      cwe: 'CWE-20',
      reachability: 'reachable',
      location: `${relPath}:${dup.line}`,
      evidence: `[${dup.section}] duplicate key "${dup.key}"`,
      remediation: 'Remove duplicate selector, kconfig, or labels keys so tree matching remains unambiguous.'
    });
  }

  // Package & upatch structure checks
  if (!parsed.package.name || !String(parsed.package.name).trim()) {
    findings.push({
      ruleId: 'SHIRUDO-BEE-003',
      title: 'Missing [package].name in Shirudo Beefile',
      severity: 'medium',
      category: 'config',
      cwe: 'CWE-1188',
      reachability: 'reachable',
      location: `${relPath}:1`,
      evidence: '[package] name is empty or missing',
      remediation: 'Declare [package] name = "<shield-name>" in Beefile so SPDX SBOM and signed tree metadata remain attributable.'
    });
  }

  if (!parsed.upatches.length && !parsed.files.length) {
    findings.push({
      ruleId: 'SHIRUDO-BEE-003',
      title: 'Shirudo Beefile defines zero [[upatches]] entries',
      severity: 'medium',
      category: 'config',
      cwe: 'CWE-1188',
      reachability: 'reachable',
      location: `${relPath}:1`,
      evidence: 'No [[upatches]] sections found',
      remediation: 'Define at least one scoped [[upatches]] block referencing a verified BPF or runtime shield artifact.'
    });
  }

  const baseDirRel = path.posix.dirname(String(relPath || '').replace(/\\/g, '/'));

  // SHIRUDO-BEE-003 (4): [[files]] source path safety
  for (const fEntry of parsed.files) {
    const fSrc = String(fEntry.source || '').trim().replace(/\\/g, '/');
    if (fSrc && (path.posix.isAbsolute(fSrc) || fSrc.split('/').includes('..'))) {
      findings.push({
        ruleId: 'SHIRUDO-BEE-003',
        title: 'Path traversal or absolute path in Shirudo [[files]].source',
        severity: 'high',
        category: 'appsec',
        cwe: 'CWE-22',
        reachability: 'reachable',
        location: `${relPath}:${fEntry.line}`,
        evidence: `source = "${fEntry.source}"`,
        remediation: 'Keep [[files]].source relative to the Beefile directory with no ".." segments or absolute paths.'
      });
    }
  }

  for (const up of parsed.upatches) {
    const src = String(up.source || '').trim();
    if (!src) {
      findings.push({
        ruleId: 'SHIRUDO-BEE-003',
        title: 'Shirudo [[upatches]] entry missing source field',
        severity: 'medium',
        category: 'config',
        cwe: 'CWE-1188',
        reachability: 'reachable',
        location: `${relPath}:${up.line}`,
        evidence: '[[upatches]] block has no source = "..."',
        remediation: 'Specify a workspace-relative source path inside [[upatches]].'
      });
    } else {
      const normSrc = src.replace(/\\/g, '/');
      if (path.posix.isAbsolute(normSrc) || normSrc.split('/').includes('..')) {
        findings.push({
          ruleId: 'SHIRUDO-BEE-003',
          title: 'Path traversal or absolute path in Shirudo upatch.source',
          severity: 'high',
          category: 'appsec',
          cwe: 'CWE-22',
          reachability: 'reachable',
          location: `${relPath}:${up.line}`,
          evidence: `source = "${src}"`,
          remediation: 'Keep upatch.source relative to the Beefile package directory with no ".." segments or absolute paths.'
        });
      }

      // SHIRUDO-BEE-003 (1): [upatches.tree] id must equal stripped basename of source
      if (up.treeId) {
        const expectedTreeId = strippedUpatchBasename(normSrc);
        if (up.treeId !== expectedTreeId) {
          findings.push({
            ruleId: 'SHIRUDO-BEE-003',
            title: `[upatches.tree] id "${up.treeId}" does not match stripped source basename "${expectedTreeId}"`,
            severity: 'high',
            category: 'config',
            cwe: 'CWE-1188',
            reachability: 'reachable',
            location: `${relPath}:${up.treeLine || up.line}`,
            evidence: `id = "${up.treeId}" vs source = "${src}"`,
            remediation: `Set [upatches.tree] id = "${expectedTreeId}" so bpm build and bpm tree sync resolve the artifact cleanly.`
          });
        }
      }
    }

    // SHIRUDO-BEE-003 (3): load_target / unload_target directly under upatches/
    for (const [tKey, tVal] of [['load_target', up.load_target], ['unload_target', up.unload_target]]) {
      const cleanT = String(tVal || '').trim().replace(/\\/g, '/');
      if (cleanT && (!LOAD_TARGET_RE.test(cleanT) || cleanT.split('/').includes('..'))) {
        findings.push({
          ruleId: 'SHIRUDO-BEE-003',
          title: `Shirudo upatch ${tKey} outside upatches/ directory`,
          severity: 'high',
          category: 'config',
          cwe: 'CWE-1188',
          reachability: 'reachable',
          location: `${relPath}:${up.line}`,
          evidence: `${tKey} = "${tVal}"`,
          remediation: `Place ${tKey} directly under "upatches/<filename>" so bpm install loads the artifact.`
        });
      }
    }

    // SHIRUDO-BEE-001: Control chars in tree.id & selector cardinality/wildcards
    if (up.treeId && CTRL_ESCAPE_RE.test(up.treeId)) {
      findings.push({
        ruleId: 'SHIRUDO-BEE-001',
        title: 'Control-character escape in Shirudo [upatches.tree] id',
        severity: 'high',
        category: 'appsec',
        cwe: 'CWE-116',
        reachability: 'reachable',
        location: `${relPath}:${up.treeLine || up.line}`,
        evidence: `id = "${up.treeId}"`,
        remediation: 'Remove escape/control sequences from [upatches.tree] id.'
      });
    }

    const upSelectors = parsed.selectors.filter(s => s.upatchLine === up.line);
    let hasWildcardSelector = false;
    for (const sel of upSelectors) {
      if (sel.rawVal === '[]' || sel.values.length === 0) {
        findings.push({
          ruleId: 'SHIRUDO-BEE-001',
          title: `Empty selector array "${sel.key} = []" breaks Shirudo tree sync`,
          severity: 'high',
          category: 'config',
          cwe: 'CWE-20',
          reachability: 'reachable',
          location: `${relPath}:${sel.line}`,
          evidence: `${sel.key} = []`,
          remediation: 'Provide 1 to 16 explicit selector values or omit the empty key.'
        });
      } else if (sel.values.length > 16) {
        findings.push({
          ruleId: 'SHIRUDO-BEE-001',
          title: `Selector array "${sel.key}" exceeds 16-value Beefile limit (${sel.values.length})`,
          severity: 'high',
          category: 'config',
          cwe: 'CWE-20',
          reachability: 'reachable',
          location: `${relPath}:${sel.line}`,
          evidence: `${sel.key} (${sel.values.length} entries)`,
          remediation: 'Limit each selector array to at most 16 values.'
        });
      }
      if (CTRL_ESCAPE_RE.test(sel.key) || sel.values.some(v => CTRL_ESCAPE_RE.test(v))) {
        findings.push({
          ruleId: 'SHIRUDO-BEE-001',
          title: `Control-character escape in Shirudo selector "${sel.key}"`,
          severity: 'high',
          category: 'appsec',
          cwe: 'CWE-116',
          reachability: 'reachable',
          location: `${relPath}:${sel.line}`,
          evidence: `${sel.key} = ${sel.rawVal}`.slice(0, 180),
          remediation: 'Remove control-character escapes (\\n, \\r, \\t) from selector keys and values.'
        });
      }
      if (sel.key === '*' || sel.values.some(v => v.trim() === '*')) {
        hasWildcardSelector = true;
      }
    }

    const totalSelectorKeys =
      Object.keys(up.selectorFields).length +
      Object.keys(up.kconfigFields).length +
      Object.keys(up.selectorLabels).length;
    const isEnforcingOrCve = (Array.isArray(up.fixes) && up.fixes.length > 0) || up.type === 'bpf' || up.hasTreeSection;

    if ((totalSelectorKeys === 0 && isEnforcingOrCve) || hasWildcardSelector) {
      cantTellReasons.push({
        code: 'SHIRUDO-BEE-001',
        path: relPath,
        line: up.treeLine || up.line,
        message: hasWildcardSelector
          ? `Shirudo upatch "${src || up.treeId || 'upatch'}" at ${relPath}:${up.line} uses a "*" wildcard selector; scope fleet blast radius before signing.`
          : `Shirudo [upatches.tree] "${up.treeId || src || 'upatch'}" fixes CVE/runtime behavior without [upatches.tree.selector]; verify unintended nodes will not pull it.`
      });
    }

    // SHIRUDO-BEE-002: [[upatches.rodata]] generator / update execvp command checks
    for (const ro of up.rodata) {
      for (const [field, arr] of [['generator', ro.generator], ['update', ro.update]]) {
        if (!Array.isArray(arr) || !arr.length) continue;
        const joined = arr.join(' ');
        const exeBase = path.posix.basename(String(arr[0] || '').replace(/\\/g, '/'));
        const hasTraversalOrAbs = arr.some(arg => {
          const s = String(arg || '');
          return s.split(/[\\/]/).includes('..') || path.posix.isAbsolute(s) || /^[A-Za-z]:[\\/]/.test(s);
        });
        if (RO_DANGER_EXEC_RE.test(exeBase) || RO_PIPE_FETCH_RE.test(joined) || hasTraversalOrAbs) {
          findings.push({
            ruleId: 'SHIRUDO-BEE-002',
            title: `Unsafe command/path in [[upatches.rodata]].${field} runs with operator key privileges`,
            severity: 'high',
            category: 'appsec',
            cwe: 'CWE-78',
            reachability: 'reachable',
            location: `${relPath}:${ro.line}`,
            evidence: `${field} = ${JSON.stringify(arr)}`.slice(0, 220),
            remediation: `Replace shells, network fetchers, absolute paths, and ".." segments in [[upatches.rodata]].${field} with a reviewed deterministic relative generator script.`
          });
        } else if (!/shirudo-generator-reviewed/i.test(ro.commentAbove || '')) {
          cantTellReasons.push({
            code: 'SHIRUDO-BEE-002',
            path: relPath,
            line: ro.line,
            message: `Unreviewed [[upatches.rodata]].${field} command (${arr[0]}) at ${relPath}:${ro.line} runs via execvp during bpm build/update; review before operator signing.`
          });
        }
      }
    }

    // SHIRUDO-BEE-003 (2): [[upatches.policy]] limits, unique 64-bit one-hot bit, path glob placement
    if (up.policies.length > 64) {
      findings.push({
        ruleId: 'SHIRUDO-BEE-003',
        title: `Shirudo [[upatches.policy]] count (${up.policies.length}) exceeds 64-entry cap`,
        severity: 'high',
        category: 'config',
        cwe: 'CWE-20',
        reachability: 'reachable',
        location: `${relPath}:${up.policies[64].line}`,
        evidence: `${up.policies.length} [[upatches.policy]] blocks`,
        remediation: 'Keep at most 64 [[upatches.policy]] entries per upatch.'
      });
    }
    const seenPolicyIds = new Set();
    const seenPolicyBits = new Set();
    for (const pol of up.policies) {
      if (pol.id) {
        if (seenPolicyIds.has(pol.id)) {
          findings.push({
            ruleId: 'SHIRUDO-BEE-003',
            title: `Duplicate [[upatches.policy]] id "${pol.id}"`,
            severity: 'high',
            category: 'config',
            cwe: 'CWE-20',
            reachability: 'reachable',
            location: `${relPath}:${pol.line}`,
            evidence: `id = "${pol.id}"`,
            remediation: 'Assign a unique id to each [[upatches.policy]] entry.'
          });
        }
        seenPolicyIds.add(pol.id);
      }
      if (!isOneHot64BitHex(pol.bit)) {
        findings.push({
          ruleId: 'SHIRUDO-BEE-003',
          title: `Invalid non-one-hot 64-bit hex mask in [[upatches.policy]].bit ("${pol.bit}")`,
          severity: 'high',
          category: 'config',
          cwe: 'CWE-20',
          reachability: 'reachable',
          location: `${relPath}:${pol.line}`,
          evidence: `bit = "${pol.bit}"`,
          remediation: 'Use a unique power-of-two 64-bit hex bitmask (e.g., "0x01", "0x02", "0x04").'
        });
      } else {
        const bitKey = BigInt(pol.bit.trim()).toString(16);
        if (seenPolicyBits.has(bitKey)) {
          findings.push({
            ruleId: 'SHIRUDO-BEE-003',
            title: `Duplicate [[upatches.policy]] bit mask "${pol.bit}"`,
            severity: 'high',
            category: 'config',
            cwe: 'CWE-20',
            reachability: 'reachable',
            location: `${relPath}:${pol.line}`,
            evidence: `bit = "${pol.bit}"`,
            remediation: 'Assign a distinct one-hot 64-bit bitmask to every [[upatches.policy]] entry.'
          });
        }
        seenPolicyBits.add(bitKey);
      }
      for (const p of pol.paths || []) {
        const byteLen = Buffer.byteLength(p, 'utf8');
        const dirPart = path.posix.dirname(p);
        const dirHasWildcard = /[*?]/.test(dirPart);
        if (!p.startsWith('/') || byteLen > 255 || (p.length > 1 && p.endsWith('/')) || dirHasWildcard) {
          findings.push({
            ruleId: 'SHIRUDO-BEE-003',
            title: `Invalid [[upatches.policy]] path pattern "${p}"`,
            severity: 'high',
            category: 'config',
            cwe: 'CWE-20',
            reachability: 'reachable',
            location: `${relPath}:${pol.line}`,
            evidence: `paths includes "${p}"`,
            remediation: 'Policy paths must be absolute (/...), <= 255 bytes, not end with "/", and use * or ? only in the final filename segment.'
          });
        }
      }
    }

    // Optional workspace disk verification
    if (root && src && !path.posix.isAbsolute(src.replace(/\\/g, '/')) && !src.replace(/\\/g, '/').split('/').includes('..')) {
      const normSrc = src.replace(/\\/g, '/');
      const joinedRel = baseDirRel && baseDirRel !== '.' ? path.posix.join(baseDirRel, normSrc) : normSrc;
      let exists = false;
      try {
        const res = await resolveWithinRoot(root, joinedRel);
        await fs.access(res.fullPath);
        exists = true;
      } catch {
        exists = false;
      }
      if (!exists) {
        cantTellReasons.push({
          code: 'shirudo-upatch-missing-source',
          path: relPath,
          line: up.line,
          message: `Referenced upatch artifact "${src}" (${joinedRel}) was not found inside workspace.`
        });
      }

      if (/\.(?:bpf\.o|bee|upatch)$/i.test(normSrc)) {
        const siblingBase = normSrc.replace(/\.(?:bpf\.o|bee|upatch)$/i, '');
        let hasSource = false;
        for (const ext of ['.bpf.c', '.upatch.c']) {
          const siblingRel = baseDirRel && baseDirRel !== '.' ? path.posix.join(baseDirRel, `${siblingBase}${ext}`) : `${siblingBase}${ext}`;
          try {
            const sibRes = await resolveWithinRoot(root, siblingRel);
            await fs.access(sibRes.fullPath);
            hasSource = true;
            break;
          } catch {
            // Try next extension
          }
        }
        if (!hasSource) {
          cantTellReasons.push({
            code: 'shirudo-upatch-opaque-object',
            path: relPath,
            line: up.line,
            message: `Upatch "${src}" references compiled bytecode/object with no sibling Plain BPF C source (${siblingBase}.bpf.c) to inspect.`
          });
        }
      }
    }
  }

  return { parsed, findings, cantTellReasons };
}

function auditBpfUpatchSource(relPath, text) {
  const findings = [];
  const cantTellReasons = [];
  const src = String(text || '');
  const lines = src.split(/\r?\n/);

  const SCOPING_HINT_RE = /\b(?:bpf_get_current_pid_tgid|bpf_get_current_uid_gid|bpf_get_current_comm|bpf_get_current_cgroup_id|d_name|inode|comm|pid|uid|tgid|cgroup)\b/;
  const BROAD_HOOK_RE = /\bSEC\s*\(\s*["'](?:lsm\/|kprobe\/|tracepoint\/syscalls\/|raw_tp\/)[^"']*["']\s*\)/g;
  const HAS_LICENSE_RE = /\bSEC\s*\(\s*["']license["']\s*\)|char\s+(?:_?license|LICENSE)\s*\[\s*\]/i;
  const POLICY_MAP_WRITE_RE = /\bbpf_map_(?:update|delete)_elem\s*\(\s*&\s*(?:shirudo_task_policy|shirudo_sock_policy)\b/;

  const hasGlobalScopeFilter = SCOPING_HINT_RE.test(src);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) continue;

    if (/\bbpf_probe_write_user\s*\(/.test(line)) {
      findings.push({
        ruleId: 'SHIRUDO-BPF-LEGACY-001',
        title: 'Unsafe bpf_probe_write_user() helper inside Shirudo BPF upatch',
        severity: 'high',
        category: 'appsec',
        cwe: 'CWE-787',
        reachability: 'reachable',
        location: `${relPath}:${i + 1}`,
        evidence: trimmed.slice(0, 220),
        remediation: 'Avoid modifying arbitrary userspace memory with bpf_probe_write_user(); prefer scoped LSM return checks or read-only ringbuf telemetry.'
      });
    }

    if (/\bbpf_override_return\s*\(/.test(line) && !/\/\/\s*shirudo-guard:/i.test(line)) {
      findings.push({
        ruleId: 'SHIRUDO-BPF-LEGACY-002',
        title: 'Unguarded bpf_override_return() in Shirudo BPF upatch',
        severity: 'high',
        category: 'appsec',
        cwe: 'CWE-284',
        reachability: 'reachable',
        location: `${relPath}:${i + 1}`,
        evidence: trimmed.slice(0, 220),
        remediation: 'Restrict bpf_override_return() to tightly scoped error injection paths and document an explicit "// shirudo-guard: <justification>" rationale.'
      });
    }

    if (/\bbpf_send_signal(?:_thread)?\s*\(\s*(?:9|SIGKILL)\b/.test(line) && !hasGlobalScopeFilter) {
      findings.push({
        ruleId: 'SHIRUDO-BPF-LEGACY-003',
        title: 'Unfiltered SIGKILL inside Shirudo BPF upatch risk of host-wide DoS',
        severity: 'medium',
        category: 'appsec',
        cwe: 'CWE-400',
        reachability: 'reachable',
        location: `${relPath}:${i + 1}`,
        evidence: trimmed.slice(0, 220),
        remediation: 'Guard bpf_send_signal(SIGKILL) behind explicit process/cgroup/uid/inode predicates (e.g., bpf_get_current_comm or bpf_get_current_cgroup_id).'
      });
    }

    // SHIRUDO-BPF-004: Writing/deleting shared Shirudo policy maps from upatch code
    if (POLICY_MAP_WRITE_RE.test(line)) {
      findings.push({
        ruleId: 'SHIRUDO-BPF-004',
        title: 'Shirudo upatch mutates read-only pinned policy map (shirudo_task_policy/sock_policy)',
        severity: 'high',
        category: 'appsec',
        cwe: 'CWE-732',
        reachability: 'reachable',
        location: `${relPath}:${i + 1}`,
        evidence: trimmed.slice(0, 220),
        remediation: 'Treat pinned shirudo_task_policy and shirudo_sock_policy maps as strictly read-only from enforcement BPF programs (use bpf_map_lookup_elem only).'
      });
    }
  }

  // SHIRUDO-BPF-001, SHIRUDO-BPF-002, SHIRUDO-BPF-003 across extracted SEC(...) program bodies
  const hasVerifiedMarker = /\/\/\s*shirudo-verified:/i.test(src);
  const programs = extractSecPrograms(src);
  for (const prog of programs) {
    const fm = FMOD_RET_TAG_RE.exec(prog.secTag);
    if (!fm) continue;
    const isSleepable = Boolean(fm[1]);
    const sym = fm[2];

    // SHIRUDO-BPF-001
    if (isSleepable && !SAFE_FMOD_SYM_RE.test(sym)) {
      findings.push({
        ruleId: 'SHIRUDO-BPF-001',
        title: `Illegal sleepable fmod_ret.s target "${sym}" (rejected by BTF verifier scan)`,
        severity: 'high',
        category: 'appsec',
        cwe: 'CWE-703',
        reachability: 'reachable',
        location: `${relPath}:${prog.secLine}`,
        evidence: `SEC("${prog.secTag}")`,
        remediation: 'Restrict fmod_ret.s/ to __x64_sys_*, __arm64_sys_*, or security_* symbols, or use SEC("lsm/...") / non-sleepable fmod_ret.'
      });
    } else if (!isSleepable && LSM_COVERED_FMOD_SYM_RE.test(sym)) {
      // SHIRUDO-BPF-003
      cantTellReasons.push({
        code: 'SHIRUDO-BPF-003',
        path: relPath,
        line: prog.secLine,
        message: `Hook SEC("${prog.secTag}") at ${relPath}:${prog.secLine} targets a VFS/exec/socket path covered by BPF LSM; prefer SEC("lsm/...") to prevent re-entrant fail-open bypasses.`
      });
    } else if (!isSleepable && !SAFE_FMOD_SYM_RE.test(sym) && !hasVerifiedMarker) {
      // SHIRUDO-BPF-001 (unverified internal kernel fmod_ret target)
      cantTellReasons.push({
        code: 'SHIRUDO-BPF-001',
        path: relPath,
        line: prog.secLine,
        message: `Unverified internal kernel fmod_ret target "${sym}" at ${relPath}:${prog.secLine}; confirm no inline unlocks/refcounts are bypassed.`
      });
    }

    // SHIRUDO-BPF-002 (return 0 path & invalid return codes inside fmod_ret body)
    if (prog.cleanBody) {
      const hasReturnZero = /\breturn\s+(?:0(?:[uUlL]{0,2})|[^;\n]*[?:]\s*0(?:[uUlL]{0,2}))\s*;/.test(prog.cleanBody);
      if (!hasReturnZero) {
        findings.push({
          ruleId: 'SHIRUDO-BPF-002',
          title: `fmod_ret program SEC("${prog.secTag}") lacks any "return 0;" pass-through path`,
          severity: 'high',
          category: 'appsec',
          cwe: 'CWE-755',
          reachability: 'reachable',
          location: `${relPath}:${prog.secLine}`,
          evidence: `SEC("${prog.secTag}") misses return 0;`,
          remediation: 'Ensure every fmod_ret hook returns 0 on non-matching calls so benign callers on the host are not broken.'
        });
      }

      const retRe = /\breturn\s+([^;{}]+);/g;
      let rm;
      while ((rm = retRe.exec(prog.cleanBody)) !== null) {
        const expr = rm[1].trim();
        let badExpr = false;
        if (BAD_FMOD_POS_INT_RE.test(expr) || BAD_FMOD_ERRNO_RE.test(expr)) {
          badExpr = true;
        } else {
          const negM = BAD_FMOD_NEG_INT_RE.exec(expr);
          if (negM) {
            const val = Number(negM[1]);
            if (val === 1 || val === 11 || val === 90 || val === 115 || val >= 512) {
              badExpr = true;
            }
          }
        }
        if (badExpr) {
          const retLine = prog.bodyStartLine + prog.cleanBody.slice(0, rm.index).split('\n').length - 1;
          findings.push({
            ruleId: 'SHIRUDO-BPF-002',
            title: `Invalid fmod_ret return value "return ${expr};" rejected by fmodret scan`,
            severity: 'high',
            category: 'appsec',
            cwe: 'CWE-755',
            reachability: 'reachable',
            location: `${relPath}:${retLine}`,
            evidence: `return ${expr};`,
            remediation: 'Return 0 on allow paths or standard blocking error codes (-EPERM / -EACCES); never return retry codes (-EAGAIN/-EINPROGRESS/-EMSGSIZE), positive values, -1, or <= -512.'
          });
        }
      }
    }
  }

  if (!HAS_LICENSE_RE.test(src)) {
    cantTellReasons.push({
      code: 'shirudo-bpf-missing-license',
      path: relPath,
      line: null,
      message: `Shirudo BPF C source "${relPath}" is missing SEC("license") declaration; verifier acceptance cannot be confirmed.`
    });
  }

  let match;
  let broadLine = null;
  while ((match = BROAD_HOOK_RE.exec(src)) !== null) {
    const before = src.slice(0, match.index);
    broadLine = before.split('\n').length;
    break;
  }
  if (broadLine !== null && !hasGlobalScopeFilter) {
    cantTellReasons.push({
      code: 'shirudo-bpf-unbounded-hook',
      path: relPath,
      line: broadLine,
      message: `Broad kernel hook in "${relPath}" (line ${broadLine}) lacks process/cgroup/inode scoping predicates; verify unintended workloads are not disrupted.`
    });
  }

  return {
    findings,
    cantTellReasons,
    summary: `Audited ${relPath}: ${findings.length} finding(s), ${cantTellReasons.length} Can't Tell item(s).`
  };
}

function auditShirudoCommands(relPath, text, { allowedLines = null, isShellCommand = false } = {}) {
  const findings = [];
  const cantTellReasons = [];
  const src = String(text || '');
  if (!src.includes('shirudo')) return { findings, cantTellReasons };

  const lines = src.split(/\r?\n/);
  const isWorkflow = SHIRUDO_CI_WORKFLOW_RE.test(String(relPath || '').replace(/\\/g, '/'));
  const hasStrictShell = /^\s*set\s+-[a-zA-Z]*e/m.test(src);

  for (let i = 0; i < lines.length; i++) {
    const lineNum = i + 1;
    if (allowedLines && !allowedLines.has(lineNum)) continue;
    const raw = lines[i];
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    // Skip doc references and marlowe-ci wrapper calls
    if (/^\s*(?:marlowe-ci|npx\b[^\n]*marlowe-ci|node\b[^\n]*marlowe-ci\.cjs)/.test(trimmed)) continue;
    if (/^(?:const|let|var)\s+[A-Z0-9_]+_RE\s*=/.test(trimmed)) continue;

    // Combine trailing backslash continuations
    let cmdBlock = trimmed;
    let lookIdx = i;
    while (cmdBlock.endsWith('\\') && lookIdx + 1 < lines.length && lookIdx - i < 8) {
      lookIdx++;
      cmdBlock = `${cmdBlock.slice(0, -1)} ${lines[lookIdx].trim()}`;
    }

    // SHIRUDO-TPM-001 & SHIRUDO-TPM-003 on shirudo attest verify
    if (/\bshirudo\s+attest\s+verify\b/.test(cmdBlock)) {
      const hasExpectCred = /--expect-credential(?:=|\s+)/.test(cmdBlock);
      const akMatch = /--ak-name(?:=|\s+)([^\s;&|]+)/.exec(cmdBlock);
      const akArg = akMatch ? akMatch[1] : '';
      const selfAssertedAk = /\$\(|`|\$\{/.test(cmdBlock.slice(Math.max(0, cmdBlock.indexOf('--ak-name')))) &&
        /(?:jq\b|\.ak\.name|ev\.json|evidence)/i.test(cmdBlock);

      if (akMatch && selfAssertedAk) {
        findings.push({
          ruleId: 'SHIRUDO-TPM-001',
          title: 'Self-asserted --ak-name extracted from unpinned evidence file in shirudo attest verify',
          severity: 'high',
          category: 'appsec',
          cwe: 'CWE-345',
          reachability: 'reachable',
          location: isShellCommand ? 'bash' : `${relPath}:${lineNum}`,
          evidence: cmdBlock.slice(0, 220),
          remediation: 'Pin --ak-name to an out-of-band operator-enrolled TPM Attestation Key name or verify via --expect-credential rather than reading .ak.name from ev.json.'
        });
      } else if (!akArg && !hasExpectCred) {
        findings.push({
          ruleId: 'SHIRUDO-TPM-001',
          title: 'shirudo attest verify invoked without --ak-name or --expect-credential',
          severity: 'high',
          category: 'crypto',
          cwe: 'CWE-295',
          reachability: 'reachable',
          location: isShellCommand ? 'bash' : `${relPath}:${lineNum}`,
          evidence: cmdBlock.slice(0, 220),
          remediation: 'Pass an out-of-band pinned --ak-name=<enrolled_ak> (or --expect-credential) so throwaway software TPM quotes are rejected.'
        });
      }

      if (!/--nonce(?:=|\s+)/.test(cmdBlock)) {
        findings.push({
          ruleId: 'SHIRUDO-TPM-003',
          title: 'shirudo attest verify invoked without replay-preventing --nonce',
          severity: 'high',
          category: 'crypto',
          cwe: 'CWE-294',
          reachability: 'reachable',
          location: isShellCommand ? 'bash' : `${relPath}:${lineNum}`,
          evidence: cmdBlock.slice(0, 220),
          remediation: 'Pass a fresh challenge --nonce=<hex> to bind the TPM quote to the current verification session.'
        });
      }

      if (!/--expect-config-root(?:=|\s+)/.test(cmdBlock) && !/--expect-config-pcr(?:=|\s+)/.test(cmdBlock)) {
        cantTellReasons.push({
          code: 'SHIRUDO-TPM-003',
          path: isShellCommand ? 'bash' : relPath,
          line: lineNum,
          message: `shirudo attest verify at ${isShellCommand ? 'bash' : `${relPath}:${lineNum}`} omits --expect-config-root/--expect-config-pcr; active config image remains unapproved.`
        });
      }
    }

    // SHIRUDO-TPM-003 on shirudo status in CI workflows or gated shell scripts without --check or JSON verdict assertion
    const statusMatch = /(?:^|[\s;&|(])shirudo\s+status(?:\s|$|;|&&|\|\|)/.exec(cmdBlock);
    if (statusMatch && !/(?:marlowe-ci|echo|printf)\s+[^\n]*shirudo\s+status/.test(cmdBlock)) {
      const hasCheckFlag = /\s--check(?:\s|$|;|&&)/.test(cmdBlock);
      const hasVerdictAssert = /\.(?:verdict|tampered)\b|\|\|\s*(?:exit|return|die)/.test(cmdBlock);
      const isGatingContext = isWorkflow || hasStrictShell || /\bif\s+shirudo\s+status\b|shirudo\s+status[^\n]*&&/.test(cmdBlock);
      if (isGatingContext && !hasCheckFlag && !hasVerdictAssert) {
        findings.push({
          ruleId: 'SHIRUDO-TPM-003',
          title: 'shirudo status invoked in gating workflow/script without --check',
          severity: 'high',
          category: 'appsec',
          cwe: 'CWE-252',
          reachability: 'reachable',
          location: isShellCommand ? 'bash' : `${relPath}:${lineNum}`,
          evidence: cmdBlock.slice(0, 220),
          remediation: 'Pass --check to shirudo status (or explicitly fail on JSON .verdict == "tampered") because shirudo status exits 0 even on tampered hosts without --check.'
        });
      }
    }
  }

  return { findings, cantTellReasons };
}

function isShirudoEvidenceObject(doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return false;
  return Boolean(
    doc.ak || doc.ak_name || doc.akName ||
    doc.pcr11 !== undefined ||
    doc.nv_index !== undefined ||
    doc.register_cert || doc.nv_cert || doc.tpm_quote ||
    (doc.quote && typeof doc.quote === 'object') ||
    (Array.isArray(doc.loaded_upatches) || Array.isArray(doc.event_log))
  );
}

function auditShirudoEvidenceJson(
  relPath,
  textOrObj,
  { expectedAkName = '', expectedPcr11 = '', expectedConfigRoot = '', expectedCredential = '' } = {}
) {
  const findings = [];
  const cantTellReasons = [];
  let doc;
  if (typeof textOrObj === 'string') {
    try {
      doc = JSON.parse(textOrObj);
    } catch (err) {
      return {
        isEvidence: false,
        findings: [],
        cantTellReasons: [{
          code: 'shirudo-evidence-invalid-json',
          path: relPath,
          line: 1,
          message: `Invalid JSON in Shirudo evidence "${relPath}": ${err.message}`
        }]
      };
    }
  } else {
    doc = textOrObj;
  }

  if (!isShirudoEvidenceObject(doc)) {
    return { isEvidence: false, findings, cantTellReasons };
  }

  // SHIRUDO-TPM-001: External AK pin requirement / mismatch
  const evAkName = String(doc.ak?.name || doc.ak_name || doc.akName || '').trim();
  const cleanExpAk = String(expectedAkName || '').trim();
  const cleanExpCred = String(expectedCredential || '').trim();

  if (cleanExpAk) {
    if (evAkName && evAkName !== cleanExpAk) {
      findings.push({
        ruleId: 'SHIRUDO-TPM-001',
        title: `Shirudo evidence AK name mismatch (expected ${cleanExpAk}, got ${evAkName})`,
        severity: 'high',
        category: 'crypto',
        cwe: 'CWE-345',
        reachability: 'reachable',
        location: relPath,
        evidence: `ak.name="${evAkName}" != expected="${cleanExpAk}"`,
        remediation: 'Reject attestation evidence signed by an unrecognized TPM Attestation Key.'
      });
    } else if (!evAkName) {
      cantTellReasons.push({
        code: 'SHIRUDO-TPM-001',
        path: relPath,
        line: 1,
        message: `Evidence "${relPath}" omits ak.name; could not match pinned expected_ak_name offline.`
      });
    }
  } else if (!cleanExpCred) {
    cantTellReasons.push({
      code: 'SHIRUDO-TPM-001',
      path: relPath,
      line: 1,
      message: `Unpinned offline Shirudo audit on "${relPath}": supply out-of-band expected_ak_name (or --expect-credential) before trusting TPM identity.`
    });
  }

  // SHIRUDO-TPM-002: PCR 11 measured boot, initrd binding phase, PCR 9 anchor (0x01818E00), reset_count consistency
  const pcr11Raw = doc.pcr11 ?? doc.pcrs?.['11'] ?? doc.pcrs?.[11] ?? doc.quote?.pcrs?.['11'] ?? doc.boot?.pcr11;
  if (pcr11Raw !== undefined && pcr11Raw !== null) {
    const pcr11 = String(pcr11Raw).trim().toLowerCase();
    if (ZERO_HEX_64_RE.test(pcr11)) {
      cantTellReasons.push({
        code: 'SHIRUDO-TPM-002',
        path: relPath,
        line: 1,
        message: `Unmeasured boot PCR 11 is all zeros in "${relPath}" (direct QEMU/kernel boot without Secure Boot + UKI); cannot certify boot-chain trust.`
      });
    } else if (expectedPcr11 && pcr11 !== String(expectedPcr11).trim().toLowerCase()) {
      findings.push({
        ruleId: 'SHIRUDO-TPM-002',
        title: 'TPM PCR 11 digest mismatch against expected boot baseline',
        severity: 'high',
        category: 'crypto',
        cwe: 'CWE-345',
        reachability: 'reachable',
        location: relPath,
        evidence: `pcr11="${pcr11.slice(0, 24)}..."`,
        remediation: 'Verify UKI/initrd boot measurements before trusting the node.'
      });
    }
  }

  const bindingPhase = String(doc.binding?.phase || doc.binding_phase || doc.register_binding?.phase || '').trim().toLowerCase();
  if (doc.initrd_bound === false || (bindingPhase && bindingPhase !== 'initrd')) {
    findings.push({
      ruleId: 'SHIRUDO-TPM-002',
      title: `Shirudo register binding not anchored in initrd phase (${bindingPhase || 'initrd_bound=false'})`,
      severity: 'high',
      category: 'crypto',
      cwe: 'CWE-345',
      reachability: 'reachable',
      location: relPath,
      evidence: `binding_phase=${bindingPhase || 'false'}`,
      remediation: 'Bind Shirudo TPM measurement registers during systemd initrd phase so post-boot tampering cannot forge initial policy state.'
    });
  }

  const nvRaw = doc.nv_index ?? doc.register?.nv_index ?? doc.binding?.nv_index;
  const nvStr = nvRaw !== undefined && nvRaw !== null ? String(nvRaw).trim().toLowerCase() : '';
  const nvValid = !nvStr || nvStr === '0x01818e00' || nvStr === '0x1818e00' || nvRaw === 0x01818e00;
  if (doc.pcr9_anchor === false || !nvValid) {
    findings.push({
      ruleId: 'SHIRUDO-TPM-002',
      title: 'Missing or invalid Shirudo PCR 9 anchor / NV index (expected 0x01818E00)',
      severity: 'high',
      category: 'crypto',
      cwe: 'CWE-345',
      reachability: 'reachable',
      location: relPath,
      evidence: `nv_index=${nvStr || 'none'}, pcr9_anchor=${String(doc.pcr9_anchor)}`,
      remediation: 'Anchor measurement register NV index 0x01818E00 to PCR 9 per Shirudo TPM specification.'
    });
  }

  const eventLog = Array.isArray(doc.events)
    ? doc.events
    : Array.isArray(doc.event_log)
      ? doc.event_log
      : Array.isArray(doc.eventlog)
        ? doc.eventlog
        : null;

  const resetCounts = [];
  for (const cand of [
    doc.quote?.reset_count,
    doc.register_cert?.reset_count,
    doc.nv_cert?.reset_count,
    doc.cert?.reset_count,
    doc.init_event?.reset_count
  ]) {
    if (typeof cand === 'number' && Number.isFinite(cand)) resetCounts.push(cand);
  }
  if (eventLog) {
    const initEv = eventLog.find(e => e && (e.type === 'init' || e.event === 'init' || e.kind === 'init'));
    if (initEv && typeof initEv.reset_count === 'number' && Number.isFinite(initEv.reset_count)) {
      resetCounts.push(initEv.reset_count);
    }
  }
  if (new Set(resetCounts).size > 1) {
    findings.push({
      ruleId: 'SHIRUDO-TPM-002',
      title: `TPM reset_count mismatch across quote, register cert, and init eventlog (${[...new Set(resetCounts)].join(' vs ')})`,
      severity: 'high',
      category: 'crypto',
      cwe: 'CWE-294',
      reachability: 'reachable',
      location: relPath,
      evidence: `reset_count values: ${resetCounts.join(', ')}`,
      remediation: 'Reject stale/replayed attestation quotes recorded across different TPM reset sessions.'
    });
  }

  // SHIRUDO-TPM-003: Replay / empty log / tamper state / config-root expectation
  if (doc.nonce !== undefined && (String(doc.nonce).trim() === '' || ZERO_HEX_SHORT_RE.test(String(doc.nonce).trim()))) {
    findings.push({
      ruleId: 'SHIRUDO-TPM-003',
      title: 'Missing or all-zero attestation nonce in Shirudo evidence JSON',
      severity: 'high',
      category: 'crypto',
      cwe: 'CWE-294',
      reachability: 'reachable',
      location: relPath,
      evidence: `nonce="${String(doc.nonce)}"`,
      remediation: 'Enforce a fresh non-zero challenge nonce on every attestation verify cycle.'
    });
  }

  if (Array.isArray(eventLog) && eventLog.length === 0) {
    findings.push({
      ruleId: 'SHIRUDO-TPM-003',
      title: 'Empty Shirudo measurement eventlog in evidence JSON',
      severity: 'high',
      category: 'crypto',
      cwe: 'CWE-345',
      reachability: 'reachable',
      location: relPath,
      evidence: 'event_log length = 0',
      remediation: 'Reject evidence bundles with empty measurement eventlogs.'
    });
  }

  if (
    doc.tampered === true ||
    String(doc.verdict || '').toLowerCase() === 'tampered' ||
    Number(doc.tamper_deltas || 0) > 0
  ) {
    findings.push({
      ruleId: 'SHIRUDO-TPM-003',
      title: 'Shirudo status/evidence reports tampered runtime state',
      severity: 'critical',
      category: 'appsec',
      cwe: 'CWE-345',
      reachability: 'reachable',
      location: relPath,
      evidence: `verdict=${doc.verdict || 'tampered'}, tamper_deltas=${doc.tamper_deltas ?? 'n/a'}`,
      remediation: 'Quarantine the tampered host and re-verify initrd, upatch tree, and operator signing keys.'
    });
  }

  if (expectedConfigRoot) {
    const evCfgRoot = String(doc.config_root || doc.config?.root || '').trim().toLowerCase();
    if (evCfgRoot && evCfgRoot !== String(expectedConfigRoot).trim().toLowerCase()) {
      findings.push({
        ruleId: 'SHIRUDO-TPM-003',
        title: 'Active Shirudo config root hash mismatch against expected_config_root',
        severity: 'high',
        category: 'config',
        cwe: 'CWE-345',
        reachability: 'reachable',
        location: relPath,
        evidence: `config_root=${evCfgRoot}`,
        remediation: 'Verify approved configuration image root before trusting node enforcement.'
      });
    }
  }

  return { isEvidence: true, findings, cantTellReasons };
}

function summarizeEvidenceDoc(parsed) {
  if (!parsed || typeof parsed !== 'object') return {};
  const loaded = Array.isArray(parsed.upatches)
    ? parsed.upatches.length
    : Array.isArray(parsed.loaded_upatches)
      ? parsed.loaded_upatches.length
      : null;
  const events = Array.isArray(parsed.events)
    ? parsed.events.length
    : Array.isArray(parsed.event_log)
      ? parsed.event_log.length
      : null;
  return {
    keys: Object.keys(parsed).slice(0, 20),
    hasQuote: Boolean(parsed.quote || parsed.tpm_quote || parsed.attestation),
    loadedUpatchesCount: loaded,
    eventLogCount: events
  };
}

async function inspectShirudoTarget(root, relTarget = '.', signal = new AbortController().signal) {
  const resolved = await resolveWithinRoot(root, relTarget || '.');
  const stat = await fs.stat(resolved.fullPath);

  const candidates = [];
  if (stat.isDirectory()) {
    const walkState = { truncated: false, deadline: Date.now() + 10000 };
    for await (const fullPath of walkWorkspace(resolved.fullPath, signal, walkState)) {
      const rel = path.relative(resolved.rootReal, fullPath).split(path.sep).join('/');
      if (isShirudoArtifactPath(rel)) {
        candidates.push({ fullPath, relPath: rel });
      }
      if (candidates.length >= 200) break;
    }
  } else {
    candidates.push({ fullPath: resolved.fullPath, relPath: resolved.relPath });
  }

  const findings = [];
  const cantTellReasons = [];
  const inspectedFiles = [];

  if (!candidates.length) {
    cantTellReasons.push({
      code: 'shirudo-no-artifacts',
      path: resolved.relPath,
      line: null,
      message: `No Shirudo Beefile, .bpf.c/.upatch.c source, or .bee/.upatch package found under "${resolved.relPath}".`
    });
  }

  for (const cand of candidates) {
    signal.throwIfAborted?.();
    if (isBeefilePath(cand.relPath)) {
      const text = await readRegularTextFile(cand.fullPath);
      const res = await auditBeefile(cand.relPath, text, { root: resolved.rootReal });
      findings.push(...res.findings);
      cantTellReasons.push(...res.cantTellReasons);
      inspectedFiles.push({ path: cand.relPath, kind: 'beefile', packageName: res.parsed.package.name || '', upatches: res.parsed.upatches.length });
    } else if (isBpfSourcePath(cand.relPath)) {
      const text = await readRegularTextFile(cand.fullPath);
      const res = auditBpfUpatchSource(cand.relPath, text);
      findings.push(...res.findings);
      cantTellReasons.push(...res.cantTellReasons);
      inspectedFiles.push({ path: cand.relPath, kind: 'bpf-source' });
    } else if (/\.(?:bee|upatch)$/i.test(cand.relPath)) {
      const tri = await triageArtifact(cand.fullPath, cand.relPath, signal);
      inspectedFiles.push({ path: cand.relPath, kind: 'package-binary', sha256: tri.hashes.sha256, entropy: tri.entropy, format: tri.format });
      const sibC = cand.relPath.replace(/\.(?:bee|upatch)$/i, '.bpf.c');
      let hasSib = false;
      try {
        const sibRes = await resolveWithinRoot(resolved.rootReal, sibC);
        await fs.access(sibRes.fullPath);
        hasSib = true;
      } catch {
        hasSib = false;
      }
      if (!hasSib) {
        cantTellReasons.push({
          code: 'shirudo-binary-artifact',
          path: cand.relPath,
          line: null,
          message: `Compiled Shirudo package "${cand.relPath}" (SHA-256 ${tri.hashes.sha256.slice(0, 16)}…, entropy ${tri.entropy}/8.00) has no sibling .bpf.c source for static review.`
        });
      }
    }
  }

  const failing = findings.filter(f => f.category === 'secrets' || f.severity === 'critical' || f.severity === 'high');
  let verdict = 'holds';
  let verdictLabel = 'HOLDS UP';
  if (failing.length > 0 || findings.some(f => f.severity === 'medium')) {
    if (failing.length > 0 || findings.length > 0) {
      verdict = 'fails';
      verdictLabel = 'FAILS';
    }
  }
  if (verdict === 'holds' && cantTellReasons.length > 0) {
    verdict = 'cant-tell';
    verdictLabel = "CAN'T TELL";
  }

  return {
    verdict,
    verdictLabel,
    workspace: resolved.rootReal,
    target: resolved.relPath,
    inspectedCount: inspectedFiles.length,
    inspectedFiles,
    findings,
    cantTellReasons,
    summary: `Shirudo audit (${resolved.relPath}) → ${verdictLabel}: ${inspectedFiles.length} artifact(s), ${findings.length} finding(s), ${cantTellReasons.length} Can't Tell item(s).`
  };
}

async function verifyShirudoAttestation({
  root = process.cwd(),
  evidencePath,
  nonce = '',
  akName = '',
  expectedPcr11 = '',
  expectedConfigRoot = '',
  expectedCredential = '',
  commandPath = '',
  execFileImpl = execFileAsync
} = {}) {
  if (typeof evidencePath !== 'string' || !evidencePath.trim()) {
    throw new Error('evidence_path is required.');
  }
  const cleanNonce = String(nonce || '').trim();
  const cleanAk = String(akName || '').trim();
  if (cleanNonce && !HEX_NONCE_RE.test(cleanNonce)) {
    throw new Error('Invalid nonce: expected 8-128 hex characters.');
  }
  if (cleanAk && !AK_NAME_RE.test(cleanAk)) {
    throw new Error('Invalid ak_name: expected 4-128 alphanumeric, :, ., _, or - characters.');
  }

  const resolved = await resolveWithinRoot(root, evidencePath.trim());
  const raw = await readRegularTextFile(resolved.fullPath, 2 * 1024 * 1024);
  let parsedEvidence;
  try {
    parsedEvidence = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Invalid JSON in attestation evidence file "${resolved.relPath}": ${err.message}`);
  }
  const evidenceSummary = summarizeEvidenceDoc(parsedEvidence);
  const offlineAudit = auditShirudoEvidenceJson(resolved.relPath, parsedEvidence, {
    expectedAkName: cleanAk,
    expectedPcr11,
    expectedConfigRoot,
    expectedCredential
  });

  if (offlineAudit.findings.length > 0) {
    return {
      verdict: 'fails',
      verdictLabel: 'FAILS',
      verified: false,
      cliAvailable: false,
      evidencePath: resolved.relPath,
      evidenceSummary,
      findings: offlineAudit.findings,
      cantTellReasons: offlineAudit.cantTellReasons,
      reason: offlineAudit.findings.map(f => `[${f.ruleId}] ${f.title}`).join('; ')
    };
  }

  const searchPath = commandPath || process.env.PATH || DEFAULT_PATH;
  const binaryPath = await resolveToolBinary('shirudo', searchPath, resolved.rootReal);
  if (!binaryPath) {
    const reasons = [...offlineAudit.cantTellReasons.map(r => `[${r.code}] ${r.message}`), 'shirudo CLI is not installed on verified PATH; TPM 2.0 cryptographic signature could not be verified offline.'];
    return {
      verdict: 'cant-tell',
      verdictLabel: "CAN'T TELL",
      verified: false,
      cliAvailable: false,
      evidencePath: resolved.relPath,
      evidenceSummary,
      findings: offlineAudit.findings,
      cantTellReasons: offlineAudit.cantTellReasons,
      reason: reasons.join(' '),
      installHint: 'https://github.com/shirudo-dev/shirudo'
    };
  }

  const argv = ['attest', 'verify', `--evidence=${resolved.fullPath}`];
  if (cleanNonce) argv.push(`--nonce=${cleanNonce}`);
  if (cleanAk) argv.push(`--ak-name=${cleanAk}`);
  if (expectedConfigRoot) argv.push(`--expect-config-root=${String(expectedConfigRoot).trim()}`);

  const safeDirs = await safeSearchDirs(searchPath, resolved.rootReal);
  const env = {
    PATH: safeDirs.join(process.platform === 'win32' ? ';' : ':') || DEFAULT_PATH,
    HOME: process.env.HOME || '',
    TMPDIR: process.env.TMPDIR || '',
    LANG: 'en_US.UTF-8',
    NO_COLOR: '1'
  };

  try {
    const { stdout = '', stderr = '' } = await execFileImpl(binaryPath, argv, {
      timeout: 15000,
      env
    });
    if (offlineAudit.cantTellReasons.length > 0) {
      return {
        verdict: 'cant-tell',
        verdictLabel: "CAN'T TELL",
        verified: false,
        cliAvailable: true,
        binaryPath,
        evidencePath: resolved.relPath,
        evidenceSummary,
        findings: offlineAudit.findings,
        cantTellReasons: offlineAudit.cantTellReasons,
        reason: offlineAudit.cantTellReasons.map(r => `[${r.code}] ${r.message}`).join(' '),
        output: redactSecrets(String(stdout || stderr || '').trim().slice(0, 4000)).text
      };
    }
    return {
      verdict: 'holds',
      verdictLabel: 'HOLDS UP',
      verified: true,
      cliAvailable: true,
      binaryPath,
      evidencePath: resolved.relPath,
      evidenceSummary,
      findings: offlineAudit.findings,
      cantTellReasons: offlineAudit.cantTellReasons,
      output: redactSecrets(String(stdout || stderr || 'TPM 2.0 attestation verified.').trim().slice(0, 4000)).text
    };
  } catch (err) {
    const combined = `${err?.stdout || ''}\n${err?.stderr || ''}\n${err?.message || ''}`.trim();
    return {
      verdict: 'fails',
      verdictLabel: 'FAILS',
      verified: false,
      cliAvailable: true,
      binaryPath,
      evidencePath: resolved.relPath,
      evidenceSummary,
      findings: offlineAudit.findings,
      cantTellReasons: offlineAudit.cantTellReasons,
      reason: redactSecrets(combined.slice(0, 4000) || 'Shirudo attestation verification failed.').text
    };
  }
}

async function inspectShirudoStatus({
  root = process.cwd(),
  commandPath = '',
  execFileImpl = execFileAsync
} = {}) {
  const absRoot = await fs.realpath(path.resolve(root));
  const searchPath = commandPath || process.env.PATH || DEFAULT_PATH;
  const binaryPath = await resolveToolBinary('shirudo', searchPath, absRoot);
  if (!binaryPath) {
    return {
      verdict: 'cant-tell',
      verdictLabel: "CAN'T TELL",
      cliAvailable: false,
      reason: 'shirudo CLI is not installed on verified PATH.',
      installHint: 'https://github.com/shirudo-dev/shirudo'
    };
  }

  const safeDirs = await safeSearchDirs(searchPath, absRoot);
  const env = {
    PATH: safeDirs.join(process.platform === 'win32' ? ';' : ':') || DEFAULT_PATH,
    HOME: process.env.HOME || '',
    TMPDIR: process.env.TMPDIR || '',
    LANG: 'en_US.UTF-8',
    NO_COLOR: '1'
  };

  try {
    const { stdout = '', stderr = '' } = await execFileImpl(binaryPath, ['status', '--json', '--show-full', '--check'], {
      timeout: 10000,
      env
    });
    let status = null;
    try {
      status = JSON.parse(stdout);
    } catch {
      status = null;
    }
    const isTampered =
      status?.verdict === 'tampered' ||
      status?.tampered === true ||
      Number(status?.tamper_deltas || 0) > 0;
    if (isTampered) {
      return {
        verdict: 'fails',
        verdictLabel: 'FAILS',
        cliAvailable: true,
        binaryPath,
        status,
        reason: 'SHIRUDO-TPM-003: shirudo status reported tampered runtime state.',
        output: redactSecrets(String(stdout || stderr).trim().slice(0, 4000)).text
      };
    }
    return {
      verdict: 'holds',
      verdictLabel: 'HOLDS UP',
      cliAvailable: true,
      binaryPath,
      status,
      output: redactSecrets(String(stdout || stderr).trim().slice(0, 4000)).text
    };
  } catch (err) {
    const combined = `${err?.stdout || ''}\n${err?.stderr || ''}\n${err?.message || ''}`.trim();
    return {
      verdict: 'fails',
      verdictLabel: 'FAILS',
      cliAvailable: true,
      binaryPath,
      reason: redactSecrets(combined.slice(0, 4000) || 'shirudo status failed.').text
    };
  }
}

module.exports = {
  isBeefilePath,
  isBpfSourcePath,
  isShirudoArtifactPath,
  isShirudoDraftPath,
  parseBeefile,
  auditBeefile,
  auditBpfUpatchSource,
  auditShirudoCommands,
  auditShirudoEvidenceJson,
  inspectShirudoTarget,
  verifyShirudoAttestation,
  inspectShirudoStatus
};
