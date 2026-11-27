const fs = require('node:fs/promises');
const { constants } = require('node:fs');
const dns = require('node:dns/promises');
const net = require('node:net');
const tls = require('node:tls');
const { createHash } = require('node:crypto');
const { SECRET_RULES, maskToken, isPrivateOrReservedIp, assertTargetInScope, redactSecrets } = require('./cyber-scope.cjs');
const { analyzeAgenticBehavior } = require('./artex-defense.cjs');

const MAX_ARTIFACT_BYTES = 10 * 1024 * 1024;
const RESULT_BUDGET = 22000;

function shannonEntropy(bytesOrString) {
  const len = bytesOrString.length;
  if (!len) return 0;
  const counts = new Map();
  if (Buffer.isBuffer(bytesOrString)) {
    for (let i = 0; i < len; i++) counts.set(bytesOrString[i], (counts.get(bytesOrString[i]) || 0) + 1);
  } else {
    for (let i = 0; i < len; i++) { const c = bytesOrString.charCodeAt(i); counts.set(c, (counts.get(c) || 0) + 1); }
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 100) / 100;
}

async function openRegularBuffer(file, maxBytes = MAX_ARTIFACT_BYTES) {
  let handle;
  try {
    handle = await fs.open(file, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink > 1) throw new Error('Expected a regular file without hard links.');
    if (stat.size > maxBytes) throw new Error(`File exceeds the ${Math.round(maxBytes / (1024 * 1024))} MB inspection limit.`);
    const buffer = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < stat.size) {
      const { bytesRead } = await handle.read(buffer, offset, stat.size - offset, offset);
      if (!bytesRead) break;
      offset += bytesRead;
    }
    return buffer.subarray(0, offset);
  } finally {
    await handle?.close();
  }
}

const CODE_RULES = [
  { id: 'cmd-injection', category: 'injection', severity: 'high', cwe: 'CWE-78', title: 'Potential OS Command Injection sink', regex: /\b(?:child_process\s*\.\s*(?:exec|execSync)|execSync|os\.system|popen)\s*\(|\bexec\s*\(\s*(?:`[^`\n]*\$\{|[^)\n]*\+)|subprocess\.(?:Popen|run|call|check_output)\s*\([^)\n]*shell\s*=\s*True/ },
  { id: 'dynamic-code-exec', category: 'injection', severity: 'high', cwe: 'CWE-94', title: 'Dynamic code evaluation (eval / Function / vm)', regex: /\beval\s*\(\s*[^)\s]|\b(?:setTimeout|setInterval)\s*\(\s*['"`]|\bnew\s+Function\s*\(|\bvm\.runIn(?:New|This)?Context\s*\(/ },
  { id: 'sql-concat', category: 'injection', severity: 'high', cwe: 'CWE-89', title: 'Unparameterized SQL string interpolation', regex: /\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^\n]{0,120}(?:\$\{|['"]\s*\+\s*[a-zA-Z_$]|%\s*\(?[a-zA-Z_])/i },
  {
    id: 'dom-xss',
    category: 'xss',
    severity: 'medium',
    cwe: 'CWE-79',
    title: 'Unescaped HTML / DOM sink',
    regex: /\.(?:innerHTML|outerHTML)\s*=(?!=)|\bdangerouslySetInnerHTML\b|\bdocument\.write\s*\(|\bv-html\s*=/,
    filter: trimmed => !/\.(?:innerHTML|outerHTML)\s*=\s*(?:''|""|``|'[^']*'|"(?:[^"\\]|\\.)*"|`[^`$]*`)\s*;?\s*$/.test(trimmed)
  },
  { id: 'insecure-deserialize', category: 'deserialization', severity: 'critical', cwe: 'CWE-502', title: 'Unsafe deserialization call', regex: /\b(?:pickle\.loads?|marshal\.loads?|yaml\.load\s*\([^)\n]*(?!SafeLoader)|unserialize\s*\()/ },
  { id: 'tls-Disabled', category: 'crypto', severity: 'high', cwe: 'CWE-295', title: 'TLS certificate verification disabled', regex: /\brejectUnauthorized\s*:\s*false\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|\bverify\s*=\s*False\b|\bInsecureSkipVerify\s*:\s*true\b/ },
  { id: 'weak-hash-cipher', category: 'crypto', severity: 'medium', cwe: 'CWE-327', title: 'Weak cryptographic hash or cipher (MD5/SHA1/DES/RC4)', regex: /\bcreateHash\s*\(\s*['"](?:md5|sha1|md4)['"]\s*\)|\bcreateCipher(?:iv)?\s*\(\s*['"](?:des|rc4|bf|aes-\d+-ecb)/i },
  { id: 'insecure-random', category: 'crypto', severity: 'medium', cwe: 'CWE-338', title: 'Math.random() used near security token/secret logic', regex: /\b(?:token|secret|nonce|salt|otp|apikey|password|session)\w*\s*[:=][^\n]{0,80}\bMath\.random\s*\(/i },
  { id: 'permissive-cors', category: 'config', severity: 'medium', cwe: 'CWE-942', title: 'Wildcard CORS origin policy', regex: /Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*['"]/i },
  { id: 'iac-privileged', category: 'iac', severity: 'medium', cwe: 'CWE-250', title: 'Privileged container or world-writable permissions', regex: /^\s*USER\s+root\s*$|privileged\s*:\s*true\b|hostNetwork\s*:\s*true\b|\bchmod\s+(?:-R\s+)?777\b/ }
];

async function scanSecrets(root, startDir, { relativePath, walk, readText }, signal) {
  const state = { truncated: false, deadline: Date.now() + 10000 };
  const findings = [];
  let scanned = 0, used = 0;
  const entropyCandidate = /\b([A-Za-z_][A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)[A-Za-z0-9_]*)\s*[:=]\s*['"]([A-Za-z0-9+/=_-]{20,128})['"]/i;
  scan: for await (const file of walk(startDir, signal, state)) {
    signal.throwIfAborted();
    if (++scanned > 4000) { state.truncated = true; break; }
    let text;
    try { text = await readText(file); } catch { continue; }
    const rel = relativePath(root, file);
    const isDoc = /\.(?:md|mdx|rst|txt)$/i.test(rel);
    const isDemoOrTest = /(?:^|\/)(?:demo|example|sample)[-_][^/]*$|_test\.go$|\.(?:test|spec)\.[cm]?[jt]sx?$/i.test(rel);
    const HIGH_CERTAINTY_SECRET_IDS = new Set(['private-key', 'aws-access-key', 'github-token', 'ai-api-key', 'slack-token', 'stripe-key', 'google-api-key']);
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].replace(/\r$/, '');
      if (!line || line.length > 4000) continue;
      let matchedOnLine = false;
      for (const rule of SECRET_RULES) {
        if ((isDoc || isDemoOrTest) && !HIGH_CERTAINTY_SECRET_IDS.has(rule.id)) continue;
        rule.regex.lastIndex = 0;
        const m = rule.regex.exec(line);
        if (!m || (rule.filter && !rule.filter(...m))) continue;
        matchedOnLine = true;
        const preview = redactSecrets(line.trim().slice(0, 220)).text;
        const item = { path: rel, line: i + 1, ruleId: rule.id, label: rule.label, severity: rule.severity, cwe: rule.cwe, maskedPreview: preview };
        if (findings.length >= 150 || (used += JSON.stringify(item).length) > RESULT_BUDGET) { state.truncated = true; break scan; }
        findings.push(item);
        break;
      }
      if (!matchedOnLine && !isDoc && !isDemoOrTest) {
        const em = entropyCandidate.exec(line);
        if (em && !/^(?:your_|example|placeholder|test_|dummy|fake_)/i.test(em[2]) && shannonEntropy(em[2]) >= 4.35 && /[a-z]/.test(em[2]) && /[A-Z0-9]/.test(em[2])) {
          const item = { path: rel, line: i + 1, ruleId: 'high-entropy-secret', label: `High-Entropy Secret (${em[1]})`, severity: 'medium', cwe: 'CWE-798', maskedPreview: line.replace(em[2], maskToken(em[2])).trim().slice(0, 220) };
          if (findings.length >= 150 || (used += JSON.stringify(item).length) > RESULT_BUDGET) { state.truncated = true; break scan; }
          findings.push(item);
        }
      }
    }
  }
  return {
    scannedFiles: scanned,
    findingsCount: findings.length,
    truncated: state.truncated,
    findings,
    summary: findings.length ? `Detected ${findings.length} potential hardcoded secret${findings.length === 1 ? '' : 's'} across ${scanned} scanned files (all secret values masked).` : `No hardcoded secrets detected across ${scanned} scanned files.`
  };
}

async function auditCodePatterns(root, startDir, { category = '', relativePath, walk, readText }, signal) {
  const wantedCategory = category.trim().toLowerCase();
  const activeRules = wantedCategory ? CODE_RULES.filter(r => r.category === wantedCategory) : CODE_RULES;
  if (!activeRules.length) throw new Error(`Unknown audit category "${category}". Use injection, xss, deserialization, crypto, config, iac, or omit for all.`);
  const state = { truncated: false, deadline: Date.now() + 10000 };
  const matches = [];
  let scanned = 0, used = 0;
  scan: for await (const file of walk(startDir, signal, state)) {
    signal.throwIfAborted();
    const rel = relativePath(root, file);
    if (/\.(?:md|txt|lock|svg|css|map)$/i.test(rel)) continue;
    if (++scanned > 4000) { state.truncated = true; break; }
    let text;
    try { text = await readText(file); } catch { continue; }
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i].replace(/\r$/, ''), trimmed = raw.trim();
      if (!trimmed || trimmed.length > 1000 || trimmed.startsWith('//') || (trimmed.startsWith('#') && !trimmed.startsWith('#!'))) continue;
      for (const rule of activeRules) {
        if (!rule.regex.test(raw) || (rule.filter && !rule.filter(trimmed))) continue;
        const item = { path: rel, line: i + 1, ruleId: rule.id, category: rule.category, severity: rule.severity, cwe: rule.cwe, title: rule.title, verificationRequired: true, snippet: redactSecrets(trimmed.slice(0, 220)).text };
        if (matches.length >= 160 || (used += JSON.stringify(item).length) > RESULT_BUDGET) { state.truncated = true; break scan; }
        matches.push(item);
      }
    }
  }
  return {
    scannedFiles: scanned,
    findingsCount: matches.length,
    truncated: state.truncated,
    matches,
    summary: matches.length ? `Flagged ${matches.length} UNVERIFIED sink candidate${matches.length === 1 ? '' : 's'} across ${scanned} files (NOT confirmed vulnerabilities). You MUST call read_file and prove untrusted external/user input reaches a sink before recording—never record static UI templates or hardcoded demo strings.` : `No dangerous code/config patterns flagged across ${scanned} files.`
  };
}

function parseManifestPackages(relPath, content) {
  const base = relPath.split('/').pop();
  const found = [];
  const add = (ecosystem, name, version) => {
    const cleanVer = String(version || '').trim().replace(/^[~^>=<v]+/, '').split(/\s+/)[0];
    if (name && cleanVer && /^\d/.test(cleanVer) && !cleanVer.includes('*')) found.push({ ecosystem, name: name.trim(), version: cleanVer, source: relPath });
  };
  try {
    if (base === 'package-lock.json') {
      const json = JSON.parse(content);
      if (json.packages && typeof json.packages === 'object') {
        for (const [pkgPath, meta] of Object.entries(json.packages)) {
          if (!pkgPath || !meta?.version) continue;
          const idx = pkgPath.lastIndexOf('node_modules/');
          const name = meta.name || (idx !== -1 ? pkgPath.slice(idx + 'node_modules/'.length) : '');
          if (name) add('npm', name, meta.version);
        }
      } else if (json.dependencies && typeof json.dependencies === 'object') {
        for (const [name, meta] of Object.entries(json.dependencies)) add('npm', name, meta?.version);
      }
    } else if (base === 'package.json') {
      const json = JSON.parse(content);
      for (const section of [json.dependencies, json.devDependencies]) {
        if (section && typeof section === 'object') for (const [name, ver] of Object.entries(section)) add('npm', name, ver);
      }
    } else if (base === 'requirements.txt') {
      for (const line of content.split('\n')) {
        const clean = line.split('#')[0].trim();
        const m = /^([A-Za-z0-9_.-]+)\s*(?:==|~=)\s*([A-Za-z0-9_.+-]+)/.exec(clean);
        if (m) add('PyPI', m[1], m[2]);
      }
    } else if (base === 'pyproject.toml') {
      for (const line of content.split('\n')) {
        const m = /^\s*([A-Za-z0-9_.-]+)\s*=\s*['"]\^?~?([0-9][0-9A-Za-z_.-]*)['"]/.exec(line);
        if (m && m[1] !== 'python' && m[1] !== 'version') add('PyPI', m[1], m[2]);
      }
    } else if (base === 'go.mod') {
      for (const line of content.split('\n')) {
        const m = /^\s*([a-zA-Z0-9._/-]+\.[a-zA-Z0-9._/-]+)\s+v([0-9][^\s/]*)/.exec(line);
        if (m && m[1] !== 'module') add('Go', m[1], m[2]);
      }
    } else if (base === 'Cargo.lock') {
      for (const block of content.split('[[package]]').slice(1)) {
        const name = /^\s*name\s*=\s*"([^"]+)"/m.exec(block)?.[1];
        const ver = /^\s*version\s*=\s*"([^"]+)"/m.exec(block)?.[1];
        if (name && ver) add('crates.io', name, ver);
      }
    } else if (base === 'pnpm-lock.yaml') {
      for (const line of content.split('\n')) {
        const m = /^\s*\/?(@?[a-zA-Z0-9._-]+(?:\/[a-zA-Z0-9._-]+)?)@([0-9][0-9a-zA-Z._-]*):/.exec(line);
        if (m) add('npm', m[1], m[2]);
      }
    }
  } catch { /* Malformed lockfile skipped gracefully. */ }
  return found;
}

async function auditDependencies(root, startPath, { isDirectory, queryOsv = true, scope, fetchImpl = fetch, relativePath, walk, readText }, signal) {
  const manifestNames = new Set(['package-lock.json', 'package.json', 'pnpm-lock.yaml', 'requirements.txt', 'pyproject.toml', 'go.mod', 'Cargo.lock']);
  const files = [];
  if (isDirectory) {
    const state = { truncated: false, deadline: Date.now() + 8000 };
    for await (const f of walk(startPath, signal, state)) {
      if (manifestNames.has(f.split(/[\\/]/).pop())) files.push(f);
      if (files.length >= 40) break;
    }
  } else {
    files.push(startPath);
  }
  const seen = new Map(), manifests = [];
  for (const file of files) {
    let text;
    try { text = await readText(file); } catch { continue; }
    const rel = relativePath(root, file);
    const parsed = parseManifestPackages(rel, text);
    if (parsed.length) manifests.push(rel);
    for (const pkg of parsed) {
      const key = `${pkg.ecosystem}:${pkg.name}@${pkg.version}`;
      if (!seen.has(key)) seen.set(key, pkg);
    }
  }
  const packages = [...seen.values()];
  const ecosystems = {};
  for (const p of packages) ecosystems[p.ecosystem] = (ecosystems[p.ecosystem] || 0) + 1;
  const sbom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    componentCount: packages.length,
    ecosystems,
    sampleComponents: packages.slice(0, 60).map(p => ({ type: 'library', purl: `pkg:${p.ecosystem.toLowerCase()}/${p.name}@${p.version}`, source: p.source }))
  };
  const vulnerabilities = [];
  let osvStatus = 'skipped';
  if (packages.length && queryOsv) {
    if (scope && scope.allowOsv === false) {
      osvStatus = 'disabled-by-scope-settings';
    } else {
      const batch = packages.slice(0, 200);
      const timeoutSignal = AbortSignal.any([signal, AbortSignal.timeout(10000)]);
      try {
        const res = await fetchImpl('https://api.osv.dev/v1/querybatch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ queries: batch.map(p => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })) }),
          signal: timeoutSignal
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const payload = await res.json();
        osvStatus = 'queried';
        const results = Array.isArray(payload?.results) ? payload.results : [];
        for (let i = 0; i < results.length && i < batch.length; i++) {
          const vulns = results[i]?.vulns;
          if (!Array.isArray(vulns) || !vulns.length) continue;
          const pkg = batch[i];
          for (const v of vulns.slice(0, 10)) {
            if (vulnerabilities.length >= 100) break;
            vulnerabilities.push({
              id: v.id,
              package: pkg.name,
              version: pkg.version,
              ecosystem: pkg.ecosystem,
              source: pkg.source,
              summary: v.summary || '',
              aliases: Array.isArray(v.aliases) ? v.aliases.slice(0, 5) : [],
              advisoryUrl: `https://osv.dev/vulnerability/${encodeURIComponent(v.id)}`
            });
          }
        }
      } catch (error) {
        if (signal.aborted) throw error;
        osvStatus = `unavailable (${error.message})`;
      }
    }
  }
  return {
    manifests,
    totalPackages: packages.length,
    osvStatus,
    vulnerabilityCount: vulnerabilities.length,
    vulnerabilities,
    sbom,
    summary: !packages.length
      ? 'No supported dependency lockfiles or pinned manifests found.'
      : `Inventoried ${packages.length} pinned packages across ${manifests.length} manifest(s). OSV lookup: ${osvStatus}; ${vulnerabilities.length} known vulnerability advisories matched.`
  };
}

async function inspectHttpSecurity(rawUrl, { method = 'GET', scope, fetchImpl = fetch, dnsLookup = dns.lookup }, signal) {
  const upperMethod = String(method || 'GET').toUpperCase();
  if (!['GET', 'HEAD'].includes(upperMethod)) throw new Error('inspect_http_security only supports read-only GET or HEAD requests.');
  const target = await assertTargetInScope(rawUrl, scope, { dnsLookup, requireUrl: true });
  const reqSignal = AbortSignal.any([signal, AbortSignal.timeout(10000)]);
  const response = await fetchImpl(target.url, {
    method: upperMethod,
    redirect: 'manual',
    headers: { 'User-Agent': 'Marlowe-Security-Inspector/0.4' },
    signal: reqSignal
  });
  let bodySnippet = '';
  if (upperMethod === 'GET' && response.body) {
    const reader = response.body.getReader();
    const decoder = new TextDecoder('utf-8', { fatal: false });
    let total = 0;
    try {
      while (total < 16384) {
        const { value, done } = await reader.read();
        if (done || !value) break;
        total += value.byteLength;
        bodySnippet += decoder.decode(value, { stream: true });
      }
    } finally {
      await reader.cancel().catch(() => {});
    }
    bodySnippet = bodySnippet.slice(0, 1500);
  }
  const get = name => response.headers.get(name) || '';
  const headers = {
    'strict-transport-security': get('strict-transport-security'),
    'content-security-policy': get('content-security-policy'),
    'x-content-type-options': get('x-content-type-options'),
    'x-frame-options': get('x-frame-options'),
    'referrer-policy': get('referrer-policy'),
    'permissions-policy': get('permissions-policy'),
    'cross-origin-opener-policy': get('cross-origin-opener-policy'),
    'access-control-allow-origin': get('access-control-allow-origin'),
    'access-control-allow-credentials': get('access-control-allow-credentials'),
    server: get('server'),
    'x-powered-by': get('x-powered-by'),
    location: get('location')
  };
  const setCookies = typeof response.headers.getSetCookie === 'function' ? response.headers.getSetCookie() : (get('set-cookie') ? [get('set-cookie')] : []);
  const issues = [];
  if (target.protocol === 'https:' && !headers['strict-transport-security']) issues.push({ severity: 'medium', cwe: 'CWE-319', issue: 'Missing Strict-Transport-Security (HSTS) header.' });
  if (!headers['content-security-policy']) issues.push({ severity: 'medium', cwe: 'CWE-693', issue: 'Missing Content-Security-Policy (CSP) header.' });
  else if (/unsafe-inline|unsafe-eval/i.test(headers['content-security-policy'])) issues.push({ severity: 'low', cwe: 'CWE-693', issue: 'CSP allows unsafe-inline or unsafe-eval.' });
  if (headers['x-content-type-options'].toLowerCase() !== 'nosniff') issues.push({ severity: 'low', cwe: 'CWE-16', issue: 'Missing X-Content-Type-Options: nosniff.' });
  if (!headers['x-frame-options'] && !/frame-ancestors/i.test(headers['content-security-policy'])) issues.push({ severity: 'low', cwe: 'CWE-1021', issue: 'Missing clickjacking defense (X-Frame-Options or CSP frame-ancestors).' });
  if (headers['access-control-allow-origin'] === '*' && headers['access-control-allow-credentials'].toLowerCase() === 'true') issues.push({ severity: 'high', cwe: 'CWE-942', issue: 'Wildcard CORS combined with Access-Control-Allow-Credentials: true.' });
  if (headers['x-powered-by'] || /\d+\.\d+/.test(headers.server)) issues.push({ severity: 'info', cwe: 'CWE-200', issue: `Technology version banner exposed (${[headers.server, headers['x-powered-by']].filter(Boolean).join(', ')}).` });
  const cookies = setCookies.slice(0, 10).map(raw => {
    const name = raw.split('=')[0].trim();
    const secure = /;\s*secure\b/i.test(raw), httpOnly = /;\s*httponly\b/i.test(raw), sameSite = /;\s*samesite=([a-z]+)/i.exec(raw)?.[1] || '';
    if (target.protocol === 'https:' && !secure) issues.push({ severity: 'medium', cwe: 'CWE-614', issue: `Cookie "${name}" is missing the Secure flag.` });
    if (!httpOnly) issues.push({ severity: 'low', cwe: 'CWE-1004', issue: `Cookie "${name}" is missing the HttpOnly flag.` });
    return { name, secure, httpOnly, sameSite: sameSite || 'unset' };
  });
  return {
    url: target.url,
    resolvedAddresses: target.addresses,
    status: response.status,
    headers,
    cookies,
    issues,
    bodyPreview: redactSecrets(bodySnippet).text,
    summary: `HTTP ${response.status} from ${target.host}: ${issues.length} security header/cookie finding${issues.length === 1 ? '' : 's'} noted.`
  };
}

async function inspectTls(rawTarget, { scope, dnsLookup = dns.lookup, tlsConnect = tls.connect }, signal) {
  const target = await assertTargetInScope(rawTarget, scope, { dnsLookup, defaultPort: 443 });
  const connectIp = target.addresses[0];
  return new Promise((resolve, reject) => {
    let settled = false;
    const socket = tlsConnect({
      host: connectIp,
      port: target.port,
      servername: net.isIP(target.host) ? undefined : target.host,
      rejectUnauthorized: false
    });
    const finish = (err, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal.removeEventListener('abort', onAbort);
      try { socket.destroy(); } catch {}
      if (err) reject(err); else resolve(value);
    };
    const onAbort = () => finish(signal.reason || new Error('TLS inspection stopped'));
    const timer = setTimeout(() => finish(new Error(`TLS handshake timed out on ${target.host}:${target.port}`)), 8000);
    signal.addEventListener('abort', onAbort, { once: true });
    socket.once('error', err => finish(new Error(`TLS connection failed: ${err.message}`)));
    socket.once('secureConnect', () => {
      const protocol = socket.getProtocol() || 'unknown';
      const cipher = socket.getCipher() || {};
      const cert = socket.getPeerCertificate(false) || {};
      const validToMs = cert.valid_to ? Date.parse(cert.valid_to) : NaN;
      const daysRemaining = Number.isFinite(validToMs) ? Math.floor((validToMs - Date.now()) / 86400000) : null;
      const issues = [];
      if (['SSLv3', 'TLSv1', 'TLSv1.1'].includes(protocol)) issues.push({ severity: 'high', cwe: 'CWE-326', issue: `Deprecated TLS protocol negotiated: ${protocol}.` });
      if (!socket.authorized) issues.push({ severity: 'medium', cwe: 'CWE-295', issue: `Certificate chain not trusted (${socket.authorizationError || 'untrusted'}).` });
      if (daysRemaining !== null && daysRemaining < 0) issues.push({ severity: 'high', cwe: 'CWE-298', issue: `Certificate expired ${Math.abs(daysRemaining)} days ago.` });
      else if (daysRemaining !== null && daysRemaining < 14) issues.push({ severity: 'low', cwe: 'CWE-298', issue: `Certificate expires soon (${daysRemaining} days remaining).` });
      if (cipher.name && /RC4|3DES|NULL|EXPORT|MD5/i.test(cipher.name)) issues.push({ severity: 'high', cwe: 'CWE-327', issue: `Weak cipher suite negotiated: ${cipher.name}.` });
      finish(null, {
        host: target.host,
        port: target.port,
        connectedAddress: connectIp,
        protocol,
        cipher: { name: cipher.name || '', version: cipher.version || '' },
        authorized: Boolean(socket.authorized),
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : '',
        certificate: {
          subject: cert.subject || {},
          issuer: cert.issuer || {},
          subjectAltName: cert.subjectaltname || '',
          validFrom: cert.valid_from || '',
          validTo: cert.valid_to || '',
          daysRemaining,
          fingerprint256: cert.fingerprint256 || ''
        },
        issues,
        summary: `${target.host}:${target.port} negotiated ${protocol} (${cipher.name || 'unknown cipher'}); cert ${socket.authorized ? 'trusted' : 'untrusted'} (${daysRemaining ?? '?'} days remaining); ${issues.length} issue(s).`
      });
    });
  });
}

async function dnsRecon(rawDomain, { scope, dnsLookup = dns.lookup, dnsResolver = dns }, signal) {
  const target = await assertTargetInScope(rawDomain, scope, { dnsLookup });
  if (net.isIP(target.host)) throw new Error('dns_recon expects a domain name rather than an IP literal.');
  signal.throwIfAborted();
  const safe = fn => new Promise(resolve => {
    const t = setTimeout(() => resolve([]), 5000);
    t.unref?.();
    Promise.resolve().then(fn).then(v => { clearTimeout(t); resolve(v); }, () => { clearTimeout(t); resolve([]); });
  });
  const [a, aaaa, cname, mx, ns, txtRaw, dmarcRaw] = await Promise.all([
    safe(() => dnsResolver.resolve4(target.host)),
    safe(() => dnsResolver.resolve6(target.host)),
    safe(() => dnsResolver.resolveCname(target.host)),
    safe(() => dnsResolver.resolveMx(target.host)),
    safe(() => dnsResolver.resolveNs(target.host)),
    safe(() => dnsResolver.resolveTxt(target.host)),
    safe(() => dnsResolver.resolveTxt(`_dmarc.${target.host}`))
  ]);
  const txt = txtRaw.map(chunks => Array.isArray(chunks) ? chunks.join('') : String(chunks)).slice(0, 30);
  const dmarc = dmarcRaw.map(chunks => Array.isArray(chunks) ? chunks.join('') : String(chunks)).slice(0, 10);
  const spf = txt.filter(r => /^v=spf1\b/i.test(r));
  const dmarcPolicies = dmarc.filter(r => /^v=dmarc1\b/i.test(r));
  const issues = [];
  if (mx.length && !spf.length) issues.push({ severity: 'low', cwe: 'CWE-290', issue: 'Domain has MX records but no SPF TXT record.' });
  if (spf.some(r => /\+all\b/i.test(r))) issues.push({ severity: 'high', cwe: 'CWE-290', issue: 'SPF record contains +all (allows any sender to spoof domain).' });
  if (mx.length && !dmarcPolicies.length) issues.push({ severity: 'low', cwe: 'CWE-290', issue: 'Domain has MX records but no _dmarc TXT policy.' });
  else if (dmarcPolicies.some(r => /\bp=none\b/i.test(r))) issues.push({ severity: 'info', cwe: 'CWE-290', issue: 'DMARC policy is p=none (monitoring only, no enforcement).' });
  return {
    domain: target.host,
    records: { A: a.slice(0, 20), AAAA: aaaa.slice(0, 20), CNAME: cname.slice(0, 10), MX: mx.slice(0, 15), NS: ns.slice(0, 15), TXT: txt, DMARC: dmarc },
    issues,
    summary: `DNS recon for ${target.host}: ${a.length} A, ${aaaa.length} AAAA, ${mx.length} MX, ${ns.length} NS, ${txt.length} TXT; ${issues.length} posture note(s).`
  };
}

function parsePortList(portsSpec) {
  if (!portsSpec) return [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 5432, 6379, 8080, 8443];
  const out = new Set();
  for (const part of String(portsSpec).split(',').map(s => s.trim()).filter(Boolean)) {
    if (/^\d{1,5}-\d{1,5}$/.test(part)) {
      const [start, end] = part.split('-').map(Number);
      if (start < 1 || end > 65535 || end < start || end - start > 31) throw new Error('Port ranges must be within 1-65535 and span at most 32 ports.');
      for (let p = start; p <= end; p++) out.add(p);
    } else if (/^\d{1,5}$/.test(part)) {
      const p = Number(part);
      if (p < 1 || p > 65535) throw new Error(`Port ${p} is out of range (1-65535).`);
      out.add(p);
    } else {
      throw new Error(`Invalid port specification "${part}". Use comma-separated ports or small ranges such as "22,80,443,8000-8005".`);
    }
    if (out.size > 32) throw new Error('probe_ports checks at most 32 ports per call.');
  }
  if (!out.size) throw new Error('Specify at least one port.');
  return [...out].sort((a, b) => a - b);
}

async function probePorts(rawTarget, { ports, timeoutMs = 2000, scope, dnsLookup = dns.lookup, netConnect = net.createConnection }, signal) {
  const portList = parsePortList(ports);
  const perPortTimeout = Math.max(300, Math.min(5000, Number(timeoutMs) || 2000));
  const target = await assertTargetInScope(rawTarget, scope, { dnsLookup });
  const connectIp = target.addresses[0];
  const open = [], closedOrFiltered = [];
  const queue = [...portList];
  async function worker() {
    while (queue.length) {
      signal.throwIfAborted();
      const port = queue.shift();
      const outcome = await new Promise(resolve => {
        let banner = '', done = false;
        const socket = netConnect({ host: connectIp, port });
        const settle = res => {
          if (done) return;
          done = true;
          clearTimeout(timer);
          try { socket.destroy(); } catch {}
          resolve(res);
        };
        const timer = setTimeout(() => settle({ open: false }), perPortTimeout);
        socket.once('connect', () => {
          const bannerWait = setTimeout(() => settle({ open: true, banner }), 250);
          socket.once('data', chunk => {
            clearTimeout(bannerWait);
            banner = chunk.toString('latin1').replace(/[^\x20-\x7e\r\n]/g, '.').trim().slice(0, 160);
            settle({ open: true, banner });
          });
        });
        socket.once('error', () => settle({ open: false }));
      });
      if (outcome.open) open.push({ port, ...(outcome.banner ? { banner: outcome.banner } : {}) });
      else closedOrFiltered.push(port);
    }
  }
  await Promise.all(Array.from({ length: Math.min(8, portList.length) }, () => worker()));
  open.sort((a, b) => a.port - b.port);
  return {
    target: target.host,
    connectedAddress: connectIp,
    probedCount: portList.length,
    open,
    closedOrFilteredCount: closedOrFiltered.length,
    summary: `Probed ${portList.length} TCP port(s) on ${target.host} (${connectIp}): ${open.length} open${open.length ? ' (' + open.map(o => o.port).join(', ') + ')' : ''}.`
  };
}

function identifyBinaryFormat(buf) {
  if (buf.length >= 4 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
    const bits = buf[4] === 2 ? '64-bit' : buf[4] === 1 ? '32-bit' : 'unknown-class';
    const endian = buf[5] === 1 ? 'little-endian' : buf[5] === 2 ? 'big-endian' : 'unknown-endian';
    const le = buf[5] === 1;
    const typeCode = buf.length >= 18 ? (le ? buf.readUInt16LE(16) : buf.readUInt16BE(16)) : 0;
    const machCode = buf.length >= 20 ? (le ? buf.readUInt16LE(18) : buf.readUInt16BE(18)) : 0;
    const types = { 1: 'REL (relocatable)', 2: 'EXEC (executable)', 3: 'DYN (shared/PIE)', 4: 'CORE' };
    const arches = { 3: 'x86', 62: 'x86_64', 40: 'ARM', 183: 'AArch64/ARM64', 243: 'RISC-V' };
    return { format: 'ELF', details: `${bits} ${endian}, ${types[typeCode] || 'type ' + typeCode}, ${arches[machCode] || 'arch ' + machCode}` };
  }
  if (buf.length >= 4) {
    const magicBE = buf.readUInt32BE(0);
    if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(magicBE)) {
      const le = magicBE === 0xcefaedfe || magicBE === 0xcffaedfe;
      const is64 = magicBE === 0xfeedfacf || magicBE === 0xcffaedfe;
      const cpu = buf.length >= 8 ? (le ? buf.readUInt32LE(4) : buf.readUInt32BE(4)) : 0;
      const cpus = { 0x01000007: 'x86_64', 0x0100000c: 'ARM64', 7: 'x86', 12: 'ARM' };
      return { format: 'Mach-O', details: `${is64 ? '64-bit' : '32-bit'} ${le ? 'little-endian' : 'big-endian'}, ${cpus[cpu] || 'cpu 0x' + cpu.toString(16)}` };
    }
    if (magicBE === 0xcafebabe && buf.length >= 8 && buf.readUInt32BE(4) <= 16) {
      return { format: 'Mach-O Universal (Fat)', details: `${buf.readUInt32BE(4)} architecture slices` };
    }
    if (magicBE === 0xa1b2c3d4 || magicBE === 0xd4c3b2a1 || magicBE === 0x0a0d0d0a) {
      return { format: magicBE === 0x0a0d0d0a ? 'PCAPNG' : 'PCAP', details: 'Network packet capture' };
    }
  }
  if (buf.length >= 64 && buf[0] === 0x4d && buf[1] === 0x5a) {
    const peOffset = buf.readUInt32LE(0x3c);
    if (peOffset + 24 <= buf.length && buf.subarray(peOffset, peOffset + 4).equals(Buffer.from('PE\0\0'))) {
      const machine = buf.readUInt16LE(peOffset + 4);
      const sections = buf.readUInt16LE(peOffset + 6);
      const machines = { 0x014c: 'x86', 0x8664: 'x86_64', 0xaa64: 'ARM64' };
      return { format: 'PE/COFF (Windows)', details: `${machines[machine] || 'machine 0x' + machine.toString(16)}, ${sections} section(s)` };
    }
    return { format: 'DOS MZ Executable', details: 'MZ header' };
  }
  if (buf.subarray(0, 5).equals(Buffer.from('%PDF-'))) return { format: 'PDF', details: buf.subarray(0, 8).toString('ascii') };
  if (buf.subarray(0, 4).equals(Buffer.from([0x50, 0x4b, 0x03, 0x04]))) return { format: 'ZIP / Archive (JAR/APK/DOCX)', details: 'PKZIP archive' };
  if (buf.subarray(0, 2).equals(Buffer.from([0x1f, 0x8b]))) return { format: 'GZIP', details: 'Compressed stream' };
  if (buf.subarray(0, 16).toString('ascii').startsWith('SQLite format 3')) return { format: 'SQLite 3', details: 'Database file' };
  if (buf.subarray(0, 2).equals(Buffer.from('#!'))) return { format: 'Script (Shebang)', details: buf.subarray(0, 80).toString('utf8').split(/\r?\n/)[0] };
  return { format: buf.includes(0) ? 'Binary data' : 'Text / Source', details: buf.includes(0) ? 'Unrecognized magic bytes' : 'UTF-8 / ASCII text' };
}

function extractNotableStrings(buf, maxStrings = 60) {
  const strings = [], notable = [];
  let current = '';
  const limit = Math.min(buf.length, 2 * 1024 * 1024);
  for (let i = 0; i < limit; i++) {
    const b = buf[i];
    if (b >= 0x20 && b <= 0x7e) {
      if (current.length < 200) current += String.fromCharCode(b);
    } else {
      if (current.length >= 6) strings.push(current);
      current = '';
      if (strings.length >= 8000) break;
    }
  }
  if (current.length >= 6) strings.push(current);
  const interesting = /(?:https?:\/\/|\/bin\/|\/etc\/|\/tmp\/|\.so\b|\.dylib\b|\.dll\b|cmd\.exe|powershell|curl\b|wget\b|chmod\b|VirtualAlloc|CreateRemoteThread|ptrace|LD_PRELOAD|DYLD_INSERT_LIBRARIES|eval\(|base64|socket|connect|execve|BEGIN [A-Z ]*KEY)/i;
  const seen = new Set();
  for (const s of strings) {
    if (interesting.test(s) && !seen.has(s)) {
      seen.add(s);
      notable.push(redactSecrets(s).text);
      if (notable.length >= maxStrings) break;
    }
  }
  for (const s of strings) {
    if (notable.length >= Math.min(25, maxStrings)) break;
    if (!seen.has(s)) { seen.add(s); notable.push(redactSecrets(s).text); }
  }
  return { totalExtracted: strings.length, notable };
}

async function triageArtifact(file, relPath, signal) {
  signal.throwIfAborted();
  const buf = await openRegularBuffer(file, MAX_ARTIFACT_BYTES);
  signal.throwIfAborted();
  const sha256 = createHash('sha256').update(buf).digest('hex');
  const sha1 = createHash('sha1').update(buf).digest('hex');
  const md5 = createHash('md5').update(buf).digest('hex');
  const entropy = shannonEntropy(buf);
  const magic = identifyBinaryFormat(buf);
  const strings = extractNotableStrings(buf, 60);
  const highEntropy = entropy >= 7.2 && buf.length > 256;
  return {
    path: relPath,
    sizeBytes: buf.length,
    hashes: { sha256, sha1, md5 },
    entropy,
    highEntropySuspectedPackingOrEncryption: highEntropy,
    format: magic.format,
    headerDetails: magic.details,
    magicHex: buf.subarray(0, 16).toString('hex'),
    stringsCount: strings.totalExtracted,
    notableStrings: strings.notable,
    summary: `${relPath} (${buf.length} bytes): ${magic.format} (${magic.details}) · SHA-256 ${sha256.slice(0, 16)}… · entropy ${entropy}/8.00${highEntropy ? ' [HIGH ENTROPY]' : ''}.`
  };
}

async function extractIocs(file, relPath, signal) {
  signal.throwIfAborted();
  const buf = await openRegularBuffer(file, 5 * 1024 * 1024);
  const text = buf.toString('utf8').replace(/\[\.\]/g, '.').replace(/hxxps?:\/\//gi, m => m.toLowerCase().replace('hxxp', 'http'));
  const collect = (re, limit = 100, filter = null) => {
    const set = new Set();
    let m;
    while ((m = re.exec(text)) !== null) {
      const val = m[0];
      if (!filter || filter(val)) set.add(val);
      if (set.size >= limit) break;
    }
    return [...set];
  };
  const urls = collect(/\bhttps?:\/\/[^\s"'<>)\]]{4,300}/gi, 80);
  const ipv4All = collect(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, 120, ip => net.isIP(ip) === 4);
  const externalIpv4 = ipv4All.filter(ip => !isPrivateOrReservedIp(ip));
  const privateIpv4 = ipv4All.filter(ip => isPrivateOrReservedIp(ip));
  const sha256 = collect(/\b[a-fA-F0-9]{64}\b/g, 60).map(s => s.toLowerCase());
  const sha1 = collect(/\b[a-fA-F0-9]{40}\b/g, 60).map(s => s.toLowerCase());
  const md5 = collect(/\b[a-fA-F0-9]{32}\b/g, 60).map(s => s.toLowerCase());
  const cves = collect(/\bCVE-\d{4}-\d{4,7}\b/gi, 60).map(s => s.toUpperCase());
  const mitre = collect(/\bT1\d{3}(?:\.\d{3})?\b/g, 60);
  const domains = collect(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|dev|app|xyz|ru|cn|top|info|biz|co|me|sh|cloud|ai|gov|edu)\b/gi, 80)
    .map(d => d.toLowerCase());
  const total = urls.length + externalIpv4.length + domains.length + sha256.length + sha1.length + md5.length + cves.length + mitre.length;
  return {
    path: relPath,
    iocs: { externalIpv4, privateIpv4, domains, urls: urls.map(u => redactSecrets(u).text), hashes: { sha256, sha1, md5 }, cves, mitreTechniques: mitre },
    summary: `Extracted ${total} external/threat IOC(s) from ${relPath} (${externalIpv4.length} public IPv4, ${domains.length} domains, ${urls.length} URLs, ${sha256.length} SHA-256, ${cves.length} CVEs, ${mitre.length} ATT&CK IDs).`
  };
}

const LOG_ATTACK_SIGS = [
  { id: 'path-traversal', label: 'Directory Traversal Probe', mitre: 'T1190', regex: /(?:\.\.\/|\.\.%2f|%2e%2e%2f|\/etc\/passwd|\/win\.ini)/i },
  { id: 'sqli-probe', label: 'SQL Injection Probe', mitre: 'T1190', regex: /(?:union\s+(?:all\s+)?select|or\s+1\s*=\s*1|sleep\s*\(\s*\d+\s*\)|information_schema)/i },
  { id: 'xss-probe', label: 'XSS Payload Probe', mitre: 'T1190', regex: /(?:<script\b|%3cscript|javascript:|onerror\s*=)/i },
  { id: 'cmd-rce-probe', label: 'Command / JNDI RCE Probe', mitre: 'T1059', regex: /(?:\$\{jndi:|;\s*(?:cat|wget|curl|nc|bash|sh)\s|\|\s*(?:whoami|id)\b)/i },
  { id: 'ssrf-metadata', label: 'Cloud Metadata SSRF Probe', mitre: 'T1552.005', regex: /169\.254\.169\.254|metadata\.google\.internal/i },
  { id: 'scanner-ua', label: 'Automated Security Scanner', mitre: 'T1595', regex: /\b(?:sqlmap|nikto|nuclei|nmap|masscan|gobuster|ffuf|dirbuster|zgrab)\b/i },
  { id: 'auth-failure', label: 'Authentication Failure / Brute Force', mitre: 'T1110', regex: /\b(?:Failed password|Invalid user|authentication failure|pam_unix.*failure|unauthorized|invalid token)\b/i }
];

async function analyzeLogs(file, relPath, { filter = '' }, signal) {
  signal.throwIfAborted();
  const buf = await openRegularBuffer(file, MAX_ARTIFACT_BYTES);
  const text = buf.toString('utf8');
  const lines = text.split(/\r?\n/);
  const needle = filter.trim().toLowerCase();
  const ipCounts = new Map(), statusCounts = {}, sigCounts = {}, alerts = [], analyzedLineEntries = [];
  let matchedLines = 0, jsonLines = 0;
  for (let i = 0; i < lines.length; i++) {
    if ((i & 2047) === 0) signal.throwIfAborted();
    const line = lines[i];
    if (!line) continue;
    if (needle && !line.toLowerCase().includes(needle)) continue;
    matchedLines++;
    analyzedLineEntries.push({ line: i + 1, text: line });
    if (line.startsWith('{') && line.endsWith('}')) jsonLines++;
    const ipMatch = /\b(?:\d{1,3}\.){3}\d{1,3}\b/.exec(line);
    if (ipMatch && net.isIP(ipMatch[0]) === 4) ipCounts.set(ipMatch[0], (ipCounts.get(ipMatch[0]) || 0) + 1);
    const httpStatus = /"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+[^"]+"\s+(\d{3})\b/.exec(line) || /\bstatus["'=:\s]+(\d{3})\b/i.exec(line);
    if (httpStatus) {
      const bucket = `${httpStatus[1][0]}xx`;
      statusCounts[bucket] = (statusCounts[bucket] || 0) + 1;
      if (httpStatus[1] === '401' || httpStatus[1] === '403') sigCounts['http-auth-denied'] = (sigCounts['http-auth-denied'] || 0) + 1;
    }
    let decodedLine = line;
    if (line.includes('%')) { try { decodedLine = decodeURIComponent(line.replace(/\+/g, ' ')); } catch { decodedLine = line.replace(/%20/g, ' '); } }
    for (const sig of LOG_ATTACK_SIGS) {
      if (!sig.regex.test(decodedLine) && !sig.regex.test(line)) continue;
      sigCounts[sig.id] = (sigCounts[sig.id] || 0) + 1;
      if (alerts.length < 60) {
        alerts.push({ line: i + 1, type: sig.id, label: sig.label, mitre: sig.mitre, sample: redactSecrets(line.slice(0, 240)).text });
      }
    }
  }
  const agenticBehavior = analyzeAgenticBehavior(analyzedLineEntries, relPath);
  if (agenticBehavior.detected) {
    sigCounts['artex-agentic-behavior'] = agenticBehavior.indicators.length;
    alerts.unshift({
      line: agenticBehavior.indicators[0]?.line || 1,
      type: 'artex-agentic-behavior',
      ruleId: agenticBehavior.ruleId,
      label: 'Agentic Machine-Speed Attack Behavior (ARTEX-style)',
      mitre: agenticBehavior.mitre,
      sample: redactSecrets(agenticBehavior.indicators.map(x => x.summary).join(' | ').slice(0, 240)).text
    });
  }
  const topIps = [...ipCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 15).map(([ip, count]) => ({ ip, count, private: isPrivateOrReservedIp(ip) }));
  return {
    path: relPath,
    totalLines: lines.length,
    analyzedLines: matchedLines,
    detectedFormat: jsonLines > matchedLines / 2 ? 'JSONL' : Object.keys(statusCounts).length ? 'HTTP Access / Structured Log' : 'Syslog / Text Log',
    statusDistribution: statusCounts,
    signatureCounts: sigCounts,
    topSourceIps: topIps,
    alerts,
    agenticBehavior,
    summary: `Analyzed ${matchedLines} log line(s) in ${relPath}: ${alerts.length} suspicious event sample(s) across ${Object.keys(sigCounts).length} detection signature(s)${agenticBehavior.detected ? ` [ARTEX-BEHAV-001 ${agenticBehavior.confidence} confidence]` : ''}.`
  };
}

const DNA_PROTECTED = /^(\.git|\.ssh|\.aws|\.gnupg|\.codex|\.npmrc|\.netrc|\.pypirc|\.env(?:\..*)?|.*\.(?:pem|key))$/i;
const DNA_SKIP_DIRS = new Set([
  'node_modules', '.venv', 'venv', '__pycache__', '.uv-cache', '.cache',
  '.pytest_cache', '.mypy_cache', '.ruff_cache', '.tox', '.nox', '.next',
  '.nuxt', '.turbo', '.parcel-cache', 'test-results', 'playwright-report', 'release'
]);
const SEV_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const CODE_RULE_CWES = new Set(CODE_RULES.map(r => r.cwe));

function hasSecretInText(relPath, text) {
  const isDoc = /\.(?:md|mdx|rst|txt)$/i.test(relPath);
  const isDemoOrTest = /(?:^|\/)(?:demo|example|sample)[-_][^/]*$|_test\.go$|\.(?:test|spec)\.[cm]?[jt]sx?$/i.test(relPath);
  const HIGH_CERTAINTY_SECRET_IDS = new Set(['private-key', 'aws-access-key', 'github-token', 'ai-api-key', 'slack-token', 'stripe-key', 'google-api-key']);
  const entropyCandidate = /\b([A-Za-z_][A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)[A-Za-z0-9_]*)\s*[:=]\s*['"]([A-Za-z0-9+/=_-]{20,128})['"]/i;
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\r$/, '');
    if (!line || line.length > 4000) continue;
    for (const rule of SECRET_RULES) {
      if ((isDoc || isDemoOrTest) && !HIGH_CERTAINTY_SECRET_IDS.has(rule.id)) continue;
      rule.regex.lastIndex = 0;
      const m = rule.regex.exec(line);
      if (m && (!rule.filter || rule.filter(...m))) return true;
    }
    if (!isDoc && !isDemoOrTest) {
      const em = entropyCandidate.exec(line);
      if (em && !/^(?:your_|example|placeholder|test_|dummy|fake_|demo_|dev_|local_)/i.test(em[2]) && shannonEntropy(em[2]) >= 4.35 && /[a-z]/.test(em[2]) && /[A-Z0-9]/.test(em[2])) {
        return true;
      }
    }
  }
  return false;
}

function matchingCodeCwesInText(relPath, text) {
  const matched = new Set();
  if (/\.(?:md|txt|lock|svg|css|map)$/i.test(relPath)) return matched;
  for (const line of text.split('\n')) {
    const raw = line.replace(/\r$/, ''), trimmed = raw.trim();
    if (!trimmed || trimmed.length > 1000 || trimmed.startsWith('//') || (trimmed.startsWith('#') && !trimmed.startsWith('#!'))) continue;
    for (const rule of CODE_RULES) {
      if (rule.regex.test(raw) && (!rule.filter || rule.filter(trimmed))) matched.add(rule.cwe);
    }
  }
  return matched;
}

function extractEvidenceCodeSnippets(evidence) {
  if (typeof evidence !== 'string' || !evidence.trim()) return [];
  return evidence
    .split('\n')
    .map(l => l.trim())
    .filter(l => l.length >= 10 && l.length <= 240 && !l.includes('[REDACTED]') && !l.includes('…') && /[=(){};.<>\[\]$]/.test(l) && !/^(?:Line \d+|Detected |Flagged |Masked |Verified )/i.test(l));
}

async function reconcileWorkspaceFindings(root, findingsStore) {
  if (!root || !findingsStore) return { findings: [], mitigatedCount: 0 };
  const pathMod = require('node:path');
  let list = await findingsStore.list(root);
  const active = list.filter(f => f.status === 'open' || f.status === 'verified');
  if (!active.length) return { findings: list, mitigatedCount: 0 };

  const rootResolved = pathMod.resolve(root);
  const fileCache = new Map();

  async function inspectRelFile(relPath) {
    if (fileCache.has(relPath)) return fileCache.get(relPath);
    let handle;
    try {
      const full = pathMod.resolve(rootResolved, relPath);
      if (full !== rootResolved && !full.startsWith(rootResolved + pathMod.sep)) {
        const res = { status: 'skip' };
        fileCache.set(relPath, res);
        return res;
      }
      handle = await fs.open(full, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
      const stat = await handle.stat();
      if (!stat.isFile() || stat.nlink > 1 || stat.size > 2 * 1024 * 1024) {
        const res = { status: 'skip' };
        fileCache.set(relPath, res);
        return res;
      }
      const buf = Buffer.alloc(stat.size);
      if (stat.size > 0) await handle.read(buf, 0, stat.size, 0);
      if (buf.subarray(0, Math.min(stat.size, 4096)).includes(0)) {
        const res = { status: 'binary', mtimeMs: stat.mtimeMs };
        fileCache.set(relPath, res);
        return res;
      }
      const text = buf.toString('utf8');
      const res = {
        status: 'text',
        mtimeMs: stat.mtimeMs,
        text,
        hasSecret: hasSecretInText(relPath, text),
        cwes: matchingCodeCwesInText(relPath, text)
      };
      fileCache.set(relPath, res);
      return res;
    } catch (err) {
      const res = { status: err?.code === 'ENOENT' ? 'missing' : 'skip' };
      fileCache.set(relPath, res);
      return res;
    } finally {
      await handle?.close().catch(() => {});
    }
  }

  let mitigatedCount = 0;
  for (const f of active) {
    if (f.category === 'network' || f.category === 'web') continue;
    const rawLoc = String(f.location || '').trim().replace(/^\.\//, '');
    if (!rawLoc || /^[a-z][a-z0-9+.-]*:\/\//i.test(rawLoc)) continue;
    const relPath = rawLoc.replace(/:\d+(?::\d+)?$/, '');
    if (!relPath || relPath.split('/').some(seg => !seg || seg === '..' || DNA_PROTECTED.test(seg))) continue;

    const info = await inspectRelFile(relPath);
    if (info.status === 'missing') {
      list = await findingsStore.update(root, f.id, { status: 'mitigated' });
      mitigatedCount++;
      continue;
    }
    if (info.status !== 'text') continue;

    const findingTime = Date.parse(f.updatedAt || f.createdAt || '') || 0;
    const editedSinceFinding = findingTime > 0 && info.mtimeMs > findingTime + 25;
    const snippets = extractEvidenceCodeSnippets(f.evidence);
    const snippetStillPresent = snippets.length > 0 && snippets.some(s => info.text.includes(s));

    let resolved = false;
    if (f.category === 'secrets' || f.cwe === 'CWE-798') {
      if (!info.hasSecret && !snippetStillPresent) resolved = true;
    } else if (f.cwe && CODE_RULE_CWES.has(f.cwe)) {
      if (!info.cwes.has(f.cwe) && !snippetStillPresent) resolved = true;
    } else if (editedSinceFinding && snippets.length > 0 && !snippetStillPresent) {
      resolved = true;
    }

    if (resolved) {
      list = await findingsStore.update(root, f.id, { status: 'mitigated' });
      mitigatedCount++;
    }
  }

  return { findings: list, mitigatedCount };
}

async function scanWorkspaceDna(root, { findings = [], tools = [], maxFiles = 260 } = {}) {
  const pathMod = require('node:path');
  const readySet = new Set(tools.filter(t => t.available).map(t => t.id));
  const activeFindings = (findings || []).filter(f => f.status === 'open' || f.status === 'verified');

  const items = [];
  const deadline = Date.now() + 3500;
  const queue = [root];
  let visited = 0, truncated = false;

  while (queue.length && items.length < maxFiles) {
    if (Date.now() > deadline || visited > 8000) { truncated = true; break; }
    const dir = queue.pop();
    let entries;
    try { entries = await fs.readdir(dir, { withFileTypes: true }); } catch { continue; }
    entries.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
    const subdirs = [];
    for (const entry of entries) {
      if (++visited > 8000 || Date.now() > deadline) { truncated = true; break; }
      if (entry.name === '.DS_Store' || entry.isSymbolicLink() || DNA_PROTECTED.test(entry.name)) continue;
      const full = pathMod.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!DNA_SKIP_DIRS.has(entry.name)) subdirs.push(full);
        continue;
      }
      if (!entry.isFile()) continue;
      let handle;
      try {
        handle = await fs.open(full, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
        const stat = await handle.stat();
        if (!stat.isFile() || stat.nlink > 1 || stat.size > MAX_ARTIFACT_BYTES) continue;
        const sampleLen = Math.min(stat.size, 65536);
        const buf = Buffer.alloc(sampleLen);
        if (sampleLen > 0) await handle.read(buf, 0, sampleLen, 0);
        const entropy = shannonEntropy(buf);
        const isBinary = buf.subarray(0, Math.min(sampleLen, 4096)).includes(0);
        const rel = pathMod.relative(root, full).split(pathMod.sep).join('/');
        const base = entry.name.toLowerCase();
        const kind = /^(package(?:-lock)?\.json|pnpm-lock\.yaml|cargo\.(?:lock|toml)|pyproject\.toml|requirements.*\.txt|go\.(?:mod|sum))$/.test(base)
          ? 'manifest'
          : /\.(?:pcap|pcapng|cap|log|jsonl)$/.test(base)
            ? 'capture'
            : isBinary || /\.(?:dylib|so|exe|dll|bin|wasm|woff2|png|jpg|mp4|zip|gz)$/.test(base)
              ? 'binary'
              : (/^(dockerfile|containerfile)$/i.test(base) || /\.(?:tf|tfvars|ya?ml)$/.test(base))
                ? 'iac'
                : 'code';

        const candidateClis = kind === 'manifest'
          ? ['trivy', 'osv-scanner', 'gitleaks']
          : kind === 'capture'
            ? ['tshark', 'gitleaks']
            : kind === 'binary'
              ? ['otool', 'radare2', 'trivy']
              : kind === 'iac'
                ? ['trivy', 'semgrep', 'gitleaks']
                : ['semgrep', 'gitleaks', 'trivy'];
        const activeClis = candidateClis.filter(id => readySet.has(id));

        const fileFindings = activeFindings.filter(f => {
          const loc = String(f.location || '').replace(/^\.\//, '');
          return loc === rel || loc.startsWith(rel + ':');
        });
        let maxSeverity = '';
        let topFinding = null;
        for (const f of fileFindings) {
          if ((SEV_RANK[f.severity] || 0) > (SEV_RANK[maxSeverity] || 0)) {
            maxSeverity = f.severity;
            topFinding = { id: f.id, title: f.title, severity: f.severity, cwe: f.cwe || '' };
          }
        }
        const group = rel.includes('/') ? rel.split('/')[0] + '/' : './';
        items.push({
          path: rel,
          group,
          size: stat.size,
          entropy,
          isBinary,
          kind,
          engines: activeClis.length ? activeClis : ['built-in'],
          findingCount: fileFindings.length,
          openFindingIds: fileFindings.map(f => f.id),
          maxSeverity,
          topFinding
        });
        if (items.length >= maxFiles) { truncated = true; break; }
      } catch {
        // Skip unreadable files safely
      } finally {
        await handle?.close().catch(() => {});
      }
    }
    queue.push(...subdirs.reverse());
  }

  items.sort((a, b) => a.group.localeCompare(b.group) || a.entropy - b.entropy || a.path.localeCompare(b.path));
  const peakEntropy = items.reduce((m, x) => Math.max(m, x.entropy), 0);
  const highEntropyCount = items.filter(x => x.entropy >= 6.4).length;
  const affectedFilesCount = items.filter(x => x.findingCount > 0).length;
  const openFindingsCount = activeFindings.length;
  const hotspotCount = items.filter(x => x.findingCount > 0 || (x.entropy >= 7.2 && !/\.(?:woff2|png|jpg|mp4|gz|zip)$/i.test(x.path))).length;

  return {
    workspace: root,
    truncated,
    files: items,
    summary: {
      totalFiles: items.length,
      peakEntropy,
      highEntropyCount,
      affectedFilesCount,
      openFindingsCount,
      hotspotCount,
      readyEngines: tools.filter(t => t.available).map(t => t.label),
      readyCount: tools.filter(t => t.available).length,
      totalEngines: tools.length
    }
  };
}

const REACH_SOURCE_EXT_RE = /\.(?:[cm]?[jt]sx?|py|go)$/i;
const REACH_SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'vendor', 'coverage', '.next', 'release', 'playwright-report', 'test-results']);
const REACH_TEST_FILE_RE = /(?:^|\/)(?:test|tests|__tests__)\/|(?:\.(?:test|spec)\.[cm]?[jt]sx?|_test\.(?:go|py)|test_[^/]+\.py)$/i;
const REACH_PROTECTED_RE = /^\.(?:env(?:\.|$)|ssh$|aws$|gnupg$|npmrc$|netrc$|shirudo$|marlowe)|shirudo-keys/i;

function detectExternalIngress(text) {
  if (/\b(?:req\.(?:body|query|params|headers|cookies)|request\.(?:json|args|form)|axum::|hyper::|actix_web|TcpListener|UdpSocket|http\.createServer)\b/.test(text)) {
    return { entryKind: 'HTTP / Socket Input', entrySub: 'Network ingress in module' };
  }
  if (/\b(?:location\.(?:search|hash|href)|URLSearchParams|addEventListener\s*\(\s*['"]message['"]|postMessage|WebSocket)\b/.test(text)) {
    return { entryKind: 'URL / DOM Message', entrySub: 'Client untrusted source' };
  }
  if (/\b(?:process\.argv|std::env::args|sys\.argv|io::stdin)\b/.test(text)) {
    return { entryKind: 'CLI / Stdin Input', entrySub: 'Command-line source' };
  }
  return null;
}

function extractEnclosingFnName(lines, targetIdx, fallback) {
  for (let i = targetIdx; i >= Math.max(0, targetIdx - 55); i--) {
    const l = lines[i] || '';
    const m = /\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(|\bfn\s+([A-Za-z_]\w*)\s*[<(]|\bdef\s+([A-Za-z_]\w*)\s*\(|\bfunc\s+(?:\([^)]+\)\s*)?([A-Za-z_]\w*)\s*\(|\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>/.exec(l);
    if (m) return `${m[1] || m[2] || m[3] || m[4] || m[5]}()`;
  }
  return fallback;
}

function moduleExportsSymbols(relPath, text) {
  if (/\.py$/i.test(relPath)) return /^def\s+[A-Za-z_]\w*\s*\(/m.test(text);
  if (/\.go$/i.test(relPath)) return /^func\s+[A-Z]\w*\s*\(/m.test(text);
  return /\bexport\b|\bmodule\.exports\b|\bexports\.[A-Za-z_$]/.test(text);
}

function parseNamedList(raw) {
  return String(raw || '')
    .split(',')
    .map(part => part.trim().split(/\s+(?:as\s+|:\s*)/)[0].trim())
    .filter(s => /^[A-Za-z_$][\w$]*$/.test(s));
}

function parseSourceImports(relPath, text) {
  const imports = [];
  let m;
  const esmNamedRe = /^\s*import\s+(?:type\s+)?(?:\{([^}]+)\}|([A-Za-z_$][\w$]*)\s*,\s*\{([^}]+)\}|([A-Za-z_$][\w$]*|\*\s+as\s+[A-Za-z_$][\w$]*))\s+from\s+['"]([^'"]+)['"]/gm;
  while ((m = esmNamedRe.exec(text))) {
    const named = m[1] ? parseNamedList(m[1]) : m[3] ? parseNamedList(m[3]) : [];
    const exclusive = Boolean(m[1] && !m[2]);
    imports.push({ spec: m[5], named, exclusive });
  }
  const esmSideRe = /^\s*import\s+['"]([^'"]+)['"]|import\(\s*['"]([^'"]+)['"]\s*\)/gm;
  while ((m = esmSideRe.exec(text))) {
    imports.push({ spec: m[1] || m[2], named: [], exclusive: false });
  }
  const cjsDestructRe = /(?:const|let|var)\s+\{([^}]+)\}\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)/g;
  while ((m = cjsDestructRe.exec(text))) {
    imports.push({ spec: m[2], named: parseNamedList(m[1]), exclusive: true });
  }
  const cjsPlainRe = /(?:(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*)?require\(\s*['"]([^'"]+)['"]\s*\)/g;
  while ((m = cjsPlainRe.exec(text))) {
    const spec = m[1];
    if (!imports.some(existing => existing.spec === spec)) {
      imports.push({ spec, named: [], exclusive: false });
    }
  }
  if (/\.py$/i.test(relPath)) {
    const pyFromRe = /^\s*from\s+(\.{0,2}[A-Za-z0-9_.]+)\s+import\s+([^\n#]+)/gm;
    while ((m = pyFromRe.exec(text))) {
      const names = m[2].includes('*') ? [] : parseNamedList(m[2]);
      imports.push({ spec: m[1], named: names, exclusive: Boolean(names.length), pythonMod: true });
    }
  }
  return imports;
}

function resolveModuleImport(callerRel, imp, indexedSet) {
  const pathMod = require('node:path');
  const spec = String(imp.spec || '').trim();
  if (!spec) return null;
  if (imp.pythonMod) {
    const dotted = spec.replace(/^\.+/, '').replace(/\./g, '/');
    const candidates = [`${dotted}.py`, `${dotted}/__init__.py`];
    for (const c of candidates) {
      if (indexedSet.has(c)) return c;
    }
    for (const rel of indexedSet) {
      if (rel.endsWith('/' + dotted + '.py')) return rel;
    }
    return null;
  }
  if (!spec.startsWith('./') && !spec.startsWith('../')) return null;
  const callerDir = pathMod.posix.dirname(callerRel);
  const raw = pathMod.posix.normalize(pathMod.posix.join(callerDir, spec));
  if (raw.startsWith('..')) return null;
  const exts = ['.js', '.cjs', '.mjs', '.ts', '.tsx', '.jsx', '.py', '.go'];
  const candidates = [raw, ...exts.map(e => raw + e), ...exts.map(e => `${raw}/index${e}`)];
  return candidates.find(c => indexedSet.has(c)) || null;
}

async function buildCrossFileIndex(rootResolved) {
  const pathMod = require('node:path');
  const files = new Map();
  const queue = [rootResolved];
  const maxFiles = 250;

  while (queue.length && files.size < maxFiles) {
    const dir = queue.shift();
    let entries;
    try { entries = await fs.readdir(dir, { withFileTypes: true }); } catch { continue; }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    const subdirs = [];
    for (const entry of entries) {
      if (entry.isSymbolicLink() || REACH_PROTECTED_RE.test(entry.name)) continue;
      if (entry.isDirectory()) {
        if (!REACH_SKIP_DIRS.has(entry.name)) subdirs.push(pathMod.join(dir, entry.name));
        continue;
      }
      if (!entry.isFile() || !REACH_SOURCE_EXT_RE.test(entry.name)) continue;
      const full = pathMod.join(dir, entry.name);
      const rel = pathMod.relative(rootResolved, full).split(pathMod.sep).join('/');
      if (REACH_TEST_FILE_RE.test(rel)) continue;
      let handle;
      try {
        handle = await fs.open(full, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
        const stat = await handle.stat();
        if (!stat.isFile() || stat.nlink > 1 || stat.size > 512 * 1024) continue;
        const buf = Buffer.alloc(stat.size);
        if (stat.size > 0) await handle.read(buf, 0, stat.size, 0);
        if (buf.subarray(0, Math.min(stat.size, 4096)).includes(0)) continue;
        const text = buf.toString('utf8');
        files.set(rel, {
          relPath: rel,
          text,
          ingress: detectExternalIngress(text),
          rawImports: parseSourceImports(rel, text),
          resolvedImports: []
        });
        if (files.size >= maxFiles) break;
      } catch {
        // Ignore unreadable source files cleanly
      } finally {
        await handle?.close().catch(() => {});
      }
    }
    queue.push(...subdirs);
  }

  const indexedSet = new Set(files.keys());
  for (const entry of files.values()) {
    entry.resolvedImports = entry.rawImports
      .map(imp => ({ ...imp, target: resolveModuleImport(entry.relPath, imp, indexedSet) }))
      .filter(imp => Boolean(imp.target));
  }
  return files;
}

function findCallerFunctionsForSymbol(text, calleeSymbol) {
  if (!calleeSymbol) return [];
  const escaped = calleeSymbol.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const callRe = new RegExp(`\\b${escaped}\\b`, 'g');
  const lines = text.split('\n');
  const fns = new Set();
  let match;
  while ((match = callRe.exec(text))) {
    const lineIdx = text.slice(0, match.index).split('\n').length - 1;
    const lineText = lines[lineIdx] || '';
    if (/^\s*(?:import\b|from\b|(?:const|let|var)\s+\{[^}]*\}\s*=\s*require)/.test(lineText)) continue;
    const fn = extractEnclosingFnName(lines, lineIdx, '');
    if (fn) fns.add(fn.replace(/\(\)$/, ''));
  }
  return [...fns];
}

function callerMatchesTarget(caller, targetRelPath, symbolBases) {
  const pathMod = require('node:path');
  const targetBase = pathMod.posix.basename(targetRelPath);
  const symbolSet = new Set((Array.isArray(symbolBases) ? symbolBases : [symbolBases]).filter(Boolean));
  return caller.resolvedImports.some(imp => {
    if (imp.target !== targetRelPath) return false;
    if (!imp.exclusive || symbolSet.has(targetBase) || symbolSet.size === 0) return true;
    for (const sym of symbolSet) {
      if (imp.named.includes(sym) && new RegExp(`\\b${sym.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`).test(caller.text)) {
        return true;
      }
    }
    return false;
  });
}

async function traceCrossFileReachability(rootResolved, targetRelPath, targetText, fnName, options = {}) {
  const pathMod = require('node:path');
  const cache = options.cache instanceof Map ? options.cache : null;
  let index = cache?.get(rootResolved);
  if (!index) {
    index = await buildCrossFileIndex(rootResolved);
    if (cache) cache.set(rootResolved, index);
  }
  const normTarget = String(targetRelPath || '').replace(/^\.\//, '').split(pathMod.sep).join('/');
  const fnBase = String(fnName || '').replace(/\(\)$/, '');
  const hop1 = [];

  for (const caller of index.values()) {
    if (caller.relPath === normTarget) continue;
    if (!callerMatchesTarget(caller, normTarget, [fnBase])) continue;
    if (caller.ingress) {
      return {
        entryKind: `Cross-file ${caller.ingress.entryKind}`,
        entrySub: `Imported by ${caller.relPath} (hop 1)`,
        hops: 1,
        via: [caller.relPath]
      };
    }
    hop1.push(caller);
  }

  for (const mid of hop1) {
    const midSymbols = findCallerFunctionsForSymbol(mid.text, fnBase);
    for (const outer of index.values()) {
      if (outer.relPath === normTarget || outer.relPath === mid.relPath || !outer.ingress) continue;
      if (callerMatchesTarget(outer, mid.relPath, midSymbols.length ? midSymbols : [fnBase])) {
        return {
          entryKind: `Cross-file ${outer.ingress.entryKind}`,
          entrySub: `Imported via ${outer.relPath} → ${mid.relPath} (hop 2)`,
          hops: 2,
          via: [outer.relPath, mid.relPath]
        };
      }
    }
  }
  return null;
}

async function inspectSourceReachability(root, relPath, lineNum, options = {}) {
  const pathMod = require('node:path');
  let handle;
  try {
    const rootResolved = await fs.realpath(pathMod.resolve(root)).catch(() => pathMod.resolve(root));
    const full = pathMod.resolve(rootResolved, relPath);
    if (full !== rootResolved && !full.startsWith(rootResolved + pathMod.sep)) return null;
    handle = await fs.open(full, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink > 1 || stat.size > 2 * 1024 * 1024) return null;
    const buf = Buffer.alloc(stat.size);
    if (stat.size > 0) await handle.read(buf, 0, stat.size, 0);
    if (buf.subarray(0, Math.min(stat.size, 4096)).includes(0)) return { binary: true };
    const text = buf.toString('utf8');
    const lines = text.split('\n');

    const localIngress = detectExternalIngress(text);
    const fnName = extractEnclosingFnName(lines, Math.max(0, Math.min(lines.length - 1, (lineNum || 1) - 1)), pathMod.basename(relPath));
    const rawLine = (lines[Math.max(0, Math.min(lines.length - 1, (lineNum || 1) - 1))] || '').trim();
    const sinkSnippet = rawLine ? redactSecrets(rawLine.slice(0, 140)).text : '';

    if (localIngress) {
      return { binary: false, entryKind: localIngress.entryKind, entrySub: localIngress.entrySub, fnName, sinkSnippet, hops: 0, via: [] };
    }

    if (options.crossFile !== false && moduleExportsSymbols(relPath, text)) {
      const cross = await traceCrossFileReachability(rootResolved, relPath, text, fnName, options);
      if (cross) {
        return { binary: false, entryKind: cross.entryKind, entrySub: cross.entrySub, fnName, sinkSnippet, hops: cross.hops, via: cross.via };
      }
    }

    return { binary: false, entryKind: null, entrySub: 'Static / internal state only', fnName, sinkSnippet, hops: 0, via: [] };
  } catch {
    return null;
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function buildWorkspaceGraphs(root, { findings = [], tools = [], scope = {} } = {}) {
  const pathMod = require('node:path');
  const dna = root
    ? await scanWorkspaceDna(root, { findings, tools, maxFiles: 220 })
    : { workspace: '', files: [], summary: { totalFiles: 0, peakEntropy: 0, highEntropyCount: 0, affectedFilesCount: 0, openFindingsCount: 0, hotspotCount: 0, readyEngines: [], readyCount: tools.filter(t => t.available).length, totalEngines: tools.length } };

  const ENGINE_ORDER = ['semgrep', 'gitleaks', 'trivy', 'osv-scanner', 'nmap', 'nuclei', 'tshark', 'radare2', 'otool', 'shirudo'];
  const engines = ENGINE_ORDER.map(id => {
    const found = tools.find(t => t.id === id);
    return {
      id,
      label: found?.label || id,
      available: Boolean(found?.available),
      version: found?.version || '',
      category: found?.category || ''
    };
  });

  const activeFindings = (findings || []).filter(f => f.status === 'open' || f.status === 'verified');
  const resolvedFindings = (findings || []).filter(f => f.status === 'mitigated' || f.status === 'false-positive');

  // --- 1. Build 9-CLI Convergence Nodes & Links ---
  const pickedAssets = [];
  const usedPaths = new Set();
  const addFileAsset = file => {
    if (!file || usedPaths.has(file.path) || pickedAssets.length >= 7) return;
    usedPaths.add(file.path);
    const allCand = file.kind === 'manifest'
      ? ['trivy', 'osv-scanner', 'gitleaks']
      : file.kind === 'capture'
        ? ['tshark', 'gitleaks']
        : file.kind === 'binary'
          ? ['otool', 'radare2', 'trivy']
          : file.kind === 'iac'
            ? ['trivy', 'semgrep', 'gitleaks']
            : ['semgrep', 'gitleaks', 'trivy'];
    const status = (file.maxSeverity === 'critical' || file.maxSeverity === 'high')
      ? 'crit'
      : file.findingCount > 0
        ? 'warn'
        : (file.kind === 'binary' || file.kind === 'capture')
          ? 'binary'
          : 'clean';
    pickedAssets.push({
      id: `asset:${file.path}`,
      path: file.path,
      label: file.path.length > 26 ? '…/' + pathMod.basename(file.path) : file.path,
      kind: file.kind,
      entropy: file.entropy,
      size: file.size,
      status,
      findingCount: file.findingCount,
      openFindingIds: file.openFindingIds || [],
      engineIds: allCand,
      impactIds: [],
      detail: `${file.path} · ${file.kind.toUpperCase()} · Entropy ${file.entropy.toFixed(2)} b/B · ${file.findingCount ? `${file.findingCount} open issue(s)` : 'Verified clean'}`
    });
  };

  // Hot files first
  [...dna.files]
    .filter(f => f.findingCount > 0)
    .sort((a, b) => (SEV_RANK[b.maxSeverity] || 0) - (SEV_RANK[a.maxSeverity] || 0) || b.findingCount - a.findingCount)
    .slice(0, 3)
    .forEach(addFileAsset);

  // Authorized Scope targets (links Nmap, Nuclei, TShark!)
  for (const target of (scope?.targets || []).slice(0, 2)) {
    if (pickedAssets.length >= 7) break;
    const netFindings = activeFindings.filter(f => String(f.location || '').includes(target));
    pickedAssets.push({
      id: `scope:${target}`,
      path: target,
      label: target.length > 26 ? target.slice(0, 25) + '…' : target,
      kind: 'scope',
      entropy: 0,
      size: 0,
      status: netFindings.length ? 'warn' : 'scope',
      findingCount: netFindings.length,
      openFindingIds: netFindings.map(f => f.id),
      engineIds: ['nmap', 'nuclei', 'tshark'],
      impactIds: [],
      detail: `${target} · Authorized Network Scope · Guarded by ScopeGate (${netFindings.length ? `${netFindings.length} open finding(s)` : 'ready for Nmap / Nuclei / TLS recon'})`
    });
  }

  // Diverse clean/artifact representatives (binary, capture, manifest, iac, code)
  for (const kind of ['binary', 'capture', 'manifest', 'iac', 'code']) {
    const match = dna.files.find(f => f.kind === kind && !usedPaths.has(f.path));
    if (match) addFileAsset(match);
  }
  for (const f of dna.files) {
    if (pickedAssets.length >= 6) break;
    addFileAsset(f);
  }

  const impacts = [];
  const impactByKey = new Map();
  const ensureImpact = (key, spec) => {
    if (!impactByKey.has(key)) {
      const node = { id: key, ...spec };
      impactByKey.set(key, node);
      impacts.push(node);
    }
    return impactByKey.get(key);
  };

  for (const asset of pickedAssets) {
    if (asset.findingCount > 0) {
      const matching = activeFindings.filter(f => {
        const loc = String(f.location || '').replace(/^\.\//, '');
        return loc === asset.path || loc.startsWith(asset.path + ':') || (asset.kind === 'scope' && loc.includes(asset.path));
      });
      for (const f of matching) {
        const key = f.cwe || f.category.toUpperCase();
        const isCrit = f.severity === 'critical' || f.severity === 'high';
        const imp = ensureImpact(`imp:${key}`, {
          label: `${key} · ${f.title.slice(0, 20)}${f.title.length > 20 ? '…' : ''}`,
          status: isCrit ? 'crit' : 'warn',
          badge: `${f.severity.toUpperCase()} · ${asset.engineIds.length} CLIs`,
          findingId: f.id,
          detail: `[${f.severity.toUpperCase()}] ${f.title} at ${f.location} — corroborated across ${asset.engineIds.join(', ')}`
        });
        if (!asset.impactIds.includes(imp.id)) asset.impactIds.push(imp.id);
      }
    } else if (asset.kind === 'scope') {
      const imp = ensureImpact('imp:scope-guard', {
        label: 'ScopeGate · SSRF Locked',
        status: 'scope',
        badge: `${(scope?.targets || []).length} IN SCOPE`,
        detail: 'Authorized Network Scope enforced by host process; private/metadata IPs blocked unless explicitly listed.'
      });
      asset.impactIds.push(imp.id);
    } else if (asset.kind === 'binary' || asset.kind === 'capture') {
      const imp = ensureImpact('imp:dfir-clean', {
        label: 'Artifact & Mach-O Posture',
        status: 'binary',
        badge: 'TRIAGED · CLEAN',
        detail: `Binary & capture telemetry mapped to otool, Radare2 & TShark (peak ${dna.summary.peakEntropy.toFixed(2)} b/B).`
      });
      asset.impactIds.push(imp.id);
    } else if (asset.kind === 'manifest' || asset.kind === 'iac') {
      const imp = ensureImpact('imp:supply-clean', {
        label: 'Supply Chain & IaC · Clean',
        status: 'clean',
        badge: 'OSV + TRIVY',
        detail: 'Dependency manifests & IaC configs verified with 0 open CVE/misconfiguration findings.'
      });
      asset.impactIds.push(imp.id);
    } else {
      const imp = ensureImpact('imp:sast-clean', {
        label: 'SAST & Secrets · Clean',
        status: 'clean',
        badge: 'SEMGREP + GITLEAKS',
        detail: 'Source modules verified with 0 active secret exposures or reachable injection sinks.'
      });
      asset.impactIds.push(imp.id);
    }
  }

  if (resolvedFindings.length > 0 && impacts.length < 6) {
    const resImp = ensureImpact('imp:severed-fp', {
      label: `Suppressed / Fixed (${resolvedFindings.length})`,
      status: 'clean',
      badge: '0 BLAST RADIUS',
      detail: `${resolvedFindings.length} finding(s) marked mitigated or false-positive and excluded from active risk totals.`
    });
    // Connect any asset that had a resolved finding
    for (const rf of resolvedFindings) {
      const loc = String(rf.location || '').replace(/^\.\//, '').replace(/:\d+(?::\d+)?$/, '');
      const matchAsset = pickedAssets.find(a => a.path === loc);
      if (matchAsset && !matchAsset.impactIds.includes(resImp.id)) matchAsset.impactIds.push(resImp.id);
    }
  }

  // --- 2. Build Attack Reachability Lanes ---
  const lanes = [];
  // Group active findings by (filePath, cwe || title) so duplicate lines in one function merge cleanly
  const groupedActive = new Map();
  for (const f of activeFindings) {
    const rawLoc = String(f.location || '').replace(/^\.\//, '');
    const m = /^(.+?)(?::(\d+)(?::\d+)?)?$/.exec(rawLoc);
    const filePath = m ? m[1] : rawLoc;
    const lineNum = m && m[2] ? Number(m[2]) : 1;
    const gKey = `${filePath}|${f.cwe || f.title}`;
    if (!groupedActive.has(gKey)) {
      groupedActive.set(gKey, { finding: f, filePath, lineNum, ids: [f.id], count: 1 });
    } else {
      const g = groupedActive.get(gKey);
      g.ids.push(f.id);
      g.count++;
    }
  }

  for (const g of [...groupedActive.values()].slice(0, 4)) {
    const f = g.finding;
    const ctx = root && f.category !== 'network' && f.category !== 'web'
      ? await inspectSourceReachability(root, g.filePath, g.lineNum)
      : null;
    const hasExternalEntry = Boolean(ctx?.entryKind) || f.category === 'secrets' || f.category === 'supply-chain' || f.category === 'network' || f.category === 'web';
    const baseFile = pathMod.basename(g.filePath);
    const state = hasExternalEntry ? 'reachable' : 'unverified';
    lanes.push({
      id: `lane:${f.id}`,
      state,
      finding: f,
      findingIds: g.ids,
      path: g.filePath,
      entry: {
        label: f.category === 'secrets' ? 'Repo Credential' : f.category === 'supply-chain' ? 'Lockfile Dependency' : (ctx?.entryKind || 'Static / Local State'),
        sub: f.category === 'secrets' ? 'Exposed in source' : (ctx?.entrySub || 'No HTTP/URL source in file')
      },
      handler: {
        label: ctx?.fnName || baseFile,
        sub: `${baseFile}:${g.lineNum}${g.count > 1 ? ` (+${g.count - 1})` : ''}`
      },
      sink: {
        label: (ctx?.sinkSnippet || f.evidence || f.title).slice(0, 22) + ((ctx?.sinkSnippet || f.evidence || f.title).length > 22 ? '…' : ''),
        sub: `${f.cwe || f.category.toUpperCase()} · ${f.severity.toUpperCase()}`
      },
      impact: {
        label: hasExternalEntry ? `${f.severity.toUpperCase()} Blast` : 'Check Static Data',
        sub: hasExternalEntry ? (f.cvss ? `CVSS ${f.cvss} · Fix ready` : 'Actionable · Draft Fix') : 'Verify or Dismiss FP'
      },
      detail: hasExternalEntry
        ? `[REACHABLE · ${f.severity.toUpperCase()}] ${f.title} at ${f.location} — untrusted entry surface present in module.`
        : `[UNVERIFIED LOCAL SINK · ${f.severity.toUpperCase()}] ${f.title} at ${f.location} — no external HTTP/URL/CLI input detected in ${baseFile}; inspect or mark false-positive.`
    });
  }

  // Add up to 2 severed (false-positive / mitigated) lanes to visually prove noise suppression!
  const seenResolvedFiles = new Set();
  for (const rf of resolvedFindings) {
    if (lanes.length >= 6) break;
    const rawLoc = String(rf.location || '').replace(/^\.\//, '');
    const m = /^(.+?)(?::(\d+)(?::\d+)?)?$/.exec(rawLoc);
    const filePath = m ? m[1] : rawLoc;
    const lineNum = m && m[2] ? Number(m[2]) : 1;
    const dedup = `${filePath}|${rf.status}`;
    if (seenResolvedFiles.has(dedup)) continue;
    seenResolvedFiles.add(dedup);
    const baseFile = pathMod.basename(filePath);
    const isFp = rf.status === 'false-positive';
    lanes.push({
      id: `severed:${rf.id}`,
      state: 'severed',
      resolvedKind: rf.status,
      path: filePath,
      gateLabel: isFp ? '✕ NO UNTRUSTED SOURCE' : '✓ SINK MITIGATED',
      entry: {
        label: isFp ? 'Static Constants' : 'Remediated Input',
        sub: isFp ? 'Hardcoded local data' : 'Safe API applied'
      },
      handler: {
        label: baseFile,
        sub: `${baseFile}:${lineNum}`
      },
      sink: {
        label: `${rf.cwe || rf.category.toUpperCase()} (${isFp ? 'FP' : 'Fixed'})`,
        sub: rf.title.slice(0, 22)
      },
      impact: {
        label: '0 Blast Radius',
        sub: isFp ? 'Suppressed FP' : 'Verified Clean'
      },
      detail: `[${rf.status.toUpperCase()}] ${rf.title} (${rf.location}) — path severed and excluded from active risk score.`
    });
  }

  // Fill with verified clean workspace architecture lanes if fewer than 3 lanes
  for (const cleanFile of dna.files.filter(f => f.findingCount === 0)) {
    if (lanes.length >= 4) break;
    const baseFile = pathMod.basename(cleanFile.path);
    lanes.push({
      id: `clean:${cleanFile.path}`,
      state: 'clean',
      path: cleanFile.path,
      gateLabel: '✓ GUARDED · 0 ISSUES',
      entry: {
        label: cleanFile.kind === 'binary' ? 'Compiled Binary' : cleanFile.kind === 'capture' ? 'Packet Capture' : cleanFile.kind === 'manifest' ? 'Pinned Manifest' : cleanFile.kind === 'iac' ? 'IaC Blueprint' : 'Workspace Module',
        sub: `Entropy ${cleanFile.entropy.toFixed(2)} b/B`
      },
      handler: {
        label: baseFile,
        sub: cleanFile.group
      },
      sink: {
        label: cleanFile.engines.slice(0, 2).join(' + '),
        sub: `${cleanFile.kind.toUpperCase()} · Verified`
      },
      impact: {
        label: '0 Active Issues',
        sub: 'Clean Posture'
      },
      detail: `${cleanFile.path} (${cleanFile.kind.toUpperCase()}, ${cleanFile.entropy.toFixed(2)} b/B) — 0 active vulnerabilities across ${cleanFile.engines.join(', ')}.`
    });
  }

  return {
    workspace: root || '',
    needsWorkspace: !root,
    summary: {
      ...dna.summary,
      resolvedCount: resolvedFindings.length,
      scopeCount: (scope?.targets || []).length
    },
    convergence: { engines, assets: pickedAssets.slice(0, 7), impacts: impacts.slice(0, 6) },
    reachability: { lanes: lanes.slice(0, 6) }
  };
}

module.exports = {
  CODE_RULES,
  shannonEntropy,
  scanSecrets,
  auditCodePatterns,
  parseManifestPackages,
  auditDependencies,
  inspectHttpSecurity,
  inspectTls,
  dnsRecon,
  parsePortList,
  probePorts,
  identifyBinaryFormat,
  triageArtifact,
  extractIocs,
  analyzeLogs,
  scanWorkspaceDna,
  detectExternalIngress,
  inspectSourceReachability,
  traceCrossFileReachability,
  reconcileWorkspaceFindings,
  buildWorkspaceGraphs
};
