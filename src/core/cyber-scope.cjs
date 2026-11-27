const dns = require('node:dns/promises');
const net = require('node:net');

const DEFAULT_SCOPE = Object.freeze({ targets: [], allowOsv: true, redactContext: true });
const HOSTNAME_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

function parseIpv4(ip) {
  if (typeof ip !== 'string' || !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip)) return null;
  const parts = ip.split('.');
  let value = 0;
  for (const part of parts) {
    if (part.length > 1 && part.startsWith('0')) return null;
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return null;
    value = ((value << 8) | octet) >>> 0;
  }
  return value;
}

function expandIpv6(ip) {
  let addr = ip.toLowerCase();
  const zone = addr.indexOf('%');
  if (zone !== -1) addr = addr.slice(0, zone);
  if (addr.includes('.')) {
    const lastColon = addr.lastIndexOf(':');
    const v4 = parseIpv4(addr.slice(lastColon + 1));
    if (v4 === null) return null;
    addr = `${addr.slice(0, lastColon)}:${((v4 >>> 16) & 0xffff).toString(16)}:${(v4 & 0xffff).toString(16)}`;
  }
  const halves = addr.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = halves.length === 2 ? 8 - (left.length + right.length) : 0;
  if ((halves.length === 1 && left.length !== 8) || missing < 0) return null;
  const groups = [...left, ...Array(missing).fill('0'), ...right].map(g => parseInt(g, 16));
  return groups.length === 8 && groups.every(n => Number.isInteger(n) && n >= 0 && n <= 0xffff) ? groups : null;
}

function isPrivateOrReservedIpv4(num) {
  const a = (num >>> 24) & 0xff, b = (num >>> 16) & 0xff, c = (num >>> 8) & 0xff;
  return a === 0 || a === 10 || a === 127 ||
    (a === 100 && (b & 0xc0) === 64) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && (c === 0 || c === 2)) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
    (a === 203 && b === 0 && c === 113) ||
    a >= 224;
}

function isPrivateOrReservedIp(ip) {
  if (typeof ip !== 'string') return true;
  const v4 = parseIpv4(ip);
  if (v4 !== null) return isPrivateOrReservedIpv4(v4);
  if (net.isIP(ip) !== 6) return true;
  const g = expandIpv6(ip);
  if (!g) return true;
  const allZero = g.slice(0, 5).every(x => x === 0);
  if (allZero && g[5] === 0xffff) return isPrivateOrReservedIpv4(((g[6] << 16) | g[7]) >>> 0);
  if (allZero && g[5] === 0 && g[6] === 0 && (g[7] === 0 || g[7] === 1)) return true;
  if ((g[0] & 0xfe00) === 0xfc00) return true;
  if ((g[0] & 0xffc0) === 0xfe80) return true;
  if ((g[0] & 0xff00) === 0xff00) return true;
  if (g[0] === 0x2001 && g[1] === 0x0db8) return true;
  return false;
}

function parsePort(value) {
  if (value === null || value === undefined || value === '') return null;
  if (!/^\d{1,5}$/.test(String(value))) throw new Error(`Invalid port "${value}".`);
  const port = Number(value);
  if (port < 1 || port > 65535) throw new Error(`Port ${port} is out of range (1-65535).`);
  return port;
}

function splitHostPort(text) {
  if (text.startsWith('[')) {
    const end = text.indexOf(']');
    if (end === -1) throw new Error(`Invalid IPv6 host "${text}".`);
    const host = text.slice(1, end);
    const rest = text.slice(end + 1);
    if (!rest) return { host, port: null };
    if (!rest.startsWith(':')) throw new Error(`Invalid host "${text}".`);
    return { host, port: parsePort(rest.slice(1)) };
  }
  const firstColon = text.indexOf(':'), lastColon = text.lastIndexOf(':');
  if (firstColon !== -1 && firstColon === lastColon) {
    return { host: text.slice(0, firstColon), port: parsePort(text.slice(firstColon + 1)) };
  }
  return { host: text, port: null };
}

function parseScopeEntry(entry) {
  if (typeof entry !== 'string') throw new Error('Scope entry must be text.');
  const raw = entry.trim();
  if (!raw || raw.length > 320 || /[\0\r\n\s]/.test(raw)) throw new Error('Each scope entry must be a single hostname, wildcard (*.example.com), URL, IP, or IPv4 CIDR.');
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) {
    let parsed;
    try { parsed = new URL(raw); } catch { throw new Error(`Invalid scope URL "${raw}".`); }
    if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Scope URLs must use http:// or https://.');
    if (parsed.username || parsed.password) throw new Error('Scope URLs must not include credentials.');
    const host = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    const port = parsed.port ? parsePort(parsed.port) : (parsed.protocol === 'https:' ? 443 : 80);
    if (parseIpv4(host) !== null || net.isIP(host) === 6) return { kind: 'ip', raw, ip: host, port, protocol: parsed.protocol };
    if (!HOSTNAME_RE.test(host)) throw new Error(`Invalid hostname in scope URL "${raw}".`);
    return { kind: 'host', raw, host, port, protocol: parsed.protocol };
  }
  if (raw.includes('/')) {
    const [ipPart, prefixPart, extra] = raw.split('/');
    if (extra !== undefined || !/^\d{1,2}$/.test(prefixPart)) throw new Error(`Invalid CIDR "${raw}". Use IPv4 CIDR notation such as 192.168.1.0/24.`);
    const ipNum = parseIpv4(ipPart), prefix = Number(prefixPart);
    if (ipNum === null || prefix < 8 || prefix > 32) throw new Error(`CIDR "${raw}" must be a valid IPv4 network with prefix /8 to /32.`);
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return { kind: 'cidr4', raw, base: (ipNum & mask) >>> 0, mask, prefix, port: null, protocol: null };
  }
  if (raw.startsWith('*.')) {
    const { host, port } = splitHostPort(raw.slice(2));
    const suffix = host.toLowerCase();
    if (!suffix.includes('.') || !HOSTNAME_RE.test(suffix) || parseIpv4(suffix) !== null) throw new Error(`Wildcard scope "${raw}" must include a registrable domain such as *.example.com.`);
    return { kind: 'wildcard', raw, suffix, port };
  }
  const { host, port } = splitHostPort(raw);
  const lower = host.toLowerCase();
  if (parseIpv4(lower) !== null || net.isIP(lower) === 6) return { kind: 'ip', raw, ip: lower, port, protocol: null };
  if (/^\d+$/.test(lower) || (/^[\d.]+$/.test(lower) && parseIpv4(lower) === null)) throw new Error(`Invalid IPv4 address "${raw}".`);
  if (!HOSTNAME_RE.test(lower)) throw new Error(`Invalid scope host "${raw}".`);
  return { kind: 'host', raw, host: lower, port, protocol: null };
}

function parseScopeRules(targets = []) {
  if (!Array.isArray(targets) || targets.length > 100) throw new Error('Authorized scope supports up to 100 entries.');
  return targets.map(parseScopeEntry);
}

function validateScopeConfig(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Invalid scope configuration.');
  const rawTargets = Array.isArray(input.targets) ? input.targets : [];
  const seen = new Set(), targets = [];
  for (const item of rawTargets) {
    if (typeof item !== 'string') throw new Error('Scope targets must be strings.');
    const trimmed = item.trim();
    if (!trimmed) continue;
    parseScopeEntry(trimmed);
    const key = trimmed.toLowerCase();
    if (!seen.has(key)) { seen.add(key); targets.push(trimmed); }
  }
  if (targets.length > 100) throw new Error('Authorized scope supports up to 100 entries.');
  return {
    targets,
    allowOsv: input.allowOsv !== undefined ? Boolean(input.allowOsv) : true,
    redactContext: input.redactContext !== undefined ? Boolean(input.redactContext) : true
  };
}

function parseTargetEndpoint(rawTarget, { defaultPort = null, requireUrl = false } = {}) {
  if (typeof rawTarget !== 'string' || !rawTarget.trim() || rawTarget.length > 2048 || /[\0\r\n\s]/.test(rawTarget.trim())) {
    throw new Error('Provide a valid target URL, hostname, or IP address.');
  }
  const trimmed = rawTarget.trim();
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    let parsed;
    try { parsed = new URL(trimmed); } catch { throw new Error(`Invalid target URL "${trimmed}".`); }
    if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Only http:// and https:// URLs are supported.');
    if (parsed.username || parsed.password) throw new Error('Target URLs must not embed credentials.');
    const host = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    if ((/^[\d.]+$/.test(host) && parseIpv4(host) === null) || (!net.isIP(host) && !HOSTNAME_RE.test(host))) throw new Error(`Invalid target host "${host}".`);
    const port = parsed.port ? parsePort(parsed.port) : (parsed.protocol === 'https:' ? 443 : 80);
    return { host, port, protocol: parsed.protocol, url: parsed.toString() };
  }
  if (requireUrl) throw new Error(`Provide a full http:// or https:// URL such as "https://${trimmed}".`);
  if (trimmed.includes('/') || trimmed.includes('@') || trimmed.includes('?')) throw new Error('Provide a hostname or host:port (or a full https:// URL).');
  const { host: rawHost, port } = splitHostPort(trimmed);
  const host = rawHost.toLowerCase();
  if ((/^[\d.]+$/.test(host) && parseIpv4(host) === null) || (!net.isIP(host) && !HOSTNAME_RE.test(host))) throw new Error(`Invalid target host "${host}".`);
  return { host, port: port ?? defaultPort, protocol: null, url: null };
}

function ipExplicitlyAuthorized(ip, port, rules) {
  const v4 = parseIpv4(ip);
  const normIp = ip.toLowerCase();
  for (const rule of rules) {
    if (rule.kind === 'ip' && rule.ip === normIp && (rule.port === null || port === null || rule.port === port)) return true;
    if (rule.kind === 'cidr4' && v4 !== null && ((v4 & rule.mask) >>> 0) === rule.base) return true;
    if (rule.kind === 'host' && rule.host === 'localhost' && (normIp === '127.0.0.1' || normIp === '::1') && (rule.port === null || port === null || rule.port === port)) return true;
  }
  return false;
}

function matchesRule(endpoint, rule) {
  if (rule.protocol && endpoint.protocol && rule.protocol !== endpoint.protocol) return false;
  if (rule.port != null && endpoint.port != null && rule.port !== endpoint.port) return false;
  if (rule.kind === 'host') return endpoint.host === rule.host;
  if (rule.kind === 'wildcard') return endpoint.host.endsWith('.' + rule.suffix) && endpoint.host !== rule.suffix;
  if (rule.kind === 'ip') return endpoint.host === rule.ip;
  if (rule.kind === 'cidr4') {
    const v4 = parseIpv4(endpoint.host);
    return v4 !== null && ((v4 & rule.mask) >>> 0) === rule.base;
  }
  return false;
}

function checkTargetScopeSync(rawTarget, scopeConfig = DEFAULT_SCOPE, options = {}) {
  const endpoint = parseTargetEndpoint(rawTarget, options);
  const rules = parseScopeRules(scopeConfig?.targets || []);
  if (!rules.length) {
    throw new Error(`Target "${endpoint.host}" is blocked: Authorized Scope is empty. Ask the user to add "${endpoint.host}" in Scope & Security Tools before probing external or local network targets.`);
  }
  if (!rules.some(rule => matchesRule(endpoint, rule))) {
    throw new Error(`Target "${endpoint.host}${endpoint.port ? ':' + endpoint.port : ''}" is outside Authorized Scope (${(scopeConfig.targets || []).join(', ')}). Do not probe out-of-scope hosts.`);
  }
  return { endpoint, rules };
}

async function assertTargetInScope(rawTarget, scopeConfig = DEFAULT_SCOPE, { dnsLookup = dns.lookup, defaultPort = null, requireUrl = false } = {}) {
  const { endpoint, rules } = checkTargetScopeSync(rawTarget, scopeConfig, { defaultPort, requireUrl });
  if (parseIpv4(endpoint.host) !== null || net.isIP(endpoint.host) === 6) {
    return { ...endpoint, addresses: [endpoint.host] };
  }
  let resolved;
  try {
    resolved = await dnsLookup(endpoint.host, { all: true, verbatim: true });
  } catch (error) {
    throw new Error(`Could not resolve in-scope host "${endpoint.host}": ${error.code || error.message}`);
  }
  const list = (Array.isArray(resolved) ? resolved : [resolved]).map(item => typeof item === 'string' ? item : item?.address).filter(Boolean);
  if (!list.length) throw new Error(`Host "${endpoint.host}" returned no DNS addresses.`);
  for (const address of list) {
    if (isPrivateOrReservedIp(address) && !ipExplicitlyAuthorized(address, endpoint.port, rules)) {
      throw new Error(`Blocked by SSRF / DNS-rebinding guard: "${endpoint.host}" resolved to private or reserved IP ${address}, which is not explicitly listed in Authorized Scope.`);
    }
  }
  return { ...endpoint, addresses: [...new Set(list)] };
}

function maskToken(token) {
  if (token.length <= 10) return '[REDACTED]';
  return `${token.slice(0, 4)}…[REDACTED]…${token.slice(-3)}`;
}

const SECRET_RULES = [
  { id: 'private-key', label: 'PEM Private Key', cwe: 'CWE-798', severity: 'critical', regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]{16,8192}?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g, replace: () => '-----BEGIN PRIVATE KEY-----[REDACTED]-----END PRIVATE KEY-----' },
  { id: 'aws-access-key', label: 'AWS Access Key ID', cwe: 'CWE-798', severity: 'high', regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, replace: m => maskToken(m) },
  { id: 'github-token', label: 'GitHub Personal Access Token', cwe: 'CWE-798', severity: 'critical', regex: /\b(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g, replace: m => maskToken(m) },
  { id: 'ai-api-key', label: 'AI Provider API Key', cwe: 'CWE-798', severity: 'critical', regex: /\bsk-(?:proj-|ant-|live-)?[A-Za-z0-9_-]{20,255}\b/g, replace: m => maskToken(m) },
  { id: 'slack-token', label: 'Slack Token', cwe: 'CWE-798', severity: 'high', regex: /\bxox[baprs]-[0-9A-Za-z-]{12,255}\b/g, replace: m => maskToken(m) },
  { id: 'stripe-key', label: 'Stripe Secret Key', cwe: 'CWE-798', severity: 'critical', regex: /\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,255}\b/g, replace: m => maskToken(m) },
  { id: 'google-api-key', label: 'Google API Key', cwe: 'CWE-798', severity: 'medium', regex: /\bAIza[0-9A-Za-z_-]{35}\b/g, replace: m => maskToken(m) },
  { id: 'jwt-token', label: 'JSON Web Token', cwe: 'CWE-522', severity: 'medium', regex: /\beyJ[A-Za-z0-9_-]{10,500}\.eyJ[A-Za-z0-9_-]{10,1000}\.[A-Za-z0-9_-]{10,500}\b/g, replace: m => `${m.slice(0, 8)}…[REDACTED_JWT]` },
  {
    id: 'auth-header', label: 'Authorization Credential', cwe: 'CWE-522', severity: 'high',
    regex: /\b(Authorization\s*:\s*(?:Bearer|Basic|Token)\s+)([^\s"',;]{8,500})/gi,
    filter: (_m, _pre, secret) => !secret.includes('[REDACTED]') &&
      !/^[\$<{]|%[sA-Z]|\{\{/.test(secret) &&
      !/^(?:demo[-_]?|test[-_]?|dev[-_]?|local[-_]?|fake[-_]?|dummy[-_]?|sample[-_]?|example[-_]?|changeme|placeholder|token|secret|bearer|my[-_]?token|your[-_]?token|xxx+|\*+)/i.test(secret),
    replace: (_m, prefix, secret) => `${prefix}${maskToken(secret)}`
  },
  {
    id: 'url-credentials', label: 'URL Embedded Password', cwe: 'CWE-522', severity: 'high',
    regex: /\b([a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:)([^@\s/'"]{4,200})(@[^\s/'"]*)/gi,
    filter: (full, _pre, pw) => !pw.includes('[REDACTED]') &&
      !/^(?:password|passwd|pass|secret|token|changeme|example|bar|user|admin|xxx+|\*+|1234\d*|<[^>]*>|\{[^}]*\}|\$\{[^}]*\})$/i.test(pw) &&
      !/@(?:example\.(?:com|org|net)|host(?::|\/|$)|hostname\b)/i.test(full),
    replace: (_m, pre, _pw, post) => `${pre}[REDACTED]${post}`
  },
  {
    id: 'generic-secret-assignment', label: 'Hardcoded Secret Assignment', cwe: 'CWE-798', severity: 'high',
    regex: /\b((?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|password|passwd)\s*[:=]\s*['"])([^'"\r\n]{8,256})(['"])/gi,
    filter: (_m, _pre, value) => !value.includes('[REDACTED]') && !/^(?:changeme|password|example|placeholder|your[_-]|dev(?:elopment)?[-_\s]+(?:key|secret|token|pass(?:word)?)|(?:demo|test|dummy|fake|sample|local)[-_]|<|{\s*{|\$\{|REDACTED|\*+)/i.test(value.trim()),
    replace: (_m, pre, value, post) => `${pre}${maskToken(value)}${post}`
  }
];

function redactSecrets(text) {
  if (typeof text !== 'string' || !text) return { text: '', count: 0, types: [] };
  let output = text, count = 0;
  const types = new Set();
  for (const rule of SECRET_RULES) {
    output = output.replace(rule.regex, (...args) => {
      if (rule.filter && !rule.filter(...args)) return args[0];
      count++;
      types.add(rule.label);
      return rule.replace(...args);
    });
  }
  return { text: output, count, types: [...types] };
}

module.exports = {
  DEFAULT_SCOPE,
  SECRET_RULES,
  maskToken,
  parseIpv4,
  isPrivateOrReservedIp,
  parseScopeRules,
  validateScopeConfig,
  parseTargetEndpoint,
  checkTargetScopeSync,
  assertTargetInScope,
  redactSecrets
};
