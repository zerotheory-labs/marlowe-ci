const DOC_FILE_RE = /\.(?:md|mdx|rst|txt)$/i;
const TEST_FILE_RE = /(?:^|\/)(?:tests?|__tests__|benchmarks?)\/|\.(?:test|spec)\.[cm]?[jt]sx?$|_test\.go$|test_[^/]+\.py$/i;
const COMMENT_OR_RULE_RE = /^(?:\/\/|\/\*|\*|\s*(?:const|let|var)\s+[A-Z0-9_]+_RE\s*=|\s*(?:regex|re|remediation|title|message|summary)\s*:)/;

const PUBLIC_SOURCEMAP_PATH_RE = /(?:^|\/)(?:public|static|dist|build|www|assets)\/[^/]*\.(?:[cm]?js)\.map$/i;
const BUNDLER_CONFIG_RE = /(?:^|\/)(?:(?:vite|next|webpack|nuxt|svelte|rollup|esbuild)\.config\.[cm]?[jt]s|angular\.json)$/i;
const SOURCEMAP_ENABLE_RE = /\bproductionBrowserSourceMaps\s*:\s*true\b|\bsourcemap\s*:\s*true\b|\bdevtool\s*:\s*['"](?:source-map|inline-source-map|eval-source-map)['"]/i;
const DEV_ONLY_GUARD_RE = /\b(?:NODE_ENV|isDev|isDevelopment|development|devOnly|mode\s*!==\s*['"]production['"])\b/i;

const GRAPHQL_INTROSPECT_RE = /\bintrospection\s*:\s*true\b/;
const SPEC_DEBUG_ROUTE_RE = /(?:\b(?:app|router)\s*\.\s*(?:use|get)\s*\(\s*['"]\/(?:api-docs|swagger(?:-ui)?|openapi\.json|__debug__|debug\/pprof|actuator)\b|\bswaggerUi\.serve\b)/i;
const EDGE_AUTH_OR_DEV_GUARD_RE = /\b(?:requireAuth|authenticate|authorize|isAdmin|basicAuth|verifyToken|jwtAuth|NODE_ENV|isDev|isDevelopment|development|devOnly)\b/i;
const ACTUATOR_EXPOSE_RE = /management\.endpoints\.web\.exposure\.include\s*[:=]\s*['"]?(?:\*|[^'"\n]*\b(?:env|heapdump|beans|mappings)\b)/i;

const OAUTH_FILE_HINT_RE = /\b(?:oauth|oidc|passport|callback|authorize|idp)\b/i;
const OAUTH_STATE_DISABLE_RE = /\b(?:skipStateCheck|disableStateCheck)\s*:\s*true\b|\b(?:state|verifyState|checkState)\s*:\s*false\b/i;
const OPEN_REDIRECT_RE = /\bres\.redirect\s*\(\s*(?:req\.(?:query|body|params)\.(?:redirect|redirect_uri|returnTo|next|callback|continue)|redirect_uri|returnTo)\b/;
const REDIRECT_ALLOWLIST_RE = /\b(?:ALLOWED_|allowlist|isSafeRedirect|safeRedirect|startsWith\s*\(\s*['"]\/['"]\s*\)|new\s+URL\s*\()/;

const CORS_CREDENTIALS_TRUE_RE = /\bcredentials\s*:\s*true\b/;
const CORS_WILDCARD_ORIGIN_RE = /\borigin\s*:\s*(?:true|['"]\*['"])\b/;
const CORS_HEADER_WILDCARD_RE = /Access-Control-Allow-Origin['"]?\s*[:,]\s*(?:['"]\*['"]|req\.headers\.origin)/i;
const CORS_HEADER_CREDS_RE = /Access-Control-Allow-Credentials['"]?\s*[:,]\s*['"]?true\b/i;
const RESET_TOKEN_WEAK_RE = /\b(?:resetToken|recoveryToken|magicLinkToken|oauthState|inviteToken)\w*\s*[:=][^\n]{0,80}(?:Date\.now\s*\(|Math\.random\s*\(|createHash\s*\(\s*['"](?:md5|sha1)['"])/i;

const PERIPHERAL_ROUTE_RE = /\b(?:app|router)\s*\.\s*(?:get|post|put|patch|delete|use)\s*\(\s*['"]\/(?:admin|internal|backup|export|webhook|impersonate|tenant)\b/i;
const PERIPHERAL_UNAUTH_ROUTE_RE = /\b(?:app|router)\s*\.\s*(?:get|post|put|patch|delete)\s*\(\s*['"]\/(?:admin|internal|backup|export|impersonate|webhook)\b/i;
const EXPLICIT_AUTH_BYPASS_RE = /\b(?:skipAuth|allowUnauthenticated)\s*:\s*true\b|\b(?:verifySignature|requireAuth|auth)\s*:\s*false\b/i;
const AUTH_OR_SIG_HINT_RE = /\b(?:requireAuth|authenticate|authorize|verifyToken|verifySignature|timingSafeEqual|createHmac|isAdmin|jwt|session|basicAuth|x-signature|stripe-signature|apiKey)\b/i;

const STATIC_ASSET_EXT_RE = /\.(?:css|png|jpe?g|gif|svg|ico|woff2?|ttf|webp)(?:\?|$)/i;
const RECON_PATH_RE = /\.js\.map(?:\?|$)|\/(?:openapi\.json|swagger(?:\.json|-ui)?|api-docs|graphql(?:\?[^\s]*__schema)?|\.well-known\/openid-configuration|actuator\/(?:env|beans|mappings))/i;
const AUTH_PIVOT_PATH_RE = /\/(?:oauth|auth|login|token|reset-password|forgot-password|password-reset|admin|backup|impersonate|api\/v\d+\/(?:users|tokens|keys|admin))\b/i;

const HTTP_REQ_RE = /"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s"]+)[^"]*"\s+(\d{3})\b/;
const JSON_METHOD_RE = /"(?:method|httpMethod)"\s*:\s*"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)"/i;
const JSON_PATH_RE = /"(?:path|url|uri|endpoint)"\s*:\s*"([^"]+)"/i;
const JSON_STATUS_RE = /"(?:status|statusCode|code)"\s*:\s*(\d{3})\b/i;
const JSON_TS_RE = /"(?:ts|timestamp|time|createdAt)"\s*:\s*"([^"]+)"/i;
const JSON_IP_RE = /"(?:ip|clientIp|remoteAddr|srcIp)"\s*:\s*"([^"]+)"/i;
const JSON_UA_RE = /"(?:ua|userAgent|user_agent)"\s*:\s*"([^"]+)"/i;
const ISO_TS_RE = /\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b/;
const CLF_TS_RE = /\[(\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]/;
const IPV4_EXTRACT_RE = /\b((?:\d{1,3}\.){3}\d{1,3})\b/;
const ERROR_STATUS_SET = new Set([400, 401, 403, 404, 422]);
const SUCCESS_STATUS_SET = new Set([200, 201, 204, 302]);

function isCommentOrRuleLine(raw) {
  const trimmed = String(raw || '').trim();
  if (!trimmed) return true;
  if (COMMENT_OR_RULE_RE.test(trimmed)) return true;
  if (trimmed.startsWith('#') && !trimmed.startsWith('#!')) return true;
  return false;
}

function normalizePath(p) {
  return String(p || '').replace(/\\/g, '/').replace(/^\.\//, '');
}

function scanArtexEdgeSurface(relPath, text, { allowedLines = null } = {}) {
  const norm = normalizePath(relPath);
  const findings = [];
  const cantTellReasons = [];
  if (!norm || DOC_FILE_RE.test(norm) || TEST_FILE_RE.test(norm)) {
    return { findings, cantTellReasons };
  }

  if (PUBLIC_SOURCEMAP_PATH_RE.test(norm)) {
    cantTellReasons.push({
      code: 'ARTEX-EDGE-001',
      path: norm,
      line: 1,
      message: `Public JS source map "${norm}" is under a web-served path; verify .map artifacts are stripped before production deploy to deny ARTEX source/route harvesting.`
    });
    return { findings, cantTellReasons };
  }

  const lines = String(text || '').split(/\r?\n/);
  const fullText = lines.join('\n');
  const isBundlerCfg = BUNDLER_CONFIG_RE.test(norm);
  const hasOauthHint = OAUTH_FILE_HINT_RE.test(`${norm}\n${fullText}`);
  const hasFileCorsCreds = CORS_HEADER_CREDS_RE.test(fullText);
  const hasFileAuthHint = AUTH_OR_SIG_HINT_RE.test(fullText);

  const windowHas = (idx, before, after, re) => {
    const start = Math.max(0, idx - before);
    const end = Math.min(lines.length - 1, idx + after);
    for (let j = start; j <= end; j++) {
      if (re.test(lines[j])) return true;
    }
    return false;
  };

  for (let i = 0; i < lines.length; i++) {
    const lineNum = i + 1;
    if (allowedLines && !allowedLines.has(lineNum)) continue;
    const raw = lines[i].replace(/\r$/, '');
    const trimmed = raw.trim();
    if (!trimmed || raw.length > 2000 || isCommentOrRuleLine(trimmed)) continue;

    // ARTEX-EDGE-001: Bundler production sourcemaps without dev-only guard
    if (isBundlerCfg && SOURCEMAP_ENABLE_RE.test(raw) && !windowHas(i, 2, 0, DEV_ONLY_GUARD_RE)) {
      cantTellReasons.push({
        code: 'ARTEX-EDGE-001',
        path: norm,
        line: lineNum,
        message: `Source map generation enabled in "${norm}:${lineNum}" without a production/dev guard; confirm .map files are blocked in production.`
      });
    }

    // ARTEX-EDGE-001: GraphQL introspection enabled without dev guard
    if (GRAPHQL_INTROSPECT_RE.test(raw) && !windowHas(i, 2, 0, DEV_ONLY_GUARD_RE)) {
      findings.push({
        ruleId: 'ARTEX-EDGE-001',
        title: 'GraphQL schema introspection enabled without production guard',
        severity: 'high',
        category: 'config',
        cwe: 'CWE-200',
        reachability: 'reachable',
        location: `${norm}:${lineNum}`,
        evidence: trimmed.slice(0, 220),
        remediation: 'Disable GraphQL introspection outside development (introspection: process.env.NODE_ENV !== "production") to block schema harvesting.'
      });
    }

    // ARTEX-EDGE-001: Unauthenticated Swagger / OpenAPI / debug route
    if (SPEC_DEBUG_ROUTE_RE.test(raw) && !windowHas(i, 3, 3, EDGE_AUTH_OR_DEV_GUARD_RE)) {
      findings.push({
        ruleId: 'ARTEX-EDGE-001',
        title: 'Unauthenticated API spec or debug endpoint exposed (ARTEX recon surface)',
        severity: 'high',
        category: 'config',
        cwe: 'CWE-200',
        reachability: 'reachable',
        location: `${norm}:${lineNum}`,
        evidence: trimmed.slice(0, 220),
        remediation: 'Gate Swagger/OpenAPI docs and debug/actuator endpoints behind admin authentication or non-production environment checks.'
      });
    }

    // ARTEX-EDGE-001: Spring Actuator wildcard or sensitive endpoints
    if (ACTUATOR_EXPOSE_RE.test(raw)) {
      findings.push({
        ruleId: 'ARTEX-EDGE-001',
        title: 'Sensitive Spring Actuator endpoints exposed over HTTP',
        severity: 'high',
        category: 'config',
        cwe: 'CWE-200',
        reachability: 'reachable',
        location: `${norm}:${lineNum}`,
        evidence: trimmed.slice(0, 220),
        remediation: 'Restrict management.endpoints.web.exposure.include to health,info and require authentication for operational actuator endpoints.'
      });
    }

    // ARTEX-EDGE-002: OAuth/OIDC CSRF state validation disabled
    if (hasOauthHint && OAUTH_STATE_DISABLE_RE.test(raw)) {
      findings.push({
        ruleId: 'ARTEX-EDGE-002',
        title: 'OAuth/OIDC CSRF state validation disabled',
        severity: 'high',
        category: 'appsec',
        cwe: 'CWE-352',
        reachability: 'reachable',
        location: `${norm}:${lineNum}`,
        evidence: trimmed.slice(0, 220),
        remediation: 'Enforce cryptographically random OAuth state verification on every authorization callback.'
      });
    }

    // ARTEX-EDGE-002: Unvalidated open redirect in auth/OAuth flow
    if (OPEN_REDIRECT_RE.test(raw) && !windowHas(i, 4, 0, REDIRECT_ALLOWLIST_RE)) {
      findings.push({
        ruleId: 'ARTEX-EDGE-002',
        title: 'Unvalidated redirect target in auth/OAuth flow (open redirect)',
        severity: 'high',
        category: 'appsec',
        cwe: 'CWE-601',
        reachability: 'reachable',
        location: `${norm}:${lineNum}`,
        evidence: trimmed.slice(0, 220),
        remediation: 'Validate redirect/returnTo destinations against an explicit relative-path or allowlisted-origin check before redirecting.'
      });
    }

    // ARTEX-EDGE-002: Credentialed wildcard or reflected-origin CORS
    const hasWindowWildcardCors =
      (CORS_CREDENTIALS_TRUE_RE.test(raw) && windowHas(i, 4, 4, CORS_WILDCARD_ORIGIN_RE)) ||
      (CORS_HEADER_WILDCARD_RE.test(raw) && hasFileCorsCreds);
    if (hasWindowWildcardCors) {
      findings.push({
        ruleId: 'ARTEX-EDGE-002',
        title: 'Credentialed wildcard or reflected-origin CORS exposes authenticated APIs',
        severity: 'high',
        category: 'config',
        cwe: 'CWE-942',
        reachability: 'reachable',
        location: `${norm}:${lineNum}`,
        evidence: trimmed.slice(0, 220),
        remediation: 'Never pair credentialed cookies with wildcard or reflected origins; restrict CORS to an explicit origin allowlist.'
      });
    }

    // ARTEX-EDGE-002: Predictable password-reset or OAuth state token
    if (RESET_TOKEN_WEAK_RE.test(raw)) {
      findings.push({
        ruleId: 'ARTEX-EDGE-002',
        title: 'Predictable password-reset or OAuth state token generator',
        severity: 'high',
        category: 'crypto',
        cwe: 'CWE-330',
        reachability: 'reachable',
        location: `${norm}:${lineNum}`,
        evidence: trimmed.slice(0, 220),
        remediation: 'Generate reset, magic-link, and OAuth state tokens with crypto.randomBytes(32) / CSPRNG.'
      });
    }

    // ARTEX-EDGE-003: Explicit auth/signature bypass on operational endpoint
    const nearPeripheral = PERIPHERAL_ROUTE_RE.test(raw) || windowHas(i, 3, 3, PERIPHERAL_ROUTE_RE);
    if (nearPeripheral && EXPLICIT_AUTH_BYPASS_RE.test(raw)) {
      findings.push({
        ruleId: 'ARTEX-EDGE-003',
        title: 'Authentication or webhook signature verification explicitly disabled on sensitive endpoint',
        severity: 'high',
        category: 'appsec',
        cwe: 'CWE-306',
        reachability: 'reachable',
        location: `${norm}:${lineNum}`,
        evidence: trimmed.slice(0, 220),
        remediation: 'Require authenticated admin authorization and HMAC signature validation on backup, export, impersonation, and webhook handlers.'
      });
    } else if (PERIPHERAL_UNAUTH_ROUTE_RE.test(raw) && !hasFileAuthHint) {
      cantTellReasons.push({
        code: 'ARTEX-EDGE-003',
        path: norm,
        line: lineNum,
        message: `Peripheral admin/backup/webhook route at ${norm}:${lineNum} shows no auth or signature check in file; verify access control before exposing.`
      });
    }
  }

  return { findings, cantTellReasons };
}

function parseClfTimestampMs(raw) {
  const m = /^(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{4})$/.exec(raw);
  if (!m) return null;
  const parsed = Date.parse(`${m[1]} ${m[2]} ${m[3]} ${m[4]}:${m[5]}:${m[6]} GMT${m[7]}`);
  return Number.isFinite(parsed) ? parsed : null;
}

function parseHttpEvent(lineText, lineNum) {
  const s = String(lineText || '');
  let method = '';
  let reqPath = '';
  let status = null;
  let tsMs = null;
  let ip = '';
  let ua = '';

  const httpM = HTTP_REQ_RE.exec(s);
  if (httpM) {
    method = httpM[1].toUpperCase();
    reqPath = httpM[2];
    status = Number(httpM[3]);
  } else if (s.startsWith('{')) {
    const pm = JSON_PATH_RE.exec(s);
    const sm = JSON_STATUS_RE.exec(s);
    if (pm && sm) {
      reqPath = pm[1];
      status = Number(sm[1]);
      method = JSON_METHOD_RE.exec(s)?.[1]?.toUpperCase() || 'GET';
      const tsField = JSON_TS_RE.exec(s)?.[1];
      if (tsField) {
        const parsed = Date.parse(tsField);
        if (Number.isFinite(parsed)) tsMs = parsed;
      }
      ip = JSON_IP_RE.exec(s)?.[1] || '';
      ua = JSON_UA_RE.exec(s)?.[1] || '';
    }
  }

  if (!reqPath || !Number.isFinite(status)) return null;

  if (tsMs === null) {
    const iso = ISO_TS_RE.exec(s)?.[1];
    if (iso) {
      const parsed = Date.parse(iso);
      if (Number.isFinite(parsed)) tsMs = parsed;
    } else {
      const clf = CLF_TS_RE.exec(s)?.[1];
      if (clf) tsMs = parseClfTimestampMs(clf);
    }
  }
  if (!ip) {
    ip = IPV4_EXTRACT_RE.exec(s)?.[1] || '';
  }

  return {
    line: lineNum,
    tsMs,
    ip,
    method,
    path: reqPath,
    status,
    ua,
    isStaticAsset: STATIC_ASSET_EXT_RE.test(reqPath),
    isReconPath: RECON_PATH_RE.test(reqPath),
    isAuthPivotPath: AUTH_PIVOT_PATH_RE.test(reqPath)
  };
}

function computeMedian(sortedNums) {
  if (!sortedNums.length) return null;
  const mid = Math.floor(sortedNums.length / 2);
  return sortedNums.length % 2 === 0
    ? Math.round(((sortedNums[mid - 1] + sortedNums[mid]) / 2) * 100) / 100
    : Math.round(sortedNums[mid] * 100) / 100;
}

function analyzeAgenticBehavior(lineEntries = [], relPath = '') {
  const events = [];
  for (let i = 0; i < lineEntries.length; i++) {
    const entry = lineEntries[i];
    const lineNum = typeof entry === 'object' ? entry.line : i + 1;
    const text = typeof entry === 'object' ? entry.text : String(entry || '');
    const ev = parseHttpEvent(text, lineNum);
    if (ev) events.push(ev);
  }

  const nonStatic = events.filter(e => !e.isStaticAsset);
  const distinctIps = new Set(events.map(e => e.ip).filter(Boolean)).size;
  const distinctNonStaticPaths = new Set(nonStatic.map(e => e.path)).size;
  const errorResponses = nonStatic.filter(e => ERROR_STATUS_SET.has(e.status)).length;
  const reconEvents = nonStatic.filter(e => e.isReconPath);
  const authPivotEvents = nonStatic.filter(e => e.isAuthPivotPath);

  const gaps = [];
  for (let i = 1; i < nonStatic.length; i++) {
    if (nonStatic[i].tsMs !== null && nonStatic[i - 1].tsMs !== null) {
      const diff = nonStatic[i].tsMs - nonStatic[i - 1].tsMs;
      if (diff >= 0 && diff <= 120000) gaps.push(diff);
    }
  }
  gaps.sort((a, b) => a - b);
  const medianGapMs = computeMedian(gaps);

  const indicators = [];

  // 1. recon-to-auth-pivot: .js.map / openapi.json / introspection -> OAuth/auth/admin pivot
  if (reconEvents.length >= 1) {
    const firstRecon = reconEvents[0];
    const pivotsAfter = authPivotEvents.filter(p => {
      if (p.line <= firstRecon.line) return false;
      if (p.tsMs !== null && firstRecon.tsMs !== null) {
        return p.tsMs >= firstRecon.tsMs && (p.tsMs - firstRecon.tsMs) <= 15 * 60 * 1000;
      }
      return true;
    });
    if (pivotsAfter.length >= 2) {
      indicators.push({
        id: 'recon-to-auth-pivot',
        line: firstRecon.line,
        summary: `API/sourcemap recon (${firstRecon.path}) followed by ${pivotsAfter.length} auth/OAuth/admin pivot probe(s) across ${Math.max(1, distinctIps)} IP(s).`
      });
    }
  }

  // 2. error-adaptation-loop: rapid 400/401/403/422 retries with mutated paths/queries
  const nonStaticWithTs = nonStatic.filter(e => e.tsMs !== null);
  let adaptationHit = null;
  for (let i = 0; i < nonStaticWithTs.length; i++) {
    const winStart = nonStaticWithTs[i].tsMs;
    const winEvents = [];
    for (let j = i; j < nonStaticWithTs.length && (nonStaticWithTs[j].tsMs - winStart) <= 15000; j++) {
      winEvents.push(nonStaticWithTs[j]);
    }
    if (winEvents.length < 6) continue;
    const errCount = winEvents.filter(e => ERROR_STATUS_SET.has(e.status)).length;
    const uniqPaths = new Set(winEvents.map(e => e.path)).size;
    const winGaps = [];
    for (let k = 1; k < winEvents.length; k++) winGaps.push(winEvents[k].tsMs - winEvents[k - 1].tsMs);
    winGaps.sort((a, b) => a - b);
    const winMedianGap = computeMedian(winGaps);
    if (errCount >= 4 && uniqPaths >= 3 && (winMedianGap === null || winMedianGap <= 2500)) {
      const hasBreakthrough = nonStatic.some(e => e.line > winEvents[0].line && e.line <= winEvents[winEvents.length - 1].line + 3 && SUCCESS_STATUS_SET.has(e.status));
      adaptationHit = {
        id: 'error-adaptation-loop',
        line: winEvents[0].line,
        breakthrough: hasBreakthrough,
        summary: `${winEvents.length} machine-paced requests (${errCount} 4xx errors, ${uniqPaths} mutated targets, median gap ${winMedianGap ?? '?'}ms${hasBreakthrough ? ', followed by 2xx/302 breakthrough' : ''}).`
      };
      break;
    }
  }
  if (adaptationHit) indicators.push(adaptationHit);

  // 3. machine-speed-enumeration: >=8 distinct non-static paths in <=10s with low static asset ratio
  const staticRatio = events.length > 0 ? (events.length - nonStatic.length) / events.length : 0;
  for (let i = 0; i < nonStaticWithTs.length; i++) {
    const winStart = nonStaticWithTs[i].tsMs;
    const winEvents = [];
    for (let j = i; j < nonStaticWithTs.length && (nonStaticWithTs[j].tsMs - winStart) <= 10000; j++) {
      winEvents.push(nonStaticWithTs[j]);
    }
    const uniqPaths = new Set(winEvents.map(e => e.path)).size;
    if (uniqPaths >= 8 && staticRatio < 0.15) {
      const winErrCount = winEvents.filter(e => ERROR_STATUS_SET.has(e.status)).length;
      const winReconCount = winEvents.filter(e => e.isReconPath).length;
      const winAuthCount = winEvents.filter(e => e.isAuthPivotPath).length;
      if (winErrCount < 2 && winReconCount < 1 && winAuthCount < 3) continue;
      const winGaps = [];
      for (let k = 1; k < winEvents.length; k++) winGaps.push(winEvents[k].tsMs - winEvents[k - 1].tsMs);
      winGaps.sort((a, b) => a - b);
      const winMedianGap = computeMedian(winGaps);
      if (winMedianGap === null || winMedianGap <= 1200) {
        indicators.push({
          id: 'machine-speed-enumeration',
          line: winEvents[0].line,
          summary: `${uniqPaths} distinct API/edge endpoints probed in <=10s (${winErrCount} 4xx errors, median gap ${winMedianGap ?? '?'}ms, static asset ratio ${(staticRatio * 100).toFixed(0)}%).`
        });
        break;
      }
    }
  }

  return {
    detected: indicators.length > 0,
    confidence: indicators.length >= 2 ? 'high' : indicators.length === 1 ? 'medium' : 'none',
    ruleId: 'ARTEX-BEHAV-001',
    mitre: 'T1595',
    path: normalizePath(relPath),
    indicators,
    burstMetrics: {
      totalHttpEvents: events.length,
      distinctIps,
      distinctNonStaticPaths,
      errorResponses,
      medianGapMs,
      reconHits: reconEvents.length,
      authPivotHits: authPivotEvents.length
    }
  };
}

module.exports = {
  scanArtexEdgeSurface,
  analyzeAgenticBehavior
};
