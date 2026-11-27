const fs = require('node:fs/promises');
const path = require('node:path');
const { SECRET_RULES, maskToken, redactSecrets } = require('../core/cyber-scope.cjs');
const {
  CODE_RULES,
  shannonEntropy,
  parseManifestPackages,
  auditDependencies,
  identifyBinaryFormat,
  inspectSourceReachability
} = require('../core/cyber-analyzers.cjs');
const { detectSecurityTools, prepareScannerSpec, executeScannerRun } = require('../core/cyber-toolchain.cjs');
const { loginPath, DEFAULT_PATH } = require('../core/toolchain.cjs');
const {
  isProtectedRelPath,
  resolveWithinRoot,
  readRegularTextFile,
  readRegularBuffer,
  walkWorkspace,
  loadScopeConfig
} = require('../core/fs-safe.cjs');
const { normalizeFinding, toSarifReport, toMarkdownReport } = require('../core/findings.cjs');
const { getGitDiff } = require('./git-diff.cjs');
const { detectGuardrailRegressions } = require('./regressions.cjs');
const { loadBaseline, applyBaseline } = require('./baseline.cjs');
const {
  isBeefilePath,
  isBpfSourcePath,
  auditBeefile,
  auditBpfUpatchSource,
  auditShirudoCommands,
  auditShirudoEvidenceJson
} = require('../core/shirudo.cjs');
const { scanAgentGuard } = require('../core/agent-guard.cjs');
const { scanArtexEdgeSurface } = require('../core/artex-defense.cjs');

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const SAFE_MEDIA_RE = /\.(?:png|jpe?g|webp|gif|svg|ico|mp4|webm|mov|woff2?|ttf|otf|pdf|lock)$/i;
const MANIFEST_NAME_RE = /^(?:package-lock\.json|package\.json|pnpm-lock\.yaml|requirements\.txt|pyproject\.toml|go\.mod|Cargo\.lock)$/;
const HIGH_CERTAINTY_SECRET_IDS = new Set([
  'private-key',
  'aws-access-key',
  'github-token',
  'ai-api-key',
  'slack-token',
  'stripe-key',
  'google-api-key'
]);
const ENTROPY_SECRET_RE = /\b([A-Za-z_][A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)[A-Za-z0-9_]*)\s*[:=]\s*['"]([A-Za-z0-9+/=_-]{20,128})['"]/i;
const REACHABLE_STATIC_CATEGORIES = new Set(['deserialization', 'crypto', 'iac']);
const AUTO_SCANNER_PRIORITY = ['gitleaks', 'semgrep', 'trivy', 'osv-scanner'];
const TEST_OR_FIXTURE_PATH_RE = /(?:^|\/)(?:tests?|testing|__tests__|benchmarks?|fixtures?|testdata)\/|(?:\.(?:test|spec)\.[cm]?[jt]sx?|_test\.(?:go|py)|test_[^/]+\.py)$/i;
const DEV_BUILD_SCRIPT_PATH_RE = /(?:^|\/)(?:build|scripts|tools|hack)\//i;
const HTML_TEMPLATE_RE = /\.(?:html?|ejs|hbs|handlebars|njk|jinja2?|twig)$/i;
const HTML_SCRIPT_OPEN_RE = /<script(?:\s+(?![^>]*type\s*=\s*['"](?:application\/(?:ld\+)?json|text\/(?:template|html|plain))['"])[^>]*)?>/i;
const HTML_SCRIPT_CLOSE_RE = /<\/script>/i;
const CLIENT_JS_RULE_IDS = new Set(['dynamic-code-exec', 'dom-xss', 'insecure-random', 'permissive-cors']);

function scanTextLines(relPath, text, { allowedLines = null } = {}) {
  const isDoc = /\.(?:md|mdx|rst|txt)$/i.test(relPath) || /(?:^|\/)(?:docs|docs_src|documentation)\//i.test(relPath);
  const isDemoOrTest = TEST_OR_FIXTURE_PATH_RE.test(relPath);
  const isHtmlTemplate = HTML_TEMPLATE_RE.test(relPath);
  let inScriptBlock = false;
  const secretHits = [];
  const codeHits = [];
  const lines = text.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const lineNum = i + 1;
    const raw = lines[i].replace(/\r$/, '');
    let lineInScript = false;
    if (isHtmlTemplate) {
      const opensScript = HTML_SCRIPT_OPEN_RE.test(raw);
      const closesScript = HTML_SCRIPT_CLOSE_RE.test(raw);
      lineInScript = inScriptBlock || opensScript;
      if (opensScript && !closesScript) inScriptBlock = true;
      if (closesScript) inScriptBlock = false;
    }
    if (allowedLines && !allowedLines.has(lineNum)) continue;
    const trimmed = raw.trim();
    if (!trimmed || raw.length > 4000) continue;

    const isCommentLine = trimmed.startsWith('//') || trimmed.startsWith('/*') || /^\*(?:\s|$)/.test(trimmed) || (trimmed.startsWith('#') && !trimmed.startsWith('#!'));

    let matchedSecret = false;
    const restrictToHighCertaintySecrets = isDoc || (isHtmlTemplate && !lineInScript);
    if (!isCommentLine && !isDemoOrTest) {
      for (const rule of SECRET_RULES) {
        if (restrictToHighCertaintySecrets && !HIGH_CERTAINTY_SECRET_IDS.has(rule.id)) continue;
        rule.regex.lastIndex = 0;
        const m = rule.regex.exec(raw);
        if (!m || (rule.filter && !rule.filter(...m))) continue;
        matchedSecret = true;
        secretHits.push({
          title: rule.label,
          severity: rule.severity,
          category: 'secrets',
          cwe: rule.cwe,
          reachability: 'reachable',
          location: `${relPath}:${lineNum}`,
          evidence: redactSecrets(trimmed.slice(0, 220)).text,
          remediation: 'Remove the hardcoded secret from source control, rotate the exposed credential, and inject it via environment secrets.'
        });
        break;
      }
    }

    if (!matchedSecret && !isCommentLine && !isDoc && !isDemoOrTest && !(isHtmlTemplate && !lineInScript)) {
      const em = ENTROPY_SECRET_RE.exec(raw);
      if (
        em &&
        !/^(?:your_|example|placeholder|test_|dummy|fake_)/i.test(em[2]) &&
        shannonEntropy(em[2]) >= 4.35 &&
        /[a-z]/.test(em[2]) &&
        /[A-Z0-9]/.test(em[2])
      ) {
        secretHits.push({
          title: `High-Entropy Secret (${em[1]})`,
          severity: 'medium',
          category: 'secrets',
          cwe: 'CWE-798',
          reachability: 'reachable',
          location: `${relPath}:${lineNum}`,
          evidence: raw.replace(em[2], maskToken(em[2])).trim().slice(0, 220),
          remediation: 'Verify whether this high-entropy literal is a live credential and move secrets out of tracked files.'
        });
      }
    }

    if (isDemoOrTest || isDoc || isCommentLine || /\.(?:md|txt|lock|svg|css|map)$/i.test(relPath)) continue;
    if (trimmed.length > 1000) continue;

    for (const rule of CODE_RULES) {
      if (isHtmlTemplate) {
        if (!lineInScript && !(rule.id === 'dom-xss' && /\bv-html\s*=/i.test(raw))) continue;
        if (lineInScript && !CLIENT_JS_RULE_IDS.has(rule.id)) continue;
      }
      if (!rule.regex.test(raw) || (rule.filter && !rule.filter(trimmed))) continue;
      codeHits.push({
        ruleId: rule.id,
        category: rule.category,
        severity: rule.severity,
        cwe: rule.cwe,
        title: rule.title,
        line: lineNum,
        path: relPath,
        snippet: redactSecrets(trimmed.slice(0, 220)).text
      });
    }
  }

  return { secretHits, codeHits };
}

const DEP_SECTION_KEYS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];

function checkPackageJsonAddedRisk(relPath, fullText, addedLines = []) {
  const cantTell = [];
  let parsed;
  try {
    parsed = JSON.parse(String(fullText || ''));
  } catch {
    return cantTell;
  }
  if (!parsed || typeof parsed !== 'object') return cantTell;

  const riskySpecs = new Map();
  for (const secKey of DEP_SECTION_KEYS) {
    const sec = parsed[secKey];
    if (!sec || typeof sec !== 'object' || Array.isArray(sec)) continue;
    for (const [pkg, spec] of Object.entries(sec)) {
      if (typeof spec !== 'string') continue;
      if (spec === '*' || spec === 'latest' || /^(?:https?:\/\/|git\+|github:)/i.test(spec)) {
        riskySpecs.set(`${pkg}\0${spec}`, { pkg, spec });
      }
    }
  }
  if (!riskySpecs.size) return cantTell;

  for (const entry of addedLines) {
    const line = String(entry.text || '');
    const m = /"([@a-zA-Z0-9._/-]+)"\s*:\s*"([^"]+)"/.exec(line);
    if (!m) continue;
    const [, pkg, spec] = m;
    if (riskySpecs.has(`${pkg}\0${spec}`)) {
      cantTell.push({
        code: 'unpinned-dependency-added',
        path: relPath,
        line: entry.line,
        message: `Unpinned or remote dependency specifier "${pkg}": "${spec}" added at ${relPath}:${entry.line}; verify integrity and provenance.`
      });
    }
  }
  return cantTell;
}

function normalizeFindingsList(rawFindings, workspaceRoot) {
  const seen = new Set();
  const out = [];
  for (const item of rawFindings) {
    const mappedCategory = item.category === 'crypto' || item.category === 'injection' || item.category === 'xss' || item.category === 'deserialization'
      ? 'appsec'
      : item.category === 'iac'
        ? 'config'
        : item.category;
    const normalized = normalizeFinding({
      ...item,
      category: mappedCategory || 'appsec',
      status: item.reachability === 'unverified' ? 'open' : 'verified'
    }, { playbook: 'ci', runId: 'marlowe-ci' });
    normalized.reachability = item.reachability || 'reachable';
    const key = `${(normalized.ruleId || '').toLowerCase()}|${normalized.title.toLowerCase()}|${normalized.location.toLowerCase()}|${normalized.cwe}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(normalized);
  }
  return out.sort((a, b) => (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0));
}

async function runAudit({
  root = process.cwd(),
  mode = 'diff',
  staged = false,
  baseRef = '',
  files = null,
  failOn = 'high',
  queryOsv = true,
  scanners = [],
  scopeConfig = null,
  baselinePath = '',
  useBaseline = true,
  signal = new AbortController().signal
} = {}) {
  const startedAt = Date.now();
  const absRoot = await fs.realpath(path.resolve(root));
  const scope = scopeConfig || await loadScopeConfig(absRoot);
  const rawFindings = [];
  const cantTellReasons = [];
  const dnaFlags = [];
  let diffFiles = [];
  const candidates = []; // { relPath, fullPath, allowedLines: Set|null, status }

  if (Array.isArray(files) && files.length) {
    for (const f of files) {
      if (isProtectedRelPath(f)) continue;
      try {
        const res = await resolveWithinRoot(absRoot, f);
        candidates.push({ relPath: res.relPath, fullPath: res.fullPath, allowedLines: null, status: 'explicit' });
      } catch (err) {
        cantTellReasons.push({
          code: 'unreadable-target',
          path: String(f),
          line: null,
          message: `Skipped unreadable/restricted path "${f}": ${err.message}`
        });
      }
    }
  } else if (mode === 'diff') {
    const diffRes = await getGitDiff(absRoot, { staged, baseRef });
    if (!diffRes.inGitRepo) {
      cantTellReasons.push({
        code: 'not-git-repo',
        path: '.',
        line: null,
        message: 'Not inside a Git repository; diff mode could not determine changed lines — re-run with --mode full.'
      });
      return {
        verdict: 'cant-tell',
        verdictLabel: "CAN'T TELL",
        mode,
        root: absRoot,
        failOn,
        scannedFiles: 0,
        changedFiles: 0,
        findings: [],
        failingFindings: [],
        baselinedFindings: [],
        baselinedCount: 0,
        baselinePath: '',
        cantTellReasons,
        dnaFlags: [],
        dependencySummary: null,
        scannerRuns: [],
        sarif: toSarifReport({ workspace: absRoot, findings: [] }),
        markdownReport: toMarkdownReport({ workspace: absRoot, scope, findings: [] }),
        durationMs: Date.now() - startedAt
      };
    }

    diffFiles = diffRes.files;
    for (const df of diffFiles) {
      if (df.status === 'deleted' || isProtectedRelPath(df.path)) continue;
      let resolved;
      try {
        resolved = await resolveWithinRoot(absRoot, df.path);
      } catch {
        continue;
      }
      const allowedLines = df.status === 'added'
        ? null
        : new Set((df.addedLines || []).map(l => l.line));
      candidates.push({
        relPath: resolved.relPath,
        fullPath: resolved.fullPath,
        allowedLines,
        status: df.status,
        addedLines: df.addedLines || []
      });
    }
  } else {
    const walkState = { truncated: false, deadline: Date.now() + 15000 };
    for await (const fullPath of walkWorkspace(absRoot, signal, walkState)) {
      const relPath = path.relative(absRoot, fullPath).split(path.sep).join('/');
      if (isProtectedRelPath(relPath)) continue;
      candidates.push({ relPath, fullPath, allowedLines: null, status: 'full', addedLines: [] });
      if (candidates.length >= 4000) {
        walkState.truncated = true;
        break;
      }
    }
    if (walkState.truncated) {
      cantTellReasons.push({
        code: 'workspace-truncated',
        path: '.',
        line: null,
        message: 'Workspace scan hit the safety file/time cap; some files were not inspected.'
      });
    }
  }

  let scannedFiles = 0;
  const manifestPaths = [];
  const reachCache = new Map();

  for (const cand of candidates) {
    signal.throwIfAborted?.();
    const baseName = path.posix.basename(cand.relPath);
    if (MANIFEST_NAME_RE.test(baseName)) {
      manifestPaths.push(cand);
    }

    // Entropy / opaque binary inspection (especially meaningful for newly added or modified files)
    if ((mode === 'diff' || Array.isArray(files)) && !SAFE_MEDIA_RE.test(cand.relPath)) {
      try {
        const buf = await readRegularBuffer(cand.fullPath, 4 * 1024 * 1024);
        const entropy = shannonEntropy(buf.subarray(0, Math.min(buf.length, 65536)));
        const magic = identifyBinaryFormat(buf);
        const isExecBin = /^(?:ELF|Mach-O|PE\/COFF|DOS MZ|Binary data)/.test(magic.format);
        const isHighEntropyText = !buf.subarray(0, 4096).includes(0) && buf.length > 512 && entropy >= 7.15;
        if (isExecBin || (buf.length > 256 && entropy >= 7.2) || isHighEntropyText) {
          const flag = { path: cand.relPath, format: magic.format, entropy, sizeBytes: buf.length };
          dnaFlags.push(flag);
          cantTellReasons.push({
            code: 'high-entropy-or-binary',
            path: cand.relPath,
            line: null,
            message: `Added/modified ${magic.format} artifact "${cand.relPath}" (entropy ${entropy.toFixed(2)}/8.00 b/B, ${buf.length} bytes) cannot be statically proved safe.`
          });
        }
      } catch {
        // Ignore oversized/unreadable artifacts handled below.
      }
    }

    let text;
    try {
      text = await readRegularTextFile(cand.fullPath);
    } catch {
      continue;
    }
    scannedFiles++;

    if (baseName === 'package.json' && cand.addedLines?.length) {
      cantTellReasons.push(...checkPackageJsonAddedRisk(cand.relPath, text, cand.addedLines));
    }

    const { secretHits, codeHits } = scanTextLines(cand.relPath, text, { allowedLines: cand.allowedLines });
    rawFindings.push(...secretHits);

    const agentRes = scanAgentGuard(cand.relPath, text, {
      allowedLines: cand.allowedLines,
      addedLines: cand.addedLines,
      mode
    });
    rawFindings.push(...agentRes.findings);
    cantTellReasons.push(...agentRes.cantTellReasons);

    const artexRes = scanArtexEdgeSurface(cand.relPath, text, {
      allowedLines: cand.allowedLines,
      mode
    });
    rawFindings.push(...artexRes.findings);
    cantTellReasons.push(...artexRes.cantTellReasons);

    if (!TEST_OR_FIXTURE_PATH_RE.test(cand.relPath) || Array.isArray(files)) {
      if (isBeefilePath(cand.relPath)) {
        const bfRes = await auditBeefile(cand.relPath, text, { root: absRoot });
        rawFindings.push(...bfRes.findings);
        cantTellReasons.push(...bfRes.cantTellReasons);
      } else if (isBpfSourcePath(cand.relPath)) {
        const bpfRes = auditBpfUpatchSource(cand.relPath, text);
        rawFindings.push(...bpfRes.findings);
        cantTellReasons.push(...bpfRes.cantTellReasons);
      } else if (/\.(?:sh|bash|zsh|ya?ml)$|(?:^|\/)(?:Makefile|Dockerfile|Containerfile)$/i.test(cand.relPath)) {
        const cmdRes = auditShirudoCommands(cand.relPath, text, { allowedLines: cand.allowedLines });
        rawFindings.push(...cmdRes.findings);
        cantTellReasons.push(...cmdRes.cantTellReasons);
      } else if (/(?:^|\/)(?:ev|evidence|attest|attestation)[^/]*\.json$/i.test(cand.relPath)) {
        const evRes = auditShirudoEvidenceJson(cand.relPath, text);
        if (evRes.isEvidence) {
          rawFindings.push(...evRes.findings);
          cantTellReasons.push(...evRes.cantTellReasons);
        }
      }
    }

    for (const hit of codeHits) {
      const reach = await inspectSourceReachability(absRoot, hit.path, hit.line, { cache: reachCache });
      const isDevBuildCliOnly =
        DEV_BUILD_SCRIPT_PATH_RE.test(hit.path) &&
        Boolean(reach?.entryKind) &&
        !/HTTP|Socket|URL|DOM/i.test(reach.entryKind);
      const hasExternalEntry =
        (!isDevBuildCliOnly && Boolean(reach?.entryKind)) ||
        REACHABLE_STATIC_CATEGORIES.has(hit.category);
      if (hasExternalEntry) {
        const remediation = reach?.hops > 0 && reach.via?.length
          ? `Validate or parameterize untrusted input (${reach.entryKind} via ${reach.via.join(' → ')}) before reaching this sink.`
          : reach?.entryKind
            ? `Validate or parameterize untrusted input (${reach.entryKind}) before reaching this sink.`
            : 'Replace the unsafe configuration or cryptographic primitive with a hardened alternative.';
        rawFindings.push({
          title: hit.title,
          severity: hit.severity,
          category: hit.category,
          cwe: hit.cwe,
          reachability: 'reachable',
          location: `${hit.path}:${hit.line}`,
          evidence: hit.snippet,
          remediation
        });
      } else {
        rawFindings.push({
          title: `${hit.title} (Unverified Reachability)`,
          severity: hit.severity,
          category: hit.category,
          cwe: hit.cwe,
          reachability: 'unverified',
          location: `${hit.path}:${hit.line}`,
          evidence: hit.snippet,
          remediation: 'Confirm no untrusted input reaches this sink, or switch to a safe parameterized API.'
        });
        cantTellReasons.push({
          code: 'unverified-sink',
          path: hit.path,
          line: hit.line,
          message: isDevBuildCliOnly
            ? `Unverified ${hit.cwe || hit.category} sink "${hit.title}" in build/tooling CLI script ${hit.path}:${hit.line} — confirm no untrusted input reaches this sink.`
            : `Unverified ${hit.cwe || hit.category} sink "${hit.title}" at ${hit.path}:${hit.line} — no HTTP/URL/CLI ingress detected in file; verify manually.`
        });
      }
    }
  }

  // Guardrail regression checks on git diff
  if (mode === 'diff' && diffFiles.length) {
    const reg = detectGuardrailRegressions(diffFiles);
    rawFindings.push(...reg.findings);
    cantTellReasons.push(...reg.cantTellReasons);
  }

  // Dependency / OSV check for changed manifests (or root manifests in full mode)
  let dependencySummary = null;
  if (manifestPaths.length) {
    const depResults = await Promise.all(
      manifestPaths.slice(0, 10).map(m =>
        auditDependencies(absRoot, m.fullPath, {
          isDirectory: false,
          queryOsv,
          scope,
          relativePath: (r, f) => path.relative(r, f).split(path.sep).join('/'),
          walk: walkWorkspace,
          readText: readRegularTextFile
        }, signal)
      )
    );
    const totalPackages = depResults.reduce((sum, r) => sum + r.totalPackages, 0);
    const vulns = depResults.flatMap(r => r.vulnerabilities);
    const statuses = depResults.map(r => r.osvStatus);
    dependencySummary = {
      manifests: manifestPaths.map(m => m.relPath),
      totalPackages,
      osvStatus: statuses[0] || 'skipped',
      vulnerabilityCount: vulns.length
    };
    for (const v of vulns) {
      rawFindings.push({
        title: `${v.id}: Vulnerable dependency ${v.package}@${v.version}`,
        severity: 'high',
        category: 'supply-chain',
        cwe: 'CWE-1395',
        reachability: 'reachable',
        location: v.source || manifestPaths[0].relPath,
        evidence: `${v.ecosystem} ${v.package}@${v.version} — ${v.summary || v.advisoryUrl}`,
        remediation: `Upgrade ${v.package} to a patched release (${v.advisoryUrl}).`
      });
    }
    const unavailable = statuses.find(s => typeof s === 'string' && s.startsWith('unavailable'));
    if (queryOsv && totalPackages > 0 && unavailable) {
      cantTellReasons.push({
        code: 'osv-unavailable',
        path: manifestPaths[0].relPath,
        line: null,
        message: `OSV.dev advisory lookup failed (${unavailable}); dependency CVE status could not be confirmed.`
      });
    }
  }

  // Optional external security CLIs (auto or explicit list)
  const scannerRuns = [];
  const requestedScanners = Array.isArray(scanners)
    ? scanners.map(s => String(s).trim().toLowerCase()).filter(Boolean)
    : [];
  if (requestedScanners.length && !requestedScanners.includes('none')) {
    const commandPath = (await loginPath({ shell: process.env.SHELL || '', root: absRoot, env: process.env })) || process.env.PATH || DEFAULT_PATH;
    const detected = await detectSecurityTools(commandPath, { root: absRoot });
    const toRun = requestedScanners.includes('auto')
      ? AUTO_SCANNER_PRIORITY.filter(id => detected.tools.some(t => t.id === id && t.available))
      : requestedScanners;

    for (const scannerId of toRun) {
      const toolInfo = detected.tools.find(t => t.id === scannerId && t.runnable && !t.network);
      if (!toolInfo) {
        cantTellReasons.push({
          code: 'unknown-scanner',
          path: '.',
          line: null,
          message: `Requested local scanner "${scannerId}" is not a supported local workspace scanner.`
        });
        continue;
      }
      if (!toolInfo.available) {
        cantTellReasons.push({
          code: 'scanner-missing',
          path: '.',
          line: null,
          message: `Requested scanner "${scannerId}" is not installed on verified PATH (${toolInfo.installHint}).`
        });
        continue;
      }
      try {
        const scannerPlan = prepareScannerSpec({ scanner: scannerId, target: '.' }, { scope });
        const runRes = await executeScannerRun(
          { scannerPlan, seconds: 90 },
          { root: absRoot, scope, commandPath, signal }
        );
        scannerRuns.push({
          scanner: scannerId,
          exitCode: runRes.exitCode,
          findingsCount: runRes.structuredFindingsCount,
          summary: runRes.summary
        });
        for (const sf of runRes.structuredFindings) {
          rawFindings.push({
            title: sf.rule || sf.id || sf.title || `${scannerId} finding`,
            severity: ['critical', 'high', 'medium', 'low', 'info'].includes(sf.severity) ? sf.severity : 'medium',
            category: scannerId === 'gitleaks' ? 'secrets' : scannerId === 'osv-scanner' ? 'supply-chain' : 'appsec',
            cwe: sf.cwe || '',
            reachability: 'reachable',
            location: sf.location || sf.target || '.',
            evidence: sf.message || sf.description || sf.summary || sf.title || scannerId,
            remediation: `Review and resolve the ${scannerId} finding.`
          });
        }
      } catch (err) {
        cantTellReasons.push({
          code: 'scanner-error',
          path: '.',
          line: null,
          message: `External scanner "${scannerId}" failed to complete: ${err.message}`
        });
      }
    }
  }

  const allFindings = normalizeFindingsList(rawFindings, absRoot);
  const baseline = useBaseline ? await loadBaseline(absRoot, baselinePath) : null;
  const { activeFindings: findings, baselinedFindings } = applyBaseline(allFindings, baseline);

  // If an unverified-sink finding was explicitly baselined, remove its matching unverified-sink notice
  // while never silencing secrets, regressions, untriaged binaries, or new unverified sinks.
  const baselinedLocs = new Set(baselinedFindings.map(f => f.location.toLowerCase()));
  const filteredCantTell = cantTellReasons.filter(r => {
    if (r.code !== 'unverified-sink') return true;
    const key = `${String(r.path || '').replace(/^\.\//, '')}:${r.line || ''}`.toLowerCase();
    return !baselinedLocs.has(key);
  });

  const threshold = SEVERITY_RANK[String(failOn || 'high').toLowerCase()] ?? SEVERITY_RANK.high;
  const failingFindings = findings.filter(
    f => f.category === 'secrets' || (f.reachability !== 'unverified' && (SEVERITY_RANK[f.severity] ?? 0) >= threshold)
  );

  let verdict = 'holds';
  let verdictLabel = 'HOLDS UP';
  if (failingFindings.length > 0) {
    verdict = 'fails';
    verdictLabel = 'FAILS';
  } else if (filteredCantTell.length > 0) {
    verdict = 'cant-tell';
    verdictLabel = "CAN'T TELL";
  }

  return {
    verdict,
    verdictLabel,
    mode,
    root: absRoot,
    failOn,
    scannedFiles,
    changedFiles: diffFiles.length || candidates.length,
    findings,
    failingFindings,
    baselinedFindings,
    baselinedCount: baselinedFindings.length,
    baselinePath: baseline?.path || '',
    cantTellReasons: filteredCantTell,
    dnaFlags,
    dependencySummary,
    scannerRuns,
    sarif: toSarifReport({ workspace: absRoot, findings }),
    markdownReport: toMarkdownReport({ workspace: absRoot, scope, findings }),
    durationMs: Date.now() - startedAt
  };
}

module.exports = {
  SEVERITY_RANK,
  scanTextLines,
  runAudit
};
