const readline = require('node:readline');
const path = require('node:path');
const { assertTargetInScope } = require('../core/cyber-scope.cjs');
const { resolveWithinRoot, walkWorkspace, readRegularTextFile, loadScopeConfig } = require('../core/fs-safe.cjs');
const {
  triageArtifact,
  auditDependencies,
  inspectHttpSecurity,
  inspectTls,
  dnsRecon,
  extractIocs,
  analyzeLogs
} = require('../core/cyber-analyzers.cjs');
const { detectSecurityTools } = require('../core/cyber-toolchain.cjs');
const { inspectShirudoTarget, verifyShirudoAttestation } = require('../core/shirudo.cjs');
const { loginPath, DEFAULT_PATH } = require('../core/toolchain.cjs');
const { runAudit } = require('../engine/verdict.cjs');

const { version: PACKAGE_VERSION } = require('../../package.json');

const SERVER_INFO = {
  name: 'marlowe-ci',
  version: PACKAGE_VERSION
};

const MCP_TOOLS = [
  {
    name: 'marlowe_scan_diff',
    description: 'Audit the current git working-tree, staged changes, or branch diff against a base ref. Returns Marlowe verdict (holds / fails / cant-tell), findings, Can\'t Tell items, and SARIF summary.',
    inputSchema: {
      type: 'object',
      properties: {
        base_ref: { type: 'string', description: 'Optional git base ref (e.g. main or origin/main) to compare HEAD against.' },
        staged: { type: 'boolean', description: 'Audit staged git index changes only.' },
        fail_on: { type: 'string', enum: ['critical', 'high', 'medium', 'low'], description: 'Minimum severity that triggers FAILS verdict (default: high).' },
        query_osv: { type: 'boolean', description: 'Query OSV.dev for known dependency CVEs when manifests changed (default: true).' }
      },
      additionalProperties: false
    }
  },
  {
    name: 'marlowe_scan_workspace',
    description: 'Run a full static audit (secrets, reachable code sinks, dependency advisories) across a workspace directory.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Workspace-relative path or . (default: .).' },
        fail_on: { type: 'string', enum: ['critical', 'high', 'medium', 'low'], description: 'Minimum severity threshold (default: high).' },
        query_osv: { type: 'boolean', description: 'Query OSV.dev advisory database (default: true).' }
      },
      additionalProperties: false
    }
  },
  {
    name: 'marlowe_audit_dependencies',
    description: 'Inventory pinned dependencies across package.json, package-lock.json, pnpm-lock.yaml, requirements.txt, pyproject.toml, go.mod, and Cargo.lock, emit CycloneDX 1.5 SBOM metadata, and check OSV.dev.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Workspace-relative directory or manifest path (default: .).' },
        query_osv: { type: 'boolean', description: 'Query OSV.dev (default: true).' }
      },
      additionalProperties: false
    }
  },
  {
    name: 'marlowe_triage_artifact',
    description: 'Read-only static triage of a regular workspace file or binary: hashes, Shannon byte entropy, ELF/Mach-O/PE/PDF/PCAP format identification, and masked strings.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Workspace-relative path to artifact.' }
      },
      required: ['path'],
      additionalProperties: false
    }
  },
  {
    name: 'marlowe_check_scope',
    description: 'Validate a URL, hostname, or IP against .marlowe-scope.json / .marlowe.json and Marlowe SSRF/DNS-rebinding guards before probing.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Target URL, hostname, or IP address.' }
      },
      required: ['target'],
      additionalProperties: false
    }
  },
  {
    name: 'marlowe_doctor',
    description: 'Detect which of the 10 supported local security CLIs (semgrep, trivy, gitleaks, osv-scanner, nmap, nuclei, tshark, radare2, otool, shirudo) are installed on verified PATH.',
    inputSchema: {
      type: 'object',
      properties: {},
      additionalProperties: false
    }
  },
  {
    name: 'marlowe_inspect_http',
    description: 'Inspect HTTP security headers (CSP, HSTS, X-Frame-Options, nosniff, CORS) and Set-Cookie flags on an Authorized Scope URL using non-redirecting GET or HEAD.',
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'Full http:// or https:// URL inside .marlowe-scope.json.' },
        method: { type: 'string', enum: ['GET', 'HEAD'], description: 'HTTP method (default: GET).' }
      },
      required: ['url'],
      additionalProperties: false
    }
  },
  {
    name: 'marlowe_inspect_tls',
    description: 'Inspect TLS protocol version, cipher suite, certificate chain trust, SANs, and expiration on an Authorized Scope host or host:port.',
    inputSchema: {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Hostname or host:port inside .marlowe-scope.json.' }
      },
      required: ['target'],
      additionalProperties: false
    }
  },
  {
    name: 'marlowe_dns_recon',
    description: 'Query A, AAAA, CNAME, MX, NS, TXT, and DMARC records for an Authorized Scope domain and evaluate SPF/DMARC spoofing defenses.',
    inputSchema: {
      type: 'object',
      properties: {
        domain: { type: 'string', description: 'Domain name inside .marlowe-scope.json.' }
      },
      required: ['domain'],
      additionalProperties: false
    }
  },
  {
    name: 'marlowe_analyze_logs',
    description: 'Analyze JSONL, HTTP access, or syslog/auth logs inside the workspace for brute-force spikes, traversal/SQLi/XSS/JNDI/SSRF probes, scanner signatures, and top IPs.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Workspace-relative log file path.' },
        filter: { type: 'string', description: 'Optional case-insensitive substring filter.' }
      },
      required: ['path'],
      additionalProperties: false
    }
  },
  {
    name: 'marlowe_extract_iocs',
    description: 'Extract and classify Indicators of Compromise (public/private IPs, domains, defanged URLs, hashes, CVEs, and MITRE ATT&CK IDs) from a workspace file or log.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Workspace-relative file path.' }
      },
      required: ['path'],
      additionalProperties: false
    }
  },
  {
    name: 'marlowe_shirudo_audit',
    description: 'Audit Shirudo Beefiles, Plain BPF C (.bpf.c/.upatch.c) runtime upatches, and .bee/.upatch bundles for embedded keys, insecure registries, path traversal, unsafe BPF helpers, and wildcard selectors.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Workspace-relative path to a Beefile, .bpf.c file, .bee package, or directory (default: .).' }
      },
      additionalProperties: false
    }
  },
  {
    name: 'marlowe_shirudo_verify_attestation',
    description: 'Inspect a Shirudo TPM 2.0 attestation evidence JSON file in the workspace and verify it offline via trusted shirudo CLI when installed.',
    inputSchema: {
      type: 'object',
      properties: {
        evidence_path: { type: 'string', description: 'Workspace-relative path to the Shirudo TPM 2.0 attestation evidence JSON file.' },
        nonce: { type: 'string', description: 'Optional expected hex nonce (8-128 hex chars).' },
        ak_name: { type: 'string', description: 'Optional expected attestation key (AK) name.' },
        expected_pcr11: { type: 'string', description: 'Optional expected SHA-256 PCR 11 digest for UKI/initrd boot verification.' },
        expected_config_root: { type: 'string', description: 'Optional expected active Shirudo configuration image root hash.' }
      },
      required: ['evidence_path'],
      additionalProperties: false
    }
  }
];

async function executeMcpTool(name, args = {}, { root = process.cwd() } = {}) {
  const signal = new AbortController().signal;
  const scope = await loadScopeConfig(root);

  switch (name) {
    case 'marlowe_scan_diff': {
      const res = await runAudit({
        root,
        mode: 'diff',
        baseRef: typeof args.base_ref === 'string' ? args.base_ref.trim() : '',
        staged: Boolean(args.staged),
        failOn: typeof args.fail_on === 'string' ? args.fail_on : 'high',
        queryOsv: args.query_osv !== undefined ? Boolean(args.query_osv) : true,
        scopeConfig: scope,
        signal
      });
      return {
        verdict: res.verdict,
        verdictLabel: res.verdictLabel,
        scannedFiles: res.scannedFiles,
        changedFiles: res.changedFiles,
        findings: res.findings,
        failingFindingsCount: res.failingFindings.length,
        cantTellReasons: res.cantTellReasons,
        dnaFlags: res.dnaFlags,
        dependencySummary: res.dependencySummary,
        durationMs: res.durationMs
      };
    }

    case 'marlowe_scan_workspace': {
      const relTarget = typeof args.path === 'string' && args.path.trim() ? args.path.trim() : '.';
      const resolved = await resolveWithinRoot(root, relTarget);
      const res = await runAudit({
        root: resolved.fullPath,
        mode: 'full',
        failOn: typeof args.fail_on === 'string' ? args.fail_on : 'high',
        queryOsv: args.query_osv !== undefined ? Boolean(args.query_osv) : true,
        scopeConfig: scope,
        signal
      });
      return {
        verdict: res.verdict,
        verdictLabel: res.verdictLabel,
        scannedFiles: res.scannedFiles,
        findings: res.findings,
        failingFindingsCount: res.failingFindings.length,
        cantTellReasons: res.cantTellReasons,
        dependencySummary: res.dependencySummary,
        durationMs: res.durationMs
      };
    }

    case 'marlowe_audit_dependencies': {
      const relTarget = typeof args.path === 'string' && args.path.trim() ? args.path.trim() : '.';
      const resolved = await resolveWithinRoot(root, relTarget);
      const fs = require('node:fs/promises');
      const stat = await fs.stat(resolved.fullPath);
      return auditDependencies(
        resolved.rootReal,
        resolved.fullPath,
        {
          isDirectory: stat.isDirectory(),
          queryOsv: args.query_osv !== undefined ? Boolean(args.query_osv) : true,
          scope,
          relativePath: (r, f) => path.relative(r, f).split(path.sep).join('/'),
          walk: walkWorkspace,
          readText: readRegularTextFile
        },
        signal
      );
    }

    case 'marlowe_triage_artifact': {
      if (typeof args.path !== 'string' || !args.path.trim()) {
        throw new Error('path is required.');
      }
      const resolved = await resolveWithinRoot(root, args.path.trim());
      return triageArtifact(resolved.fullPath, resolved.relPath, signal);
    }

    case 'marlowe_check_scope': {
      if (typeof args.target !== 'string' || !args.target.trim()) {
        throw new Error('target is required.');
      }
      const checked = await assertTargetInScope(args.target.trim(), scope);
      return { allowed: true, ...checked };
    }

    case 'marlowe_doctor': {
      const commandPath = (await loginPath({ shell: process.env.SHELL || '', root, env: process.env })) || process.env.PATH || DEFAULT_PATH;
      return detectSecurityTools(commandPath, { root });
    }

    case 'marlowe_inspect_http': {
      if (typeof args.url !== 'string' || !args.url.trim()) throw new Error('url is required.');
      const method = typeof args.method === 'string' ? args.method : 'GET';
      return inspectHttpSecurity(args.url.trim(), { method, scope }, signal);
    }

    case 'marlowe_inspect_tls': {
      if (typeof args.target !== 'string' || !args.target.trim()) throw new Error('target is required.');
      return inspectTls(args.target.trim(), { scope }, signal);
    }

    case 'marlowe_dns_recon': {
      if (typeof args.domain !== 'string' || !args.domain.trim()) throw new Error('domain is required.');
      return dnsRecon(args.domain.trim(), { scope }, signal);
    }

    case 'marlowe_analyze_logs': {
      if (typeof args.path !== 'string' || !args.path.trim()) throw new Error('path is required.');
      const resolved = await resolveWithinRoot(root, args.path.trim());
      return analyzeLogs(resolved.fullPath, resolved.relPath, { filter: typeof args.filter === 'string' ? args.filter : '' }, signal);
    }

    case 'marlowe_extract_iocs': {
      if (typeof args.path !== 'string' || !args.path.trim()) throw new Error('path is required.');
      const resolved = await resolveWithinRoot(root, args.path.trim());
      return extractIocs(resolved.fullPath, resolved.relPath, signal);
    }

    case 'marlowe_shirudo_audit': {
      const relTarget = typeof args.path === 'string' && args.path.trim() ? args.path.trim() : '.';
      return inspectShirudoTarget(root, relTarget, signal);
    }

    case 'marlowe_shirudo_verify_attestation': {
      if (typeof args.evidence_path !== 'string' || !args.evidence_path.trim()) {
        throw new Error('evidence_path is required.');
      }
      const commandPath = (await loginPath({ shell: process.env.SHELL || '', root, env: process.env })) || process.env.PATH || DEFAULT_PATH;
      return verifyShirudoAttestation({
        root,
        evidencePath: args.evidence_path.trim(),
        nonce: typeof args.nonce === 'string' ? args.nonce : '',
        akName: typeof args.ak_name === 'string' ? args.ak_name : '',
        expectedPcr11: typeof args.expected_pcr11 === 'string' ? args.expected_pcr11 : '',
        expectedConfigRoot: typeof args.expected_config_root === 'string' ? args.expected_config_root : '',
        commandPath
      });
    }

    default:
      throw new Error(`Unknown tool "${name}".`);
  }
}

async function handleJsonRpcMessage(msg, context = {}) {
  if (!msg || typeof msg !== 'object' || msg.jsonrpc !== '2.0') {
    return {
      jsonrpc: '2.0',
      id: msg?.id ?? null,
      error: { code: -32600, message: 'Invalid JSON-RPC 2.0 request.' }
    };
  }

  const hasId = Object.prototype.hasOwnProperty.call(msg, 'id') && msg.id !== undefined;
  const method = msg.method;

  if (method === 'notifications/initialized' || (!hasId && String(method).startsWith('notifications/'))) {
    return null;
  }

  if (method === 'initialize') {
    const protocolVersion = typeof msg.params?.protocolVersion === 'string' && msg.params.protocolVersion
      ? msg.params.protocolVersion
      : '2025-03-26';
    return {
      jsonrpc: '2.0',
      id: msg.id,
      result: {
        protocolVersion,
        capabilities: { tools: {} },
        serverInfo: SERVER_INFO
      }
    };
  }

  if (method === 'ping') {
    return { jsonrpc: '2.0', id: msg.id, result: {} };
  }

  if (method === 'tools/list') {
    return {
      jsonrpc: '2.0',
      id: msg.id,
      result: { tools: MCP_TOOLS }
    };
  }

  if (method === 'tools/call') {
    const name = msg.params?.name;
    const args = msg.params?.arguments || {};
    try {
      const data = await executeMcpTool(name, args, context);
      return {
        jsonrpc: '2.0',
        id: msg.id,
        result: {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
          isError: false
        }
      };
    } catch (err) {
      return {
        jsonrpc: '2.0',
        id: msg.id,
        result: {
          content: [{ type: 'text', text: `Error: ${err.message}` }],
          isError: true
        }
      };
    }
  }

  if (!hasId) return null;

  return {
    jsonrpc: '2.0',
    id: msg.id,
    error: { code: -32601, message: `Method not found: ${method}` }
  };
}

function startMcpServer({ root = process.cwd() } = {}) {
  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  const writeLine = obj => {
    if (obj) process.stdout.write(JSON.stringify(obj) + '\n');
  };

  let chain = Promise.resolve();
  rl.on('line', line => {
    const trimmed = line.trim();
    if (!trimmed) return;
    chain = chain.then(async () => {
      let msg;
      try {
        msg = JSON.parse(trimmed);
      } catch (err) {
        writeLine({
          jsonrpc: '2.0',
          id: null,
          error: { code: -32700, message: `Parse error: ${err.message}` }
        });
        return;
      }
      const response = await handleJsonRpcMessage(msg, { root });
      writeLine(response);
    }).catch(err => {
      process.stderr.write(`[marlowe-ci mcp] Unhandled error: ${err.stack || err.message}\n`);
    });
  });

  return new Promise(resolve => {
    rl.once('close', () => chain.then(() => resolve(0)));
  });
}

module.exports = {
  SERVER_INFO,
  MCP_TOOLS,
  executeMcpTool,
  handleJsonRpcMessage,
  startMcpServer
};
