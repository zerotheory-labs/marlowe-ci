const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { spawn } = require('node:child_process');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const execFileAsync = promisify(execFile);
const CLI = path.resolve(__dirname, '../bin/marlowe-ci.cjs');
const pkg = require('../package.json');

test('MCP stdio server handles initialize, tools/list, and tools/call over newline-delimited JSON-RPC 2.0', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'marlowe-mcp-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));

  await execFileAsync('git', ['init', '-b', 'main'], { cwd: dir });
  await execFileAsync('git', ['config', 'user.email', 'ci@example.com'], { cwd: dir });
  await execFileAsync('git', ['config', 'user.name', 'Marlowe Test'], { cwd: dir });
  await fs.writeFile(path.join(dir, 'hello.js'), 'export const hello = "world";\n', 'utf8');
  await fs.writeFile(
    path.join(dir, 'incident.log'),
    [
      '198.51.100.7 - - "GET /search?q=1%20union%20select%20password HTTP/1.1" 500',
      '203.0.113.8 - - "GET /meta?u=http://169.254.169.254/latest/meta-data HTTP/1.1" 403',
      'Defanged IOC hxxps://bad[.]example[.]net/drop CVE-2026-1234 T1190'
    ].join('\n') + '\n',
    'utf8'
  );
  await fs.writeFile(
    path.join(dir, 'Beefile'),
    [
      '[package]',
      'name = "demo-shield"',
      'description = "Scoped test shield"',
      '',
      '[[upatches]]',
      'source = "guard.bpf.c"',
      'type = "bpf"',
      '',
      '[upatches.tree]',
      'id = "guard"',
      '',
      '[upatches.tree.selector.labels]',
      'role = ["edge"]'
    ].join('\n') + '\n',
    'utf8'
  );
  await fs.writeFile(
    path.join(dir, 'guard.bpf.c'),
    [
      'char LICENSE[] SEC("license") = "Dual BSD/GPL";',
      'SEC("lsm/file_open")',
      'int handle_open(void *ctx) {',
      '  unsigned int pid = bpf_get_current_pid_tgid() >> 32;',
      '  return pid ? 0 : 0;',
      '}'
    ].join('\n') + '\n',
    'utf8'
  );
  await fs.writeFile(
    path.join(dir, 'attestation.json'),
    JSON.stringify({ quote: 'tpm2-quote', upatches: ['demo-shield'] }),
    'utf8'
  );
  await fs.writeFile(path.join(dir, '.marlowe-scope.json'), JSON.stringify({ targets: ['https://example.com'] }), 'utf8');
  await execFileAsync('git', ['add', '.'], { cwd: dir });
  await execFileAsync('git', ['commit', '-m', 'init'], { cwd: dir });

  const requests = [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'test', version: '1.0' } } },
    { jsonrpc: '2.0', method: 'notifications/initialized', params: {} },
    { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'marlowe_scan_diff', arguments: { query_osv: false } } },
    { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'marlowe_triage_artifact', arguments: { path: 'hello.js' } } },
    { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'marlowe_check_scope', arguments: { target: 'http://169.254.169.254/latest' } } },
    { jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'marlowe_doctor', arguments: {} } },
    { jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'marlowe_analyze_logs', arguments: { path: 'incident.log' } } },
    { jsonrpc: '2.0', id: 8, method: 'tools/call', params: { name: 'marlowe_extract_iocs', arguments: { path: 'incident.log' } } },
    { jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name: 'marlowe_inspect_http', arguments: { url: 'http://169.254.169.254/latest/meta-data' } } },
    { jsonrpc: '2.0', id: 10, method: 'tools/call', params: { name: 'marlowe_inspect_tls', arguments: { target: '10.0.0.1:443' } } },
    { jsonrpc: '2.0', id: 11, method: 'tools/call', params: { name: 'marlowe_dns_recon', arguments: { domain: 'unauthorized.example.org' } } },
    { jsonrpc: '2.0', id: 12, method: 'tools/call', params: { name: 'marlowe_shirudo_audit', arguments: { path: '.' } } },
    { jsonrpc: '2.0', id: 13, method: 'tools/call', params: { name: 'marlowe_shirudo_verify_attestation', arguments: { evidence_path: 'attestation.json', nonce: 'abcdef01' } } }
  ];

  const responses = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, 'mcp', '--path', dir], {
      stdio: ['pipe', 'pipe', 'pipe']
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', d => { stdout += d.toString('utf8'); });
    child.stderr.on('data', d => { stderr += d.toString('utf8'); });
    child.on('error', reject);
    child.on('close', code => {
      assert.equal(code, 0, `MCP exited ${code}: ${stderr}`);
      const lines = stdout.trim().split('\n').filter(Boolean);
      resolve(lines.map(l => JSON.parse(l)));
    });
    for (const req of requests) {
      child.stdin.write(JSON.stringify(req) + '\n');
    }
    child.stdin.end();
  });

  // notifications/initialized produces no response; 13 request IDs -> 13 JSON lines
  assert.equal(responses.length, 13);
  const byId = Object.fromEntries(responses.map(r => [r.id, r]));

  assert.equal(byId[1].result.serverInfo.name, 'marlowe-ci');
  assert.equal(byId[1].result.serverInfo.version, pkg.version);
  assert.equal(byId[1].result.protocolVersion, '2025-03-26');

  const toolNames = byId[2].result.tools.map(tool => tool.name);
  assert.deepEqual(toolNames, [
    'marlowe_scan_diff',
    'marlowe_scan_workspace',
    'marlowe_audit_dependencies',
    'marlowe_triage_artifact',
    'marlowe_check_scope',
    'marlowe_doctor',
    'marlowe_inspect_http',
    'marlowe_inspect_tls',
    'marlowe_dns_recon',
    'marlowe_analyze_logs',
    'marlowe_extract_iocs',
    'marlowe_shirudo_audit',
    'marlowe_shirudo_verify_attestation'
  ]);

  const scanRes = JSON.parse(byId[3].result.content[0].text);
  assert.equal(scanRes.verdict, 'holds');

  const triageRes = JSON.parse(byId[4].result.content[0].text);
  assert.equal(triageRes.path, 'hello.js');
  assert.ok(typeof triageRes.hashes.sha256 === 'string');

  // Out-of-scope SSRF check returns isError: true
  assert.equal(byId[5].result.isError, true);

  const doctorRes = JSON.parse(byId[6].result.content[0].text);
  assert.equal(doctorRes.totalCount, 10);

  const logsRes = JSON.parse(byId[7].result.content[0].text);
  assert.ok(logsRes.signatureCounts['sqli-probe'] >= 1);
  assert.ok(logsRes.signatureCounts['ssrf-metadata'] >= 1);

  const iocsRes = JSON.parse(byId[8].result.content[0].text);
  assert.ok(iocsRes.iocs.cves.includes('CVE-2026-1234'));
  assert.ok(iocsRes.iocs.mitreTechniques.includes('T1190'));
  assert.ok(iocsRes.iocs.urls.some(u => u.includes('https://bad.example.net/drop')));

  // ScopeGate rejects out-of-scope / SSRF targets on all 3 Recon tools
  assert.equal(byId[9].result.isError, true);
  assert.equal(byId[10].result.isError, true);
  assert.equal(byId[11].result.isError, true);

  const shirudoAuditRes = JSON.parse(byId[12].result.content[0].text);
  assert.equal(shirudoAuditRes.verdict, 'holds');
  assert.equal(shirudoAuditRes.inspectedCount, 2);

  const attestRes = JSON.parse(byId[13].result.content[0].text);
  assert.equal(attestRes.evidencePath, 'attestation.json');
  assert.ok(['holds', 'fails', 'cant-tell'].includes(attestRes.verdict));
});

test('release metadata matches the npm package and documents its supported series', async () => {
  const pkg = JSON.parse(await fs.readFile(path.resolve(__dirname, '../package.json'), 'utf8'));
  const manifest = JSON.parse(await fs.readFile(path.resolve(__dirname, '../server.json'), 'utf8'));
  assert.equal(manifest.name, pkg.mcpName);
  assert.equal(manifest.version, pkg.version);
  assert.equal(manifest.packages[0].identifier, pkg.name);
  assert.equal(manifest.packages[0].version, pkg.version);
  assert.equal(manifest.packages[0].transport.type, 'stdio');
  const policy = await fs.readFile(path.resolve(__dirname, '../SECURITY.md'), 'utf8');
  const [major, minor] = pkg.version.split('.');
  assert.ok(policy.split('\n').some(line => line.startsWith(`| \`${major}.${minor}.x\` | Yes |`)),
    `SECURITY.md must list the current ${major}.${minor}.x series as supported`);
});
