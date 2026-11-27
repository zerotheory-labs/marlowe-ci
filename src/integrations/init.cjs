const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');

const MARLOWE_CLAUDE_MARKER = 'marlowe-ci claude';
const GIT_HOOK_START = '# --- marlowe-ci-pre-commit start ---';
const GIT_HOOK_END = '# --- marlowe-ci-pre-commit end ---';
const CODEX_MCP_START = '# --- marlowe-ci-mcp start ---';
const CODEX_MCP_END = '# --- marlowe-ci-mcp end ---';

function parseCommandPrefix(commandPrefix = 'npx --yes @zerotheory-labs/marlowe-ci') {
  const parts = String(commandPrefix || '').trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return { command: 'npx', baseArgs: ['--yes', '@zerotheory-labs/marlowe-ci'] };
  return { command: parts[0], baseArgs: parts.slice(1) };
}

async function readJsonOrDefault(filePath, fallback = {}) {
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : fallback;
  } catch (err) {
    if (err && err.code === 'ENOENT') return fallback;
    throw new Error(`Cannot parse existing JSON at ${filePath}: ${err.message}`);
  }
}

async function writeJsonPretty(filePath, data) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, JSON.stringify(data, null, 2) + '\n', 'utf8');
}

function stripMarloweEntries(list) {
  if (!Array.isArray(list)) return [];
  return list.filter(entry => {
    const inner = Array.isArray(entry?.hooks) ? entry.hooks : [];
    const hasMarlowe = inner.some(h => typeof h?.command === 'string' && h.command.includes(MARLOWE_CLAUDE_MARKER));
    return !hasMarlowe;
  });
}

async function installClaudeHooks({
  targetDir = process.cwd(),
  global = false,
  commandPrefix = 'npx --yes @zerotheory-labs/marlowe-ci'
} = {}) {
  const baseDir = global ? os.homedir() : path.resolve(targetDir);
  const settingsPath = path.join(baseDir, '.claude', 'settings.json');
  const settings = await readJsonOrDefault(settingsPath, {});
  const hooks = settings.hooks && typeof settings.hooks === 'object' ? { ...settings.hooks } : {};

  const preList = stripMarloweEntries(hooks.PreToolUse);
  preList.push({
    matcher: 'Bash|Read|Edit|Write|MultiEdit|WebFetch',
    hooks: [{ type: 'command', command: `${commandPrefix} claude pre-tool`, timeout: 10 }]
  });
  hooks.PreToolUse = preList;

  const postList = stripMarloweEntries(hooks.PostToolUse);
  postList.push({
    matcher: 'Edit|Write|MultiEdit',
    hooks: [{ type: 'command', command: `${commandPrefix} claude post-tool`, timeout: 15 }]
  });
  hooks.PostToolUse = postList;

  const stopList = stripMarloweEntries(hooks.Stop);
  stopList.push({
    hooks: [{ type: 'command', command: `${commandPrefix} claude stop`, timeout: 30 }]
  });
  hooks.Stop = stopList;

  settings.hooks = hooks;
  await writeJsonPretty(settingsPath, settings);
  return { path: settingsPath };
}

async function installMcpConfig({
  targetDir = process.cwd(),
  command = 'npx',
  args = ['--yes', '@zerotheory-labs/marlowe-ci', 'mcp']
} = {}) {
  const mcpPath = path.join(path.resolve(targetDir), '.mcp.json');
  const existing = await readJsonOrDefault(mcpPath, {});
  const servers = existing.mcpServers && typeof existing.mcpServers === 'object' ? { ...existing.mcpServers } : {};
  servers.marlowe = { command, args };
  existing.mcpServers = servers;
  await writeJsonPretty(mcpPath, existing);
  return { path: mcpPath };
}

const GITHUB_WORKFLOW_TEMPLATE = `name: Marlowe CI Security Guard

on:
  pull_request:
  push:
    branches: [main, master]

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  marlowe-guard:
    name: Marlowe Security Verdict
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Marlowe CI / Guard
        id: marlowe
        uses: zerotheory-labs/marlowe-ci@v0.6.0
        with:
          mode: diff
          fail-on: high
          sarif-file: marlowe.sarif
          comment-pr: 'true'
          github-token: \${{ secrets.GITHUB_TOKEN }}

      - name: Upload SARIF to GitHub Code Scanning
        if: always() && steps.marlowe.outputs.sarif-file != ''
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: marlowe.sarif
          category: marlowe-ci
`;

async function installGitHubWorkflow({ targetDir = process.cwd() } = {}) {
  const workflowPath = path.join(path.resolve(targetDir), '.github', 'workflows', 'marlowe-ci.yml');
  await fs.mkdir(path.dirname(workflowPath), { recursive: true });
  await fs.writeFile(workflowPath, GITHUB_WORKFLOW_TEMPLATE, 'utf8');
  return { path: workflowPath };
}

async function installGitPreCommitHook({
  targetDir = process.cwd(),
  commandPrefix = 'npx --yes @zerotheory-labs/marlowe-ci'
} = {}) {
  const absRoot = path.resolve(targetDir);
  const hookDir = path.join(absRoot, '.git', 'hooks');
  try {
    const stat = await fs.stat(path.join(absRoot, '.git'));
    if (!stat.isDirectory()) throw new Error('Not a regular .git directory.');
  } catch {
    throw new Error(`No .git directory found at ${absRoot}; run "git init" before installing git hooks.`);
  }

  await fs.mkdir(hookDir, { recursive: true });
  const hookPath = path.join(hookDir, 'pre-commit');
  let existing = '';
  try {
    existing = await fs.readFile(hookPath, 'utf8');
  } catch (err) {
    if (!err || err.code !== 'ENOENT') throw err;
  }

  const block = [
    GIT_HOOK_START,
    `${commandPrefix} scan --staged --no-osv --fail-on high`,
    GIT_HOOK_END
  ].join('\n');

  let updated;
  const blockRe = new RegExp(`${GIT_HOOK_START}[\\s\\S]*?${GIT_HOOK_END}`, 'm');
  if (blockRe.test(existing)) {
    updated = existing.replace(blockRe, block);
  } else if (existing.trim()) {
    updated = `${existing.trimEnd()}\n\n${block}\n`;
  } else {
    updated = `#!/bin/sh\nset -e\n\n${block}\n`;
  }

  await fs.writeFile(hookPath, updated, { mode: 0o755 });
  await fs.chmod(hookPath, 0o755);
  return { path: hookPath };
}

const AGENT_GUARD_RULE_TEXT = `# Marlowe Guardrails

1. Verify untrusted inputs (HTTP, URL, DOM, CLI) and parameterize SQL/shell calls — never interpolate untrusted data.
2. Never read, print, or transmit \`.env*\`, \`.ssh/\`, \`.aws/\`, \`.shirudo/\`, or \`*.pem\`/\`*.key\` files.
3. Run \`marlowe_scan_diff\` (or \`npx --yes @zerotheory-labs/marlowe-ci scan\`) before finishing security-sensitive edits.
4. Confirm any \`CAN'T TELL\` finding instead of adding inline scanner suppression comments.
`;

async function installCursorConfig({
  targetDir = process.cwd(),
  command = 'npx',
  args = ['--yes', '@zerotheory-labs/marlowe-ci', 'mcp']
} = {}) {
  const absRoot = path.resolve(targetDir);
  const mcpPath = path.join(absRoot, '.cursor', 'mcp.json');
  const existing = await readJsonOrDefault(mcpPath, {});
  const servers = existing.mcpServers && typeof existing.mcpServers === 'object' ? { ...existing.mcpServers } : {};
  servers.marlowe = { command, args };
  existing.mcpServers = servers;
  await writeJsonPretty(mcpPath, existing);

  const rulePath = path.join(absRoot, '.cursor', 'rules', 'marlowe-guard.mdc');
  await fs.mkdir(path.dirname(rulePath), { recursive: true });
  await fs.writeFile(
    rulePath,
    `---\ndescription: Marlowe CI read-only security guardrails\nalwaysApply: true\n---\n\n${AGENT_GUARD_RULE_TEXT}`,
    'utf8'
  );
  return { path: mcpPath, rulePath };
}

async function installVscodeConfig({
  targetDir = process.cwd(),
  command = 'npx',
  args = ['--yes', '@zerotheory-labs/marlowe-ci', 'mcp']
} = {}) {
  const absRoot = path.resolve(targetDir);
  const mcpPath = path.join(absRoot, '.vscode', 'mcp.json');
  const existing = await readJsonOrDefault(mcpPath, {});
  const servers = existing.servers && typeof existing.servers === 'object' ? { ...existing.servers } : {};
  servers.marlowe = { type: 'stdio', command, args };
  existing.servers = servers;
  await writeJsonPretty(mcpPath, existing);
  return { path: mcpPath };
}

async function installCodexConfig({
  targetDir = process.cwd(),
  command = 'npx',
  args = ['--yes', '@zerotheory-labs/marlowe-ci', 'mcp']
} = {}) {
  const absRoot = path.resolve(targetDir);
  const configPath = path.join(absRoot, '.codex', 'config.toml');
  await fs.mkdir(path.dirname(configPath), { recursive: true });

  let existing = '';
  try {
    existing = await fs.readFile(configPath, 'utf8');
  } catch (err) {
    if (!err || err.code !== 'ENOENT') throw err;
  }

  const serializedArgs = JSON.stringify(args);
  const block = [
    CODEX_MCP_START,
    '[mcp_servers.marlowe]',
    `command = ${JSON.stringify(command)}`,
    `args = ${serializedArgs}`,
    CODEX_MCP_END
  ].join('\n');

  const blockRe = new RegExp(`${CODEX_MCP_START}[\\s\\S]*?${CODEX_MCP_END}`, 'm');
  let updated;
  if (blockRe.test(existing)) {
    updated = existing.replace(blockRe, block);
  } else if (existing.trim()) {
    updated = `${existing.trimEnd()}\n\n${block}\n`;
  } else {
    updated = `${block}\n`;
  }

  await fs.writeFile(configPath, updated, 'utf8');
  return { path: configPath };
}

async function installWindsurfConfig({
  targetDir = process.cwd(),
  command = 'npx',
  args = ['--yes', '@zerotheory-labs/marlowe-ci', 'mcp']
} = {}) {
  const absRoot = path.resolve(targetDir);
  const mcpPath = path.join(absRoot, '.windsurf', 'mcp.json');
  const existing = await readJsonOrDefault(mcpPath, {});
  const servers = existing.mcpServers && typeof existing.mcpServers === 'object' ? { ...existing.mcpServers } : {};
  servers.marlowe = { command, args };
  existing.mcpServers = servers;
  await writeJsonPretty(mcpPath, existing);

  const rulePath = path.join(absRoot, '.windsurf', 'rules', 'marlowe-guard.md');
  await fs.mkdir(path.dirname(rulePath), { recursive: true });
  await fs.writeFile(rulePath, `---\ntrigger: always_on\n---\n\n${AGENT_GUARD_RULE_TEXT}`, 'utf8');
  return { path: mcpPath, rulePath };
}

module.exports = {
  parseCommandPrefix,
  installClaudeHooks,
  installMcpConfig,
  installCursorConfig,
  installVscodeConfig,
  installCodexConfig,
  installWindsurfConfig,
  installGitHubWorkflow,
  installGitPreCommitHook
};
