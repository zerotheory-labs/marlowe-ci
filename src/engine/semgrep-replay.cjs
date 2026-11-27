const fs = require('node:fs/promises');
const { devNull, tmpdir } = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { resolveToolBinary, safeSearchDirs } = require('../core/cyber-toolchain.cjs');
const { isProtectedRelPath } = require('../core/fs-safe.cjs');
const { runGit, commitId, parseUnifiedDiff } = require('./git-diff.cjs');

const execFileAsync = promisify(execFile);

function repoPath(value) {
  if (typeof value !== 'string' || !value || value.length > 4096 || /[\\:\x00-\x1f*?"<>|]/.test(value) ||
      value.split('/').some(part => !part || part === '.' || /[. ]$/.test(part)) || isProtectedRelPath(value)) {
    throw new Error('Expected a regular repository-relative path.');
  }
  return value;
}

// Read Git blobs directly. A PR can change symlinks, attributes and checkout filters.
async function readBlob(root, sha, file, optional = false) {
  const { stdout } = await runGit(root, ['--literal-pathspecs', 'ls-tree', '-l', sha, '--', file]);
  if (!stdout && optional) return null;
  const match = /^100(?:644|755) blob ([0-9a-f]+)\s+(\d+)\t/.exec(stdout);
  if (!match || Number(match[2]) > 1024 * 1024) {
    throw new Error(`Expected a committed regular file up to 1 MiB at ${file} (${sha.slice(0, 12)}).`);
  }
  const blob = await runGit(root, ['cat-file', 'blob', match[1]]);
  if (blob.stdout.includes('\0')) throw new Error(`Expected text in ${file}.`);
  return blob.stdout;
}

async function loadSpec(root, sha, manifest) {
  const text = await readBlob(root, sha, repoPath(manifest));
  let spec;
  try { spec = JSON.parse(text); } catch { throw new Error('Invalid JSON in the base replay manifest.'); }
  const config = repoPath(spec?.config);
  const target = repoPath(spec?.target);
  if (!/\.(?:ya?ml|json)$/i.test(config)) throw new Error('The replay config must be a local Semgrep YAML or JSON file.');
  if (typeof spec.rule !== 'string' || !/^[\w.-]+$/.test(spec.rule)) throw new Error('Expected a Semgrep rule ID in the base manifest.');
  const fixture = await readBlob(root, sha, repoPath(spec.fixture));
  return { config, rule: spec.rule, target, fixture };
}

async function snapshotInputs(root, sha, spec) {
  const files = new Map([[spec.config, await readBlob(root, sha, spec.config)]]);
  const directory = path.posix.dirname(spec.target);
  if (directory !== '.') {
    const tree = await runGit(root, ['cat-file', '-t', `${sha}:${directory}`]).catch(() => null);
    if (tree?.stdout.trim() !== 'tree') throw new Error(`Missing target directory ${directory} at ${sha.slice(0, 12)}.`);
  }
  // Only ancestors of the fixture can contribute ignore rules. Let Semgrep
  // interpret them, including rule-level paths in the original scanner config.
  const pending = [];
  for (let dir = directory; ; dir = path.posix.dirname(dir)) {
    for (const name of ['.gitignore', '.semgrepignore']) {
      pending.push({ file: path.posix.join(dir, name), optional: true });
    }
    if (dir === '.') break;
  }
  for (const { file, optional } of pending) {
    if (files.has(file)) continue;
    if (pending.length > 256) throw new Error('Too many replay configuration files.');
    const text = await readBlob(root, sha, file, optional);
    if (text === null) continue;
    files.set(file, text);
    if (path.posix.basename(file) !== '.semgrepignore' && optional) continue;
    for (const line of text.split(/\r?\n/)) {
      const include = /^:include\s+(.+)$/.exec(line.trim());
      if (!include) continue;
      const relative = include[1].trim();
      if (relative.startsWith('~') || path.posix.isAbsolute(relative)) {
        throw new Error('An ignore include points outside the replay repository.');
      }
      pending.push({ file: repoPath(path.posix.join(path.posix.dirname(file), relative)), optional: false });
    }
  }
  if (files.has(spec.target)) throw new Error('The replay target collides with a configuration file.');
  return files;
}

async function scanSide({ root, side, sha, spec, scratch, binary, env, signal }) {
  const inputs = await snapshotInputs(root, sha, spec);
  const cwd = path.join(scratch, side);
  const target = path.join(cwd, spec.target);
  await fs.mkdir(path.dirname(target), { recursive: true });
  await fs.writeFile(target, spec.fixture);
  await runGit(cwd, ['init', '--quiet', '--template='], env);
  await runGit(cwd, ['add', '--force', '--', spec.target], env);
  for (const [file, content] of inputs) {
    const dest = path.join(cwd, file);
    await fs.mkdir(path.dirname(dest), { recursive: true });
    await fs.writeFile(dest, content, { flag: 'wx' });
  }

  // A directory target exercises Semgrep's normal file discovery and exclusions.
  const args = ['scan', '--json', '--quiet', '--strict', '--metrics=off', '--disable-version-check',
    '--no-rewrite-rule-ids', '--config', `./${spec.config}`, '--', '.'];
  let report;
  try {
    const { stdout } = await execFileAsync(binary, args, { cwd, env, signal, timeout: 60000, maxBuffer: 4 * 1024 * 1024 });
    report = JSON.parse(stdout);
  } catch (err) {
    const detail = err.killed ? 'timed out' : err.code ? `exited with ${err.code}` : 'returned invalid JSON';
    throw new Error(`Semgrep ${detail} on the ${side} configuration.`);
  }
  if (!Array.isArray(report?.results) || !Array.isArray(report.errors) || report.errors.length ||
      report.skipped_rules?.length || !Array.isArray(report.paths?.scanned)) {
    throw new Error(`Semgrep returned incomplete results on the ${side} configuration.`);
  }
  const isTarget = file => typeof file === 'string' && path.resolve(cwd, file) === target;
  const matched = report.results.some(r => r.check_id === spec.rule && isTarget(r.path) && !r.extra?.is_ignored);
  const scanned = report.paths.scanned.some(isTarget);
  let outcome = 'not scanned';
  if (scanned) outcome = 'scanned without a match';
  if (matched) outcome = 'matched';
  return { inputs, outcome };
}

async function runSemgrepReplay({ root, manifest, baseRef, headRef, signal }) {
  const result = { status: 'inconclusive', base: {}, head: {}, changedConfigs: [] };
  let scratch;
  try {
    if (!baseRef || !headRef) throw new Error('The replay requires both base and PR commit IDs.');
    try {
      result.base.commit = await commitId(root, baseRef);
      result.head.commit = await commitId(root, headRef);
    } catch { throw new Error('A replay commit is unavailable. Fetch the base and PR head with fetch-depth: 0.'); }

    const spec = await loadSpec(root, result.base.commit, manifest);
    Object.assign(result, { config: spec.config, rule: spec.rule, target: spec.target });
    const dirs = await safeSearchDirs(process.env.PATH, root);
    const commandPath = dirs.join(path.delimiter);
    const binary = await resolveToolBinary('semgrep', commandPath, root);
    if (!binary) throw new Error('Install Semgrep on the runner PATH to replay this fixture.');
    scratch = await fs.realpath(await fs.mkdtemp(path.join(tmpdir(), 'marlowe-semgrep-')));
    const env = {
      PATH: commandPath, XDG_CONFIG_HOME: scratch, XDG_CACHE_HOME: scratch, SEMGREP_ENABLE_VERSION_CHECK: '0',
      GIT_CONFIG_GLOBAL: devNull, GIT_CONFIG_NOSYSTEM: '1', GIT_ATTR_NOSYSTEM: '1',
      ...(process.env.SSL_CERT_FILE && { SSL_CERT_FILE: process.env.SSL_CERT_FILE }),
      ...(process.env.SystemRoot && { SystemRoot: process.env.SystemRoot })
    };
    const runs = {};
    const errors = [];
    for (const side of ['base', 'head']) {
      try {
        runs[side] = await scanSide({ root, side, sha: result[side].commit, spec, scratch, binary, env, signal });
        result[side].outcome = runs[side].outcome;
      } catch (err) {
        result[side].outcome = 'unavailable';
        errors.push(`${side}: ${err.message}`);
      }
    }
    if (errors.length) throw new Error(errors.join(' '));
    const paths = new Set([...runs.base.inputs.keys(), ...runs.head.inputs.keys()]);
    result.changedConfigs = [...paths].filter(file => runs.base.inputs.get(file) !== runs.head.inputs.get(file));
    if (result.base.outcome !== 'matched') {
      throw new Error(`The base configuration did not detect ${spec.rule} in ${spec.target}.`);
    }
    if (result.head.outcome !== 'matched' && !result.changedConfigs.length) {
      throw new Error('Semgrep returned different outcomes for identical replay inputs.');
    }
    result.status = result.head.outcome === 'matched' ? 'preserved' : 'regression';
    if (result.status === 'regression' && result.changedConfigs.length === 1) {
      const [file] = result.changedConfigs;
      const diff = await runGit(root, ['--literal-pathspecs', 'diff', '--no-ext-diff', '--no-textconv',
        '--unified=0', result.base.commit, result.head.commit, '--', file]).catch(() => null);
      const [change] = parseUnifiedDiff(diff?.stdout);
      // Only attribute a line when there is a single candidate in the head.
      if (change?.addedLines.length === 1) result.changedLine = change.addedLines[0].line;
    }
  } catch (err) {
    result.reason = err.message;
  } finally {
    if (scratch) await fs.rm(scratch, { recursive: true, force: true });
  }
  return result;
}

module.exports = { runSemgrepReplay };
