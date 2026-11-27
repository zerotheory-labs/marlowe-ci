const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const path = require('node:path');
const { resolveWithinRoot, readRegularTextFile, isProtectedRelPath } = require('../core/fs-safe.cjs');

const execFileAsync = promisify(execFile);
const GIT_TIMEOUT_MS = 15000;
const GIT_MAX_BUFFER = 12 * 1024 * 1024;

function runGit(root, args) {
  return execFileAsync('git', args, {
    cwd: root,
    shell: false,
    timeout: GIT_TIMEOUT_MS,
    maxBuffer: GIT_MAX_BUFFER,
    env: { ...process.env, GIT_TERMINAL_PROMPT: '0', LC_ALL: 'C' }
  });
}

function unquoteGitPath(rawPath) {
  const trimmed = String(rawPath || '').trim();
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    try {
      return JSON.parse(trimmed);
    } catch {
      return trimmed.slice(1, -1);
    }
  }
  return trimmed;
}

function parseUnifiedDiff(diffText) {
  if (!diffText || typeof diffText !== 'string') return [];
  const lines = diffText.split(/\r?\n/);
  const files = [];
  let current = null;
  let oldLine = 0;
  let newLine = 0;
  let inHunk = false;

  const flush = () => {
    if (current) files.push(current);
    current = null;
    inHunk = false;
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line.startsWith('diff --git ')) {
      flush();
      const rest = line.slice('diff --git '.length);
      const match = /^"?a\/(.+?)"?\s+"?b\/(.+?)"?$/.exec(rest);
      const filePath = match ? unquoteGitPath(match[2]) : '';
      current = {
        path: filePath,
        oldPath: match ? unquoteGitPath(match[1]) : filePath,
        status: 'modified',
        isBinary: false,
        addedLines: [],
        removedLines: []
      };
      continue;
    }

    if (!current) continue;

    if (!inHunk) {
      if (line.startsWith('new file mode ')) {
        current.status = 'added';
        continue;
      }
      if (line.startsWith('deleted file mode ')) {
        current.status = 'deleted';
        continue;
      }
      if (line.startsWith('rename to ')) {
        current.status = 'renamed';
        current.path = unquoteGitPath(line.slice('rename to '.length));
        continue;
      }
      if (line.startsWith('--- ')) continue;
      if (line.startsWith('+++ ')) {
        const rhs = line.slice(4).trim();
        if (rhs !== '/dev/null') {
          const clean = unquoteGitPath(rhs).replace(/^b\//, '');
          if (clean) current.path = clean;
        }
        continue;
      }
      if (line.startsWith('Binary files ') || line === 'GIT binary patch') {
        current.isBinary = true;
        continue;
      }
    }

    if (line.startsWith('@@ ')) {
      const hunkMatch = /^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@/.exec(line);
      if (hunkMatch) {
        oldLine = Number(hunkMatch[1]);
        newLine = Number(hunkMatch[3]);
        inHunk = true;
      }
      continue;
    }

    if (!inHunk) continue;

    if (line.startsWith('+') && !line.startsWith('+++ ')) {
      current.addedLines.push({ line: newLine, text: line.slice(1) });
      newLine++;
    } else if (line.startsWith('-') && !line.startsWith('--- ')) {
      current.removedLines.push({ line: oldLine, text: line.slice(1) });
      oldLine++;
    } else if (line.startsWith(' ')) {
      oldLine++;
      newLine++;
    } else if (line.startsWith('\\ No newline')) {
      continue;
    }
  }

  flush();
  return files.filter(f => f.path);
}

async function synthesizeUntrackedFiles(root) {
  const { stdout } = await runGit(root, ['ls-files', '--others', '--exclude-standard', '-z']);
  const relPaths = stdout.split('\0').map(s => s.trim()).filter(Boolean);
  const added = [];
  for (const rel of relPaths.slice(0, 400)) {
    if (isProtectedRelPath(rel)) continue;
    let resolved;
    try {
      resolved = await resolveWithinRoot(root, rel);
    } catch {
      continue;
    }
    try {
      const text = await readRegularTextFile(resolved.fullPath);
      const addedLines = text.split('\n').map((raw, idx) => ({
        line: idx + 1,
        text: raw.replace(/\r$/, '')
      }));
      added.push({
        path: resolved.relPath,
        oldPath: resolved.relPath,
        status: 'added',
        isBinary: false,
        addedLines,
        removedLines: []
      });
    } catch (err) {
      const isBin = /Binary file/i.test(err?.message || '');
      added.push({
        path: resolved.relPath,
        oldPath: resolved.relPath,
        status: 'added',
        isBinary: isBin,
        addedLines: [],
        removedLines: []
      });
    }
  }
  return added;
}

async function getGitDiff(root, { staged = false, baseRef = '', headRef = '' } = {}) {
  const absRoot = path.resolve(root);
  try {
    const { stdout } = await runGit(absRoot, ['rev-parse', '--is-inside-work-tree']);
    if (stdout.trim() !== 'true') {
      return { inGitRepo: false, files: [], error: 'Not inside a Git work tree.' };
    }
  } catch {
    return { inGitRepo: false, files: [], error: 'Git repository not found or git CLI unavailable.' };
  }

  let diffText = '';
  if (staged) {
    const { stdout } = await runGit(absRoot, ['diff', '--cached', '--unified=0', '--no-color']);
    diffText = stdout;
    return { inGitRepo: true, files: parseUnifiedDiff(diffText) };
  }

  if (baseRef) {
    if (baseRef.startsWith('-')) throw new Error('Invalid baseRef.');
    if (headRef) {
      if (headRef.startsWith('-')) throw new Error('Invalid headRef.');
      // A push replaces one tree with another, including on divergent or rewound branches.
      const { stdout } = await runGit(absRoot, ['diff', '--unified=0', '--no-color', baseRef, headRef, '--']);
      return { inGitRepo: true, files: parseUnifiedDiff(stdout) };
    }
    try {
      const { stdout } = await runGit(absRoot, ['diff', '--unified=0', '--no-color', `${baseRef}...HEAD`]);
      diffText = stdout;
    } catch {
      const { stdout } = await runGit(absRoot, ['diff', '--unified=0', '--no-color', baseRef, 'HEAD']);
      diffText = stdout;
    }
    return { inGitRepo: true, files: parseUnifiedDiff(diffText) };
  }

  // Working tree mode: staged + unstaged relative to HEAD (or index when repo has zero commits) + untracked files.
  let hasHead = true;
  try {
    await runGit(absRoot, ['rev-parse', '--verify', 'HEAD']);
  } catch {
    hasHead = false;
  }

  if (hasHead) {
    const { stdout } = await runGit(absRoot, ['diff', '--unified=0', '--no-color', 'HEAD']);
    diffText = stdout;
  } else {
    const [cachedRes, workingRes] = await Promise.all([
      runGit(absRoot, ['diff', '--cached', '--unified=0', '--no-color']),
      runGit(absRoot, ['diff', '--unified=0', '--no-color'])
    ]);
    diffText = `${cachedRes.stdout}\n${workingRes.stdout}`;
  }

  const parsed = parseUnifiedDiff(diffText);
  const seenPaths = new Set(parsed.map(f => f.path));
  const untracked = await synthesizeUntrackedFiles(absRoot);
  for (const item of untracked) {
    if (!seenPaths.has(item.path)) {
      seenPaths.add(item.path);
      parsed.push(item);
    }
  }

  return { inGitRepo: true, files: parsed };
}

module.exports = {
  runGit,
  parseUnifiedDiff,
  getGitDiff
};
