const fs = require('node:fs/promises');
const { devNull, tmpdir } = require('node:os');
const path = require('node:path');
const { runGit, commitId, isObjectId } = require('./engine/git-diff.cjs');

const PUSH_PAYLOAD_COMMIT_LIMIT = 2048;

async function isAncestor(root, before, after) {
  try {
    await runGit(root, ['merge-base', '--is-ancestor', before, after]);
    return true;
  } catch (err) {
    if (err.code === 1) return false;
    throw err;
  }
}

async function listCommitRanges(root, previous, head, emptyTree, { commits, size }) {
  // Git history covers an existing ref even when GitHub truncates the event.
  let revisions = ['--reverse', '--topo-order', previous ? `${previous}..${head}` : head];
  if (!previous && Array.isArray(commits)) {
    // A complete new-ref payload excludes commits that predate the branch.
    const complete = size === undefined ? commits.length < PUSH_PAYLOAD_COMMIT_LIMIT : commits.length === size;
    if (complete) {
      if (!commits.length) return [];
      const ids = commits.map(commit => commit?.id);
      if (!ids.every(isObjectId)) throw new Error('Invalid commit ID in the GitHub push event.');
      revisions = ['--no-walk=unsorted', ...ids];
    }
  }

  const { stdout } = await runGit(root, ['rev-list', '--parents', ...revisions, '--']);
  const ranges = [];
  for (const line of stdout.trim().split('\n').filter(Boolean)) {
    const [commit, firstParent] = line.split(' ');
    if (!firstParent) {
      // A shallow boundary looks like a root to rev-list even when its commit has parents.
      const object = await runGit(root, ['cat-file', '-p', commit]);
      if (/^parent /m.test(object.stdout.split('\n\n', 1)[0])) throw new Error('Incomplete commit history.');
    }
    ranges.push({ headRef: commit, baseRef: firstParent || emptyTree });
  }
  return ranges;
}

async function resolvePushRange(root, explicitBase) {
  let event;
  try {
    event = JSON.parse(await fs.readFile(process.env.GITHUB_EVENT_PATH, 'utf8'));
  } catch (cause) {
    throw new Error('Cannot read the GitHub push event to determine the pushed commits.', { cause });
  }
  const { before, after } = event || {};
  if (!isObjectId(after) || (!explicitBase && !isObjectId(before))) {
    throw new Error('The GitHub push event is missing valid before/after object IDs.');
  }
  if (/^0+$/.test(after)) return null;

  const head = await commitId(root, after);
  if (head !== (await commitId(root, 'HEAD'))) {
    throw new Error('The checkout does not match the push event after SHA. Check out the pushed commit before running Marlowe.');
  }
  try {
    const newRef = !explicitBase && /^0+$/.test(before);
    const previous = newRef ? '' : await commitId(root, explicitBase || before);
    const { stdout: empty } = await runGit(root, ['hash-object', '-t', 'tree', devNull]);
    const emptyTree = empty.trim();

    const ranges = await listCommitRanges(root, previous, head, emptyTree, event);
    // Creating or moving a ref backwards/sideways can expose files inherited from older commits.
    if (newRef || !(await isAncestor(root, previous, head))) {
      const baseRef = previous || emptyTree;
      if (!ranges.some(range => range.headRef === head && range.baseRef === baseRef)) {
        ranges.push({ headRef: head, baseRef });
      }
    }
    return ranges;
  } catch (cause) {
    throw new Error('Cannot resolve the push range. Fetch the previous tip and use fetch-depth: 0 in checkout.', { cause });
  }
}

async function* pushSnapshots(workspace, ranges) {
  if (!ranges.length) return;
  const dir = await fs.mkdtemp(path.join(tmpdir(), 'marlowe-push-'));
  const root = path.join(await fs.realpath(dir), 'snapshot');
  const config = ['-c', `core.hooksPath=${devNull}`, '-c', 'core.sparseCheckout=false'];
  let registered = false;
  try {
    await runGit(workspace, [...config, 'worktree', 'add', '--quiet', '--detach', '--no-checkout', root, ranges[0].headRef]);
    registered = true;
    let checkedOut;
    for (const { baseRef, headRef } of ranges) {
      if (checkedOut !== headRef) {
        await runGit(root, [...config, 'checkout', '--quiet', '--detach', '--force', '--no-recurse-submodules', headRef]);
        checkedOut = headRef;
      }
      yield { root, baseRef, headRef, commitSha: headRef };
    }
  } finally {
    try {
      if (registered) await runGit(workspace, [...config, 'worktree', 'remove', '--force', root]);
    } finally {
      await fs.rm(dir, { recursive: true, force: true });
    }
  }
}

module.exports = { resolvePushRange, pushSnapshots };
