const { setTimeout: sleep } = require('node:timers/promises');

async function waitForNpmVersion({ name, version }, {
  ref, request = fetch, pause = sleep, maxAttempts = 40
} = {}) {
  if (ref?.startsWith('refs/tags/')) {
    const tag = ref.slice('refs/tags/'.length);
    if (tag !== version && tag !== `v${version}`) {
      throw new Error(`Git tag ${tag} does not match package version ${version}`);
    }
  }

  const spec = `${name}@${version}`;
  // The MCP Registry requests this exact URL, including the escaped slash in scoped names.
  const url = `https://registry.npmjs.org/${name.replace('/', '%2F')}/${encodeURIComponent(version)}`;
  async function checkRegistry() {
    let response, metadata;
    try {
      response = await request(url, {
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(10_000)
      });
      if (response.status === 200) metadata = await response.json();
      else await response.body?.cancel();
    } catch (error) {
      return `registry request failed (${error.message})`;
    }

    if (response.status === 200) {
      if (metadata?.name !== name || metadata?.version !== version) {
        throw new Error(`Expected ${spec} from npm, got ${metadata?.name}@${metadata?.version}`);
      }
      return null;
    }
    if ([404, 408, 429].includes(response.status) || response.status >= 500) {
      return `HTTP ${response.status}`;
    }
    throw new Error(`npm returned HTTP ${response.status} for ${spec}`);
  }

  for (let attempt = 1; ; attempt++) {
    const reason = await checkRegistry();
    if (reason === null) {
      console.log(`npm serves ${spec}`);
      return;
    }
    if (attempt >= maxAttempts) {
      throw new Error(`npm did not serve ${spec} after ${attempt} attempts (${reason})`);
    }
    console.log(`Waiting for ${spec} on npm (attempt ${attempt}/${maxAttempts}, ${reason})`);
    await pause(15_000);
  }
}

if (require.main === module) {
  waitForNpmVersion(require('../package.json'), { ref: process.env.GITHUB_REF }).catch(error => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

module.exports = { waitForNpmVersion };
