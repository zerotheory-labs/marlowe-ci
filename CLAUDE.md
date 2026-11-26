# CLAUDE.md

Guidance for AI coding agents and maintainers working in `zerotheory-labs/marlowe-ci`.

## What This Repository Is

**Marlowe CI / Guard** (`@zerotheory-labs/marlowe-ci`, MCP Registry `io.github.zerotheory-labs/marlowe-ci`) is Zero Theory Labs' **zero-dependency**, source-available (`PolyForm-Noncommercial-1.0.0`) security guardrail CLI, Claude Code hook runtime, 13-tool read-only `stdio` MCP server, and GitHub Marketplace Action (`node24`).

Every audit emits an explicit three-state verdict — **`HOLDS UP`**, **`FAILS`**, or **`CAN'T TELL`** — never rounding unknown evidence up to a pass.

## Essential Commands

Requires **Node.js `>=20.0.0`** (CI runs on Node `20` and `22`). Zero runtime `dependencies` allowed.

```sh
npm test                  # Run full node --test suite across test/*.test.cjs
npm run bench             # Run 33-scenario reproducible diff benchmark -> benchmarks/results.json
npm run self-check        # Run Marlowe CI against its own workspace diff (--no-osv)
npm pack --dry-run        # Inspect npm tarball whitelist (excludes test/, benchmarks/, docs/)
```

## Architecture

- `bin/marlowe-ci.cjs`: CLI entry (`scan`, `baseline`, `recon`, `dfir`, `shirudo`, `claude`, `mcp`, `init`, `doctor`).
- `src/engine/`: Core diff/full audit pipeline (`verdict.cjs`, `git-diff.cjs`, `regressions.cjs`, `baseline.cjs`, `format.cjs`).
  - `checkPackageJsonAddedRisk` inspects dependency blocks only (`dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`), not `repository.url` / metadata.
  - `regressions.cjs` exempts non-code docs and JSON metadata manifests from removed-control heuristics.
- `src/core/`:
  - `fs-safe.cjs`: Workspace confinement (`realpath`, `O_NOFOLLOW`, `nlink === 1`, blocked credential segments including `.shirudo`, `shirudo-keys`, `.env*`, `.ssh`, `.aws`, `.gnupg`, `.npmrc`, `.netrc`).
  - `cyber-scope.cjs`: `ScopeGate` + SSRF / DNS-rebinding guard + `redactSecrets` / `maskToken`.
  - `cyber-analyzers.cjs`: Secrets, CWE sinks, 2-hop cross-file reachability (`inspectSourceReachability`), OSV dependency checks, HTTP/TLS/DNS recon, DFIR log/IOC triage, and Shannon entropy.
  - `agent-guard.cjs`: Trojan Source bidirectional Unicode (`CWE-116`), Unicode tag/zero-width smuggling, indirect prompt injection (`CWE-74`), npm lifecycle script rug-pulls (`CWE-506`), and untrusted MCP configs.
  - `shirudo.cjs`: 10-rule pure-Node static verifier across `.bpf.c` (`SHIRUDO-BPF-001..004`), `Beefile` (`SHIRUDO-BEE-001..003`), and TPM 2.0 attestation workflows/evidence JSON (`SHIRUDO-TPM-001..003`), plus `shirudo status --check` and offline-enforced `verifyShirudoAttestation`.
  - `findings.cjs`: Normalizer + SARIF v2.1.0 generator (`ruleId` first-class when set, falling back to `cwe`) + Markdown report builder.
- `src/integrations/`:
  - `claude-hooks.cjs`: `PreToolUse` (blocks sensitive paths, SSRF, `curl | sh`, Bash Trojan Source, dangerous `Beefile` generators `SHIRUDO-BEE-002`, and unpinned/self-asserted `shirudo attest` / `status` commands `SHIRUDO-TPM-001`/`003`), `PostToolUse` (masked secret + CWE + `agent-guard` + `shirudo` feedback), and loop-safe `Stop` hook.
  - `mcp-server.cjs`: Strict newline-delimited JSON-RPC 2.0 `stdio` server exposing 13 read-only tools. Diagnostics must NEVER be written to `stdout`.
  - `init.cjs`: Idempotent installers for Claude hooks, `.mcp.json`, `--cursor`, `--vscode`, `--codex`, `--windsurf`, `--all-agents`, `--github`, and `--git-hook`.

## Guardrail Hygiene When Editing This Repo

- **Self-check discipline:** Keep `npm run self-check` returning **`HOLDS UP`**. In test fixtures and benchmarks, split synthetic secrets (`'AKIA' + '...'`), SQL strings (`'SEL' + 'ECT ...'`), suppression words (`'nosem' + 'grep'`), and Unicode control characters (`String.fromCodePoint(0x202e)`), and keep detection patterns on `const ..._RE =` lines.
- **No secrets or personal paths:** Never commit `.mcpregistry_*` tokens or personal filesystem paths anywhere in tracked files.
- **Keep README.md / server.json / action.yml in sync:** Bump versions consistently across `package.json`, `server.json`, `init.cjs` workflow template, banner SVGs, `README.md`, and `SECURITY.md`.
- **OIDC publishing:** `.github/workflows/release-npm-mcp.yml` automates npm (`--provenance` via Trusted Publishing) and MCP Registry (`mcp-publisher login github-oidc`); `.github/workflows/publish-mcp.yml` syncs `server.json` independently. `server.json` `description` must remain `<= 100` characters.
