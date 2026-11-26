# Security Policy

## Supported Versions

| Version | Supported | Runtime |
| --- | --- | --- |
| `0.6.x` | Yes | Node.js `>=20.0.0` (macOS, Linux, Windows, GitHub Actions `node24`) |
| `< 0.6.0` | No | Superseded |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for suspected security vulnerabilities in Marlowe CI / Guard (such as `ScopeGate` / SSRF bypasses, `PROTECTED_SEGMENTS_RE` / symlink traversal bypasses, hook `stdout` JSON injection, `agent-guard` bypasses, `SHIRUDO-*` rule bypasses, or CLI argument/shell injection).

Report vulnerabilities privately through **GitHub Private Vulnerability Reporting**:

- `https://github.com/zerotheory-labs/marlowe-ci/security/advisories/new`

Or contact `access@zerotheorylabs.com` with reproduction steps, expected boundary vs. observed behavior, and commit hash.

## Enforced Trust Boundaries

- **Workspace & Symlink Confinement (`src/core/fs-safe.cjs`):** File inspections open files with `O_RDONLY | O_NOFOLLOW`, verify `stat.isFile()` and `nlink === 1`, resolve symlinks against the realpath of the workspace root, and refuse protected secret paths (`.git`, `.ssh`, `.aws`, `.gnupg`, `.codex`, `.shirudo`, `shirudo-keys`, `.npmrc`, `.netrc`, `.pypirc`, `.env` / `.env.*` other than safe templates, `*.pem`, `*.key`).
- **ScopeGate & SSRF Confinement (`src/core/cyber-scope.cjs`):** Network targets validate against `.marlowe-scope.json` / `.marlowe.json` and refuse loopback, RFC1918, link-local, cloud metadata (`169.254.169.254`), and embedded URL credentials unless explicitly authorized.
- **Agent Supply-Chain & Prompt-Injection Guard (`src/core/agent-guard.cjs`):** Detects Trojan Source bidirectional Unicode (`CWE-116`), Unicode tag/zero-width smuggling, indirect prompt injection in agent instruction files & HTML comments (`CWE-74`), malicious package lifecycle hooks (`CWE-506`), and untrusted MCP server configs across diffs and `PreToolUse` / `PostToolUse` hooks.
- **Shirudo eBPF, Beefile & TPM Verification (`src/core/shirudo.cjs`):** Enforces 10 static rules (`SHIRUDO-BPF-001..004`, `SHIRUDO-BEE-001..003`, `SHIRUDO-TPM-001..003`) across `.bpf.c` upatches, `Beefile` manifests (`[[upatches.rodata]]` generator RCE & selector/policy invariants), and offline TPM 2.0 `ev.json` / CI workflows (`--ak-name` pinning, PCR 11 / `0x01818E00` / `reset_count`, `shirudo status --check`).
- **No Shell Interpolation (`shell: false`):** All git commands (`execFile('git', ...)`) and external security CLIs (`spawn(binaryPath, argv, { shell: false })`) execute without shell interpolation against clean, workspace-excluded `PATH` directories.
- **Hook & MCP Stdout Purity:** Claude Code hooks (`marlowe-ci claude ...`) and the `stdio` MCP server (`marlowe-ci mcp`) emit strictly framed JSON on `stdout`; diagnostics never leak into `stdout`.
