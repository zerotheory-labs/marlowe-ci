<div align="center">

<p>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./docs/assets/marlowe-ci-banner-dark.svg" />
    <source media="(prefers-color-scheme: light)" srcset="./docs/assets/marlowe-ci-banner-light.svg" />
    <img alt="Marlowe CI. — Guardrails for AI agents and pull requests. By Zero Theory Labs." src="./docs/assets/marlowe-ci-banner-dark.svg" width="100%" />
  </picture>
</p>

<p>
  <a href="https://github.com/zerotheory-labs/marlowe-ci/releases/tag/v0.6.0"><img alt="Release v0.6.0" src="https://img.shields.io/badge/release-v0.6.0-3ddc97?style=flat-square&labelColor=181714" /></a>&nbsp;&nbsp;
  <a href="https://www.npmjs.com/package/@zerotheory-labs/marlowe-ci"><img alt="npm @zerotheory-labs/marlowe-ci" src="https://img.shields.io/badge/npm-%40zerotheory--labs%2Fmarlowe--ci-3ddc97?style=flat-square&labelColor=181714" /></a>&nbsp;&nbsp;
  <a href="https://registry.modelcontextprotocol.io/v0/servers?search=io.github.zerotheory-labs/marlowe-ci"><img alt="MCP Registry io.github.zerotheory-labs/marlowe-ci" src="https://img.shields.io/badge/MCP_Registry-io.github.zerotheory--labs-3ddc97?style=flat-square&labelColor=181714" /></a>&nbsp;&nbsp;
  <a href="./LICENSE"><img alt="License: PolyForm Noncommercial 1.0.0" src="https://img.shields.io/badge/license-PolyForm_Noncommercial_1.0.0-e5c07b?style=flat-square&labelColor=181714" /></a>&nbsp;&nbsp;
  <a href="./package.json"><img alt="Node.js >= 20" src="https://img.shields.io/badge/node-%3E%3D20-3ddc97?style=flat-square&labelColor=181714" /></a>&nbsp;&nbsp;
  <a href="./package.json"><img alt="Zero Dependencies" src="https://img.shields.io/badge/dependencies-0-3ddc97?style=flat-square&labelColor=181714" /></a>&nbsp;&nbsp;
  <a href="./server.json"><img alt="13 MCP Tools" src="https://img.shields.io/badge/MCP_tools-13_read--only-3ddc97?style=flat-square&labelColor=181714" /></a>
</p>

<p>
  <a href="#1-claude-code-hooks--mcp-one-command"><b>Claude Code</b></a> &nbsp;·&nbsp;
  <a href="#2-universal-mcp-server-cursor-codex-windsurf-antigravity"><b>MCP Server</b></a> &nbsp;·&nbsp;
  <a href="#3-github-actions-sarif--pr-verdict-comment"><b>GitHub Action</b></a> &nbsp;·&nbsp;
  <a href="https://github.com/zerotheory-labs/marlowe"><b>Marlowe Desktop</b></a> &nbsp;·&nbsp;
  <a href="./SECURITY.md"><b>Security Policy</b></a> &nbsp;·&nbsp;
  <a href="./LICENSE"><b>License</b></a>
</p>

</div>

---

AI coding agents mutate files, run shell commands, and open pull requests in seconds. Giving an agent an unguarded shell is a liability — and shallow static scanners drown teams in unreachable alerts.

**Marlowe CI / Guard** (`v0.6.0`) brings [Marlowe](https://github.com/zerotheory-labs/marlowe)'s host-enforced security boundaries directly into **Claude Code hooks**, **MCP clients** (Claude Code, Cursor, VS Code, Codex CLI, Windsurf, Antigravity), **GitHub Actions (SARIF v2.1.0)**, and **git pre-commit** hooks with zero runtime dependencies and no LLM key required.

### What's New in `v0.6.0`
- **10-Rule Shirudo Static & Offline Verifier (`SHIRUDO-BPF-001..004`, `SHIRUDO-BEE-001..003`, `SHIRUDO-TPM-001..003`):**
  - **`.bpf.c` upatches:** Flags illegal sleepable `fmod_ret.s/` targets (`BPF-001`), missing `return 0;` or stripped `-EAGAIN` / `<= -512` / positive returns (`BPF-002`), `fmod_ret/` where `lsm/` avoids re-entrant fail-open gaps (`BPF-003`), and writes to read-only `shirudo_task_policy` / `shirudo_sock_policy` maps (`BPF-004`).
  - **`Beefile` manifests & `PreToolUse`:** Enforces selector cardinality, control-char escapes, and omitted CVE/enforcing selectors (`BEE-001`), blocks `[[upatches.rodata]]` shell/network `generator` & `update` hooks running with operator key privileges (`BEE-002`), and checks `tree.id` matching, 64-bit one-hot policy bitmasks, path glob placement, `load_target`, and TOML subset validity (`BEE-003`).
  - **TPM 2.0 & Verifier Boundaries:** Catches `shirudo status` without `--check`, self-asserted `--ak-name=$(jq ...)` / missing `--nonce`, unpinned offline `ev.json`, zero PCR 11 QEMU boots, missing `0x01818E00` PCR 9 anchors, and `reset_count` mismatches (`TPM-001..003`).
- **ARTEX Defense & Behavioral Pack (`ARTEX-EDGE-001..003`, `ARTEX-BEHAV-001`):**
  - **Pre-merge Edge & Identity Rules:** Flags unauthenticated Swagger/OpenAPI/GraphQL introspection and public `.js.map` / production sourcemaps (`EDGE-001`), OAuth `state: false` / open redirects / credentialed wildcard CORS / weak reset tokens (`EDGE-002`), and `skipAuth` or unauthenticated `/admin` / `/backup` / `/webhook` routes (`EDGE-003`).
  - **Behavioral Agentic Log Detector (`analyzeLogs`):** Detects machine-speed HTTP recon → OAuth/auth pivots, `400`/`422` payload adaptation bursts, and low-static-ratio enumeration even behind rotated IPs and browser User-Agents (`ARTEX-BEHAV-001`, MITRE `T1595`).
- **Expanded 40-Scenario Benchmark Suite (`npm run bench`) & 12-Repo + 135-PR Real-World OSS Corpus (`npm run bench:corpus`):** Lifted Shirudo `3/3` → `12/12`, added `7/7` ARTEX Edge Defense (`40/40` `100%` accuracy, `0%` clean FP `0/10`, `19.83ms` p50), and benchmarked across **9 production OSS repos (135 real PR commits replayed via `--mode diff`: `0%` FAILS `0/135`, `11.32ms` p50)** plus **3 intentionally vulnerable targets (`98` failing issues across `8` CWE classes)**.
- **SARIF First-Class `ruleId`s + Maintainer Docs:** Preserves explicit `SHIRUDO-*` and `ARTEX-*` rule IDs in SARIF v2.1.0 output and adds [`CLAUDE.md`](./CLAUDE.md).

---

## Three Answers, Never Two

Every audit emits one explicit verdict:

| Verdict | Meaning | Exit Code |
| :--- | :--- | :---: |
| **`HOLDS UP`** | Diff/workspace checked; no exposed secrets, reachable sinks, CVEs, or unverified guard gaps. | `0` |
| **`FAILS`** | Confirmed hardcoded secret, reachable CWE sink, TLS bypass, or vulnerable dependency $\ge$ `--fail-on`. | `1` |
| **`CAN'T TELL`** | Unknown is never rounded to a pass — triggers on unverified local sinks without external ingress, security/auth files edited without tests, scanner suppression directives (`nosemgrep`, `gitleaks:allow`), high-entropy binaries, or unavailable OSV/CLI checks. | `0` (`2` with `--fail-on-cant-tell`) |

---

## Recorded Benchmark Scorecard (`npm run bench`)

Executed offline via [`benchmarks/run-benchmarks.cjs`](./benchmarks/run-benchmarks.cjs) against 40 ephemeral Git diff repositories (`Node.js v26.12.0`, `darwin-arm64`, `0` skipped; saved in [`benchmarks/results.json`](./benchmarks/results.json)):

- **Exact 3-State Verdict Accuracy:** `40/40` (**`100%`**)
- **`FAILS` Precision / Recall / F1:** `100% / 100% / 100%` (`FP = 0`, `FN = 0`)
- **Clean / Benign False-Positive Rate:** **`0%`** (`0/10`)
- **`CAN'T TELL` Exact Match:** **`9/9`**
- **Latency (`p50` / `p95` / `mean`):** **`19.83ms` / `25.11ms` / `20.84ms`**

| Domain | Passed | Accuracy | p50 | p95 |
| :--- | :---: | :---: | :---: | :---: |
| AppSec & Cross-File Reachability | `6/6` | `100%` | `20.93ms` | `33.82ms` |
| Secrets & Masking | `3/3` | `100%` | `24.59ms` | `28.07ms` |
| Guardrail Regressions & Precision | `5/5` | `100%` | `20.23ms` | `21.27ms` |
| Agent Guard (Prompt Injection / Trojan / Rug-Pull) | `5/5` | `100%` | `19.81ms` | `22.4ms` |
| Shirudo eBPF, Beefile & TPM Attestation | `12/12` | `100%` | `19.71ms` | `20.67ms` |
| ARTEX Edge Defense (Maps / OAuth / CORS / Admin) | `7/7` | `100%` | `19.59ms` | `21.11ms` |
| Binaries & Clean Refactors | `2/2` | `100%` | `19.18ms` | `19.72ms` |

#### Real-World 12-Repo OSS Corpus & 135-PR Replay (`npm run bench:corpus`)

Executed across **9 production OSS repositories** (`JS`, `TS`, `Python`, `Go`, `eBPF / C / Rust` — 15 recent non-merge commits replayed each in `--mode diff --no-osv`, **`128 HOLDS UP / 7 CAN'T TELL / 0 FAILS`**, `0%` PR false-fail rate, `11.32ms` p50 / `18.58ms` p95) plus **3 intentionally vulnerable OWASP targets** (`98` failing issues caught across `8` CWE/rule classes; saved to [`benchmarks/corpus-results.json`](./benchmarks/corpus-results.json)):

| Cohort · Repository (Pinned SHA) | Ecosystem | PR Diff Replay (`15` commits) | Full-Repo Failing | Full Verdict / Summary |
| :--- | :--- | :---: | :---: | :--- |
| Clean · `expressjs/express` (`43fca52`) | JS | `13H / 2CT / 0F` (`11.07ms` p50) | `0` | **`HOLDS UP`** (`215` files, `34.74ms`) |
| Clean · `fastify/fastify` (`a94dc37`) | JS | `14H / 1CT / 0F` (`11.11ms` p50) | `0` | **`HOLDS UP`** (`397` files, `81.69ms`) |
| Clean · `honojs/hono` (`717dc17`) | TS | `15H / 0CT / 0F` (`11.24ms` p50) | `0` | **`CAN'T TELL`** (`3` CT: `build/` CLI `execSync` & DOM setter) |
| Clean · `koajs/koa` (`98a19bc`) | JS | `15H / 0CT / 0F` (`11.49ms` p50) | `0` | **`HOLDS UP`** (`124` files, `25.97ms`) |
| Clean · `colinhacks/zod` (`d40c329`) | TS | `15H / 0CT / 0F` (`14.74ms` p50) | `0` | **`CAN'T TELL`** (`1` CT: V8 benchmark `eval`) |
| Clean · `pallets/flask` (`49943b5`) | Python | `15H / 0CT / 0F` (`10.93ms` p50) | `0` | **`CAN'T TELL`** (`1` CT: `src/flask/cli.py` startup `eval`) |
| Clean · `fastapi/fastapi` (`05e6df7`) | Python | `15H / 0CT / 0F` (`11.61ms` p50) | `1` | `FAILS` (`1` hit in `3,078` files: `fastapi/security/http.py:42` docstring example `Bearer` literal) |
| Clean · `gin-gonic/gin` (`0f09c3a`) | Go | `13H / 2CT / 0F` (`10.93ms` p50) | `0` | **`HOLDS UP`** (`128` files, `29.06ms`) |
| Clean · `shirudo-dev/shirudo` (`5879ce3`) | eBPF / C / Rust | `13H / 2CT / 0F` (`10.99ms` p50) | `0` | **`CAN'T TELL`** (`21` CT; `0` failing across `24` direct Shirudo artifacts) |
| Vuln · `OWASP/NodeGoat` (`c5cb68a`) | Node.js | — | **`7`** | **`FAILS`** (`CWE-94: 6`, `CWE-798: 1`; `39.57ms`) |
| Vuln · `juice-shop/juice-shop` (`c9f9922`) | Node.js / TS | — | **`65`** | **`FAILS`** (`CWE-798: 26`, `CWE-89: 13`, `CWE-200: 9`, `CWE-502: 6`, `CWE-116: 6`, `CWE-94: 5`) |
| Vuln · `adeyosemanputra/pygoat` (`2aa4cc1`) | Python / Django | — | **`26`** | **`FAILS`** (`CWE-798: 13`, `CWE-502: 5`, `CWE-78: 3`, `CWE-522: 3`, `CWE-94: 2`) |

#### Recorded Live Localhost Purple-Team Run (`npm run bench:artex`)

Executed against a sealed `127.0.0.1` Node HTTP target server (`662.48ms` total, [`benchmarks/run-artex-purple-team.cjs`](./benchmarks/run-artex-purple-team.cjs) → [`benchmarks/artex-purple-team-results.json`](./benchmarks/artex-purple-team-results.json); note this uses a controlled local Planner→Worker HTTP attacker with rotated `X-Forwarded-For` IPs & standard Chrome `User-Agent`, not an external third-party binary):

| Phase | Pre-Merge Gate | Live Compromises | DFIR `ARTEX-BEHAV-001` | Classic `scanner-ua` Hits |
| :--- | :---: | :---: | :---: | :---: |
| **A. Before Hardening** | `FAILS` (`EDGE-001..003`) | **`4/4`** (recon, open redirect, CORS, unauth backup) | **Detected** (`high` confidence) | `0` |
| **B. After Hardening** | `HOLDS UP` (`0` issues) | **`0/4`** (all blocked) | **Detected** (`high` confidence) | `0` |
| **C. Benign Human Browser** | — | — | **Clean (`false`)** (`0` alerts) | `0` |

---

## Quickstart

### 1. Claude Code Hooks + MCP (One Command)

Install `PreToolUse`, `PostToolUse`, and `Stop` hooks into `.claude/settings.json` plus the read-only `stdio` MCP server into `.mcp.json`:

```sh
npx --yes @zerotheory-labs/marlowe-ci init --claude --mcp
```

What gets enforced automatically inside Claude Code:
- **`PreToolUse` (`Read|Edit|Write|MultiEdit|WebFetch|Bash`):**
  - Blocks reading/writing sensitive credential paths (`.env*` excluding `.env.example`/`.sample`/`.template`, `.ssh`, `.aws`, `.gnupg`, `.shirudo`, `shirudo-keys`, `.npmrc`, `.netrc`, `*.pem`, `*.key`) and symlink escapes outside the workspace.
  - Enforces SSRF guards on `WebFetch` and `Bash` (`169.254.169.254`, `metadata.google.internal`, private RFC1918/loopback targets unless explicitly listed in `.marlowe-scope.json`).
  - Blocks `curl | sh`, Node TLS verification bypass overrides, catastrophic `rm -rf`, and credential exfiltration pipelines; prompts (`ask`) on `git push --force`, `git reset --hard`, `chmod 777`, `sudo`, `wrangler deploy`, and live **Shirudo** (`shirudo upatch load|unload|reconcile`, `shirudo bpm build|push|tree append`, `shirudo genkey|keys|init|image`).
- **`PostToolUse` (`Edit|Write|MultiEdit`):**
  - Scans modified files in milliseconds for secrets (masked before model feedback), CWE sinks, high-entropy blobs, suppression directives, and Shirudo `Beefile` / `*.bpf.c` issues so Claude fixes vulnerabilities on the next turn.
- **`Stop`:**
  - Runs a diff-scoped verdict check before Claude ends its turn and blocks completion on `FAILS` (honoring `stop_hook_active: true` to prevent loops).

---

### 2. Universal MCP Server (Cursor, VS Code, Codex, Windsurf, Antigravity)

Configure supported editors & coding agents in one command (preserves existing entries):

```sh
# Install across Cursor, VS Code, Codex CLI, Windsurf, Claude Code & .mcp.json:
npx --yes @zerotheory-labs/marlowe-ci init --all-agents

# Or target a single client:
npx --yes @zerotheory-labs/marlowe-ci init --cursor
npx --yes @zerotheory-labs/marlowe-ci init --vscode
npx --yes @zerotheory-labs/marlowe-ci init --codex
npx --yes @zerotheory-labs/marlowe-ci init --windsurf
```

Or wire `stdio` manually (listed on the [official MCP Registry](https://registry.modelcontextprotocol.io/v0/servers?search=io.github.zerotheory-labs/marlowe-ci) as `io.github.zerotheory-labs/marlowe-ci`):

```json
{
  "mcpServers": {
    "marlowe": {
      "command": "npx",
      "args": ["--yes", "@zerotheory-labs/marlowe-ci", "mcp"]
    }
  }
}
```

Exposed read-only tools (**13 total** across AppSec, Authorized Recon, DFIR & Shirudo):
- **AppSec & Supply Chain:** `marlowe_scan_diff`, `marlowe_scan_workspace`, `marlowe_audit_dependencies`, `marlowe_doctor`
- **Authorized Recon (ScopeGate-enforced):** `marlowe_check_scope`, `marlowe_inspect_http`, `marlowe_inspect_tls`, `marlowe_dns_recon`
- **DFIR (`O_NOFOLLOW`-confined):** `marlowe_triage_artifact`, `marlowe_analyze_logs`, `marlowe_extract_iocs`
- **Shirudo Runtime Upatch & TPM 2.0 Attestation:** `marlowe_shirudo_audit`, `marlowe_shirudo_verify_attestation`

---

### 3. GitHub Actions (SARIF + PR Verdict Comment)

Add `.github/workflows/marlowe-ci.yml` (or run `npx --yes @zerotheory-labs/marlowe-ci init --github`):

```yaml
name: Marlowe CI Security Guard

on:
  pull_request:

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  marlowe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: zerotheory-labs/marlowe-ci@v0.6.0
        with:
          mode: diff
          fail-on: high
          sarif-file: marlowe.sarif
          comment-pr: 'true'
          github-token: ${{ secrets.GITHUB_TOKEN }}

      - uses: github/codeql-action/upload-sarif@v4
        if: always() && hashFiles('marlowe.sarif') != ''
        with:
          sarif_file: marlowe.sarif
```

#### Live PR Verdict Example

Real sticky comment posted automatically on [`zerotheory-labs/marlowe#1`](https://github.com/zerotheory-labs/marlowe/pull/1):

> ## 🟡 Marlowe CI Verdict: **CAN'T TELL**
>
> > Evidence is incomplete or contains unverified sinks — never rounded to a pass.
>
> - **Mode:** `diff` · **Files inspected:** `2` · **Threshold:** `high` · **Duration:** `18ms`
>
> _No security findings detected._
>
> ### Can't Tell Items (1)
>
> - `sensitive-surface-untested` — Security-sensitive surface modified without any test changes (`.github/workflows/marlowe-ci.yml`).

---

### 4. Local Diff, Recon, DFIR & Baseline CLI

```sh
# Audit working tree & untracked files
npx --yes @zerotheory-labs/marlowe-ci scan

# Audit staged changes offline before commit
npx --yes @zerotheory-labs/marlowe-ci scan --staged --no-osv

# Acknowledge non-secret legacy findings (secrets are never baselined)
npx --yes @zerotheory-labs/marlowe-ci baseline --no-osv

# ScopeGate-enforced Recon & O_NOFOLLOW DFIR
npx --yes @zerotheory-labs/marlowe-ci recon http https://staging.example.com
npx --yes @zerotheory-labs/marlowe-ci dfir logs ./access.log
npx --yes @zerotheory-labs/marlowe-ci dfir iocs ./incident.txt

# Shirudo Beefile / Plain BPF C audit & TPM 2.0 quote verification
npx --yes @zerotheory-labs/marlowe-ci shirudo audit ./shields
npx --yes @zerotheory-labs/marlowe-ci shirudo attest ./evidence.json --nonce deadbeef
npx --yes @zerotheory-labs/marlowe-ci shirudo status

# Install .git/hooks/pre-commit & inspect 10 local security CLIs
npx --yes @zerotheory-labs/marlowe-ci init --git-hook
npx --yes @zerotheory-labs/marlowe-ci doctor
```

---

## Optional Scope Configuration (`.marlowe-scope.json`)

```json
{
  "targets": ["https://staging.example.com", "127.0.0.1:3000"],
  "allowOsv": true,
  "redactContext": true
}
```

---

## Security & License

- **Security policy & trust boundaries:** [`SECURITY.md`](./SECURITY.md)
- **License:** **[PolyForm Noncommercial License 1.0.0](./LICENSE)** — Copyright © Zero Theory Labs. Free for personal, academic, educational, non-profit, and non-commercial security research. Commercial or internal business CI/CD use requires a commercial license (`access@zerotheorylabs.com`).
