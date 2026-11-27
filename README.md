<div align="center">

<p>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./docs/assets/marlowe-ci-banner-dark.svg" />
    <source media="(prefers-color-scheme: light)" srcset="./docs/assets/marlowe-ci-banner-light.svg" />
    <img alt="Marlowe CI. — Guardrails for AI agents and pull requests. By Zero Theory Labs." src="./docs/assets/marlowe-ci-banner-dark.svg" width="100%" />
  </picture>
</p>

<p>
  <a href="https://github.com/zerotheory-labs/marlowe-ci/releases/tag/v0.7.2"><img alt="Release v0.7.2" src="https://img.shields.io/badge/release-v0.7.2-3ddc97?style=flat-square&labelColor=181714" /></a>&nbsp;&nbsp;
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
  <a href="https://zerotheorylabs.com/benchmarks"><b>Benchmarks</b></a> &nbsp;·&nbsp;
  <a href="https://zerotheorylabs.com/marlowe-ci#playground"><b>Live Playground</b></a> &nbsp;·&nbsp;
  <a href="https://github.com/zerotheory-labs/marlowe"><b>Marlowe Desktop</b></a> &nbsp;·&nbsp;
  <a href="./SECURITY.md"><b>Security Policy</b></a> &nbsp;·&nbsp;
  <a href="./LICENSE"><b>License</b></a>
</p>

</div>

---

AI coding agents mutate files, run shell commands, and open pull requests in seconds. Giving an agent an unguarded shell is a liability — and shallow static scanners drown teams in unreachable alerts.

**Marlowe CI / Guard** (`v0.7.2`) brings [Marlowe](https://github.com/zerotheory-labs/marlowe)'s host-enforced security boundaries directly into **Claude Code hooks**, **MCP clients** (Claude Code, Cursor, VS Code, Codex CLI, Windsurf, Antigravity), **GitHub Actions (SARIF v2.1.0)**, and **git pre-commit** hooks with zero runtime dependencies and no LLM key required.

### What's New in `v0.7.2`

The release workflow waits for npm to serve the tagged package version before publishing the MCP Registry entry. If npm initially returns a 404, the workflow retries every 15 seconds for up to ten minutes. [Release workflow change](https://github.com/zerotheory-labs/marlowe-ci/pull/6)

### What's New in `v0.7.1`

You can verify which GitHub Actions workflow and tagged source commit produced the npm tarball using the provenance on the [npm package page](https://www.npmjs.com/package/@zerotheory-labs/marlowe-ci/v/0.7.1).

### What's New in `v0.7.0`

Semgrep replay checks whether a pull request drops coverage for a known, harmless fixture. The Action and CLI compare the same base-committed fixture and expected rule against both revisions. A lost match produces a high-severity finding in the PR summary and SARIF. Incomplete evidence produces `CAN'T TELL`. [Configure Semgrep replay](#replay-semgrep-coverage-on-pull-requests)

### What's New in `v0.6.1`

The GitHub Action scans each pushed commit. A secret added and removed in the same push fails the check, and the step summary and SARIF report identify the commit and line.

### What's New in `v0.6.0`
- **10-Rule Shirudo Static & Offline Verifier (`SHIRUDO-BPF-001..004`, `SHIRUDO-BEE-001..003`, `SHIRUDO-TPM-001..003`):**
  - **`.bpf.c` upatches:** Flags illegal sleepable `fmod_ret.s/` targets (`BPF-001`), missing `return 0;` or stripped `-EAGAIN` / `<= -512` / positive returns (`BPF-002`), `fmod_ret/` where `lsm/` avoids re-entrant fail-open gaps (`BPF-003`), and writes to read-only `shirudo_task_policy` / `shirudo_sock_policy` maps (`BPF-004`).
  - **`Beefile` manifests & `PreToolUse`:** Enforces selector cardinality, control-char escapes, and omitted CVE/enforcing selectors (`BEE-001`), blocks `[[upatches.rodata]]` shell/network `generator` & `update` hooks running with operator key privileges (`BEE-002`), and checks `tree.id` matching, 64-bit one-hot policy bitmasks, path glob placement, `load_target`, and TOML subset validity (`BEE-003`).
  - **TPM 2.0 & Verifier Boundaries:** Catches `shirudo status` without `--check`, self-asserted `--ak-name=$(jq ...)` / missing `--nonce`, unpinned offline `ev.json`, zero PCR 11 QEMU boots, missing `0x01818E00` PCR 9 anchors, and `reset_count` mismatches (`TPM-001..003`).
- **ARTEX Defense & Behavioral Pack (`ARTEX-EDGE-001..003`, `ARTEX-BEHAV-001`):**
  - **Pre-merge Edge & Identity Rules:** Flags unauthenticated Swagger/OpenAPI/GraphQL introspection and public `.js.map` / production sourcemaps (`EDGE-001`), OAuth `state: false` / open redirects / credentialed wildcard CORS / weak reset tokens (`EDGE-002`), and `skipAuth` or unauthenticated `/admin` / `/backup` / `/webhook` routes (`EDGE-003`).
  - **Behavioral Agentic Log Detector (`analyzeLogs`):** Detects machine-speed HTTP recon → OAuth/auth pivots, `400`/`422` payload adaptation bursts, and low-static-ratio enumeration even behind rotated IPs and browser User-Agents (`ARTEX-BEHAV-001`, MITRE `T1595`).
- **Expanded 40-Scenario Benchmark Suite (`npm run bench`) & 18-Repo + 225-PR + Real-CVE OSS Corpus (`npm run bench:corpus`):** Lifted Shirudo `3/3` → `12/12`, added `7/7` ARTEX Edge Defense (`40/40` `100%` accuracy, `0%` clean FP `0/10`, `24.1ms` p50), and benchmarked across **6 blind held-out OSS repos (`90` real PRs: `0/90` false `FAILS`, `12.42ms` p50) + 9 calibration repos (`135` real PRs: `0/135` false `FAILS`)**, **3 code-only OWASP targets (`86` failing issues, HTML tutorial prose excluded)**, and **4 real historical CVE fix commits**. Marlowe CI is a fast, zero-dependency **AI-agent & pre-merge guardrail** (pairable with `--scanners auto` for `semgrep`/`gitleaks`/`trivy`), not a full-AST taint analyzer.
- **SARIF First-Class `ruleId`s + Maintainer Docs:** Preserves explicit `SHIRUDO-*` and `ARTEX-*` rule IDs in SARIF v2.1.0 output and adds [`CLAUDE.md`](./CLAUDE.md).

---

## Three Answers, Never Two

Every audit emits one explicit verdict:

| Verdict | Meaning | Exit Code |
| :--- | :--- | :---: |
| **`HOLDS UP`** | Diff/workspace checked; no exposed secrets, reachable sinks, CVEs, or unverified guard gaps. | `0` |
| **`FAILS`** | Confirmed hardcoded secret, reachable CWE sink, TLS bypass, or vulnerable dependency ≥ `--fail-on`. | `1` |
| **`CAN'T TELL`** | Unknown is never rounded to a pass — triggers on unverified local sinks without external ingress, security/auth files edited without tests, scanner suppression directives (`nosemgrep`, `gitleaks:allow`), high-entropy binaries, or unavailable OSV/CLI checks. | `0` (`2` with `--fail-on-cant-tell`) |

---

## Recorded Benchmark Scorecard (`npm run bench`)

Executed offline via [`benchmarks/run-benchmarks.cjs`](./benchmarks/run-benchmarks.cjs) against 40 ephemeral Git diff repositories (`Node.js v26.12.0`, `darwin-arm64`, `0` skipped; saved in [`benchmarks/results.json`](./benchmarks/results.json)):

- **Exact 3-State Verdict Accuracy:** `40/40` (**`100%`**)
- **`FAILS` Precision / Recall / F1:** `100% / 100% / 100%` (`FP = 0`, `FN = 0`)
- **Clean / Benign False-Positive Rate:** **`0%`** (`0/10`)
- **`CAN'T TELL` Exact Match:** **`9/9`**
- **Latency (`p50` / `p95` / `mean`):** **`24.1ms` / `26.31ms` / `24.56ms`**

| Domain | Passed | Accuracy | p50 | p95 |
| :--- | :---: | :---: | :---: | :---: |
| AppSec & Cross-File Reachability | `6/6` | `100%` | `23.78ms` | `41.04ms` |
| Secrets & Masking | `3/3` | `100%` | `24.1ms` | `24.28ms` |
| Guardrail Regressions & Precision | `5/5` | `100%` | `22.91ms` | `23.77ms` |
| Agent Guard (Prompt Injection / Trojan / Rug-Pull) | `5/5` | `100%` | `24.22ms` | `25.33ms` |
| Shirudo eBPF, Beefile & TPM Attestation | `12/12` | `100%` | `24.4ms` | `26.31ms` |
| ARTEX Edge Defense (Maps / OAuth / CORS / Admin) | `7/7` | `100%` | `24.27ms` | `25.5ms` |
| Binaries & Clean Refactors | `2/2` | `100%` | `22.18ms` | `23.26ms` |

#### Real-World 18-Repo OSS Corpus, 225-PR Replay & Real CVE Check (`npm run bench:corpus`)

Separated cleanly into **Calibration (9 repos · 135 PRs)**, **Blind Held-Out (6 unseen repos · 90 PRs, raw/untuned)**, **Code-Only OWASP Targets (HTML prose excluded)**, and **4 Verified Historical CVE Fix Replays** ([`benchmarks/corpus-results.json`](./benchmarks/corpus-results.json)):

| Cohort · Repository (Pinned SHA) | Ecosystem | PR Diff Replay (`15` commits) | Full-Repo Failing | Full Verdict / Notes |
| :--- | :--- | :---: | :---: | :--- |
| Blind · `axios/axios` (`71c87d5`) | JS | `12H / 3CT / 0F` (`13.71ms` p50) | `0` | **`CAN'T TELL`** (`514` files; `17` CT incl. `webpack.config.js` sourcemap & demo `.innerHTML`) |
| Blind · `trpc/trpc` (`105754b`) | TS | `15H / 0CT / 0F` (`12.79ms` p50) | `0` | **`CAN'T TELL`** (`2,052` files; `scripts/preview-urls.ts` CLI + unverified DOM sinks) |
| Blind · `pallets/click` (`08b803c`) | Python | `13H / 2CT / 0F` (`12.81ms` p50) | `0` | **`CAN'T TELL`** (`177` files; extensionless `examples/completion/README` `eval` note) |
| Blind · `psf/requests` (`3c7baaa`) | Python | `9H / 6CT / 0F` (`11.38ms` p50) | `0` | **`HOLDS UP`** (`114` files; `6` CT PRs flagged untested `.github/workflows/*.yml` edits) |
| Blind · `gofiber/fiber` (`0d4d872`) | Go | `9H / 6CT / 0F` (`12.79ms` p50) | `0` | **`HOLDS UP`** (`575` files; `6` CT PRs caught `//nolint:wrapcheck` & untested middleware edits) |
| Blind · `tokio-rs/axum` (`14122ea`) | Rust | `10H / 5CT / 0F` (`12.42ms` p50) | `0` | **`HOLDS UP`** (`490` files; `5` CT PRs flagged untested CI & `from_fn.rs` middleware edits) |
| Cal · `expressjs/express` (`43fca52`) | JS | `13H / 2CT / 0F` (`12.74ms` p50) | `0` | **`HOLDS UP`** (`215` files, `39.15ms`) |
| Cal · `fastify/fastify` (`a94dc37`) | JS | `14H / 1CT / 0F` (`13.2ms` p50) | `0` | **`HOLDS UP`** (`397` files, `89.87ms`) |
| Cal · `honojs/hono` (`717dc17`) | TS | `15H / 0CT / 0F` (`11.24ms` p50) | `0` | **`CAN'T TELL`** (`3` CT: `build/` CLI `execSync` & DOM setter) |
| Cal · `koajs/koa` (`98a19bc`) | JS | `15H / 0CT / 0F` (`11.49ms` p50) | `0` | **`HOLDS UP`** (`124` files) |
| Cal · `colinhacks/zod` (`d40c329`) | TS | `15H / 0CT / 0F` (`14.74ms` p50) | `0` | **`CAN'T TELL`** (`1` CT: V8 benchmark `eval`) |
| Cal · `pallets/flask` (`49943b5`) | Python | `15H / 0CT / 0F` (`13.35ms` p50) | `0` | **`CAN'T TELL`** (`1` CT: `src/flask/cli.py` startup `eval`) |
| Cal · `fastapi/fastapi` (`05e6df7`) | Python | `15H / 0CT / 0F` (`14.04ms` p50) | `1` | `FAILS` (`1` residual hit in `3,078` files: `fastapi/security/http.py:42` OpenAPI docstring `Bearer` example) |
| Cal · `gin-gonic/gin` (`0f09c3a`) | Go | `13H / 2CT / 0F` (`13.57ms` p50) | `0` | **`HOLDS UP`** (`128` files) |
| Cal · `shirudo-dev/shirudo` (`cb8aeaa`) | eBPF / C / Rust | `14H / 1CT / 0F` (`12.86ms` p50) | `0` | **`CAN'T TELL`** (`21` CT; `0` failing across `24` direct Shirudo artifacts) |
| Vuln · `OWASP/NodeGoat` (`c5cb68a`) | Node.js | — | **`3`** | **`FAILS`** (`3` `CWE-94` `eval(req.body.*)` in `app/routes/contributions.js`; HTML tutorial prose excluded) |
| Vuln · `juice-shop/juice-shop` (`c9f9922`) | Node.js / TS | — | **`65`** | **`FAILS`** (`26` `CWE-798`, `13` `CWE-89`, `9` `ARTEX-EDGE-001`, `6` `CWE-502`, `6` `CWE-116`, `5` `CWE-94`) |
| Vuln · `adeyosemanputra/pygoat` (`2aa4cc1`) | Python / Django | — | **`18`** | **`FAILS`** (`10` `CWE-798`, `3` `CWE-502` `pickle`/`yaml.Loader`, `3` `CWE-522`, `2` `CWE-94`; HTML prose excluded) |

> **Honest Real-CVE Replay (`1 / 4` pre-patch, `0 / 4` in line-diff alone):** Replaying verified pre-patch states for `CVE-2021-21315` (`sebhildebrandt/systeminformation`), `CVE-2022-25912` (`steveukx/git-js`), `CVE-2021-23337` (`lodash/lodash`), and `CVE-2020-14343` (`yaml/pyyaml`) returned `CAN'T TELL` (`27` unverified sink items at file level) for `CVE-2021-21315` and `HOLDS UP` on the other three. Sanitizer/argument/class-hierarchy bypasses require AST dataflow analysis (`--scanners auto` with `semgrep`), reinforcing Marlowe CI's role as a fast pre-merge & agentic guardrail layer rather than a standalone AST SAST replacement.

#### Recorded Live Localhost Purple-Team Run (`npm run bench:artex`)

Executed against a sealed `127.0.0.1` Node HTTP target server (`662.48ms` total, [`benchmarks/run-artex-purple-team.cjs`](./benchmarks/run-artex-purple-team.cjs) → [`benchmarks/artex-purple-team-results.json`](./benchmarks/artex-purple-team-results.json); note this uses a controlled local Planner→Worker HTTP attacker with rotated `X-Forwarded-For` IPs & standard Chrome `User-Agent`, not an external third-party binary):

| Phase | Pre-Merge Gate | Live Compromises | DFIR `ARTEX-BEHAV-001` | Classic `scanner-ua` Hits |
| :--- | :---: | :---: | :---: | :---: |
| **A. Before Hardening** | `FAILS` (`EDGE-001..003`) | **`4/4`** (recon, open redirect, CORS, unauth backup) | **Detected** (`high` confidence) | `0` |
| **B. After Hardening** | `HOLDS UP` (`0` issues) | **`0/4`** (all blocked) | **Detected** (`high` confidence) | `0` |
| **C. Benign Human Browser (`5` reqs)** | — | — | **Clean (`false`)** (`0` alerts) | `0` |

> An additional `10`-request rapid `200 OK` SPA API burst (`0` static assets, `0` alerts) is pinned in [`test/artex-defense.test.cjs`](./test/artex-defense.test.cjs). See all charts interactively at [`zerotheorylabs.com/benchmarks`](https://zerotheorylabs.com/benchmarks).

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

In diff mode, pull requests use their merge base. On a push, Marlowe checks each newly reachable commit against its first parent, including commits on merged branches. A secret added and then removed in the same push fails the check. The step summary and SARIF report identify the commit and line.

For a new ref, Marlowe checks the commits listed in the event and the final tracked tree. If the event lacks a complete commit list, it walks the new ref's history. A force push also checks what changed between the old and new tips. Deleting a ref skips the check. Use `fetch-depth: 0` so Git can read the push history.

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

      - uses: zerotheory-labs/marlowe-ci@v0.7.2
        id: marlowe
        with:
          mode: diff
          fail-on: high
          sarif-file: marlowe.sarif
          comment-pr: 'true'
          github-token: ${{ secrets.GITHUB_TOKEN }}

      - uses: github/codeql-action/upload-sarif@v4
        if: always() && steps.marlowe.outputs.sarif-file != ''
        with:
          sarif_file: marlowe.sarif
```

#### Replay Semgrep coverage on pull requests

Set the Action input `semgrep-replay: .marlowe/replay.json` and install the Semgrep CLI on the runner. Use `fetch-depth: 0` so Git can read both commits named in the pull request event.

Commit the manifest and a harmless fixture to the base branch. For example, a team with a `no-console-log` rule in `.semgrep/rules.yml` can put `console.log("Marlowe replay");` in `.marlowe/fixtures/console.js` and use this manifest in `.marlowe/replay.json`.

```json
{
  "config": ".semgrep/rules.yml",
  "rule": "no-console-log",
  "fixture": ".marlowe/fixtures/console.js",
  "target": "services/payments/marlowe-replay.js"
}
```

Marlowe places the same fixture bytes at `target` in two temporary Git repositories. Each uses its revision’s checked-in Semgrep YAML or JSON configuration and the ignore files governing that path. The target directory must exist in both revisions. The replay uses local Semgrep rules. Hosted policies and flags set by a separate workflow are outside its scope.

The PR summary shows both commit SHAs, the rule, the fixture path, and each scan’s outcome. A base match that disappears on the PR produces a high-severity `MARLOWE-SEMGREP-REPLAY` finding in the verdict and SARIF. An unavailable scanner, invalid configuration, or missing base match produces `CAN'T TELL`. Set `fail-on-cant-tell: 'true'` to require complete evidence before merging.

To replay locally against the committed `HEAD`, run `marlowe-ci scan --base origin/main --semgrep-replay .marlowe/replay.json`.

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
