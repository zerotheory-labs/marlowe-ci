#!/usr/bin/env sh
set -eu

# Repeatable Linux validation harness for Marlowe CI / Guard + Shirudo CLI + optional swtpm/TPM 2.0.
ROOT_DIR="${1:-$(pwd)}"
CLI="$(cd "$(dirname "$0")/.." && pwd)/bin/marlowe-ci.cjs"

echo "=== Host Environment ==="
uname -srmo
node -v

echo "=== 10-CLI Toolchain Doctor ==="
node "$CLI" doctor --path "$ROOT_DIR" --json

echo "=== Shirudo Runtime & Binary Status ==="
node "$CLI" shirudo status --path "$ROOT_DIR" --json || true

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

cat > "$TMP_DIR/Beefile" <<'EOF'
[package]
name = "linux-smoke-shield"
description = "Linux Shirudo validation smoke check"

[[upatches]]
source = "smoke.bpf.c"
type = "bpf"

[upatches.tree]
id = "smoke"

[upatches.tree.selector.labels]
env = ["smoke"]
EOF

cat > "$TMP_DIR/smoke.bpf.c" <<'EOF'
char LICENSE[] SEC("license") = "Dual BSD/GPL";
SEC("lsm/file_open")
int smoke_check(void *ctx) {
  unsigned int pid = bpf_get_current_pid_tgid() >> 32;
  return pid ? 0 : 0;
}
EOF

echo "=== Shirudo Beefile & eBPF Static Audit ==="
node "$CLI" shirudo audit "$TMP_DIR" --path "$TMP_DIR" --json

if command -v tpm2_quote >/dev/null 2>&1 || command -v swtpm >/dev/null 2>&1; then
  echo "=== TPM Toolchain Detected ==="
  command -v tpm2_quote || true
  command -v swtpm || true
else
  echo "=== TPM Toolchain Not Installed (skipping live swtpm quote) ==="
fi
