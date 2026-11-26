#!/usr/bin/env bash
# Acceptance verification for cross-cluster vulnerability de-duplication,
# attribution and workload aggregation (UID 43093).
#
# Safe to re-run. It:
#   1. selects a Go >= 1.25 toolchain (uses the cached one if present),
#   2. builds the deepfence_server module,
#   3. runs the pure de-duplication acceptance tests,
#   4. runs the HTTP/API compatibility tests (inline data, no Neo4j needed),
#   5. runs the dependency-free CLI acceptance scenario.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$REPO_ROOT/deepfence_server"
cd "$SERVER_DIR"

# --- toolchain -------------------------------------------------------------
if ! command -v go >/dev/null 2>&1; then
  echo "go toolchain not found on PATH" >&2
  exit 1
fi

GO_VER_OK="$(go version | grep -oE 'go[0-9]+\.[0-9]+' | head -1 | sed 's/go//' | awk -F. '$1>1 || ($1==1 && $2>=25){print 1}')"
if [ "${GO_VER_OK:-}" != "1" ]; then
  CACHED_TC="$(ls -d "$HOME"/.codex-relay-home-*/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25* 2>/dev/null | head -1 || true)"
  if [ -n "${CACHED_TC:-}" ] && [ -x "$CACHED_TC/bin/go" ]; then
    export PATH="$CACHED_TC/bin:$PATH"
    export GOTOOLCHAIN=local
  else
    export GOTOOLCHAIN=auto
  fi
fi

# /tmp is a small tmpfs on some machines; redirect Go scratch space.
if [ -d /home/dev ] && [ -w /home/dev ]; then
  mkdir -p /home/dev/tmp-43093
  export TMPDIR=/home/dev/tmp-43093
  export GOTMPDIR=/home/dev/tmp-43093
fi
# Reuse the warm module cache when available.
if [ -d /home/dev/gomodcache ]; then
  export GOMODCACHE=/home/dev/gomodcache
fi

echo "Using: $(go version)"

echo "[1/5] building deepfence_server..."
go build ./...

echo "[2/5] de-duplication / attribution / workload tests..."
go test -v ./reporters/vulndedup/

echo "[3/5] API + compatibility handler tests (vet off: pre-existing warnings)..."
go test -vet=off -run 'TestHTTP_' ./handler/

echo "[4/5] vulnview package build/vet..."
go vet ./reporters/vulnview/

echo "[5/5] CLI acceptance scenario..."
go run ./cmd/vulndedup | tee /tmp/vulndedup-acceptance.txt
grep -q "deduplicated_total=3" /tmp/vulndedup-acceptance.txt
grep -q "verify_ok" /tmp/vulndedup-acceptance.txt

echo
echo "ALL_CHECKS_PASSED"
