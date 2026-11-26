#!/bin/bash
set -euo pipefail

DRY_RUN=false
if [ "${1:-}" = "--dry-run" ]; then
  DRY_RUN=true
  shift
fi

if [ -z "${1:-}" ]; then
  echo "Usage: ./scripts/release.sh [--dry-run] <tag> (e.g., ./scripts/release.sh v1.9.0)"
  exit 1
fi

NEW_VERSION="$1"

# Compare two Go semantic versions (major.minor[.patch]). Returns 0 if $1 > $2.
version_gt() {
  local IFS=.
  local -a v1=($1) v2=($2)
  local i n1 n2
  for i in 0 1 2; do
    n1=${v1[i]:-0}
    n2=${v2[i]:-0}
    if (( 10#$n1 > 10#$n2 )); then
      return 0
    elif (( 10#$n1 < 10#$n2 )); then
      return 1
    fi
  done
  return 1
}

is_valid_go_version() {
  [[ "$1" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]
}

resolve_latest_go_version() {
  local candidate=""

  # 1. Explicit GO_VERSION environment override, if provided.
  if [ -n "${GO_VERSION:-}" ]; then
    candidate="${GO_VERSION#go}"
    if is_valid_go_version "$candidate"; then
      echo "$candidate"
      return 0
    fi
    echo "Error: invalid GO_VERSION override '$GO_VERSION'" >&2
    return 1
  fi

  # 2. Query go.dev for the latest stable Go release.
  if command -v curl >/dev/null 2>&1; then
    candidate=$(curl -fsSL --max-time 10 "https://go.dev/VERSION?m=text" 2>/dev/null | head -n 1 | tr -d '\r\n ' || true)
    candidate="${candidate#go}"
    if is_valid_go_version "$candidate"; then
      echo "$candidate"
      return 0
    fi
  fi

  # 3. Fall back to the locally installed Go toolchain version.
  if command -v go >/dev/null 2>&1; then
    candidate=$(go env GOVERSION 2>/dev/null | tr -d '\r\n ' || true)
    candidate="${candidate#go}"
    if is_valid_go_version "$candidate"; then
      echo "$candidate"
      return 0
    fi
  fi

  return 1
}

CURRENT_GO_VERSION=$(awk '/^go [0-9]/{print $2; exit}' go.mod)
TARGET_GO_VERSION=$(resolve_latest_go_version || echo "$CURRENT_GO_VERSION")

echo "Preparing release for $NEW_VERSION..."

if git rev-parse -q --verify "refs/tags/$NEW_VERSION" >/dev/null; then
  echo "Error: tag '$NEW_VERSION' already exists." >&2
  exit 1
fi

if [ "$DRY_RUN" = true ]; then
  echo "   - [dry-run] Current go.mod Go version: $CURRENT_GO_VERSION"
  echo "   - [dry-run] Latest stable Go version:  $TARGET_GO_VERSION"
  if version_gt "$TARGET_GO_VERSION" "$CURRENT_GO_VERSION"; then
    echo "   - [dry-run] Would upgrade go.mod: $CURRENT_GO_VERSION -> $TARGET_GO_VERSION"
  else
    echo "   - [dry-run] Would keep go.mod at $CURRENT_GO_VERSION (no downgrade)"
  fi
  echo "   - [dry-run] Would tag $NEW_VERSION and push main + $NEW_VERSION to origin"
  exit 0
fi

BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$BRANCH" != "main" ]; then
  echo "   - Checking out main branch"
  git checkout main >/dev/null 2>&1 || git checkout -b main
fi

if [[ -n $(git status -s) ]]; then
  echo "   - Auto-committing uncommitted changes"
  git add .
  git commit -m "chore: auto-commit before release $NEW_VERSION"
fi

echo "   - Pulling latest from origin/main"
git pull --ff-only origin main

if version_gt "$TARGET_GO_VERSION" "$CURRENT_GO_VERSION"; then
  echo "   - Upgrading Go version in go.mod: $CURRENT_GO_VERSION -> $TARGET_GO_VERSION"
  GOTOOLCHAIN=auto go mod edit -go="$TARGET_GO_VERSION"
else
  echo "   - Keeping Go version in go.mod at $CURRENT_GO_VERSION (latest detected: $TARGET_GO_VERSION)"
fi

GOTOOLCHAIN=auto go mod tidy

if [[ -n $(git status -s) ]]; then
  git add go.mod go.sum
  git commit -m "chore: release $NEW_VERSION (Go $TARGET_GO_VERSION)"
fi

echo "Tagging checkmate with $NEW_VERSION..."
git tag -a "$NEW_VERSION" -m "Release $NEW_VERSION"

echo "Pushing checkmate to origin/main and tag $NEW_VERSION..."
git push origin main
git push origin "$NEW_VERSION"

echo "----------------------------------------"
echo "CheckMate $NEW_VERSION release initiated!"
