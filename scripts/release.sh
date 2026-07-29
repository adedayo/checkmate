#!/bin/bash
set -e

if [ -z "$1" ]; then
  echo "Usage: ./scripts/release.sh <tag> (e.g., ./scripts/release.sh v1.1.0)"
  exit 1
fi

NEW_VERSION=$1
GO_VERSION="1.26.1"

echo "🧹 Preparing release for $NEW_VERSION..."

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
git pull origin main >/dev/null 2>&1 || true

echo "   - Updating Go version to $GO_VERSION"
go mod edit -go=$GO_VERSION
go mod tidy

if [[ -n $(git status -s) ]]; then
  git add .
  git commit -m "chore: release $NEW_VERSION"
fi

echo "🏷️ Tagging checkmate with $NEW_VERSION..."
git tag "$NEW_VERSION" 2>/dev/null || true

echo "🚀 Pushing checkmate to origin/main and tag $NEW_VERSION..."
git push origin main
git push origin "$NEW_VERSION"

echo "----------------------------------------"
echo "✅ CheckMate $NEW_VERSION release initiated!"
