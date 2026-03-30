#!/usr/bin/env bash
set -euo pipefail

# Release script for gitveil
# Usage: ./scripts/release.sh [--dry-run]
#
# This script:
#   1. Reads the version from Cargo.toml
#   2. Builds a release binary
#   3. Creates a tarball
#   4. Creates a GitHub release with the tarball
#   5. Updates the Homebrew formula with new version, URL, and sha256
#   6. Commits and pushes the formula

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TAP_DIR="$HOME/Projects/Private/homebrew-gitveil"
FORMULA="$TAP_DIR/Formula/gitveil.rb"
DRY_RUN=false

if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=true
    echo "==> DRY RUN MODE (no changes will be pushed)"
fi

# --- 1. Read version from Cargo.toml ---
VERSION=$(grep '^version' "$REPO_DIR/Cargo.toml" | head -1 | sed 's/.*"\(.*\)"/\1/')
TAG="v$VERSION"
TARBALL="gitveil-${VERSION}-darwin-arm64.tar.gz"

echo "==> Releasing gitveil $VERSION ($TAG)"

# Check for uncommitted changes
if ! git -C "$REPO_DIR" diff --quiet HEAD 2>/dev/null; then
    echo "ERROR: uncommitted changes in gitveil repo. Commit or stash first."
    exit 1
fi

# Check tag doesn't already exist on remote
if gh release view "$TAG" --repo lucatescari/gitveil &>/dev/null; then
    echo "ERROR: release $TAG already exists on GitHub."
    echo "       Bump the version in Cargo.toml first."
    exit 1
fi

# --- 2. Build ---
echo "==> Building release binary..."
(cd "$REPO_DIR" && cargo build --release)

# --- 3. Create tarball ---
echo "==> Creating tarball..."
tar czf "/tmp/$TARBALL" -C "$REPO_DIR/target/release" gitveil

# --- 4. Compute sha256 ---
SHA256=$(shasum -a 256 "/tmp/$TARBALL" | awk '{print $1}')
echo "==> SHA256: $SHA256"

if $DRY_RUN; then
    echo "==> [dry-run] Would create GitHub release $TAG with /tmp/$TARBALL"
    echo "==> [dry-run] Would update formula to version=$VERSION sha256=$SHA256"
    echo "==> Done (dry run)."
    rm -f "/tmp/$TARBALL"
    exit 0
fi

# --- 5. Create GitHub release ---
echo "==> Creating GitHub release $TAG..."
gh release create "$TAG" "/tmp/$TARBALL" \
    --repo lucatescari/gitveil \
    --title "$TAG" \
    --generate-notes

# --- 6. Get the download URL ---
DOWNLOAD_URL="https://github.com/lucatescari/gitveil/releases/download/${TAG}/${TARBALL}"

# --- 7. Update Homebrew formula ---
echo "==> Updating Homebrew formula..."

cat > "$FORMULA" << EOF
class Gitveil < Formula
  desc "Transparent file encryption in git (git-crypt compatible)"
  homepage "https://github.com/lucatescari/gitveil"
  version "$VERSION"
  license "GPL-3.0"

  on_macos do
    on_arm do
      url "$DOWNLOAD_URL"
      sha256 "$SHA256"
    end
  end

  def install
    bin.install "gitveil"
  end

  test do
    assert_match "gitveil", shell_output("\#{bin}/gitveil --version")
  end
end
EOF

# --- 8. Commit and push formula ---
echo "==> Committing and pushing formula..."
(cd "$TAP_DIR" && git add Formula/gitveil.rb && git commit -m "Update gitveil to $VERSION" && git push)

# --- 9. Cleanup ---
rm -f "/tmp/$TARBALL"

echo ""
echo "==> Released gitveil $VERSION!"
echo "    Users can update with: brew update && brew upgrade gitveil"
