#!/usr/bin/env bash
set -euo pipefail

REPO="${SNYK_CLI_REPO:-denjamio/snyk-cli}"
BIN="snyk"
BASE_URL="${SNYK_CLI_BASE_URL:-https://github.com/${REPO}}"
API_URL="${SNYK_CLI_API_URL:-https://api.github.com/repos/${REPO}/releases/latest}"
DEST="${SNYK_CLI_INSTALL_DIR:-${HOME}/.local/bin}"

fail() { echo "error: $1" >&2; exit 1; }

detect_os() {
  case "$(uname -s)" in
    Linux) echo "linux" ;;
    Darwin) echo "darwin" ;;
    *) return 1 ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64 | amd64) echo "amd64" ;;
    arm64 | aarch64) echo "arm64" ;;
    *) return 1 ;;
  esac
}

OS="$(detect_os)" || fail "unsupported OS '$(uname -s)' - grab a binary from ${BASE_URL}/${BIN}/releases"
ARCH="$(detect_arch)" || fail "unsupported architecture '$(uname -m)' - grab a binary from ${BASE_URL}/${BIN}/releases"

VERSION="${SNYK_CLI_VERSION:-}"
if [ -z "$VERSION" ]; then
  VERSION="$(curl -fsSL "$API_URL" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)"
fi
[ -n "$VERSION" ] || fail "could not determine latest release (offline? set SNYK_CLI_VERSION)"
VER_NUM="${VERSION#v}"

ASSET="${BIN}_${VER_NUM}_${OS}_${ARCH}.tar.gz"
DL="${BASE_URL}/releases/download/${VERSION}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Installing ${BIN} ${VERSION} (${OS}/${ARCH})..."
echo "Downloading ${DL}/${ASSET}"
curl -fsSL -o "${TMP}/${ASSET}" "${DL}/${ASSET}" || fail "download failed: ${DL}/${ASSET}"
curl -fsSL -o "${TMP}/checksums.txt" "${DL}/checksums.txt" || fail "download failed: checksums.txt"

want="$(awk -v f="${ASSET}" '$NF == f { print $1 }' "${TMP}/checksums.txt")"
[ -n "$want" ] || fail "checksum for ${ASSET} not found in checksums.txt"
if command -v sha256sum >/dev/null 2>&1; then
  got="$(sha256sum "${TMP}/${ASSET}" | awk '{print $1}')"
else
  got="$(shasum -a 256 "${TMP}/${ASSET}" | awk '{print $1}')"
fi
[ "$got" = "$want" ] || fail "checksum mismatch for ${ASSET}"

tar -xzf "${TMP}/${ASSET}" -C "$TMP"
mkdir -p "$DEST"
mv "${TMP}/${BIN}" "${DEST}/${BIN}"
chmod +x "${DEST}/${BIN}"

case ":${PATH}:" in
  *":${DEST}:"*) : ;;
  *) echo "note: add ${DEST} to your PATH: export PATH=\"${DEST}:\$PATH\"" ;;
esac

"${DEST}/${BIN}" version && echo "Installed to ${DEST}/${BIN}"
echo "tip: snyk skill install --global installs the agent skill"
