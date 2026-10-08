#!/usr/bin/env bash
# install.sh — set up repo-health: check/fetch trivy, offer semgrep via pipx,
# and optionally symlink the CLI onto your PATH.
#
# Never runs sudo. Anything that would need root is printed for you to run.
#
#   ./install.sh                 interactive
#   ./install.sh --yes           accept the no-sudo defaults (trivy + symlink)
#   ./install.sh --bin-dir DIR   where to put trivy and the repo-health symlink (default ~/.local/bin)

set -euo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$HOME/.local/bin"
ASSUME_YES=0
TRIVY_INSTALLER="https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh"

while [ $# -gt 0 ]; do
  case "$1" in
    --yes|-y)   ASSUME_YES=1; shift ;;
    --bin-dir)  BIN_DIR=$2; shift 2 ;;
    -h|--help)  sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

# ask <prompt> <default y|n> — reads from the terminal even when piped.
ask() {
  local ans=""
  if [ "$ASSUME_YES" = 1 ]; then ans=$2
  elif [ -r /dev/tty ]; then read -r -p "$1" ans < /dev/tty || ans=""
  fi
  [ -n "$ans" ] || ans=$2
  case "$ans" in [Yy]*) return 0 ;; *) return 1 ;; esac
}

have() { command -v "$1" >/dev/null 2>&1; }

echo "repo-health installer (no sudo will be used)"
echo

chmod +x "$ROOT/bin/repo-health"
mkdir -p "$ROOT/targets.d"

if ! have curl; then
  echo "curl is required. Install it first:"
  echo "  Debian/Ubuntu: sudo apt-get install -y curl    macOS: brew install curl"
  exit 1
fi
have jq || echo "note: jq is recommended (sudo apt-get install -y jq  |  brew install jq)"

# --- trivy ------------------------------------------------------------------
if have trivy; then
  echo "trivy: found ($(trivy --version 2>/dev/null | head -n 1))"
elif have brew && ask "Install trivy with Homebrew? [Y/n] " y; then
  brew install trivy
elif ask "Install trivy to $BIN_DIR with Aqua Security's official installer (no sudo; verifies checksums)? [Y/n] " y; then
  mkdir -p "$BIN_DIR"
  echo "fetching $TRIVY_INSTALLER"
  curl -sSfL "$TRIVY_INSTALLER" | sh -s -- -b "$BIN_DIR"
else
  echo "trivy skipped. Install later: https://trivy.dev/latest/getting-started/installation/"
fi

# --- semgrep ----------------------------------------------------------------
if have semgrep; then
  echo "semgrep: found ($(semgrep --version 2>/dev/null | head -n 1))"
elif have pipx; then
  if ask "Install semgrep (SAST) with pipx? It's optional and ~200MB. [y/N] " n; then
    pipx install semgrep
  else
    echo "semgrep skipped. Install later: pipx install semgrep"
  fi
elif have brew; then
  if ask "Install semgrep (SAST) with Homebrew? [y/N] " n; then brew install semgrep; fi
else
  echo "semgrep (optional SAST) needs pipx, which needs sudo to install — run this yourself if you want it:"
  echo "  sudo apt-get install -y pipx && pipx ensurepath && pipx install semgrep"
fi

# --- PATH symlink -----------------------------------------------------------
if ask "Symlink repo-health into $BIN_DIR? [Y/n] " y; then
  mkdir -p "$BIN_DIR"
  ln -sf "$ROOT/bin/repo-health" "$BIN_DIR/repo-health"
  echo "linked $BIN_DIR/repo-health -> $ROOT/bin/repo-health"
  case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) echo "note: $BIN_DIR is not on your PATH. Add to your shell profile:  export PATH=\"$BIN_DIR:\$PATH\"" ;;
  esac
fi

echo
echo "Done. Next steps:"
echo "  repo-health init      # pick a notification channel"
echo "  repo-health doctor    # see what else could be installed"
