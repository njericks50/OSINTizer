#!/usr/bin/env bash
# OSINTizer installer for Kali Linux (works on any Debian-based distro with Python 3.9+).
#
#   ./install.sh               install for all users (/opt/osintizer + /usr/local/bin/osintizer)
#   ./install.sh --user        install for just you (~/.local, no sudo)
#   ./install.sh --with-tools  also apt-install the OSINT collectors OSINTizer drives
set -euo pipefail

BLUE='\033[34m'; GREEN='\033[32m'; YELLOW='\033[33m'; RED='\033[31m'; RESET='\033[0m'
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_MODE=0; WITH_TOOLS=0
for arg in "$@"; do
  case "$arg" in
    --user) USER_MODE=1 ;;
    --with-tools) WITH_TOOLS=1 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo -e "${RED}Unknown option: $arg${RESET}"; exit 1 ;;
  esac
done

command -v python3 >/dev/null || { echo -e "${RED}python3 is required${RESET}"; exit 1; }
python3 - <<'EOF' || { echo -e "\033[31mPython 3.9+ is required\033[0m"; exit 1; }
import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)
EOF

SUDO=""
if [[ $USER_MODE -eq 0 && $EUID -ne 0 ]]; then SUDO="sudo"; fi

if [[ $USER_MODE -eq 1 ]]; then
  PREFIX="$HOME/.local/share/osintizer-app"
  BIN="$HOME/.local/bin"
  APPS="$HOME/.local/share/applications"
else
  PREFIX="/opt/osintizer"
  BIN="/usr/local/bin"
  APPS="/usr/share/applications"
fi

echo -e "${BLUE}[*]${RESET} Installing OSINTizer to ${PREFIX}"
$SUDO mkdir -p "$PREFIX" "$BIN" "$APPS"
$SUDO rm -rf "$PREFIX/osintizer"
$SUDO cp -r "$SRC/osintizer" "$PREFIX/"
$SUDO cp "$SRC/README.md" "$SRC/LICENSE" "$PREFIX/" 2>/dev/null || true
$SUDO find "$PREFIX" -name '__pycache__' -prune -exec rm -rf {} +

$SUDO tee "$BIN/osintizer" >/dev/null <<EOF
#!/bin/sh
PYTHONPATH="$PREFIX\${PYTHONPATH:+:\$PYTHONPATH}" exec python3 -m osintizer "\$@"
EOF
$SUDO chmod 755 "$BIN/osintizer"

# Menu entry under Kali's "Information Gathering" (plus a generic category for other desktops).
$SUDO tee "$APPS/osintizer.desktop" >/dev/null <<EOF
[Desktop Entry]
Name=OSINTizer
Comment=Collect, auto-extract and organize OSINT recon findings
Exec=x-terminal-emulator -e $BIN/osintizer
Icon=utilities-terminal
Terminal=false
Type=Application
Categories=01-info-gathering;Network;Security;
EOF

if [[ $WITH_TOOLS -eq 1 ]]; then
  echo -e "${BLUE}[*]${RESET} Installing collectors with apt"
  sudo apt-get update
  # Install one at a time so a single unavailable package doesn't abort the rest.
  for pkg in theharvester whois dnsutils subfinder amass assetfinder sherlock whatweb nmap pipx; do
    sudo apt-get install -y "$pkg" >/dev/null 2>&1 \
      && echo -e "  ${GREEN}✔${RESET} $pkg" || echo -e "  ${YELLOW}!${RESET} $pkg (not available - skipped)"
  done
  if command -v pipx >/dev/null; then
    for pkg in holehe maigret; do
      pipx install "$pkg" >/dev/null 2>&1 && echo -e "  ${GREEN}✔${RESET} $pkg (pipx)" || echo -e "  ${YELLOW}!${RESET} $pkg (pipx failed)"
    done
    pipx ensurepath >/dev/null 2>&1 || true
  fi
fi

echo -e "${GREEN}[+] Installed.${RESET}"
if [[ $USER_MODE -eq 1 && ":$PATH:" != *":$BIN:"* ]]; then
  echo -e "${YELLOW}[!] Add ${BIN} to your PATH:${RESET}  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc"
fi
echo
echo "  osintizer          start the dashboard at http://127.0.0.1:8787"
echo "  osintizer doctor   see which collectors are installed"
echo "  osintizer --help   all commands"
