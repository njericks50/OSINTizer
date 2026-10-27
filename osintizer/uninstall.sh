#!/usr/bin/env bash
# Removes OSINTizer. Your cases are kept in ~/.local/share/osintizer unless you pass --purge.
set -euo pipefail
SUDO=""; [[ $EUID -ne 0 ]] && SUDO="sudo"
$SUDO rm -rf /opt/osintizer /usr/local/bin/osintizer /usr/share/applications/osintizer.desktop
rm -rf "$HOME/.local/share/osintizer-app" "$HOME/.local/bin/osintizer" "$HOME/.local/share/applications/osintizer.desktop"
if [[ "${1:-}" == "--purge" ]]; then
  rm -rf "$HOME/.local/share/osintizer"
  echo "Removed OSINTizer and all case data."
else
  echo "Removed OSINTizer. Case data kept in ~/.local/share/osintizer (use --purge to delete it)."
fi
