#!/bin/bash
# vulnwatch first-time setup: detects this Mac and writes config/config.json.
# Local only: it makes no network request. Run it as yourself, never with sudo.
#   ./setup.sh                 interactive (asks for language and project folders)
#   ./setup.sh --yes           accept what was detected
#   ./setup.sh --help          all options
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd -P)"

if [ "$(id -u)" = 0 ]; then
  echo "Do not run setup with sudo: run ./setup.sh as yourself." >&2
  exit 1
fi
if [ "$(uname -s)" != "Darwin" ]; then
  echo "vulnwatch supports macOS only." >&2
  exit 1
fi
if ! /usr/bin/xcode-select -p >/dev/null 2>&1 || ! /usr/bin/python3 -c 'import sys' >/dev/null 2>&1; then
  echo "vulnwatch needs Apple's Command Line Tools (for /usr/bin/python3 and git)." >&2
  echo "Install them with:  xcode-select --install   then run ./setup.sh again." >&2
  exit 1
fi
if ! /usr/bin/git -C "$REPO" rev-parse HEAD >/dev/null 2>&1; then
  echo "Run setup from a git clone of vulnwatch (install.sh installs an exact commit)." >&2
  exit 1
fi

exec /usr/bin/python3 -I -B "$REPO/vulnwatch.py" setup "$@"
