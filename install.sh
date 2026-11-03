#!/bin/bash
# vulnwatch: hardened install.
#   sudo ./install.sh <commit>                 install or update exactly the reviewed commit (must be HEAD)
#   sudo ./install.sh <commit> --no-first-run  same, without starting the first run right away
#   sudo ./install.sh --uninstall              remove code, plist and command (your state and logs stay)
#   sudo ./install.sh --uninstall --purge      also delete your state and logs
#   ./install.sh --test-root DIR --test-user NAME --test-home DIR [...]
#                                              tests only: no root, chown, launchctl or test suite
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd -P)"
LABEL="local.vulnwatch"
PREFIX=""
MODE="install"
TEST=0
TUSER=""
THOME=""
SHA=""
FIRST_RUN=1
PURGE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --uninstall) MODE="uninstall" ;;
    --purge) PURGE=1 ;;
    --no-first-run) FIRST_RUN=0 ;;
    --test-root) PREFIX="${2:?}"; TEST=1; shift ;;
    --test-user) TUSER="${2:?}"; shift ;;
    --test-home) THOME="${2:?}"; shift ;;
    *)
      if [ -z "$SHA" ] && [[ "$1" =~ ^[0-9a-f]{7,40}$ ]]; then SHA="$1"
      else echo "unknown argument: $1" >&2; exit 2; fi ;;
  esac
  shift
done

if [ "$PURGE" = 1 ] && [ "$MODE" != "uninstall" ]; then
  echo "--purge only works together with --uninstall" >&2
  exit 2
fi

# The home folder comes from the account database (dscl prints values with spaces on a second line).
home_of() {
  /usr/bin/python3 -I -c 'import pwd, sys; print(pwd.getpwnam(sys.argv[1]).pw_dir)' "$1" 2>/dev/null || true
}

if [ "$TEST" = 1 ]; then
  if [ -z "$TUSER" ]; then echo "--test-user is required" >&2; exit 2; fi
  USER_NAME="$TUSER"
  USER_HOME="${THOME:-$(home_of "$USER_NAME")}"
else
  if [ "$(uname -s)" != "Darwin" ]; then echo "vulnwatch supports macOS only" >&2; exit 1; fi
  if [ "$(id -u)" != 0 ]; then echo "run it with sudo: sudo ./install.sh \"\$(git rev-parse HEAD)\"" >&2; exit 1; fi
  USER_NAME="${SUDO_USER:-}"
  if [ -z "$USER_NAME" ] || [ "$USER_NAME" = "root" ]; then
    echo "run it with sudo from your own account, not from a root shell" >&2; exit 1
  fi
  USER_HOME="$(home_of "$USER_NAME")"
fi
case "$USER_HOME" in
  /*) ;;
  *) echo "cannot determine the home folder of $USER_NAME (got: '$USER_HOME')" >&2; exit 1 ;;
esac
if [[ "$USER_HOME" == *$'\n'* ]]; then echo "the home folder of $USER_NAME contains a newline" >&2; exit 1; fi

DEST="$PREFIX/usr/local/libexec/vulnwatch"
PLIST="$PREFIX/Library/LaunchAgents/$LABEL.plist"
WRAPPER="$PREFIX/usr/local/bin/vulnwatch"
USER_UID="$(id -u "$USER_NAME")"
STATE_DIR="$USER_HOME/Library/Application Support/vulnwatch"
LOG_DIR="$USER_HOME/Library/Logs/vulnwatch"

as_user() {
  if [ "$TEST" = 1 ]; then "$@"; else /usr/bin/sudo -u "$USER_NAME" "$@"; fi
}

own_root() {
  if [ "$TEST" != 1 ]; then /usr/sbin/chown -R root:wheel "$@"; fi
}

if [ "$MODE" = "uninstall" ]; then
  if [ "$TEST" != 1 ]; then /bin/launchctl bootout "gui/$USER_UID/$LABEL" 2>/dev/null || true; fi
  rm -f "$PLIST" "$WRAPPER"
  rm -rf "$DEST"
  if [ "$PURGE" = 1 ]; then
    as_user rm -rf "$STATE_DIR" "$LOG_DIR"
    echo "vulnwatch uninstalled; state and logs deleted."
  else
    echo "vulnwatch uninstalled. Your state and logs are still in $STATE_DIR and $LOG_DIR (use --purge to delete them)."
  fi
  exit 0
fi

# 1. Preflight: system Python, a clean repo, the reviewed commit, a local configuration.
if [ "$TEST" != 1 ] && ! /usr/bin/python3 -c 'import sys' >/dev/null 2>&1; then
  echo "/usr/bin/python3 is not usable: install the Command Line Tools with  xcode-select --install" >&2
  exit 1
fi
if [ -n "$(as_user git -C "$REPO" status --porcelain)" ]; then
  echo "the repo is not clean: commit or discard your changes before installing" >&2
  exit 1
fi
if [ -z "$SHA" ]; then
  echo "usage: sudo ./install.sh <reviewed commit>   (for example: sudo ./install.sh \"\$(git rev-parse HEAD)\")" >&2
  exit 2
fi
COMMIT="$(as_user git -C "$REPO" rev-parse --verify --quiet "$SHA^{commit}")" || { echo "unknown commit $SHA" >&2; exit 1; }
HEAD_SHA="$(as_user git -C "$REPO" rev-parse HEAD)"
if [ "$COMMIT" != "$HEAD_SHA" ]; then
  echo "the given commit ($COMMIT) is not HEAD ($HEAD_SHA): check out the commit you reviewed" >&2
  exit 1
fi
# The machine configuration is not in the repo: it is the local, git-ignored config/config.json.
if [ ! -f "$REPO/config/config.json" ]; then
  echo "config/config.json is missing: run ./setup.sh first (as yourself, without sudo)" >&2
  exit 1
fi
echo "Installing commit $COMMIT"

# 2. The test suite must pass, run as the user (never as root).
if [ "$TEST" != 1 ]; then
  echo "Running the test suite..."
  (cd "$REPO" && as_user /usr/bin/python3 -I -B -m unittest discover -s tests -t . -p 'test_*.py' -q) || {
    echo "the tests fail: installation cancelled" >&2; exit 1; }
fi

# 3. Copy into a fresh folder, root-owned and read-only, plus a manifest of hashes.
STAGE="$DEST.new"
rm -rf "$STAGE"
mkdir -p "$STAGE"
# Only the content of the commit: no files changed after the review, no git-ignored files.
as_user git -C "$REPO" archive --format=tar "$COMMIT" vulnwatch.py vulnwatch config | tar -x -C "$STAGE"
cp "$REPO/config/config.json" "$STAGE/config/config.json"
echo "Local configuration installed, sha256 $(/usr/bin/shasum -a 256 "$STAGE/config/config.json" | /usr/bin/awk '{print $1}')"
printf '%s\n' "$COMMIT" > "$STAGE/VERSION"
find "$STAGE" -name '__pycache__' -type d -prune -exec rm -rf {} +
find "$STAGE" -name '*.pyc' -delete
find "$STAGE" -type d -exec chmod 755 {} +
find "$STAGE" -type f -exec chmod 644 {} +
/usr/bin/python3 -I -B -c 'import sys; sys.path.insert(0, sys.argv[1]); from vulnwatch.selfcheck import write_manifest; write_manifest(sys.argv[1])' "$STAGE"
chmod 644 "$STAGE/manifest.json"
own_root "$STAGE"

# 4. Atomic swap with the previous version.
mkdir -p "$(dirname "$DEST")"
if [ -d "$DEST" ]; then rm -rf "$DEST.old"; mv "$DEST" "$DEST.old"; fi
mv "$STAGE" "$DEST"
rm -rf "$DEST.old"

# 5. Root-owned LaunchAgent (the job itself still runs as the user, without privileges).
mkdir -p "$(dirname "$PLIST")"
# Escape the home for XML (& < >), then for the sed replacement (\ | &).
HOME_XML="$(printf '%s' "$USER_HOME" | /usr/bin/sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g')"
HOME_SED="$(printf '%s' "$HOME_XML" | /usr/bin/sed -e 's/[\\|&]/\\&/g')"
as_user git -C "$REPO" show "$COMMIT:launchd/$LABEL.plist.in" | /usr/bin/sed -e "s|@HOME@|$HOME_SED|g" > "$PLIST.tmp"
chmod 644 "$PLIST.tmp"
own_root "$PLIST.tmp"
/usr/bin/plutil -lint "$PLIST.tmp" > /dev/null
mv "$PLIST.tmp" "$PLIST"

# 6. The `vulnwatch` command, always pointing at the installed copy.
mkdir -p "$(dirname "$WRAPPER")"
printf '#!/bin/sh\nexec /usr/bin/python3 -I -B /usr/local/libexec/vulnwatch/vulnwatch.py "$@"\n' > "$WRAPPER"
chmod 755 "$WRAPPER"
own_root "$WRAPPER"

# 7. The user's state and log folders, then load the LaunchAgent in their session.
as_user mkdir -p "$STATE_DIR" "$LOG_DIR"
if [ "$TEST" != 1 ]; then
  /bin/launchctl bootout "gui/$USER_UID/$LABEL" 2>/dev/null || true
  /bin/launchctl bootstrap "gui/$USER_UID" "$PLIST"
  as_user /usr/bin/python3 -I -B "$DEST/vulnwatch.py" selfcheck
fi
echo "vulnwatch $COMMIT installed in $DEST"
echo "It runs every day at 07:30 and starts in shadow mode: it reports, it never applies anything on its own."
if [ "$FIRST_RUN" = 1 ]; then
  if [ "$TEST" != 1 ]; then /bin/launchctl kickstart "gui/$USER_UID/$LABEL" || true; fi
  echo "The first run has started in the background. It takes about 2 hours the first time (it downloads public"
  echo "vulnerability data); you get a notification when the report is ready. Follow it with: vulnwatch status"
else
  echo "Start the first run whenever you like with: vulnwatch run   (about 2 hours the first time)"
fi
