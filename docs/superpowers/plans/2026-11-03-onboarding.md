# vulnwatch onboarding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make vulnwatch installable by anyone on macOS in three steps (clone → `./setup.sh` → `sudo ./install.sh <sha>`), with a bilingual (en/it) interface, optional Homebrew/npm, a `status` command and public-ready docs.

**Architecture:**
- **i18n:** a tiny module of inline `t(en, it)` pairs, with the language set once per process from the config.
- **setup:** a new subcommand that detects the machine with injectable probes (fully unit-testable, no network) and writes a strict-valid config.
- **status:** a read-only command over the state DB, the install root and launchd.
- **install.sh:** gains a preflight, a VERSION file, a first-run kickstart and `--purge`.

**Tech Stack:** Python 3.9 stdlib only (`/usr/bin/python3 -I -B`), unittest, bash, launchd.

**Spec:** `docs/superpowers/specs/2026-11-03-onboarding-design.md`

## Global Constraints

- Python 3.9 stdlib only; run as `/usr/bin/python3 -I -B`; no new dependencies.
- Test command (the whole suite): `/usr/bin/python3 -I -B -m unittest discover -s tests -t . -p 'test_*.py'`.
- No network access in setup, status or any test.
- I1 unchanged: requests to sources never depend on the inventory.
- English is the canonical language of code, comments, docs and identifiers. User-facing runtime text goes through `t(en, it)`.
- Default language `"en"`; allowed `"en"` and `"it"` only.
- Setup must refuse to run as root and must never overwrite `config/config.json` without `--force`.
- Install mode stays root-owned and exact-commit (`install.sh` refuses a dirty repo or a SHA other than HEAD).
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **A Mac without Homebrew or npm.** Setup writes `"brew": null` / `"npm_global": null`, and `run` and `apply` skip those parts instead of crashing (Task 5 tests).
2. **Running `sudo ./setup.sh`.** It refuses with a clear message, so the config never ends up owned by root (Task 6 test).
3. **Re-running setup when a config exists.** It refuses without `--force`; with `--force` it rewrites the file (Task 6 test).
4. **Project folders with spaces** (e.g. `~/My Projects`). Setup, the config and install.sh handle them quoted end to end (Task 6 and Task 8 tests).
5. **A language value other than en/it in the config, or an unset `LANG`.** The first gives a ConfigError; the second makes setup default to `en` (Task 1 and Task 6 tests).

---

### Task 1: Config — `language`, nullable `brew` / `npm_global` / `path_node`, English errors

**Files:** Modify `vulnwatch/config.py`; Test `tests/test_config.py`

**Interfaces:**
- **Produces:**
  - `Config.language: str` (`"en"` | `"it"`, default `"en"` when the key is absent);
  - `Config.brew: Optional[str]`;
  - `Config.npm_global: Optional[NpmGlobal]`;
  - `Config.path_node: Optional[str]`.
  - `language` is the only optional key; every other key stays required.

- [ ] **Step 1: Write the failing tests** in `tests/test_config.py`:
  - `test_language_defaults_to_en`: no `language` key → `cfg.language == "en"`;
  - `test_language_it`: `"language": "it"` → `"it"`;
  - `test_language_invalid`: `"language": "fr"` → `ConfigError`;
  - `test_nullable_brew_npm_path_node`: `brew`, `npm_global` and `path_node` set to `None` → those fields are `None`;
  - `test_errors_are_english`: a missing key → the message contains `"missing keys"`.

  Existing tests that assert Italian error text switch to the English wording.
- [ ] **Step 2: Run** `/usr/bin/python3 -I -B -m unittest discover -s tests -t . -p 'test_config.py'`. **Expected:** the new tests FAIL.
- [ ] **Step 3: Implement.**
  - English messages: `"unreadable configuration: %s"`, `"unknown keys: %s"`, `"missing keys: %s"`, `"%s: expected a list of strings"`, and so on.
  - `brew` and `path_node` accept `None` or a non-empty string; `npm_global` accepts `None` or the object.
- [ ] **Step 4: Run** the whole suite. **Expected:** OK.
- [ ] **Step 5: Commit** `feat(config): optional language, nullable brew/npm_global/path_node, English errors`.

### Task 2: i18n module and wiring

**Files:** Create `vulnwatch/i18n.py`; Modify `vulnwatch/cli.py` (call `set_language(cfg.language)` right after loading the config); Test `tests/test_i18n.py`

**Interfaces:**
- **Produces:**
  - `LANGUAGES = ("en", "it")`;
  - `set_language(lang: str) -> None` (raises `ValueError` for unknown values);
  - `language() -> str`;
  - `t(en: str, it: str) -> str`.
- **Default and tests:** the default is `"en"`. Tests that change the language restore it in `tearDown` (`set_language("en")`).

- [ ] **Step 1: Write the failing tests:**
  - `test_default_en`;
  - `test_switch_it`: `t("Report", "Rapporto")` returns the Italian text after `set_language("it")`;
  - `test_unknown_language_raises`.
- [ ] **Step 2: Run them.** **Expected:** FAIL with an ImportError.
- [ ] **Step 3: Implement** the module and the CLI wiring.
- [ ] **Step 4: Run** the suite. **Expected:** OK.
- [ ] **Step 5: Commit** `feat(i18n): inline en/it text pairs`.

### Task 3: Bilingual report, notifications, lanes (English reason codes)

**Files:** Modify `vulnwatch/report.py`, `vulnwatch/lanes.py`, `vulnwatch/grouping.py`, `vulnwatch/runner.py`; Tests `tests/test_report.py`, `tests/test_lanes.py`, `tests/test_runner*.py`, `tests/test_acceptance*.py` (assertions to English)

**Interfaces:**
- **Produces:**
  - English reason codes: `not_kev_not_critical`, `range_not_primary`, `manual_channel`, `on_hold`, `approximate_match`, `fix_version_unknown`, `audit_red`, `malicious_package`;
  - `lanes.REASONS: Dict[str, Tuple[str, str]]` (en, it);
  - `lanes.reason_text(code: str) -> str`.
- **Notifications:** texts still match `report._NOTIFY_RE`.

- [ ] **Step 1: Write the failing tests:**
  - `test_report_english_default`: the rendered markdown contains `"## Waiting for you"` and the summary line starts with `"Summary per item:"`;
  - `test_report_italian`: after `set_language("it")` it contains `"## Aspetta te"` and `"Riepilogo per elemento:"`;
  - `test_reason_codes_english`: a held finding has `"on_hold"` in `reasons`;
  - `test_notification_italian_matches_regex`: the Italian notification text matches `_NOTIFY_RE`.
- [ ] **Step 2: Run them.** **Expected:** FAIL.
- [ ] **Step 3: Implement.**
  - Wrap every user-facing string in these files in `t()`.
  - English section titles:
    - `Malicious packages`;
    - `Applied automatically`;
    - `Would have applied (shadow mode)`;
    - `Waiting for you`;
    - `No patch yet`;
    - `To verify`;
    - `Ignored`;
    - `Errors`.
  - Update the existing assertions to the English text.
- [ ] **Step 4: Run** the whole suite. **Expected:** OK.
- [ ] **Step 5: Commit** `feat(i18n): bilingual report, notifications and lanes; English reason codes`.

### Task 4: Bilingual CLI, apply, selfcheck, audits and source errors

**Files:**
- Modify:
  - `vulnwatch/cli.py`, `vulnwatch/apply.py`, `vulnwatch/selfcheck.py`;
  - `vulnwatch/audit/npm.py`, `vulnwatch/audit/brew.py`, `vulnwatch/brew_client.py`;
  - `vulnwatch/net.py`, `vulnwatch/versions.py`, `vulnwatch/store.py`, `vulnwatch/match.py`;
  - `vulnwatch/sources/*.py`.
- Tests: affected assertions in `tests/`.

**Interfaces:**
- **Apply confirmation prompt:** `[y/N]` in en (accepts `y`/`yes`), `[s/N]` in it (accepts `s`/`si`/`sì`).
- **Check names:** the `name` values (`publisher`, `cooldown`, …) stay unchanged; only the `detail` text is translated.

- [ ] **Step 1: Write the failing tests:**
  - `test_apply_prompt_english`: a fake `input` receiving `"y"` applies; receiving `"s"` in en cancels;
  - `test_apply_prompt_italian`: `"s"` applies in it;
  - `test_cli_help_english`: `_parser().format_help()` contains `"Daily vulnerability check"`.
- [ ] **Step 2: Run them.** **Expected:** FAIL.
- [ ] **Step 3: Implement.**
  - Wrap every user-facing string in `t()`.
  - Update the module docstring of `cli.py`; there is no longer an "Italian" note.
  - Translate the comments that are in Italian to English.
- [ ] **Step 4: Run** the whole suite. **Expected:** OK. Then check that no Italian is left outside `t()`: `grep -rn -E '"[^"]*(è|à|ò|ù) ' vulnwatch | grep -v "t("` should print nothing that is user-facing.
- [ ] **Step 5: Commit** `feat(i18n): bilingual CLI, apply, selfcheck and audits`.

### Task 5: Work without Homebrew, without npm, without a PATH node

**Files:** Modify `vulnwatch/cli.py` (`_ctx.inventory`), `vulnwatch/inventory/__init__.py`, `vulnwatch/runner.py`, `vulnwatch/apply.py`; Test `tests/test_optional_tools.py`

**Interfaces:**
- **Consumes:** the nullable `Config` fields from Task 1.
- **Produces:**
  - `collect()` skips the brew items when `brew_info is None` and the npm globals when `cfg.npm_global is None`;
  - `_ctx.inventory()` passes `None` instead of running brew when `cfg.brew is None`;
  - `argv_for` raises `ValueError(t("Homebrew is not configured", ...))` for brew items when `cfg.brew is None`, and likewise for npm;
  - the `path_node` before/after check is skipped when `cfg.path_node is None`.

- [ ] **Step 1: Write the failing tests:**
  - `test_collect_without_brew_and_npm`: with config `brew=None`, `npm_global=None` and fake run/apps, `collect` returns no `brew_*` or `npm_global` items and does not raise;
  - `test_argv_for_brew_without_brew_raises`;
  - `test_owner_node_none_without_npm`: the runner's npm audit path is not reached.
- [ ] **Step 2: Run them.** **Expected:** FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the suite. **Expected:** OK.
- [ ] **Step 5: Commit** `feat: Homebrew, npm and PATH node are optional`.

### Task 6: `setup` command and `setup.sh`

**Files:** Create `vulnwatch/setup.py`, `setup.sh`; Modify `vulnwatch/cli.py` (dispatch `setup` before loading the config); Test `tests/test_setup.py`

**Interfaces:**
- **Consumes:**
  - `load_config` (validate what is written);
  - `inventory.collect` (preview);
  - `i18n.set_language` / `t`.
- **Produces:**
  - `@dataclass class Detected` with these fields:
    - `user: str`, `language: str`;
    - `brew: Optional[str]`, `npm_global: Optional[Dict[str, str]]`, `path_node: Optional[str]`;
    - `runtimes: List[Dict[str, str]]`;
    - `roots: List[str]`.
  - `detect(home: str, env: Mapping[str, str], run, user: str, exists=os.path.exists, glob_fn=glob.glob, realpath=os.path.realpath, access=os.access) -> Detected`
  - `build_config(d: Detected, repo_root: str, roots: Sequence[str], language: str) -> dict`: a full config that `load_config` accepts. It uses:
    - `protected_dirs = ["~/Documents", "~/Desktop", "~/Downloads", "~/Library/Mobile Documents", "<repo_root>/tests/fixtures"]`;
    - `venv_roots = roots`;
    - `hold = []`, `auto_apply = false`;
    - the same `allowed_hosts`, intervals and limits as `config/config.example.json`.
  - `preview(cfg: Config, run) -> List[str]`: one line per inventory kind with counts, local only.
  - `main(argv: List[str], repo_root: str, run=None, env=None, home=None, user=None, input_fn=input, out=print, euid=os.geteuid) -> int`:
    - exit codes: 0 = written, 1 = refused (root, or an existing config without `--force`), 2 = usage error;
    - flags: `--yes`, `--force`, `--lang {en,it}`, `--roots DIR [DIR ...]`.
  - `cli.main(["setup", ...])` → `setup.main(argv[1:], REPO_ROOT)`, without loading a config.
- **Detection rules:**
  - **brew:** the first of `/opt/homebrew/bin/brew`, `/usr/local/bin/brew` that exists, otherwise `None`.
  - **npm:** the first executable `npm` on `env["PATH"]`, otherwise `None`.
    - `prefix` = stdout of `run([npm, "config", "get", "prefix"])`;
    - `node` = the `node` executable in the same directory;
    - `npm_global` is `None` if any of these fails.
  - **path_node:** the first `node` on PATH, resolved with `realpath`.
  - **runtimes:**
    - every `node`/`bun` on PATH;
    - the glob patterns `~/.nvm/versions/node/*/bin/node`, `~/.volta/tools/image/node/*/bin/node`, `~/.local/share/fnm/node-versions/*/installation/bin/node`, `~/.asdf/installs/nodejs/*/bin/node`, `~/.local/share/mise/installs/node/*/bin/node`, `~/.bun/bin/bun`, `/usr/local/bin/node`;
    - glob patterns are kept as patterns when they match at least once;
    - entries whose `realpath` is under a Homebrew Cellar are dropped (brew covers them);
    - duplicates are removed by `realpath`;
    - `label` is the tool name (`nvm`, `volta`, `fnm`, `asdf`, `mise`, `bun`, or `PATH`).
  - **roots:** the existing directories among `~/Code`, `~/Projects`, `~/Developer`, `~/dev`, `~/src`, `~/work`, `~/repos`, `~/git`, `~/GitHub`, `~/workspace`, written with `~`.
  - **language:** `"it"` if `env.get("LANG", "")` starts with `"it"` or the first `AppleLanguages` entry (`run(["/usr/bin/defaults", "read", "-g", "AppleLanguages"])`) starts with `it`; otherwise `"en"`.
- **Flow:**
  1. Refuse if `euid() == 0`.
  2. Refuse if the config exists and `--force` is not given.
  3. Detect.
  4. Show the detection, then ask for language and roots unless `--yes`.
  5. Build the config and validate it with `load_config` on a temp file.
  6. Write `config/config.json` (mode 0644).
  7. Print the preview and the next step: `sudo ./install.sh "$(git rev-parse HEAD)"`.

  Setup never touches the network.
- **`setup.sh`** (bash, `set -euo pipefail`):
  - refuse if `id -u` is 0;
  - refuse if `uname` is not `Darwin`;
  - if `xcode-select -p` fails, print `xcode-select --install`;
  - `exec /usr/bin/python3 -I -B "$REPO/vulnwatch.py" setup "$@"`.

- [ ] **Step 1: Write the failing tests** (all probes faked; temp repo_root and home):
  - `test_refuses_root` (`euid=lambda: 0` → 1);
  - `test_refuses_existing_config_without_force` and `test_force_overwrites`;
  - `test_detect_without_brew_and_npm` → `brew is None`, `npm_global is None`, and the written config loads;
  - `test_detect_runtimes_dedup_and_globs`: two PATH entries resolving to the same file give one runtime; an nvm glob that matches is kept as the pattern; a Cellar path is dropped;
  - `test_roots_with_spaces`: `--roots "~/My Projects"` is written verbatim and `load_config` expands it;
  - `test_language_default_en_when_lang_unset` and `test_language_it_from_lang`;
  - `test_yes_is_non_interactive`: an `input_fn` that raises is never called;
  - `test_written_config_protects_fixtures`: `protected_dirs` contains `<repo_root>/tests/fixtures`;
  - `test_cli_dispatches_setup_without_config`.
- [ ] **Step 2: Run them.** **Expected:** FAIL with an ImportError.
- [ ] **Step 3: Implement** `vulnwatch/setup.py`, the CLI dispatch and `setup.sh` (`chmod 755`).
- [ ] **Step 4: Run** the suite. **Expected:** OK. Manual smoke test: `./setup.sh --help` prints the usage and exits 0.
- [ ] **Step 5: Commit** `feat: setup command detects the Mac and writes the config`.

### Task 7: `status` command

**Files:** Create `vulnwatch/status.py`; Modify `vulnwatch/store.py`, `vulnwatch/cli.py`; Test `tests/test_status.py`

**Interfaces:**
- **Produces:**
  - `Store.last_run() -> Optional[Dict[str, Optional[str]]]`: the keys are `started_at`, `finished_at` and `status` of the newest row in `runs`.
  - `Store.pending_count() -> int`.
  - `status_lines(cfg: Config, install_root: str, plist: str, run, uid: int, store: Optional[Store]) -> List[str]`, one line each, in this order:
    1. installed commit, from `<install_root>/VERSION`, or "not installed";
    2. integrity, from `selfcheck.verify`;
    3. schedule: `run(["/bin/launchctl", "print", "gui/<uid>/local.vulnwatch"])` returns 0 → "scheduled daily at 07:30", otherwise "not loaded";
    4. last run, with its status;
    5. a first-run note when pending > 0, or when there has been no finished run yet ("first run in progress: the first download takes about 2 hours");
    6. the latest report path, plus its summary line (the first line starting with the translated "Summary per item:");
    7. mode: shadow / automatic lane on.
  - `vulnwatch status` works for the installed copy and with `--dev`.

- [ ] **Step 1: Write the failing tests:**
  - `test_status_not_installed` (empty dirs → "not installed", "not loaded", "no runs yet");
  - `test_status_after_run` (fake store with a finished `ok` run, a report file and VERSION → the lines contain the commit, `ok` and the report path);
  - `test_status_first_run_in_progress` (`pending_count` > 0);
  - `test_store_last_run_and_pending`.
- [ ] **Step 2: Run them.** **Expected:** FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** the suite. **Expected:** OK.
- [ ] **Step 5: Commit** `feat: status command`.

### Task 8: install.sh — English, preflight, VERSION, first run, purge

**Files:** Modify `install.sh`; Test `tests/test_install.py`

**Interfaces:**
- **Produces:**
  - `$DEST/VERSION` containing the full commit SHA and a newline, written before the manifest (so it is covered).
  - New flags:
    - `--no-first-run`;
    - `--purge`, valid only with `--uninstall`; it also removes `~/Library/Application Support/vulnwatch` and `~/Library/Logs/vulnwatch` of the target user.
  - Without `--no-first-run`, after bootstrap it runs `launchctl kickstart "gui/$UID/local.vulnwatch"` and prints that the first run started, takes ~2 h, and can be followed with `vulnwatch status`.
  - Preflight messages:
    - not Darwin → `vulnwatch supports macOS only`;
    - `/usr/bin/python3` not runnable → "install the Command Line Tools: xcode-select --install";
    - config missing → `run ./setup.sh first`.

- [ ] **Step 1: Write the failing tests** (test mode, temp root):
  - `test_version_file_written_and_in_manifest`;
  - `test_missing_config_points_to_setup` (stderr contains `./setup.sh`);
  - `test_purge_removes_state_and_logs`;
  - `test_purge_requires_uninstall` (exit 2);
  - `test_home_with_spaces` (`--test-home` with a space installs and writes the plist with the quoted home).
- [ ] **Step 2: Run them.** **Expected:** FAIL.
- [ ] **Step 3: Implement.** Translate all messages and comments to English.
- [ ] **Step 4: Run** the suite. **Expected:** OK.
- [ ] **Step 5: Commit** `feat(install): preflight, VERSION, first run, --purge, English`.

### Task 9: Public-ready docs, license, CI, hygiene

**Files:**
- Create:
  - `LICENSE` (MIT, `Copyright (c) 2026 cryptosecco`);
  - `README.md` (rewrite, English), `README.it.md`;
  - `SECURITY.md`, `CONTRIBUTING.md`;
  - `docs/configuration.md`;
  - `.github/workflows/tests.yml`;
  - `tests/test_hygiene.py`.
- Modify:
  - `config/config.example.json` (English, generic, `"language": "en"`; generated by `build_config` from a neutral Detected so it can never drift; a test pins this);
  - `.gitignore` (add `config/private_tokens.txt`);
  - `docs/superpowers/**` and `docs/endpoints.md` (scrub personal tool and project names).

**Interfaces:**
- **Consumes:** `setup.build_config`.
- **README sections:**
  - what it does;
  - what never leaves your Mac (I1);
  - requirements;
  - install in 3 steps;
  - what happens next (first run ~2 h, the daily report at 07:30, notifications, shadow mode);
  - daily use (status/report/apply/ignore/selfcheck);
  - turning on the automatic lane;
  - update;
  - uninstall;
  - FAQ (why sudo, why not brew/pip, is my data sent anywhere, Linux);
  - how to audit it yourself;
  - license.
- **SECURITY.md:**
  - the threat model in short;
  - invariants I1–I6;
  - how to report a vulnerability (GitHub private advisory).
- **docs/configuration.md:** every key, its type, default and meaning.
- **CI:**
  - `on: [push, pull_request]`, `permissions: contents: read`;
  - `runs-on: macos-latest`;
  - `actions/checkout` pinned to a full commit SHA, looked up with `gh api`, with the version in a comment;
  - the run step is the suite command.
- **Hygiene test:**
  - reads `config/private_tokens.txt` (one token per line, case-insensitive);
  - `skipTest` if absent;
  - fails listing `file:token` for any tracked file (`git ls-files`) containing a token.

- [ ] **Step 1: Write the failing tests:**
  - `test_example_config_matches_build_config` (`config.example.json` == `build_config(neutral)` for a neutral Detected, with `user` = `"your-username"`);
  - `test_example_config_loads`;
  - `test_no_private_tokens_in_tracked_files`.
- [ ] **Step 2: Run them.** **Expected:** FAIL (the example differs; tokens are found in the docs).
- [ ] **Step 3: Implement:**
  - write the docs;
  - regenerate `config.example.json`;
  - scrub the docs: replace personal tool names with generic descriptions ("an agent tool's bundled Node", "a held npm global", "a project folder");
  - write `config/private_tokens.txt` locally (git-ignored) with the owner's personal tokens.
- [ ] **Step 4: Run** the suite. **Expected:** OK, and the hygiene test is not skipped locally.
- [ ] **Step 5: Commit** `docs: public-ready README (en/it), security policy, configuration reference, MIT license, CI`.

### Final

- [ ] Run the whole suite; run `./setup.sh --yes --lang it --force` in a temp copy pointed at a temp repo_root, as a smoke test of the real probes (local only).
- [ ] Do a whole-branch review with a fresh reviewer; fix the Critical and Important findings in one pass.
- [ ] Merge into `main` (fast-forward) and add `"language": "it"` to the owner's local `config/config.json`. Then the owner reinstalls with `sudo ./install.sh "$(git rev-parse HEAD)"`.
- [ ] Ask the owner about publishing: make `cryptosecco/vulnwatch` public, and whether to start a fresh single-commit history so that older commits with personal names are not exposed.
