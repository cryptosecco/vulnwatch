# vulnwatch for everyone: onboarding design

Date: 2026-11-03. The owner asked for vulnwatch to become "a repo anyone can install, with simple and effective onboarding" and chose to skip the questions ("procedi con le tue scelte"). Every decision below is my call and is marked as such.

## Intent

Anyone running macOS should be able to go from `git clone` to a scheduled daily vulnerability check in about five minutes. They should understand what will run, what leaves the machine and how to undo it. The security posture that makes vulnwatch worth installing must not get weaker. It rests on four rules:
- uniform fetching (I1);
- fixed command templates;
- fail closed;
- installing the exact reviewed commit, with root-owned code.

## Goals

- **Three steps:** clone, `./setup.sh`, `sudo ./install.sh "$(git rev-parse HEAD)"`. After that, `vulnwatch status` tells the user what is happening.
- **Setup detects the machine.** Nobody hand-edits JSON on day one. It detects:
  - user and language;
  - Homebrew;
  - the npm global prefix and its node/npm;
  - copies of Node and Bun from PATH and from the common version managers;
  - project folders;
  - private folders not to scan.
- **Setup shows a local-only preview** of what will be inventoried, with counts by kind and no network. That builds trust before installing.
- **A first run starts right after install**, in the background. Its expected duration (~2 h the first time) is stated up front.
- **Works without Homebrew and without npm.** Those inventories and lanes simply switch off.
- **Bilingual interface (en/it)** for reports, notifications and the CLI, chosen in setup (default from the system language; `en` otherwise).
- **Public-ready repo:** English README with an Italian translation, SECURITY.md, configuration reference, MIT license, CI on macOS. No personal tool or project names in tracked files.

## Non-goals

- Linux or Windows.
- A Homebrew tap or a PyPI package.
- Any `curl | sh` installer.
- Self-update.
- A GUI.
- A user-level (non-root) install mode. The hardened install stays the only mode.

## Anti-goals

These would be failures even if everything technically works:
- Setup or status making a network request, or sending anything about the machine anywhere.
- Setup silently overwriting an existing `config/config.json`.
- An onboarding shortcut that installs code other than the reviewed commit, or that runs as root more than install.sh already does.

## Decisions (my calls)

- **Platform:** macOS only (Apple Silicon and Intel). The system `/usr/bin/python3` (3.9, from the Command Line Tools) and stdlib only, unchanged.
- **Entry point:** `./setup.sh` is a short shell wrapper.
  - It checks for macOS, the Command Line Tools (`xcode-select -p`) and git, and refuses to run as root.
  - It then runs `/usr/bin/python3 -I -B vulnwatch.py setup "$@"`.
  - The `setup` subcommand runs before any config exists.
- **Setup flags:** `--yes` (accept the detected defaults, no prompts), `--lang en|it`, `--roots DIR...`, `--force` (overwrite an existing config).
- **Config changes:**
  - New optional key `language` (`"en"`/`"it"`, default `"en"`).
  - `brew`, `npm_global` and `path_node` may be `null`.
  - Config errors are in English (they are shown before a language is known).
- **i18n:**
  - Inline pairs `t(en, it)` in a tiny `vulnwatch/i18n.py`, with a module-level language set once per process from the config. No catalog files.
  - Internal reason codes become English identifiers.
- **Status:** `vulnwatch status` is a read-only summary:
  - installed commit;
  - integrity;
  - schedule;
  - last run and its outcome;
  - first-run progress (pending queue);
  - latest report path and summary line.
- **install.sh:**
  - English messages, plus a preflight that points to `./setup.sh` when the config is missing.
  - Writes a `VERSION` file (the installed commit), which the manifest covers.
  - Starts the first run with `launchctl kickstart` unless `--no-first-run` is given.
  - `--uninstall --purge` also deletes the user's state and logs.
- **Docs:** English is canonical. `README.it.md` mirrors the README. The internal design docs stay, scrubbed of personal tool and project names. A git-ignored `config/private_tokens.txt` feeds a hygiene test that fails if any listed token appears in a tracked file; the test is skipped when the file is absent.
- **CI:** `.github/workflows/tests.yml` on `macos-latest`, read-only permissions, actions pinned by commit SHA. It runs the unittest suite with `/usr/bin/python3`.
- **License:** MIT, copyright holder `cryptosecco`.
- **Publishing:** making the GitHub repository public (and whether to start a fresh history) is a separate step and needs the owner's explicit confirmation.

## Left to the builder

- The wording of prompts and docs.
- The exact list of version-manager globs.
- How the status output is laid out.
