```text
  .----------.
  |       // |                 _                          _          _
  |      //  |  __   __ _   _ | | _ __  __      __  __ _ | |_   ___ | |__
  | \\  //   |  \ \ / /| | | || || '_ \ \ \ /\ / / / _` || __| / __|| '_ \
  |  \\//    |   \ V / | |_| || || | | | \ V  V / | (_| || |_ | (__ | | | |
   \  \/    /     \_/   \__,_||_||_| |_|  \_/\_/   \__,_| \__| \___||_| |_|
    '.____.'

  public data          your Mac                            you
 +-------------+      +----------------------------+      +----------------------+
 | cve.now     |      | what you have installed    |      | report at 07:30      |
 | CISA KEV    | ---> | is matched here, locally;  | ---> | vulnwatch apply <id> |
 | CVE records |      | upgrades are audited first |      |                      |
 | OSV         |      |                            |      |                      |
 +-------------+      +----------------------------+      +----------------------+
                  <----- nothing about your Mac goes back -----
```

**A daily vulnerability check for your Mac that never tells anyone what you run.**

[![tests](https://github.com/cryptosecco/vulnwatch/actions/workflows/tests.yml/badge.svg)](https://github.com/cryptosecco/vulnwatch/actions/workflows/tests.yml) · macOS · Python standard library only · [MIT](LICENSE) · *[Leggi in italiano](README.it.md)*

## Why

A developer's Mac runs hundreds of things that get security fixes:
- macOS and its apps;
- Homebrew formulae and global npm tools;
- the copies of Node that other tools bring along;
- the dependencies pinned in every project you have cloned.

New vulnerabilities are published every day, and some are already being exploited by the time you read about them. Keeping up by hand is not realistic. The usual shortcut, sending your package list to a scanning service, gives a third party an exact map of what is unpatched on your machine.

vulnwatch does the whole check **on your Mac**:
- Every morning at 07:30 it downloads the same public vulnerability data everyone gets and compares it locally with what you have installed.
- It tells you what is affected, what the fix is, and the exact command to apply it after a fresh audit.
- It starts in **shadow mode**: it reports and never changes anything on its own, until you choose to turn on automatic upgrades.

## What you get

A macOS notification such as *"3 waiting for you · 0 applied · 0 malicious"*, and a daily report in Markdown (plus JSON). One entry looks like this; the vulnerability ids and versions are made up:

```markdown
### brew formula `openssl@3` `3.5.9` · 2 vulnerabilities
- Location: `/opt/homebrew`
- Fixed version: 3.5.10 (source: cverecord)
- KEV: no · Critical: yes (1)
- Vulnerabilities: `CVE-2026-1111` (`7c1f0a2b9d4e`), `CVE-2026-2222` (`2b8e4d1c0f3a`)

| check | result | detail |
|---|---|---|
| tap_core | ✅ ok |  |
| candidate | ✅ ok | `3.5.10` |
| same_major | ✅ ok |  |
| bottle_available | ✅ ok |  |
| dry_run_only_target | ✅ ok |  |
| post_install_unchanged | ✅ ok |  |
| caveats_unchanged | ✅ ok |  |
| not_running_service | ✅ ok |  |
| not_deprecated | ✅ ok |  |
| cooldown | ✅ ok | `published 96 hours ago` |

- Command: `vulnwatch apply 7c1f0a2b9d4e`
> [untrusted text] `OpenSSL: example advisory title`
```

The report also lists what has no patch yet, approximate matches to verify, malicious packages, ignored entries and whether every source answered. It also shows what vulnwatch would have upgraded on its own while it is in shadow mode.

## Why you can trust it

- **Private by design.** What it downloads from the vulnerability sources never depends on what you have installed, so the sources cannot learn your software from the requests. All matching happens locally.
- **Audit first, apply later.** Before an upgrade is applied it is checked on the official channel:
  - who published it;
  - its install scripts and new dependencies;
  - its provenance;
  - a 48-hour cooldown.

  Anything unknown counts as a failure.
- **Hardened install.** The code is installed root-owned and read-only from the exact git commit you reviewed. Every run checks it against a manifest of hashes.
- **Nothing to install.** It uses the Python that ships with Apple's Command Line Tools and only its standard library: no pip, no npm, no Homebrew needed.

## What it checks

| Source (public data) | What it brings |
|---|---|
| [cve.now](https://cve.now) | Fresh critical and known-exploited entries |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Vulnerabilities exploited in the wild |
| [CVE records](https://github.com/CVEProject/cvelistV5) | Official affected-version ranges |
| [OSV](https://osv.dev) (npm, PyPI) | Package advisories and malicious packages |

It matches them against:
- macOS itself and the apps in `/Applications`;
- Homebrew formulae and casks;
- global npm packages;
- copies of Node and Bun (on your PATH, or installed with nvm, volta, fnm, asdf or mise);
- the packages pinned in your projects' lockfiles: `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock` and `requirements.txt`.

## How it compares

| Tool | What it covers | What it sends out |
|---|---|---|
| `brew outdated` / `brew upgrade` | Homebrew only; every update, not just security fixes | nothing beyond Homebrew's own requests |
| `npm audit` | one project at a time | that project's dependency list, to the npm registry |
| Dependabot, Snyk and similar | the repositories you connect | they read your manifests and lockfiles in their service |
| `osv-scanner` | the folders you point it at | package names and versions to the OSV API, unless run offline |
| **vulnwatch** | the whole Mac: macOS, apps, Homebrew, npm globals, Node/Bun copies, every project's lockfile | nothing about your software to the vulnerability sources |

It does not replace those tools: keep Dependabot on your repositories, because vulnwatch watches the machine you work on. It also audits every upgrade before applying it, which none of the others do for you.

## Install (about 5 minutes)

You need macOS (Apple Silicon or Intel), an administrator account and Apple's Command Line Tools (`xcode-select --install` if `git` is missing). Homebrew and npm are optional.

```bash
git clone https://github.com/cryptosecco/vulnwatch.git
cd vulnwatch
./setup.sh                                   # detects your Mac, asks two questions, writes config/config.json
sudo ./install.sh "$(git rev-parse HEAD)"    # installs exactly the commit you have checked out
```

**What `./setup.sh` does:**
- It finds Homebrew, your npm global packages, your copies of Node and Bun, your project folders and your language.
- It asks you to confirm the language and the project folders.
- It shows a local count of what will be checked.

It sends nothing over the network itself (npm's own update check is turned off), and it never runs as root.

**What `install.sh` does:**
1. It refuses a repo with uncommitted changes, or a commit other than the one checked out.
2. It runs the test suite as you.
3. It copies that commit into `/usr/local/libexec/vulnwatch` (root-owned, read-only) and writes a hash manifest.
4. It installs the daily job in `/Library/LaunchAgents/local.vulnwatch.plist` and the `vulnwatch` command.
5. It starts the first run.

## What happens next

- **The first run** starts right after install and takes **about 2 hours**: it downloads 90 days of public data. Follow it with `vulnwatch status`.
- **The report** is written to `~/Library/Application Support/vulnwatch/reports/<date>.md` (plus a `.json`). A notification tells you how many items wait for you.
- **Every morning at 07:30** it repeats the check, downloading only what changed. If the Mac is asleep, it runs when it wakes.
- **Nothing is applied** while shadow mode is on. Each report entry says what to do, and for Homebrew formulae and npm globals it gives the exact `vulnwatch apply <id>` command.

```
$ vulnwatch status
Installed:   commit 0123456789ab
Integrity:   intact
Schedule:    every day at 07:30
Last run:    started 2026-11-03T06:30:00Z, finished 2026-11-03 06:41:12 UTC, status ok
Report:      ~/Library/Application Support/vulnwatch/reports/2026-11-03.md
             Summary per item: 0 malicious · 0 applied · 0 in shadow · 3 waiting for you · 1 without a patch · …
Mode:        shadow (reports only, never applies anything on its own)
```

## Daily use

| Command | What it does |
|---|---|
| `vulnwatch status` | installation, schedule, last run, latest report |
| `vulnwatch report` | path of the latest report |
| `vulnwatch apply <id>` | re-runs the audit, shows every check, asks for confirmation, installs the audited version |
| `vulnwatch apply <id> --accept-fresh` | same, accepting a version younger than the 48-hour cooldown |
| `vulnwatch ignore <id> --reason "…"` | hides an entry from the to-do list (it stays listed under "Ignored") |
| `vulnwatch selfcheck` | verifies the installed copy against its manifest |
| `vulnwatch run` | runs the daily check now |

Logs are in `~/Library/Logs/vulnwatch/`. `actions.jsonl` records every change vulnwatch made, and `requests-<date>.log` lists every HTTP request vulnwatch made (in `run` and in `apply`).

## Turning on the automatic lane

When a few reports have convinced you:
1. Set `"auto_apply": true` in `config/config.json`.
2. Reinstall with `sudo ./install.sh "$(git rev-parse HEAD)"`.

From then on vulnwatch applies upgrades on its own, but only for **Homebrew formulae from homebrew/core and global npm packages**, only when the audit is fully green, and only on days when every source answered. These stay manual by design:
- Python, Node and Bun formulae (other tools depend on them);
- apps, casks and macOS;
- anything in your projects;
- anything on your `hold` list.

## Update

vulnwatch never updates itself. To update, run:

```bash
git pull
git log -p ORIG_HEAD..HEAD                   # read what changed
sudo ./install.sh "$(git rev-parse HEAD)"
```

## Uninstall

```bash
sudo ./install.sh --uninstall           # removes the code, the job and the command; keeps your reports and logs
sudo ./install.sh --uninstall --purge   # also deletes reports, state and logs
```

## What leaves your Mac

- **To the sources** (cve.now, CISA, the CVE list on GitHub, OSV): the same generic requests for everyone. These are the "latest critical entries" feed, the full KEV catalog, CVE records by id from the public change log, and OSV's full exports. Nothing about your software is ever in a URL, a header or a body.
- **To the official channels, during an audit only:**
  - `registry.npmjs.org` is asked for the metadata of the one npm package being audited, as `npm` itself fetches it.
  - `api.github.com` is asked for the commit history of the one Homebrew formula being audited (for the cooldown).
  - It happens when an audit runs: in the daily job, for each Homebrew or npm item that has a known fix, and when you run `vulnwatch apply`.
- **Homebrew and npm themselves, when vulnwatch runs them:**
  - the daily job runs `brew update` before auditing a Homebrew item that has a fix;
  - an apply runs `brew upgrade` or `npm install -g`, which download the package;
  - those requests are Homebrew's and npm's own, the same as when you run them by hand, so they are not in vulnwatch's request log.
- **Nothing else.** There is no telemetry and no account, and every HTTP request vulnwatch itself makes is in `requests-<date>.log`.

## FAQ

**Why does install need sudo?** The installed code and its configuration are owned by root, so nothing running as you, including malware or a compromised dependency, can quietly change what the daily job does. The job itself runs as you, without privileges.

**Why not Homebrew or pip?** Because the point is to install exactly the code you reviewed. `install.sh` installs one git commit, verified, and nothing else.

**Does it work without Homebrew or npm?** Yes. Setup detects what you have, and those checks simply switch off.

**Linux or Windows?** No. vulnwatch is built around macOS: launchd, `/Applications`, code signatures and Homebrew.

**The first run is slow.** Yes. It downloads 90 days of public data (cve.now asks for at most one request every 2 seconds). Later runs only fetch what changed.

## Audit it yourself

It is about 5,000 lines of standard-library Python, with no dependencies. Good places to start:
- `vulnwatch/runner.py`: the order of a run;
- `vulnwatch/net.py`: the host allowlist and request log;
- `vulnwatch/apply.py`: the fixed command templates;
- `vulnwatch/audit/`: the checks;
- `vulnwatch/selfcheck.py`: the tamper check;
- `install.sh`.

Run the tests with:

```bash
/usr/bin/python3 -I -B -m unittest discover -s tests -t . -p 'test_*.py'
```

See also [SECURITY.md](SECURITY.md), [docs/configuration.md](docs/configuration.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
