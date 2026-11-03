# Security

vulnwatch reads hostile data every day (vulnerability feeds whose text anyone can influence) and can upgrade software on your Mac. This page says what it defends against and the rules the code keeps.

## Reporting a vulnerability

Please report it privately through GitHub: **Security → Report a vulnerability** on this repository (a private security advisory). Do not open a public issue for a vulnerability. Include the version (`vulnwatch status` shows the installed commit), what you did, and what happened.

## Threat model

**In scope:**
- **Hostile feed content.** Advisory text, titles and version fields may contain shell metacharacters, Markdown or links, escape sequences, invisible Unicode, absurd version ranges or prompt-injection attempts.
- **Poisoned or malicious packages.** An upgrade may come from a hijacked maintainer account, a typosquat, a new install script or new dependencies, or a release that is too fresh to have been noticed.
- **A source that is down, slow or lying.** Missing data must never look like "you are safe".
- **Local tampering by non-root code.** Something running as you may try to change what the daily job does.
- **Privacy.** The sources must not learn what you run.

**Out of scope:**
- An attacker who already has root on your Mac.
- A compromised Apple toolchain (`/usr/bin/python3`, `git`).
- The correctness of upstream advisories themselves.

## Invariants

These hold for every code path and are covered by tests (`tests/test_acceptance.py` exercises them end to end).

1. **I1. Nothing of yours reaches the sources.**
   - Requests to cve.now, CISA, the CVE list and OSV never depend on your inventory.
   - Sync functions do not even receive it.
   - Every listed entry is fetched the same way, whether or not it concerns you.
   - Matching is local.
2. **I2. Commands come only from fixed templates.**
   - No command is ever built from advisory text.
   - No shell is used.
   - Package names and versions are validated against strict patterns before they reach an argv list.
   - External text in reports is made inert (defanged links, no Markdown links, control characters stripped, marked "[untrusted text]").
3. **I3. Fail closed.**
   - An unknown check result counts as a failure.
   - A missing source turns the automatic lane off for the day.
   - A run with no data says **NO DATA**, never "all clear".
4. **I4. Install exactly what was audited.**
   - The audit picks one exact version.
   - The upgrade installs that version, from the fixed registry, with a 48-hour cooldown that also covers npm's dependency tree (`--before`).
   - The audit is repeated right before applying, so it cannot go stale between check and use.
5. **I5. No root at runtime.**
   - Only `install.sh` uses root, to place root-owned, read-only code and configuration.
   - The daily job and `vulnwatch apply` run as you.
6. **I6. Everything is logged.**
   - Every change goes to `~/Library/Logs/vulnwatch/actions.jsonl`, with before/after versions, the audit and a rollback hint.
   - Every HTTP request vulnwatch makes, in `run` and in `apply`, goes to `requests-<date>.log`.
   - The tools it starts (`brew`, `npm`, Google's updater) make their own requests, which are not in that log.

## Audit checks before an upgrade

- **npm:**
  - same maintainers;
  - publisher is a maintainer, or is the same npm trusted publisher with provenance;
  - no new or changed install scripts;
  - no new dependencies;
  - provenance not dropped;
  - `engines` compatible with the Node that runs it;
  - not reported as malicious;
  - not deprecated;
  - same major version;
  - 48-hour cooldown.
- **Homebrew:**
  - the dry run must touch only the target;
  - `post_install` and caveats are reviewed;
  - a bottle exists for your architecture;
  - cooldown from the formula's commit history;
  - no running service or process still uses the old keg.

## Tamper check

Before every run and every apply, `vulnwatch selfcheck` verifies the installed copy:
- every file is owned by root and is not writable by others;
- there are no symlinks and no bytecode;
- every file's hash matches the manifest written at install time.

A mismatch stops the job before any network request and sends a notification.

## Supply chain of this repository

- Zero dependencies: only Python's standard library.
- CI actions are pinned by commit SHA and run with read-only permissions.
- `install.sh` installs a single reviewed commit with `git archive`. Untracked or ignored files never reach the installed copy, except your local `config/config.json`, whose hash is printed at install time.
