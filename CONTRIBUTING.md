# Contributing

Thanks for helping. A few rules keep vulnwatch auditable.

- **Standard library only.** No third-party dependency, in the code or in the tests. The code must run on the system `/usr/bin/python3` (3.9).
- **No network in tests.** Use `vulnwatch.net.FakeTransport` and `vulnwatch.proc.FakeRunner`. Recorded responses live in `tests/fixtures/`, and they must be synthetic or scrubbed: no real usernames, hostnames or paths.
- **Test first.** Every behavior change comes with a test that failed before the change.
- **User-facing text goes through `t(en, it)`** (`vulnwatch/i18n.py`), with the same `%` placeholders in both strings. Identifiers, codes and comments are in English.
- **Keep the invariants** in [SECURITY.md](SECURITY.md). A change that makes a request depend on the inventory, builds a command from external text, or turns an unknown into a pass will not be merged.

Run the suite:

```bash
/usr/bin/python3 -I -B -m unittest discover -s tests -t . -p 'test_*.py'
```

**Try a run without installing.** `--dev` uses the clone's `config/config.json`, its own `-dev` state folder, and never applies anything:

```bash
./setup.sh
/usr/bin/python3 -I -B vulnwatch.py run --dev
```

**Keep personal details out of the repository.** Optionally, list words that must never appear in a tracked file (your username, hostnames, project names) in `config/private_tokens.txt`. That file is git-ignored, and `tests/test_hygiene.py` fails if any listed word shows up in a tracked file.
