# Configuration

`./setup.sh` writes `config/config.json` for you. Edit it when you want to change something, then reinstall with `sudo ./install.sh "$(git rev-parse HEAD)"`: the installed copy is root-owned, so changes in your clone take effect only when you reinstall. The file is git-ignored, so your repo stays clean.

The loader is strict. An unknown key, a missing key or a wrong type stops the job with a clear message (`vulnwatch status` and the notification show it). Paths may start with `~`. Every key is required except `language`.

## What you are likely to change

| Key | Type | Default | Meaning |
|---|---|---|---|
| `user` | string | your username | The only account allowed to run the job. |
| `language` | `"en"` or `"it"` | `"en"` | Language of reports, notifications and messages. |
| `auto_apply` | bool | `false` | `false` = shadow mode, which reports and never applies. `true` = applies green audits for homebrew/core formulae and npm globals. |
| `hold` | list of names | `[]` | Package or formula names that are never applied automatically, even with a green audit. |
| `lockfile_roots` | list of paths | detected | Folders searched for project lockfiles. |
| `lockfile_max_depth` | int | `4` | How many folder levels below each root are searched. |
| `protected_dirs` | list of paths | Documents, Desktop, Downloads, iCloud Drive, this repo's test fixtures | Never entered while searching, even when they sit under a root. This keeps macOS from asking for permission and keeps iCloud from downloading files. |
| `venv_roots` | list of paths | same as `lockfile_roots` | Where Python virtual environments are checked after an upgrade, to report any the upgrade broke. |
| `app_dirs` | list of paths | `/Applications`, `~/Applications` | Where apps are inventoried. |

## Tools on this Mac (detected by setup)

| Key | Type | Meaning |
|---|---|---|
| `brew` | path or `null` | The Homebrew executable. `null` turns off Homebrew inventory, audits and upgrades. |
| `npm_global` | `{prefix, node, npm}` or `null` | Where global npm packages live, and the node/npm that manage them. `null` turns off npm globals. |
| `path_node` | path or `null` | The `node` first on your PATH. Its version is checked before and after every upgrade, so an unexpected change is reported. |
| `runtimes` | list of `{label, path, product}` | Extra copies of Node or Bun to inventory. `product` is `node` or `bun`; `path` may be a glob (for example `~/.nvm/versions/node/*/bin/node`). |
| `google_updater` | path | Google's updater, used by `vulnwatch apply` for Chrome. |
| `chrome_team_id` | string | The Apple Team ID expected on Chrome's signature (`EQHXZ8M8AV`). |

## Sources and limits (leave as is unless you know why)

| Key | Type | Default | Meaning |
|---|---|---|---|
| `cooldown_hours` | int | `48` | A release must be at least this old before it is applied (`--accept-fresh` overrides it for one apply). |
| `backfill_days` | int | `90` | How far back the first run reads cve.now. |
| `max_records_per_run` | int | `3000` | At most this many CVE records are downloaded per run; the rest stays queued for the next day. |
| `min_request_interval` | number | `0.2` | Seconds between any two requests. |
| `host_intervals` | object | `{"cve.now": 2.0}` | Per-host minimum interval in seconds; each host must be in `allowed_hosts`. |
| `allowed_hosts` | list | the source and registry hosts | The only hosts vulnwatch may contact, redirects included. |
| `osv_ecosystems` | list | `["npm", "PyPI"]` | OSV ecosystems to download. |
| `osv_zip_max_bytes` | int | `450000000` | Upper bound for an OSV export download. |
| `state_dir` | path | `~/Library/Application Support/vulnwatch` | Database and reports. |
| `log_dir` | path | `~/Library/Logs/vulnwatch` | Logs, the request log and `actions.jsonl`. |
| `aliases_file` | path | `aliases.json` | Maps advisory vendor/product names to installed software (relative to the config folder). |

## Exit codes of `vulnwatch run`

| Code | Meaning |
|---|---|
| 0 | Done (the report says whether every source answered). |
| 1 | Invalid configuration or wrong user. |
| 2 | Suspected tampering: the installed copy does not match its manifest; nothing was fetched or applied. |
| 3 | No data, or the inventory failed. |
| 4 | Another run is still in progress. |
