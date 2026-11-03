# Endpoint verificati (2026-11-03)

Tutte le richieste sono state fatte con User-Agent `vulnwatch/0.1`, solo verso URL generici. Per npm e GitHub si sono usati pacchetti che non abbiamo installato (`left-pad`, la formula `hello`).

## cve.now (fonte di innesco, non fidata)

| URL | Esito | Note |
|---|---|---|
| `https://cve.now/api/v1/entries?filter=critical,kev` | 200, JSON | `{"entries": [...30], "nextCursor": "<str>"}` |
| `…&cursor=<nextCursor>` (codificato) | 200 | Il parametro è **`cursor`**. La pagina 2 ha voci più vecchie. |
| `https://cve.now/api/v1/entries/<id>` | 302 | Il `Location` punta a `https://f9gkulwameaj0boi.public.blob.vercel-storage.com/public/entries/<id>.json`. |

- **Chiavi delle voci della lista:** `id`, `title`, `cvss`, `kev`, `product`, `fix`, `firstSeenAt`, `publishedAt`, `modifiedAt`, `statedSeverity`. Le date `firstSeenAt` sono ISO 8601 con `Z`.
- **Chiavi del dettaglio:**
  - di identità e testo: `id`, `aliases`, `title`, `summary.text`, `originalDescription`, `context`, `exposure`;
  - di gravità: `severity.cvss`, `statedSeverity`, `exploitation.kev`, `ssvc`;
  - di versioni e fonti: `affected`, `references`, `sources`;
  - date: `firstSeenAt`, `publishedAt`, `modifiedAt`;
  - altre: `feedId`, `status`, `supersededBy`, `related`, `bundles`, `earlyWarning`.
- **`affected` vendor/prodotto:** `[{"vendor", "product", "ranges": [{"introduced", "fixed"|"lastAffected"}]}]`.
- **`affected` di ecosistema:** `[{"ecosystem": "npm", "package": "signalk-server", "ranges": [{"introduced": "2.0.0", "fixed": "2.34.0"}]}]`.
- **Gli id GHSA arrivano in MAIUSCOLO** (`GHSA-4XM8-RG9H-JHQ2`).

Fixture: `cvenow/entries_page1.json`, `cvenow/entries_page2.json`, `cvenow/entry.json`, `cvenow/entry_ecosystem.json`.

## CISA KEV (primaria)

| URL | Esito | Note |
|---|---|---|
| `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | 200, 1,8 MB, 1766 voci | top: `catalogVersion`, `count`, `dateReleased`, `title`, `vulnerabilities` |

Chiavi di ogni voce: `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`, `dueDate`, `shortDescription`, `requiredAction`, `knownRansomwareCampaignUse`, `notes`, `cwes`, `forensicTriage`.

Fixture: `kev/catalog_small.json` (3 voci).

## Record CVE, cvelistV5 (primaria)

| URL | Esito | Note |
|---|---|---|
| `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/<anno>/<n//1000>xxx/<id>.json` | 200 | Bucket verificato: `CVE-2026-4052` sta in `4xxx`. |

Chiavi di `containers.cna`: `affected`, `metrics`, `descriptions`, `title`, `references`, `problemTypes`, `impacts`, `solutions`, `source`, `providerMetadata`, `x_generator`.

Fixture: `cverecord/record.json`.

## OSV (primaria, ecosistemi)

| URL | Esito | Note |
|---|---|---|
| `https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip` | 200 | 219 813 670 byte |
| `…/PyPI/all.zip` | 200 | 37 606 501 byte |
| `…/<eco>/modified_id.csv` | 200/206 | Supporta `Range`. Righe `<ISO8601 con nanosecondi>Z,<id>`, **dalla più recente**. |
| `…/<eco>/<id>.json` | 200 | Record OSV singolo |

`osv_zip_max_bytes` = 450 000 000 (≈ 2 × npm).

Fixture: `osv/modified_id_head.csv`, `osv/record_npm.json`, `osv/record_pypi.json`, `osv/record_mal.json`.

## Registry npm (canale ufficiale)

| URL | Esito | Note |
|---|---|---|
| `https://registry.npmjs.org/<nome>` con `Accept: application/json` | 200 | packument completo |

- **Chiavi del packument:** `name`, `dist-tags`, `maintainers`, `time` (`created`, `modified`, `<versione>`), `versions`.
- **Chiavi di ogni versione:** `_npmUser`, `maintainers`, `scripts`, `dist`, `deprecated`, `version`, …
- **`dist.attestations`:** assente su `left-pad`. Il campo esiste solo nei pacchetti pubblicati con provenance.

Fixture: `npm/packument_leftpad.json`.

## API GitHub (canale ufficiale di Homebrew)

| URL | Esito | Note |
|---|---|---|
| `https://api.github.com/repos/Homebrew/homebrew-core/commits?path=Formula/h/hello.rb&per_page=1` | 200 | `x-ratelimit-limit: 60` all'ora senza autenticazione. Data in `[0].commit.committer.date`. |

Fixture: `github/commits_hello.json`.

## Brew (locale)

- **`brew info --json=v2 <formula>`:** `formulae[0]` contiene:
  - `tap`, `versions.stable`, `revision`;
  - `bottle.stable.files` (chiavi = tag; qui `arm64_golden_gate`);
  - `dependencies`, `installed[0].{version, runtime_dependencies, time}`;
  - `post_install_defined`, `caveats`, `deprecated`, `disabled`;
  - `ruby_source_path` (es. `Formula/a/aom.rb`), `ruby_source_checksum.sha256`, `tap_git_head`.
- **`brew info --json=v2 --cask <token>`:** `casks[0]` contiene `token`, `tap`, `version`, `installed`, `artifacts`, `ruby_source_path`, `deprecated`, `disabled`.
- **`brew upgrade --dry-run`:** prima stampa un avviso sui tap non fidati, poi sezioni di più tipi:
  - `==> Would upgrade N requested outdated package(s)`
  - `==> Would upgrade N dependent(s)`
  - `==> Would upgrade N outdated packages`
  - `==> Would install N dependenc(y|ies):`

  Ogni sezione è seguita da righe `nome vecchia -> nuova (dim)` oppure `nome versione`.
  Esempio: aggiornare `aom` aggiorna anche il dipendente `ffmpeg-full`.
- **`brew services info --all --json`:** lista di oggetti con `name`, `status` (`started`), `running`, `pid`, `file`, `loaded_file`.

Fixture: `brew/info_formula.json`, `brew/info_cask.json`, `brew/dryrun_aom.txt`, `brew/services_info.json`.
