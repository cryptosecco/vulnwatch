"""First-time setup: detect this Mac, write config/config.json, preview the local inventory.

Everything here is local: no network request is ever made. Probes are injectable so the detection is testable.
"""
import argparse
import collections
import dataclasses
import glob
import json
import os
import tempfile
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from .config import ConfigError, LANGUAGES, load_config
from .i18n import set_language, t

BREW_CANDIDATES = ("/opt/homebrew/bin/brew", "/usr/local/bin/brew")
CELLAR_PREFIXES = ("/opt/homebrew/Cellar/", "/usr/local/Cellar/")
# (label, pattern, product): version managers keep one directory per version, so the glob pattern is stored.
VERSION_MANAGER_PATTERNS = (
    ("nvm", "~/.nvm/versions/node/*/bin/node", "node"),
    ("volta", "~/.volta/tools/image/node/*/bin/node", "node"),
    ("fnm", "~/.local/share/fnm/node-versions/*/installation/bin/node", "node"),
    ("asdf", "~/.asdf/installs/nodejs/*/bin/node", "node"),
    ("mise", "~/.local/share/mise/installs/node/*/bin/node", "node"),
    ("bun", "~/.bun/bin/bun", "bun"),
)
SYSTEM_PATTERNS = (("pkg", "/usr/local/bin/node", "node"),)
ROOT_NAMES = ("Code", "Projects", "Developer", "dev", "src", "work", "repos", "git", "GitHub", "workspace")

DEFAULTS = {
    "auto_apply": False,
    "cooldown_hours": 48,
    "backfill_days": 90,
    "max_records_per_run": 3000,
    "min_request_interval": 0.2,
    "host_intervals": {"cve.now": 2.0},
    "allowed_hosts": [
        "cve.now",
        "f9gkulwameaj0boi.public.blob.vercel-storage.com",
        "www.cisa.gov",
        "raw.githubusercontent.com",
        "osv-vulnerabilities.storage.googleapis.com",
        "registry.npmjs.org",
        "api.github.com",
    ],
    "osv_ecosystems": ["npm", "PyPI"],
    "osv_zip_max_bytes": 450000000,
    "hold": [],
    "app_dirs": ["/Applications", "~/Applications"],
    "lockfile_max_depth": 4,
    "google_updater": "~/Library/Application Support/Google/GoogleUpdater/Current/GoogleUpdater.app/Contents/MacOS/GoogleUpdater",
    "chrome_team_id": "EQHXZ8M8AV",
    "state_dir": "~/Library/Application Support/vulnwatch",
    "log_dir": "~/Library/Logs/vulnwatch",
    "aliases_file": "aliases.json",
}
PRIVATE_DIRS = ["~/Documents", "~/Desktop", "~/Downloads", "~/Library/Mobile Documents"]


@dataclasses.dataclass
class Detected:
    user: str
    language: str
    brew: Optional[str]
    npm_global: Optional[Dict[str, str]]
    path_node: Optional[str]
    runtimes: List[Dict[str, str]]
    roots: List[str]


def _tilde(path: str, home: str) -> str:
    home = home.rstrip("/")
    if path == home:
        return "~"
    if path.startswith(home + "/"):
        return "~" + path[len(home):]
    return path


def _expand(pattern: str, home: str) -> str:
    if pattern == "~" or pattern.startswith("~/"):
        return home.rstrip("/") + pattern[1:]
    return pattern


def _in_cellar(real: str, cellars: Sequence[str]) -> bool:
    return any(real.startswith(c) for c in cellars)


def _path_hits(env: Mapping[str, str], name: str, exists: Callable, access: Callable) -> List[str]:
    hits = []
    for d in (env.get("PATH") or "").split(":"):
        if not d:
            continue
        p = os.path.join(d, name)
        if p not in hits and exists(p) and access(p, os.X_OK):
            hits.append(p)
    return hits


def _language(env: Mapping[str, str], run) -> str:
    if (env.get("LANG") or "").lower().startswith("it"):
        return "it"
    r = run(["/usr/bin/defaults", "read", "-g", "AppleLanguages"], timeout=10)
    if r.returncode == 0:
        for line in r.stdout.splitlines():
            s = line.strip().strip(",").strip('"').strip()
            if s and s not in ("(", ")"):
                return "it" if s.lower().startswith("it") else "en"
    return "en"


def detect(home: str, env: Mapping[str, str], run, user: str, exists: Callable = os.path.exists,
           glob_fn: Callable = glob.glob, realpath: Callable = os.path.realpath, access: Callable = os.access,
           brew_candidates: Sequence[str] = BREW_CANDIDATES, cellar_prefixes: Sequence[str] = CELLAR_PREFIXES,
           system_patterns: Sequence[Tuple[str, str, str]] = SYSTEM_PATTERNS) -> Detected:
    brew = next((b for b in brew_candidates if exists(b) and access(b, os.X_OK)), None)

    npm_global = None
    npms = _path_hits(env, "npm", exists, access)
    if npms:
        npm = npms[0]
        node = os.path.join(os.path.dirname(npm), "node")
        # npm checks the registry for its own updates on every command unless told not to: setup stays offline.
        r = run([npm, "config", "get", "prefix"], timeout=30,
                env={"PATH": os.path.dirname(npm) + ":/usr/bin:/bin", "HOME": home, "npm_config_update_notifier": "false"})
        prefix = r.stdout.strip() if r.returncode == 0 else ""
        if prefix and exists(node) and access(node, os.X_OK):
            npm_global = {"prefix": _tilde(prefix, home), "node": _tilde(node, home), "npm": _tilde(npm, home)}

    nodes = _path_hits(env, "node", exists, access)
    path_node = _tilde(nodes[0], home) if nodes else None

    runtimes: List[Dict[str, str]] = []
    covered = set()
    cellar_prefixes = tuple(cellar_prefixes) + tuple(realpath(c.rstrip("/")) + "/" for c in cellar_prefixes)
    for label, pattern, product in tuple(VERSION_MANAGER_PATTERNS) + tuple(system_patterns):
        matches = [m for m in sorted(glob_fn(_expand(pattern, home)))
                   if access(m, os.X_OK) and not _in_cellar(realpath(m), cellar_prefixes)]
        if matches:
            runtimes.append({"label": label, "path": pattern, "product": product})
            covered.update(realpath(m) for m in matches)
    for product in ("node", "bun"):
        for p in _path_hits(env, product, exists, access):
            real = realpath(p)
            if real in covered or _in_cellar(real, cellar_prefixes):
                continue
            covered.add(real)
            runtimes.append({"label": "PATH", "path": _tilde(p, home), "product": product})

    roots = ["~/" + n for n in ROOT_NAMES if os.path.isdir(os.path.join(home, n))]
    return Detected(user=user, language=_language(env, run), brew=brew, npm_global=npm_global, path_node=path_node,
                    runtimes=runtimes, roots=roots)


def build_config(d: Detected, repo_root: str, roots: Sequence[str], language: str) -> dict:
    cfg = {"user": d.user, "language": language}
    cfg.update(json.loads(json.dumps(DEFAULTS)))
    cfg.update({
        "lockfile_roots": list(roots),
        "venv_roots": list(roots),
        "protected_dirs": PRIVATE_DIRS + [os.path.join(repo_root, "tests", "fixtures")],
        "npm_global": d.npm_global,
        "runtimes": d.runtimes,
        "path_node": d.path_node,
        "brew": d.brew,
    })
    return cfg


def check_roots(roots: Sequence[str], home: str, out: Callable) -> List[str]:
    """Keep the usable project folders and say why any of them will not be scanned."""
    private = [_expand(p, home).rstrip("/") for p in PRIVATE_DIRS]
    kept = []
    for r in roots:
        full = _expand(r, home)
        if not os.path.isabs(full):
            out(t("Skipped %s: write an absolute path or one starting with ~/.",
                  "Saltata %s: scrivi un percorso assoluto o che inizi con ~/.") % r)
            continue
        if any(full.rstrip("/") == p or full.startswith(p + "/") for p in private):
            out(t("Warning: %s is inside Documents, Desktop, Downloads or iCloud Drive and will not be scanned "
                  "(macOS protects those folders); keep your projects elsewhere, for example ~/Code.",
                  "Attenzione: %s è dentro Documenti, Scrivania, Download o iCloud Drive e non verrà scansionata "
                  "(macOS protegge quelle cartelle); tieni i progetti altrove, per esempio in ~/Code.") % r)
        elif not os.path.isdir(full):
            out(t("Warning: %s does not exist yet; it will be scanned once it does.",
                  "Attenzione: %s non esiste ancora; verrà scansionata quando ci sarà.") % r)
        kept.append(r)
    return kept


def _kind_label(kind: str) -> str:
    return {"macos": "macOS", "app": t("apps", "app"), "runtime": t("Node/Bun copies", "copie di Node/Bun"),
            "brew_formula": t("Homebrew formulae", "formule Homebrew"), "brew_cask": t("Homebrew casks", "cask Homebrew"),
            "npm_global": t("npm global packages", "pacchetti npm globali"),
            "lockfile_pkg": t("packages in project lockfiles", "pacchetti nei lockfile dei progetti")}.get(kind, kind)


def preview(cfg, run) -> List[str]:
    """Counts of what the daily job will inventory. Local only: nothing is sent anywhere."""
    from .brew_client import brew_env
    from .inventory import collect
    info = None
    if cfg.brew:
        r = run([cfg.brew, "info", "--json=v2", "--installed"], timeout=300, env=brew_env())
        if r.returncode == 0:
            try:
                info = json.loads(r.stdout)
            except ValueError:
                info = None
    items = collect(cfg, run, info)
    counts = collections.Counter(i.kind for i in items)
    order = ("macos", "app", "runtime", "brew_formula", "brew_cask", "npm_global", "lockfile_pkg")
    return ["  %-34s %d" % (_kind_label(k) + ":", counts[k]) for k in order if counts.get(k)]


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="./setup.sh", description="Detect this Mac and write config/config.json. "
                                "Nothing leaves this Mac.")
    p.add_argument("--yes", action="store_true", help="accept the detected values without asking")
    p.add_argument("--force", action="store_true", help="overwrite an existing config/config.json")
    p.add_argument("--lang", choices=LANGUAGES, help="interface language (default: from the system)")
    p.add_argument("--roots", nargs="+", metavar="DIR", help="project folders to scan for lockfiles")
    p.add_argument("--no-preview", action="store_true", help="skip the local inventory preview")
    return p


def main(argv: List[str], repo_root: str, run=None, env: Optional[Mapping[str, str]] = None, home: Optional[str] = None,
         user: Optional[str] = None, input_fn: Callable = input, out: Callable = print, euid: Callable = os.geteuid,
         detect_kwargs: Optional[dict] = None) -> int:
    args = _parser().parse_args(argv)
    if euid() == 0:
        out("Do not run setup as root (no sudo): run ./setup.sh as yourself. / "
            "Non lanciare il setup come root (niente sudo): lancia ./setup.sh col tuo utente.")
        return 1
    if run is None:
        from .proc import Runner
        run = Runner()
    env = dict(os.environ) if env is None else env
    home = home or os.path.expanduser("~")
    if user is None:
        import getpass
        user = getpass.getuser()
    cfg_dir = os.path.join(repo_root, "config")
    cfg_path = os.path.join(cfg_dir, "config.json")
    if os.path.exists(cfg_path) and not args.force:
        out("config/config.json already exists: keeping it. Re-run with --force to replace it. / "
            "config/config.json esiste già: lo lascio com'è. Rilancia con --force per sostituirlo.")
        return 1

    d = detect(home, env, run, user, **(detect_kwargs or {}))
    # With no terminal on stdin (a coding agent, a pipe) input() raises EOFError at once:
    # stop asking and keep the detected values, exactly as --yes does.
    interactive = not args.yes

    def ask(prompt: str) -> str:
        nonlocal interactive
        if not interactive:
            return ""
        try:
            return input_fn(prompt)
        except EOFError:
            interactive = False
            out("")
            out("No terminal to answer from: using the detected values, as with --yes. / "
                "Nessun terminale da cui rispondere: uso i valori rilevati, come con --yes.")
            return ""

    language = args.lang or d.language
    if not args.lang:
        answer = ask("Language / Lingua [en/it] (%s): " % language).strip().lower()
        if answer in LANGUAGES:
            language = answer
    set_language(language)
    roots = list(args.roots) if args.roots else list(d.roots)
    if not args.roots:
        answer = ask(t("Project folders to scan for lockfiles, comma-separated (%s): ",
                       "Cartelle dei progetti in cui cercare i lockfile, separate da virgole (%s): ")
                     % (", ".join(roots) or t("none", "nessuna"))).strip()
        if answer:
            roots = [x.strip() for x in answer.split(",") if x.strip()]
    roots = check_roots(roots, home, out)

    cfg = build_config(d, repo_root, roots, language)
    fd, tmp = tempfile.mkstemp(prefix=".config-", suffix=".json", dir=cfg_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
            f.write("\n")
        try:
            loaded = load_config(tmp)
        except ConfigError as e:
            out(t("The detected configuration is not valid: %s", "La configurazione rilevata non è valida: %s") % e)
            return 1
        os.chmod(tmp, 0o644)
        os.replace(tmp, cfg_path)
        tmp = None
    finally:
        if tmp is not None and os.path.exists(tmp):
            os.unlink(tmp)

    none = t("not found", "non trovato")
    out(t("vulnwatch setup. Everything below was detected locally; setup sent nothing over the network.",
          "Setup di vulnwatch. Tutto ciò che segue è stato rilevato in locale; il setup non ha inviato nulla in rete."))
    out("  %-22s %s" % (t("User:", "Utente:"), d.user))
    out("  %-22s %s" % (t("Language:", "Lingua:"), language))
    out("  %-22s %s" % ("Homebrew:", d.brew or none + t(" (Homebrew checks off)", " (controlli Homebrew spenti)")))
    out("  %-22s %s" % (t("npm globals:", "npm globali:"), d.npm_global["prefix"] if d.npm_global
                        else none + t(" (npm checks off)", " (controlli npm spenti)")))
    out("  %-22s %s" % (t("Node/Bun copies:", "Copie di Node/Bun:"),
                        ", ".join("%s %s" % (r["label"], r["path"]) for r in d.runtimes) or none))
    out("  %-22s %s" % (t("Project folders:", "Cartelle progetti:"), ", ".join(roots) or t("none", "nessuna")))
    out(t("Configuration written to config/config.json (you can edit it; see docs/configuration.md).",
          "Configurazione scritta in config/config.json (puoi modificarla; vedi docs/configuration.md)."))
    if not args.no_preview:
        out(t("What the daily check will look at (local count, nothing sent):",
              "Cosa guarderà il controllo giornaliero (conteggio locale, nulla viene inviato):"))
        for line in preview(loaded, run):
            out(line)
    out("")
    out(t("Next step: install exactly this commit (asks for your password):",
          "Prossimo passo: installa esattamente questo commit (chiede la tua password):"))
    out('  sudo ./install.sh "$(git rev-parse HEAD)"')
    out(t("The first run starts right after install and takes about 2 hours: it downloads public vulnerability data.",
          "Il primo run parte subito dopo l'installazione e dura circa 2 ore: scarica i dati pubblici sulle vulnerabilità."))
    return 0
