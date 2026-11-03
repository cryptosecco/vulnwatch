"""Strict loading of the root-owned configuration. Anything unexpected is an error."""
import json
import os
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class NpmGlobal:
    prefix: str
    node: str
    npm: str


@dataclass(frozen=True)
class RuntimeSpec:
    label: str
    path: str
    product: str


@dataclass(frozen=True)
class Config:
    user: str
    auto_apply: bool
    cooldown_hours: int
    backfill_days: int
    max_records_per_run: int
    min_request_interval: float
    host_intervals: Dict[str, float]
    allowed_hosts: Tuple[str, ...]
    osv_ecosystems: Tuple[str, ...]
    osv_zip_max_bytes: int
    hold: Tuple[str, ...]
    app_dirs: Tuple[str, ...]
    lockfile_roots: Tuple[str, ...]
    protected_dirs: Tuple[str, ...]
    venv_roots: Tuple[str, ...]
    lockfile_max_depth: int
    npm_global: Optional[NpmGlobal]
    runtimes: Tuple[RuntimeSpec, ...]
    path_node: Optional[str]
    google_updater: str
    chrome_team_id: str
    brew: Optional[str]
    state_dir: str
    log_dir: str
    aliases_file: str
    language: str = "en"


_STR_LISTS = ("allowed_hosts", "osv_ecosystems", "hold", "app_dirs", "lockfile_roots", "protected_dirs", "venv_roots")
_PATH_LISTS = ("app_dirs", "lockfile_roots", "protected_dirs", "venv_roots")
_INTS = ("cooldown_hours", "backfill_days", "max_records_per_run", "osv_zip_max_bytes", "lockfile_max_depth")
_STRS = ("user", "google_updater", "chrome_team_id", "state_dir", "log_dir", "aliases_file")
_PATHS = ("google_updater", "state_dir", "log_dir")
_NULLABLE_PATHS = ("path_node", "brew")
LANGUAGES = ("en", "it")
_KEYS = set(_STR_LISTS) | set(_INTS) | set(_STRS) | set(_NULLABLE_PATHS) | {
    "auto_apply", "min_request_interval", "host_intervals", "npm_global", "runtimes"}
_OPTIONAL = {"language"}


def _expand(p: str) -> str:
    return os.path.expanduser(p)


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _str_list(name, v):
    if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
        raise ConfigError("%s: expected a list of non-empty strings" % name)
    return tuple(v)


def load_config(path: str) -> Config:
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError) as e:
        raise ConfigError("unreadable configuration: %s" % e) from e
    if not isinstance(raw, dict):
        raise ConfigError("the configuration must be a JSON object")
    keys = set(raw)
    if keys - _KEYS - _OPTIONAL:
        raise ConfigError("unknown keys: %s" % ", ".join(sorted(keys - _KEYS - _OPTIONAL)))
    if _KEYS - keys:
        raise ConfigError("missing keys: %s" % ", ".join(sorted(_KEYS - keys)))

    vals = {}
    for k in _STR_LISTS:
        vals[k] = _str_list(k, raw[k])
    for k in _PATH_LISTS:
        vals[k] = tuple(_expand(p) for p in vals[k])
    for k in _INTS:
        if not _is_int(raw[k]) or raw[k] < 0:
            raise ConfigError("%s: expected a non-negative integer" % k)
        vals[k] = raw[k]
    for k in _STRS:
        if not isinstance(raw[k], str) or not raw[k]:
            raise ConfigError("%s: expected a non-empty string" % k)
        vals[k] = raw[k]
    for k in _PATHS:
        vals[k] = _expand(vals[k])
    for k in _NULLABLE_PATHS:
        v = raw[k]
        if v is not None and (not isinstance(v, str) or not v):
            raise ConfigError("%s: expected a non-empty string or null" % k)
        vals[k] = _expand(v) if v is not None else None
    lang = raw.get("language", "en")
    if lang not in LANGUAGES:
        raise ConfigError("language: expected one of %s" % ", ".join(LANGUAGES))
    vals["language"] = lang
    if not isinstance(raw["auto_apply"], bool):
        raise ConfigError("auto_apply: expected true or false")
    vals["auto_apply"] = raw["auto_apply"]
    mri = raw["min_request_interval"]
    if isinstance(mri, bool) or not isinstance(mri, (int, float)) or mri < 0:
        raise ConfigError("min_request_interval: expected a non-negative number")
    vals["min_request_interval"] = float(mri)
    hi = raw["host_intervals"]
    if not isinstance(hi, dict):
        raise ConfigError("host_intervals: expected an object")
    for host, sec in hi.items():
        if host not in vals["allowed_hosts"]:
            raise ConfigError("host_intervals: host not in allowed_hosts: %s" % host)
        if isinstance(sec, bool) or not isinstance(sec, (int, float)) or sec < 0:
            raise ConfigError("host_intervals: expected a non-negative number for %s" % host)
    vals["host_intervals"] = {h: float(s) for h, s in hi.items()}

    ng = raw["npm_global"]
    if ng is None:
        vals["npm_global"] = None
    elif not isinstance(ng, dict) or set(ng) != {"prefix", "node", "npm"} or not all(isinstance(v, str) and v for v in ng.values()):
        raise ConfigError("npm_global: expected null or an object {prefix, node, npm}")
    else:
        vals["npm_global"] = NpmGlobal(_expand(ng["prefix"]), _expand(ng["node"]), _expand(ng["npm"]))

    rts = raw["runtimes"]
    if not isinstance(rts, list):
        raise ConfigError("runtimes: expected a list")
    specs = []
    for r in rts:
        if not isinstance(r, dict) or set(r) != {"label", "path", "product"}:
            raise ConfigError("runtimes: each entry needs exactly label, path, product")
        if not all(isinstance(r[k], str) and r[k] for k in r) or r["product"] not in ("node", "bun"):
            raise ConfigError("runtimes: invalid values (product must be node or bun)")
        specs.append(RuntimeSpec(r["label"], _expand(r["path"]), r["product"]))
    vals["runtimes"] = tuple(specs)

    af = vals["aliases_file"]
    if not os.path.isabs(af):
        af = os.path.join(os.path.dirname(os.path.abspath(path)), af)
    vals["aliases_file"] = af
    return Config(**vals)
