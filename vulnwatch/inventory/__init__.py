"""Local inventory. It never leaves the machine."""
from typing import List, Optional

from ..config import Config
from ..model import InventoryItem
from .brew import brew_items
from .lockfiles import scan
from .npm import npm_globals
from .system import apps, macos_item, runtimes


def collect(cfg: Config, run, brew_info: Optional[dict]) -> List[InventoryItem]:
    """brew_info is None when Homebrew is not configured; npm globals are skipped when npm_global is None."""
    items = [macos_item(run)]
    items += apps(cfg.app_dirs, run)
    items += runtimes(cfg.runtimes, run)
    if brew_info is not None:
        items += brew_items(brew_info)
    if cfg.npm_global is not None:
        items += npm_globals(cfg.npm_global.prefix)
    items += scan(cfg.lockfile_roots, cfg.lockfile_max_depth, cfg.protected_dirs)
    return items
