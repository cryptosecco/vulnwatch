"""Neutralize external (untrusted) text before it reaches a report or a terminal."""
import re
import unicodedata

_ANSI_CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_ANSI_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_SPACE = re.compile(r"\s+")
_DROP = {"Cc", "Cf", "Co", "Cs"}


def clean_text(value: object, max_len: int = 500) -> str:
    if value is None:
        return ""
    s = value if isinstance(value, str) else str(value)
    s = _ANSI_OSC.sub("", s)
    s = _ANSI_CSI.sub("", s)
    out = []
    for ch in s:
        if ch in "\t\n":
            out.append(" ")
        elif unicodedata.category(ch) not in _DROP:
            out.append(ch)
    s = _SPACE.sub(" ", "".join(out)).strip()
    if len(s) > max_len:
        s = s[: max_len - 1] + "…"
    return s
