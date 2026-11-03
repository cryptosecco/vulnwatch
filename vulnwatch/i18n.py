"""User-facing language: inline (English, Italian) pairs, chosen once per process from the configuration."""
LANGUAGES = ("en", "it")

_current = "en"


def set_language(lang: str) -> None:
    global _current
    if lang not in LANGUAGES:
        raise ValueError("unsupported language: %r" % (lang,))
    _current = lang


def language() -> str:
    return _current


def t(en: str, it: str) -> str:
    """Return the text for the current language. Both strings must carry the same % placeholders."""
    return it if _current == "it" else en
