"""Make evidence safe to hand to a language model.

redact.py masks credentials. This adds: terminal escape and control characters removed,
private keys / JWTs / long token-like strings / e-mail addresses masked, hard size limits,
and `<` escaped so log text cannot fake the prompt's evidence tags.
"""
import re

from .redact import redact

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S)
_JWT = re.compile(r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_LONG_TOKEN = re.compile(r"\b[A-Za-z0-9+/_=-]{40,}\b")


def sanitize_text(text, max_len=600):
    t = str(text)
    t = _ANSI.sub("", t)
    t = _CTRL.sub("", t)
    t = _PEM.sub("[REDACTED-KEY]", t)
    t = _JWT.sub("[REDACTED-JWT]", t)
    t = redact(t)
    t = _EMAIL.sub("[EMAIL]", t)
    t = _LONG_TOKEN.sub("[REDACTED-TOKEN]", t)
    t = t.replace("<", "&lt;")
    if len(t) > max_len:
        t = t[:max_len] + "...[truncated]"
    return t


def evidence_for_llm(ev, summary_max=400, excerpt_max=600):
    """Only these fields ever leave the agent. Raw `data` is never sent."""
    return {"id": ev.id, "source": ev.source,
            "summary": sanitize_text(ev.summary, summary_max),
            "excerpt": sanitize_text(ev.excerpt, excerpt_max) if ev.excerpt else ""}
