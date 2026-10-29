"""Strip secrets from anything that becomes evidence, a report, or an audit entry."""
import re

_PATTERNS = [
    (re.compile(r"(?i)(authorization\s*[:=]\s*)(bearer|basic)\s+[^\s\"',]+"), r"\1\2 [REDACTED]"),
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [REDACTED]"),
    (re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key|access[_-]?key)\b(\"?\s*[:=]\s*\"?)[^\s\"',&]+"),
     r"\1\2[REDACTED]"),
    (re.compile(r"\b(ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{10,}"), "[REDACTED]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED]"),
]


def redact(text):
    text = str(text)
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return text
