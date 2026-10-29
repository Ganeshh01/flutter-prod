"""Validate what the model said before anyone reads it.

A "fact" must cite evidence ids that actually exist; otherwise it is downgraded to
"unsupported". Commands are only classified, never executed: read-only ones are shown
as verification commands, everything else is shown as "suggested, not run".
"""
import json
import re
import shlex
from dataclasses import dataclass, field

from ..collectors import assert_read_only

MAX_ITEMS = 5
_SHELL_META = re.compile(r"[;&|<>`$\\\n\r]")


class ValidationError(Exception):
    pass


@dataclass
class Cause:
    claim: str
    declared: str            # what the model called it: fact | assumption
    evidence_ids: list
    confidence: str
    status: str              # supported | unsupported | assumption
    note: str = ""


@dataclass
class Fix:
    description: str
    command: str
    command_class: str       # none | read-only | not-run


@dataclass
class LLMAnalysis:
    causes: list = field(default_factory=list)
    fixes: list = field(default_factory=list)
    verification: list = field(default_factory=list)    # (command, class)
    problems: list = field(default_factory=list)


def classify_command(cmd):
    if not isinstance(cmd, str) or not cmd.strip():
        return "none"
    if _SHELL_META.search(cmd):
        return "not-run"
    try:
        assert_read_only(shlex.split(cmd))
        return "read-only"
    except (PermissionError, ValueError):
        return "not-run"


def _extract_json(text):
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
    try:
        return json.loads(text)
    except ValueError:
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except ValueError:
                pass
    raise ValidationError("the model's answer is not valid JSON")


def validate(text, known_ids):
    data = _extract_json(text)
    if not isinstance(data, dict):
        raise ValidationError("the model's answer is not a JSON object")
    result, known = LLMAnalysis(), set(known_ids)

    for raw in (data.get("root_causes") or [])[:MAX_ITEMS]:
        if not isinstance(raw, dict) or not isinstance(raw.get("claim"), str) or not raw["claim"].strip():
            result.problems.append("a root cause was malformed and was dropped")
            continue
        ids = [i for i in raw.get("evidence_ids", []) if isinstance(i, str)]
        declared = raw.get("type") if raw.get("type") in ("fact", "assumption") else "assumption"
        confidence = raw.get("confidence") if raw.get("confidence") in ("low", "medium", "high") else "low"
        bad = [i for i in ids if i not in known]
        if declared == "fact" and (not ids or bad):
            status = "unsupported"
            note = ("cites evidence that does not exist: %s" % ", ".join(bad)) if bad else "claims to be a fact but cites no evidence"
            confidence = "low"
        elif declared == "fact":
            status, note = "supported", ""
        else:
            status, note = "assumption", "the model labelled this an assumption"
        result.causes.append(Cause(raw["claim"].strip()[:400], declared, ids, confidence, status, note))

    for raw in (data.get("suggested_fixes") or [])[:MAX_ITEMS]:
        if not isinstance(raw, dict) or not isinstance(raw.get("description"), str):
            result.problems.append("a suggested fix was malformed and was dropped")
            continue
        cmd = raw.get("command") if isinstance(raw.get("command"), str) else ""
        result.fixes.append(Fix(raw["description"].strip()[:400], cmd.strip()[:300], classify_command(cmd)))

    for cmd in (data.get("verification_commands") or [])[:MAX_ITEMS]:
        if isinstance(cmd, str) and cmd.strip():
            result.verification.append((cmd.strip()[:300], classify_command(cmd)))
    return result
