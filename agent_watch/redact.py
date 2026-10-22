"""Redaction applied to every string that leaves the tool.

The rule is that nothing is written to a report or JSON file without going
through `redact()` first. Patterns are deliberately greedy: a redacted
filename is a cheap loss, a leaked key is not.
"""

from __future__ import annotations

import re

EVIDENCE_LIMIT = 160

# Order matters: multi-line and structured secrets first, generic shapes last.
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S), "[PRIVATE_KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+){0,2}"), "[JWT]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"), "[API_KEY]"),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{10,}"), "[GITHUB_TOKEN]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{10,}"), "[GITHUB_TOKEN]"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{6,}"), "[SLACK_TOKEN]"),
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{12,}"), "[AWS_KEY]"),
    (re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{6,}", re.I), "Bearer [TOKEN]"),
    (re.compile(r"([?&](?:token|key|api_key|apikey|access_token|secret|password|sig|signature)=)[^&\s'\"]+", re.I), r"\1[REDACTED]"),
    (re.compile(r"\b((?:[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY))=)(?!\$)[^\s'\"]+"), r"\1[REDACTED]"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"), "[EMAIL]"),
    (re.compile(r"(?<![\w.])\+\d{1,3}[\s-]?\(?\d{2,4}\)?(?:[\s-]?\d{2,4}){2,4}\b"), "[PHONE]"),
    (re.compile(r"(?<![\w.])0\d{2,4}[\s-]?\d{3,4}[\s-]?\d{3,4}\b"), "[PHONE]"),
    (re.compile(r"\b[0-9a-fA-F]{32,}\b"), "[HEX]"),
    (re.compile(r"/tmp/claude-\d+/[^\s'\"]+"), "/tmp/<agent-scratch>"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "[UUID]"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[IP]"),
]

# Long base64-ish runs. Checked separately so paths and kebab-case words survive.
_B64_CANDIDATE = re.compile(r"[A-Za-z0-9+/_-]{32,}={0,2}")

_HOME = re.compile(r"(?:/home|/Users)/[^/\s'\"]+|/root(?=/|\b)")

# Extra terms that must never appear in output, set from the config file's
# `redact_terms`. Replaced, not dropped, so the evidence still reads sensibly.
_deny_terms: re.Pattern[str] | None = None


def set_redact_terms(terms: tuple[str, ...] | list[str]) -> None:
    """Set the extra terms to hide (case-insensitive). An empty list clears them."""
    global _deny_terms
    terms = [t for t in terms if t]
    _deny_terms = re.compile("|".join(re.escape(t) for t in terms), re.I) if terms else None


def _looks_like_b64(s: str) -> bool:
    if s.count("/") > 2 or s.count("-") > 3:
        return False
    return any(c.isdigit() for c in s) and any(c.isupper() for c in s) and any(c.islower() for c in s)


def redact(text: str, cwd: str | None = None) -> str:
    """Remove secrets and identifying paths from `text`.

    If `cwd` is given, that directory is rewritten to `<repo>` so evidence for
    write_outside_repo stays readable without naming the project.
    """
    if not text:
        return ""
    out = text
    if cwd:
        out = out.replace(cwd.rstrip("/"), "<repo>")
    for pattern, repl in _PATTERNS:
        out = pattern.sub(repl, out)
    out = _B64_CANDIDATE.sub(lambda m: "[B64]" if _looks_like_b64(m.group(0)) else m.group(0), out)
    out = _HOME.sub("~", out)
    # Hide directory names below a non-dot home folder (project and folder
    # names); keep the top folder and the filename so the evidence still reads.
    out = re.sub(r"~/([^./\s'\"][^/\s'\"]*)/(?:[^/\s'\"]+/)+", r"~/\1/<path>/", out)
    if _deny_terms is not None:
        out = _deny_terms.sub("[term]", out)
    return out


def truncate(text: str, limit: int = EVIDENCE_LIMIT) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def evidence(text: str, cwd: str | None = None, limit: int = EVIDENCE_LIMIT) -> str:
    """Redact then truncate. Redacting first means a key cut in half is still caught."""
    return truncate(redact(text, cwd), limit)
