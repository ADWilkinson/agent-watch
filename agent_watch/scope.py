"""Which transcripts are in scope.

All of it is driven by a JSON config file (see `load_config` and
config.example.json). With no config every project directory is read and
nothing is excluded. Privacy is applied in three layers, in this order:
1. project directories must match the include list, if one is set;
2. project directories matching the exclude pattern are dropped;
3. content filter, if a content pattern is set, in one of two modes:
   - "event" (default): a session is dropped if any human prompt in it matches
     the content pattern (the task itself was about excluded content). In the
     sessions that remain, any single tool call or assistant message that
     matches is dropped before detection, so it can never reach the report.
     Injected context (memory files, attachments, tool results) does not drop
     a whole session, because it is the same boilerplate in every session.
   - "session": the stricter original rule. Any match anywhere in the raw file
     drops the whole session.
   Only counts are reported, never names or content.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ScopeConfig:
    # Empty include lists mean every project directory is in scope.
    include_prefixes: tuple[str, ...] = ()
    include_exact: tuple[str, ...] = ()
    exclude_dir: re.Pattern[str] | None = None
    exclude_content: re.Pattern[str] | None = None
    redact_terms: tuple[str, ...] = ()
    content_mode: str = "event"  # "event" or "session"


CONFIG_KEYS = {"include_prefixes", "include_exact", "exclude_dir_pattern", "exclude_content_pattern", "redact_terms", "strict_sessions"}


def _strings(data: dict, key: str) -> tuple[str, ...]:
    val = data.get(key, [])
    if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
        raise ValueError(f"config key {key!r} must be a list of strings")
    return tuple(val)


def _pattern(data: dict, key: str) -> re.Pattern[str] | None:
    val = data.get(key)
    if val is None or val == "":
        return None
    if not isinstance(val, str):
        raise ValueError(f"config key {key!r} must be a regex string")
    return re.compile(val, re.I)


def load_config(path: Path) -> ScopeConfig:
    """Build a ScopeConfig from a JSON file. Missing keys keep their defaults."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("config must be a JSON object")
    unknown = set(data) - CONFIG_KEYS
    if unknown:
        raise ValueError(f"unknown config keys: {', '.join(sorted(unknown))}")
    return ScopeConfig(
        include_prefixes=_strings(data, "include_prefixes"),
        include_exact=_strings(data, "include_exact"),
        exclude_dir=_pattern(data, "exclude_dir_pattern"),
        exclude_content=_pattern(data, "exclude_content_pattern"),
        redact_terms=_strings(data, "redact_terms"),
        content_mode="session" if data.get("strict_sessions") else "event",
    )


def select_projects(root: Path, cfg: ScopeConfig) -> list[Path]:
    include_all = not cfg.include_prefixes and not cfg.include_exact
    out = []
    for d in sorted(p for p in root.iterdir() if p.is_dir()):
        included = include_all or d.name.startswith(cfg.include_prefixes) or d.name in cfg.include_exact
        if included and not (cfg.exclude_dir and cfg.exclude_dir.search(d.name)):
            out.append(d)
    return out


def session_files(project: Path) -> list[Path]:
    """Top-level sessions plus subagent transcripts nested under them."""
    return sorted(project.rglob("*.jsonl"))


def session_excluded(path: Path, cfg: ScopeConfig) -> bool:
    """True if the raw file text matches the content exclude pattern.

    Reads in chunks with an overlap so a match across a chunk boundary is
    still found, without loading very large transcripts into memory at once.
    """
    if cfg.exclude_content is None:
        return False
    overlap = 64
    tail = ""
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        while chunk := fh.read(1 << 20):
            if cfg.exclude_content.search(tail + chunk):
                return True
            tail = chunk[-overlap:]
    return False


def _prompt_texts(rec: dict) -> list[str]:
    """Human-typed prompt text in a user record (not tool results or meta)."""
    if rec.get("type") != "user" or rec.get("isMeta"):
        return []
    msg = rec.get("message")
    content = msg.get("content") if isinstance(msg, dict) else None
    if isinstance(content, str):
        return [content]
    if isinstance(content, list):
        return [str(i.get("text") or "") for i in content if isinstance(i, dict) and i.get("type") == "text"]
    return []


def prompt_excluded(path: Path, cfg: ScopeConfig) -> bool:
    """True if any human prompt in the session matches the content pattern."""
    if cfg.exclude_content is None:
        return False
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not cfg.exclude_content.search(line):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict) and any(cfg.exclude_content.search(x) for x in _prompt_texts(rec)):
                return True
    return False
