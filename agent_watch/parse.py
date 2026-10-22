"""Stream Claude Code JSONL transcripts into a flat list of events.

Each line of a transcript is one JSON record. We only need two things:
assistant `tool_use` items (what the agent did) and assistant `text` items
(what it said it did). Everything else is skipped. Malformed lines are counted
and ignored rather than aborting the run.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator


@dataclass
class ToolCall:
    session: str
    ts: str
    cwd: str | None
    name: str
    input: dict[str, Any]
    git_branch: str | None = None
    kind: str = "tool"


@dataclass
class AssistantText:
    session: str
    ts: str
    text: str
    kind: str = "text"


Event = ToolCall | AssistantText


@dataclass
class Session:
    id: str
    path: Path
    events: list[Event] = field(default_factory=list)
    malformed_lines: int = 0
    dropped_events: int = 0

    @property
    def tool_calls(self) -> list[ToolCall]:
        return [e for e in self.events if isinstance(e, ToolCall)]

    @property
    def root_cwd(self) -> str | None:
        """First cwd seen; treated as the project root for the whole session."""
        for e in self.events:
            if isinstance(e, ToolCall) and e.cwd:
                return e.cwd
        return None


def iter_records(path: Path) -> Iterator[dict[str, Any] | None]:
    """Yield parsed records, or None for a line that is not a JSON object."""
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                yield None
                continue
            yield rec if isinstance(rec, dict) else None


def parse_session(path: Path, since: str | None = None, drop=None) -> Session:
    """Parse one transcript file.

    The session id is the file stem: subagent transcripts share their parent's
    sessionId but are separate streams of work, so we keep them apart.
    `since` is an ISO date (YYYY-MM-DD); earlier events are dropped.
    `drop` is an optional compiled regex: any tool call (by its JSON input) or
    assistant text that matches it is dropped and counted, never analysed.
    """
    session = Session(id=path.stem, path=path)
    for rec in iter_records(path):
        if rec is None:
            session.malformed_lines += 1
            continue
        if rec.get("type") != "assistant":
            continue
        ts = str(rec.get("timestamp") or "")
        if since and ts and ts[:10] < since:
            continue
        msg = rec.get("message")
        content = msg.get("content") if isinstance(msg, dict) else None
        if not isinstance(content, list):
            continue
        for item in content:
            if not isinstance(item, dict):
                continue
            if drop is not None and item.get("type") in ("tool_use", "text"):
                blob = json.dumps(item.get("input")) if item.get("type") == "tool_use" else str(item.get("text") or "")
                if drop.search(blob):
                    session.dropped_events += 1
                    continue
            if item.get("type") == "tool_use":
                inp = item.get("input")
                session.events.append(
                    ToolCall(
                        session=session.id,
                        ts=ts,
                        cwd=rec.get("cwd"),
                        name=str(item.get("name") or ""),
                        input=inp if isinstance(inp, dict) else {},
                        git_branch=rec.get("gitBranch"),
                    )
                )
            elif item.get("type") == "text" and item.get("text"):
                session.events.append(AssistantText(session=session.id, ts=ts, text=str(item["text"])))
    return session
