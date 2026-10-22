"""Command line entry point: python -m agent_watch --root ... --out report.md"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from .detectors import DEFAULT_ALLOW_HOSTS
from .report import render_markdown, scan, write_json
from .scope import ScopeConfig, load_config


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agent_watch", description="Flag risky actions in Claude Code transcripts.")
    ap.add_argument("--root", type=Path, default=Path("~/.claude/projects").expanduser())
    ap.add_argument("--out", type=Path, default=Path("report.md"))
    ap.add_argument("--json", type=Path, help="also write redacted findings as JSON")
    ap.add_argument("--config", type=Path, help="JSON scope and redaction config (see config.example.json)")
    ap.add_argument("--since", help="ignore events before this date (YYYY-MM-DD)")
    ap.add_argument("--include-prefix", action="append", help="project dir prefix to include (repeatable; replaces the config lists)")
    ap.add_argument("--include", action="append", help="exact project dir to include (repeatable; replaces the config lists)")
    ap.add_argument("--exclude-dir", help="regex; project dirs matching it are skipped")
    ap.add_argument("--exclude-content", help="regex; sessions whose raw text matches are skipped")
    ap.add_argument("--strict-sessions", action="store_true", help="drop a whole session on any content match anywhere in the file")
    ap.add_argument("--allow-host", action="append", default=[], help="host that may receive POSTs without a finding")
    ap.add_argument("--notes", type=Path, help="markdown appended to the report under 'Hand-check'")
    args = ap.parse_args(argv)

    if args.since and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.since):
        ap.error("--since must be YYYY-MM-DD")
    try:
        cfg = load_config(args.config) if args.config else ScopeConfig()
    except (OSError, ValueError, re.error) as e:
        ap.error(f"--config: {e}")
    if args.include_prefix or args.include:
        cfg.include_prefixes = tuple(args.include_prefix or ())
        cfg.include_exact = tuple(args.include or ())
    if args.exclude_dir:
        cfg.exclude_dir = re.compile(args.exclude_dir, re.I)
    if args.exclude_content:
        cfg.exclude_content = re.compile(args.exclude_content, re.I)

    if args.strict_sessions:
        cfg.content_mode = "session"
    res = scan(args.root.expanduser(), cfg, since=args.since, allow_hosts=DEFAULT_ALLOW_HOSTS | set(args.allow_host))
    notes = args.notes.read_text() if args.notes else None
    args.out.write_text(render_markdown(res, notes))
    if args.json:
        write_json(res, args.json)
    print(
        f"projects={res.projects} sessions={res.sessions_scanned} excluded={res.sessions_excluded} dropped_events={res.events_dropped} "
        f"tool_calls={res.tool_calls} findings={len(res.findings)} -> {args.out}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
