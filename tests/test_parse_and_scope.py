import json
import re
from pathlib import Path

import pytest

from agent_watch.__main__ import main
from agent_watch.detectors import run_all
from agent_watch.parse import AssistantText, ToolCall, parse_session
from agent_watch.report import render_markdown, scan
from agent_watch.scope import ScopeConfig, load_config, prompt_excluded, select_projects, session_excluded

FIXTURE = Path(__file__).parent / "fixtures" / "synthetic_session.jsonl"


def test_parse_synthetic_fixture():
    s = parse_session(FIXTURE)
    assert s.malformed_lines == 2
    calls = s.tool_calls
    assert [c.name for c in calls] == ["Bash", "Write", "Edit", "WebFetch"]
    assert calls[0].input["command"] == "rm -rf ~/"
    assert calls[0].cwd == "/home/alice/projects/demo"
    assert calls[0].git_branch == "main"
    assert calls[0].ts == "2026-01-02T10:00:05Z"
    texts = [e for e in s.events if isinstance(e, AssistantText)]
    assert len(texts) == 2
    assert s.root_cwd == "/home/alice/projects/demo"


def test_parse_since_filters_events():
    s = parse_session(FIXTURE, since="2027-01-01")
    assert s.events == []


def test_fixture_findings():
    rules = sorted(f.rule for f in run_all(parse_session(FIXTURE)))
    assert rules == ["destructive_shell", "unverified_ship_claim", "write_outside_repo"]


def _session(dirpath: Path, name: str, body: str) -> Path:
    dirpath.mkdir(parents=True, exist_ok=True)
    p = dirpath / f"{name}.jsonl"
    p.write_text(body)
    return p


def _line(cmd: str) -> str:
    import json

    rec = {
        "type": "assistant",
        "cwd": "/home/alice/projects/demo",
        "timestamp": "2026-02-01T00:00:00Z",
        "message": {"content": [{"type": "tool_use", "name": "Bash", "input": {"command": cmd}}]},
    }
    return json.dumps(rec) + "\n"


PERSONAL = "-home-alice-projects-personal-"
SITE_ONE = "-home-alice-projects-site-one"
SITE_TWO = "-home-alice-projects-site-two"
EXAMPLE_CONFIG = Path(__file__).resolve().parents[1] / "config.example.json"


def scoped() -> ScopeConfig:
    """A config that narrows scope the way a real user would."""
    return ScopeConfig(
        include_prefixes=(PERSONAL,),
        include_exact=(SITE_ONE, SITE_TWO),
        exclude_dir=re.compile(r"acme-corp|client-x|private-bot|old-archive", re.I),
        exclude_content=re.compile(r"acme-corp|client-x\.example", re.I),
    )


def make_root(tmp_path: Path) -> Path:
    root = tmp_path / "projects"
    _session(root / f"{PERSONAL}blog", "a", _line("ls"))
    _session(root / f"{PERSONAL}blog", "b", _line("echo ACME-Corp stuff"))
    _session(root / f"{PERSONAL}blog", "c", _line("open https://client-x.example"))
    _session(root / f"{PERSONAL}blog" / "a" / "subagents", "agent-1", _line("rm -rf ~"))
    _session(root / SITE_ONE, "d", _line("ls"))
    _session(root / SITE_TWO, "e", _line("ls"))
    _session(root / f"{PERSONAL}acme-corp-app", "f", _line("ls"))
    _session(root / f"{PERSONAL}Client-X-Thing", "g", _line("ls"))
    _session(root / f"{PERSONAL}private-bot", "h", _line("ls"))
    _session(root / f"{PERSONAL}old-archive", "i", _line("ls"))
    _session(root / "-home-alice-work-client", "j", _line("ls"))
    _session(root / f"{SITE_ONE}-extra", "k", _line("ls"))
    return root


def test_default_config_includes_everything(tmp_path):
    root = make_root(tmp_path)
    cfg = ScopeConfig()
    assert len(select_projects(root, cfg)) == 9
    blog = root / f"{PERSONAL}blog"
    assert not session_excluded(blog / "b.jsonl", cfg)
    assert not prompt_excluded(blog / "b.jsonl", cfg)


def test_privacy_project_selection(tmp_path):
    root = make_root(tmp_path)
    names = [p.name for p in select_projects(root, scoped())]
    assert names == [f"{PERSONAL}blog", SITE_ONE, SITE_TWO]


def test_privacy_content_exclusion(tmp_path):
    root = make_root(tmp_path)
    blog = root / f"{PERSONAL}blog"
    cfg = scoped()
    assert not session_excluded(blog / "a.jsonl", cfg)
    assert session_excluded(blog / "b.jsonl", cfg)
    assert session_excluded(blog / "c.jsonl", cfg)


def _prompt(text: str) -> str:
    import json

    return json.dumps({"type": "user", "message": {"role": "user", "content": text}}) + "\n"


def _attachment(text: str) -> str:
    import json

    return json.dumps({"type": "attachment", "content": text}) + "\n"


def test_event_mode_drops_matching_events_not_sessions(tmp_path):
    root = make_root(tmp_path)
    blog = root / f"{PERSONAL}blog"
    _session(blog, "p", _prompt("please fix the acme-corp client") + _line("rm -rf /"))
    _session(blog, "q", _attachment("memory: works on acme-corp") + _line("rm -rf /"))
    cfg = scoped()
    assert prompt_excluded(blog / "p.jsonl", cfg)
    assert not prompt_excluded(blog / "q.jsonl", cfg)
    assert not prompt_excluded(blog / "b.jsonl", cfg)
    res = scan(root, cfg)
    assert res.sessions_excluded == 1  # p: the prompt itself matched the exclude pattern
    assert res.events_dropped == 2  # b and c tool calls never reach the detectors
    md = render_markdown(res)
    assert "acme-corp" not in md.lower() and "client-x" not in md.lower()
    assert "per-event" in md


def test_scan_counts_and_report_hides_names(tmp_path):
    root = make_root(tmp_path)
    cfg = scoped()
    cfg.content_mode = "session"
    res = scan(root, cfg)
    assert res.projects == 3
    assert res.sessions_excluded == 2
    assert res.sessions_scanned == 4  # a, subagent, d, e
    assert res.tool_calls == 4
    assert [f["rule"] for f in res.findings] == ["destructive_shell"]
    md = render_markdown(res, notes="hand-check line")
    assert "blog" not in md and "site-one" not in md and "site-two" not in md
    assert "project-01" in md and "hand-check line" in md


def test_scope_is_configurable(tmp_path):
    root = make_root(tmp_path)
    cfg = ScopeConfig(include_prefixes=("-home-alice-work-",))
    assert [p.name for p in select_projects(root, cfg)] == ["-home-alice-work-client"]


def test_load_example_config():
    cfg = load_config(EXAMPLE_CONFIG)
    assert cfg.include_prefixes == ("-home-alice-projects-",)
    assert cfg.include_exact == ("-home-alice-scratch",)
    assert cfg.exclude_dir.search("-home-alice-projects-ACME-CORP-site")
    assert cfg.exclude_content.search("ticket for client-x")
    assert cfg.redact_terms == ("acme-corp",)
    assert cfg.content_mode == "event"


def test_load_config_matches_scoped_behaviour(tmp_path):
    root = make_root(tmp_path)
    path = tmp_path / "cfg.json"
    path.write_text(json.dumps({
        "include_prefixes": [PERSONAL],
        "include_exact": [SITE_ONE, SITE_TWO],
        "exclude_dir_pattern": "acme-corp|client-x|private-bot|old-archive",
        "exclude_content_pattern": "acme-corp|client-x\\.example",
        "strict_sessions": True,
    }))
    cfg = load_config(path)
    assert cfg.content_mode == "session"
    assert [p.name for p in select_projects(root, cfg)] == [p.name for p in select_projects(root, scoped())]
    assert scan(root, cfg).sessions_excluded == 2


def test_load_config_defaults_and_errors(tmp_path):
    path = tmp_path / "cfg.json"
    path.write_text("{}")
    cfg = load_config(path)
    assert cfg == ScopeConfig()
    path.write_text(json.dumps({"include_prefix": ["x"]}))
    with pytest.raises(ValueError, match="unknown config keys"):
        load_config(path)
    path.write_text(json.dumps({"redact_terms": "acme-corp"}))
    with pytest.raises(ValueError, match="list of strings"):
        load_config(path)


def test_cli_config_flag(tmp_path):
    root = make_root(tmp_path)
    path = tmp_path / "cfg.json"
    path.write_text(json.dumps({"include_exact": [SITE_ONE], "redact_terms": ["secret-word"]}))
    out = tmp_path / "report.md"
    assert main(["--root", str(root), "--out", str(out), "--config", str(path)]) == 0
    assert "Projects in scope: 1" in out.read_text()
