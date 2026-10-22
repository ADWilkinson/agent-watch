"""Scan a transcript root and render the results.

Project directory names never reach the output: projects are numbered
project-01, project-02 ... in sorted order and the mapping is kept in memory
only. Finding evidence is already redacted by the detectors; the report
redacts again on the way out as a belt-and-braces step.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .detectors import DEFAULT_ALLOW_HOSTS, HIGH, LOW, MEDIUM, RULES, Finding, run_all
from .parse import parse_session
from .redact import redact, set_redact_terms
from .scope import ScopeConfig, prompt_excluded, select_projects, session_excluded, session_files

SEVERITIES = (HIGH, MEDIUM, LOW)
MAX_EXAMPLES = 5

# What I would do with each rule if it were wired into a live hook. Derived
# from the rule definitions, not from the counts.
POLICY = {
    "destructive_shell": "Block high (rm -rf on /, ~ or $HOME, mkfs, dd to a device, DROP via a db client). Log medium.",
    "write_outside_repo": "Block writes to shell, ssh and cloud dotfiles and to agent settings or hooks. Log the rest; /tmp is noise.",
    "git_history_rewrite": "Block bare --force to a shared branch and filter-branch. Log lease pushes, rebase -i, branch -D and amend.",
    "secret_access": "Block private key reads, keychain and password-manager reads. Log .env reads, which are usually requested.",
    "prod_branch_push": "Require confirmation for production deploys. Log pushes to main; on solo repos that is the workflow.",
    "network_exfil": "Block `curl | sh` and uploads of local files or env to non-allowlisted hosts. Log other POSTs.",
    "unverified_ship_claim": "Never block. Log and surface to the user next to the claim, since it is about honesty, not safety.",
}


@dataclass
class ScanResult:
    projects: int = 0
    sessions_scanned: int = 0
    sessions_excluded: int = 0
    events_dropped: int = 0
    strict: bool = False
    tool_calls: int = 0
    malformed_lines: int = 0
    first_ts: str | None = None
    last_ts: str | None = None
    findings: list[dict] = field(default_factory=list)


def scan(root: Path, cfg: ScopeConfig | None = None, since: str | None = None, allow_hosts: set[str] = DEFAULT_ALLOW_HOSTS) -> ScanResult:
    cfg = cfg or ScopeConfig()
    set_redact_terms(cfg.redact_terms)
    res = ScanResult(strict=cfg.content_mode == "session")
    projects = select_projects(root, cfg)
    res.projects = len(projects)
    for n, project in enumerate(projects, 1):
        label = f"project-{n:02d}"
        for path in session_files(project):
            strict = cfg.content_mode == "session"
            if (session_excluded if strict else prompt_excluded)(path, cfg):
                res.sessions_excluded += 1
                continue
            session = parse_session(path, since=since, drop=None if strict else cfg.exclude_content)
            res.events_dropped += session.dropped_events
            if not session.events:
                continue
            res.sessions_scanned += 1
            res.malformed_lines += session.malformed_lines
            res.tool_calls += len(session.tool_calls)
            stamps = [e.ts for e in session.events if e.ts]
            if stamps:
                res.first_ts = min([res.first_ts or stamps[0], *stamps])
                res.last_ts = max([res.last_ts or stamps[0], *stamps])
            for f in run_all(session, allow_hosts):
                d = f.to_dict()
                d["project"] = label
                d["session"] = f.session[-8:]
                d["evidence"] = redact(d["evidence"])
                res.findings.append(d)
    return res


def _rate(n: int, calls: int) -> str:
    return f"{1000 * n / calls:.1f}" if calls else "n/a"


def render_markdown(res: ScanResult, notes: str | None = None) -> str:
    sev = Counter(f["severity"] for f in res.findings)
    by_rule = Counter(f["rule"] for f in res.findings)
    lines = [
        "# agent-watch report",
        "",
        "## Scope",
        "",
        f"- Projects in scope: {res.projects}",
        f"- Sessions scanned (including subagent transcripts): {res.sessions_scanned}",
        f"- Privacy filter mode: {'whole-session' if res.strict else 'per-event'}",
        f"- Sessions excluded by the privacy filter: {res.sessions_excluded}",
        f"- Individual tool calls or messages dropped by the privacy filter: {res.events_dropped}",
        f"- Tool calls analysed: {res.tool_calls}",
        f"- Malformed lines skipped: {res.malformed_lines}",
        f"- Date range: {(res.first_ts or 'n/a')[:10]} to {(res.last_ts or 'n/a')[:10]}",
        f"- Total findings: {len(res.findings)} ({_rate(len(res.findings), res.tool_calls)} per 1,000 tool calls)",
        "",
        "## Severity breakdown",
        "",
        "| Severity | Findings | Per 1,000 tool calls |",
        "|---|---:|---:|",
    ]
    lines += [f"| {s} | {sev[s]} | {_rate(sev[s], res.tool_calls)} |" for s in SEVERITIES]
    lines += ["", "## Findings per rule", "", "| Rule | High | Medium | Low | Total | Per 1,000 tool calls |", "|---|---:|---:|---:|---:|---:|"]
    for rule in RULES:
        c = Counter(f["severity"] for f in res.findings if f["rule"] == rule)
        lines.append(f"| {rule} | {c[HIGH]} | {c[MEDIUM]} | {c[LOW]} | {by_rule[rule]} | {_rate(by_rule[rule], res.tool_calls)} |")
    lines += ["", "## Examples", "", "Up to five per rule, highest severity first. Evidence is redacted and truncated.", ""]
    order = {s: i for i, s in enumerate(SEVERITIES)}
    for rule in RULES:
        items = sorted((f for f in res.findings if f["rule"] == rule), key=lambda f: (order[f["severity"]], f["ts"]))
        if not items:
            continue
        lines += [f"### {rule}", ""]
        seen: set[str] = set()
        for f in items:
            if f["evidence"] in seen:
                continue
            seen.add(f["evidence"])
            ev = f["evidence"].replace("`", "'")
            lines.append(f"- **{f['severity']}** {f['project']} {f['ts'][:10]}: `{ev}`")
            if len(seen) >= MAX_EXAMPLES:
                break
        lines.append("")
    lines += ["## What I would block vs log", "", "| Rule | Policy |", "|---|---|"]
    lines += [f"| {r} | {POLICY[r]} |" for r in RULES]
    if notes:
        lines += ["", "## Hand-check", "", notes.strip()]
    return redact("\n".join(lines)) + "\n"


def write_json(res: ScanResult, path: Path) -> None:
    payload = {
        "scope": {k: getattr(res, k) for k in ("projects", "sessions_scanned", "sessions_excluded", "events_dropped", "tool_calls", "first_ts", "last_ts")},
        "findings": res.findings,
    }
    path.write_text(redact(json.dumps(payload, indent=2)) + "\n")
