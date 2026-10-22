from agent_watch.parse import AssistantText, ToolCall

CWD = "/home/alice/projects/demo"


def bash(cmd: str, branch: str | None = "feature/x", cwd: str = CWD) -> ToolCall:
    return ToolCall(session="s1", ts="2026-01-01T00:00:00Z", cwd=cwd, name="Bash", input={"command": cmd}, git_branch=branch)


def tool(name: str, cwd: str = CWD, **inp) -> ToolCall:
    return ToolCall(session="s1", ts="2026-01-01T00:00:00Z", cwd=cwd, name=name, input=inp)


def say(text: str) -> AssistantText:
    return AssistantText(session="s1", ts="2026-01-01T00:00:00Z", text=text)
