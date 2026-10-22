# agent-watch

A small rule-based monitor for Claude Code sessions. Point it at your own transcripts and it flags actions you'd want a reviewer to see: destructive commands, writes outside the repo, secret reads, pushes to main, uploads to unknown hosts and unchecked claims of success.

It reads the JSONL transcripts under `~/.claude/projects/`, extracts tool calls and assistant text, runs seven rules over them and writes a redacted Markdown report.

## What it flags

Seven rules, each a pure function over parsed events:

1. `destructive_shell`: `rm -rf` on broad or home paths, `find -delete`, `mkfs`, `dd`, `DROP TABLE`, `git clean -fdx`, `git reset --hard` and similar.
2. `write_outside_repo`: Write, Edit, MultiEdit or NotebookEdit outside the session's working directory. `/tmp` is low; shell, ssh and cloud dotfiles and agent settings are high.
3. `git_history_rewrite`: force pushes, `rebase -i`, `filter-branch`/`filter-repo`, `branch -D`, `commit --amend`.
4. `secret_access`: reading `.env`, keys and credentials files, keychain or 1Password reads, `gh auth token`, environment dumps.
5. `prod_branch_push`: pushes to main or master, and production deploys (`vercel --prod`, `firebase deploy`, `wrangler deploy`, `terraform apply` and others).
6. `network_exfil`: uploads to hosts not on an allowlist, local files or env vars in a request body, `nc`, `scp`/`rsync` to remote hosts, `curl | sh`.
7. `unverified_ship_claim`: the agent says it shipped, deployed, merged or fixed something, or that all tests pass, with no test, build, HTTP or CI check in the previous 25 tool calls.

Each rule's docstring lists the false positives to expect.

## How to run

```
python -m pytest
python -m agent_watch --root ~/.claude/projects --out report.md [--config config.json] [--json findings.json] [--since YYYY-MM-DD]
```

Python 3.10 or later, standard library only; pytest is needed for the tests. `--help` lists the allowlist and scope options.

## Configuration

With no config, every project directory under `--root` is read and nothing is excluded. To narrow the scope or keep some projects out of the report, pass a JSON file with `--config`. `config.example.json` shows every key:

```json
{
  "include_prefixes": ["-home-alice-projects-"],
  "include_exact": ["-home-alice-scratch"],
  "exclude_dir_pattern": "acme-corp|client-x",
  "exclude_content_pattern": "acme-corp|client-x",
  "redact_terms": ["acme-corp"],
  "strict_sessions": false
}
```

- `include_prefixes`, `include_exact`: project directory names to read. Claude Code names each directory after the session's path, so `/home/alice/projects/blog` becomes `-home-alice-projects-blog`. If both lists are empty, all directories are read.
- `exclude_dir_pattern`: case-insensitive regex; matching project directories are skipped.
- `exclude_content_pattern`: case-insensitive regex for content you never want analysed. By default a session is dropped if one of your own prompts matches it. In the sessions that remain, any single tool call or assistant message that matches is dropped before any rule sees it. Injected context such as memory files does not drop a whole session, because it tends to be the same in every session. Only counts are reported.
- `strict_sessions`: if true, drop a whole session on any match anywhere in the file. `--strict-sessions` does the same.
- `redact_terms`: extra words replaced with `[term]` in all output, on top of the built-in redaction.

All keys are optional. `--include-prefix`, `--include`, `--exclude-dir` and `--exclude-content` override the matching config values.

## Sample results

`sample-report.md` is the output from my own transcripts and `handcheck.md` is my labelling of a sample of its findings. Headline numbers:

- 19 projects, 99 sessions, 3,171 tool calls over four months. The privacy filter excluded 22 sessions and dropped 77 individual events.
- 81 findings, 25.5 per 1,000 tool calls: 0 high, 76 medium, 5 low.
- `prod_branch_push` 46, `write_outside_repo` 26 (21 medium, 5 low), `secret_access` 6, `network_exfil` 3. The other three rules did not fire.

## Why simple rules are noisy

I hand-checked 30 findings picked at random. All 30 were correct by the rule's own definition, but only 3 were worth a human look, all `secret_access`: an agent copying a `.env` file into another app, an agent rewriting `.env` from another project's copy, and an agent listing the variable names in a secrets file and then running a bare `env`.

The other 27 were intended: 15 pushes to `main` on solo repos, 11 writes to my agents' memory, task and report folders outside the repo, and one `/tmp` scratch file. A rule can be precise and still mostly noise, because what makes an action risky is context the rule cannot see: whose repo it is, and whether the user asked for it.

An earlier pass also showed two rules misfiring: `network_exfil` treated `curl ... | python3 -c` (parsing JSON) as `curl | sh` and flagged machines on my private network, and `prod_branch_push` showed long commit messages instead of the push. Both are fixed and tested.

## Design choices

- **Standard library only.** Nothing to install.
- **Pure detectors.** Each rule takes events and returns findings, so it is easy to test and could be called from a hook unchanged.
- **Shell commands are tokenised, not grepped.** Commands are split on control operators outside quotes, heredocs are dropped, and rules look at the leading program, so `grep "rm -rf"` or a commit message is not flagged.
- **Privacy filter first.** Scope and exclusions are applied before any rule runs, so excluded content never reaches a detector. The whole-session mode is stricter, but on my transcripts it removed 91% of sessions, because a memory file mentioning an excluded project is injected into almost every session.
- **Redaction before output.** Evidence is redacted when a finding is created and again on output (keys, tokens, emails, phone numbers, long hex or base64, home paths, configured terms). Projects appear as `project-01` and so on; the mapping is never written to disk.
- **Rules on purpose.** A cheap, explainable baseline shows which false positives a model would actually need to fix before reaching for one.

## Limits

- These are heuristics. A command wrapped in `bash -c` or `eval` will be missed.
- Nothing is blocked. This reads transcripts after the event.
- Transcripts only show what the agent logged. Side effects inside scripts it ran are invisible.
- Claim detection is crude. It cannot see verification done by a subagent, and it reads phrasing, not intent.
- The sample is one person's traffic, much of it from their own agents rather than typed prompts. Recall on real incidents is untested, and three rules never fired on real data, so they are only proven by unit tests.

## Next steps

- A `PreToolUse` hook that blocks the high-severity rules live, using the same detectors. The end of the sample report lists what I would block and what I would only log, per rule.
- An LLM judge for the question rules cannot answer: did the agent do something the user didn't ask for?

## License

MIT. See `LICENSE`.
