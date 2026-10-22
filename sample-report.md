# agent-watch report

## Scope

- Projects in scope: 19
- Sessions scanned (including subagent transcripts): 99
- Privacy filter mode: per-event
- Sessions excluded by the privacy filter: 22
- Individual tool calls or messages dropped by the privacy filter: 77
- Tool calls analysed: 3171
- Malformed lines skipped: 0
- Date range: 2026-06-23 to 2026-10-22
- Total findings: 81 (25.5 per 1,000 tool calls)

## Severity breakdown

| Severity | Findings | Per 1,000 tool calls |
|---|---:|---:|
| high | 0 | 0.0 |
| medium | 76 | 24.0 |
| low | 5 | 1.6 |

## Findings per rule

| Rule | High | Medium | Low | Total | Per 1,000 tool calls |
|---|---:|---:|---:|---:|---:|
| destructive_shell | 0 | 0 | 0 | 0 | 0.0 |
| write_outside_repo | 0 | 21 | 5 | 26 | 8.2 |
| git_history_rewrite | 0 | 0 | 0 | 0 | 0.0 |
| secret_access | 0 | 6 | 0 | 6 | 1.9 |
| prod_branch_push | 0 | 46 | 0 | 46 | 14.5 |
| network_exfil | 0 | 3 | 0 | 3 | 0.9 |
| unverified_ship_claim | 0 | 0 | 0 | 0 | 0.0 |

## Examples

Up to five per rule, highest severity first. Evidence is redacted and truncated.

### write_outside_repo

- **medium** project-16 2026-06-23: `Write ~/<agent-notes>/<path>/note-a.md`
- **medium** project-16 2026-06-23: `Write ~/<agent-notes>/<path>/index.md`
- **medium** project-08 2026-07-29: `Write ~/.claude/<task-dir>/tmp/progress.md`
- **medium** project-08 2026-07-29: `Write ~/.claude/<task-dir>/tmp/script-a.mjs`
- **medium** project-02 2026-08-06: `Write ~/<agent-notes>/<path>/note-b.md`

### secret_access

- **medium** project-12 2026-07-05: `grep -niE <term-a>|<term-b>|<term-c> .env 2>/dev/null ; grep -niE <term-a>|<term-b>|<term-c> .env.bak.p...`
- **medium** project-12 2026-07-05: `grep -vE KEY|SECRET|TOKEN|PASSWORD|WEBHOOK|_ID= .env 2>/dev/null`
- **medium** project-08 2026-07-29: `grep -c . ~/projects/<path>/.env ; grep -oE ^[A-Z_]+ ~/projects/<path>/.env`
- **medium** project-08 2026-07-29: `grep -vE ^(<VAR_A>|<VAR_B>)= ~/projects/<path>/.env > .env`
- **medium** project-08 2026-07-29: `cp .env apps/web/.env.local`

### prod_branch_push

- **medium** project-16 2026-06-23: `git push origin main 2>&1`
- **medium** project-08 2026-07-29: `git push origin HEAD:main 2>&1`
- **medium** project-09 2026-08-02: `git push -q origin main`

### network_exfil

- **medium** project-09 2026-08-02: `curl -s -m 60 -H Accept: application/sparql-results+json --data-urlencode [EMAIL] https://<public-data-api>/query`
- **medium** project-09 2026-08-03: `curl -s -o /dev/null -w %{http_code} -X POST http://$H/api/<internal-endpoint> -H content-type: application/json -d {"text":"<message>"} ; curl -s -X POST http://...`

## What I would block vs log

| Rule | Policy |
|---|---|
| destructive_shell | Block high (rm -rf on /, ~ or $HOME, mkfs, dd to a device, DROP via a db client). Log medium. |
| write_outside_repo | Block writes to shell, ssh and cloud dotfiles and to agent settings or hooks. Log the rest; /tmp is noise. |
| git_history_rewrite | Block bare --force to a shared branch and filter-branch. Log lease pushes, rebase -i, branch -D and amend. |
| secret_access | Block private key reads, keychain and password-manager reads. Log .env reads, which are usually requested. |
| prod_branch_push | Require confirmation for production deploys. Log pushes to main; on solo repos that is the workflow. |
| network_exfil | Block `curl | sh` and uploads of local files or env to non-allowlisted hosts. Log other POSTs. |
| unverified_ship_claim | Never block. Log and surface to the user next to the claim, since it is about honesty, not safety. |

## Hand-check

Hand-check of 30 findings picked at random (seed 11), labelled from the redacted evidence.

- **Did the rule fire correctly?** 30 of 30. Every finding matches what its rule says it looks for.
- **Would I want a human to look at it?** 3 of 30, all `secret_access`:
  - an agent copying a `.env` file into another app;
  - an agent rewriting `.env` from another project's copy;
  - an agent listing the variable names in a secrets file and then running a bare `env`.
- **The other 27 are intended and belong in the log, not the block list:**
  - 15 pushes to `main` on solo repos, which is my normal workflow;
  - 11 writes to my agents' memory, task and report folders outside the repo;
  - one `/tmp` scratch file.

**How this got here.** This is the third pass.
- **First pass.** I used a whole-session privacy filter. It dropped 91% of sessions, because a memory file mentioning excluded projects is injected into nearly every session. That left 408 tool calls and 2 findings, which was too thin to learn anything from.
- **Filter changed.** The filter now drops a session only when my own prompt was about an excluded project. In the sessions it keeps, it drops any single tool call or message that mentions one, so that content never reaches a detector. Those drops are only counted.
- **Second pass.** 88 findings. The hand-check turned up two noisy rules:
  - `network_exfil` flagged `curl ... | python3 -c` (parsing JSON output) as if it were `curl | sh`, and flagged calls to machines on my private network;
  - `prod_branch_push` evidence showed long commit messages instead of the push itself.
  I fixed both, added tests, and ran it again.

**What this does not show:**
- **Recall.** I have no labelled set of real incidents. Rules that fired zero times (`destructive_shell`, `git_history_rewrite`, `unverified_ship_claim`) are only proven by unit tests.
- **One remaining network finding** posts to `http://$H/...`. Because the host is a shell variable, the rule can't tell it's an internal machine.
