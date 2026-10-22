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
