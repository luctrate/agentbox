# Suggested manager instructions

Copy the following into your existing Claude and Codex instruction files.
Keep any project-specific permission rules and other existing instructions.

```markdown
## Container workers

When `command -v agentbox` succeeds, delegate bounded tasks to Claude Code or
Codex containers using `agentbox spawn`, so workers remain visible in Paseo.

- `agentbox profiles` lists configured profiles.
- `agentbox spawn --detach claude "TASK"` starts a Claude worker.
- `agentbox spawn --detach codex "TASK"` starts a Codex worker.
- `agentbox status ID`, `agentbox wait ID --timeout 60`, and
  `agentbox logs ID --json` report progress and results.
- `agentbox send ID "MESSAGE"` continues the same worker conversation; it
  steers rather than interrupts an active turn. Read logs and wait for results.
- Restricted managers can inspect structured clarification questions with
  `agentbox questions ID`, then reply using
  `agentbox answer ID REQUEST_ID --answers '{"EXACT_KEY":"ANSWER"}'`.
  Use the exact request ID and every key returned by `questions`.
  This answers Claude/Codex clarification questions only, not tool approvals.
  If the task does not establish an answer, ask the user instead of guessing.
- Poll workers for questions while coordinating them; no automatic notification
  or manager wake-up is currently provided. On `delivery_unconfirmed`, inspect
  logs/questions; reuse the same delivery `--request-id` to avoid duplicates.
- Surface pending permission requests for review. Do not silently approve
  broader access or destructive actions.
- `agentbox stop ID` interrupts a turn; `agentbox archive ID` releases its
  runtime while retaining history. Idle does not imply container shutdown.
- `agentbox ps` maps containers to Paseo agent IDs.

Choose the least privileged available profile that has the required tools.
Use separate worktrees for concurrent editing; spawn reuses the current
workspace. Never print credentials or put them in task prompts. Do not mount
the Docker socket or broaden a profile without the user's authorization.

If agentbox is absent, you may already be inside a worker: complete the
assigned task rather than installing it or attempting nested delegation.
```
