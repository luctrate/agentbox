# Contributing

Keep the wrappers small and preserve upstream provider protocols. Useful
contributions include narrower profiles, Linux deployment fixes, lifecycle
edge cases and compatibility reports with newer Paseo/CLI combinations.

```bash
bash -n bin/agentbox bin/agentbox-provider images/base/entrypoint.sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Tests use temporary fixtures and fake Docker/Vault commands. They do not need
real credentials or a running Docker daemon. GitHub Actions runs them on
Linux and macOS. Preserve compatibility with stock macOS Bash 3.2.

When changing a provider protocol, verify both Claude's SDK stream and Codex's
app-server JSON-RPC. Preserve MCP capability headers and avoid rewriting task
text. Repeat real-session checks for permission handling, rendered timelines,
restart/history recovery, worktree placement and interrupt/archive cleanup
using a separate authenticated test daemon and disposable repo. Do not claim
these live checks passed merely because fixture tests pass.

Version updates should change the exact agent version defaults and their
documentation together, rebuild all used descendants and repeat protocol
checks against the installed Paseo SDK. Keep credentials, generated daemon
config, private handoffs and personal deployment transcripts out of commits.
