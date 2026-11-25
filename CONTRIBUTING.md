# Contributing

Keep the wrappers small and preserve upstream provider protocols. Useful
contributions include narrower profiles, Linux deployment fixes, lifecycle
edge cases and compatibility reports with newer Paseo/CLI combinations.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
bash -n bin/agentbox bin/agentbox-provider bin/agentbox-catalog images/base/entrypoint.sh
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v
node --check images/research-browser/research-browser.cjs
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

For controlled CLI changes, run the credential-free pinned-harness tool-inventory
and gateway-roundtrip check in [command-policies.md](docs/command-policies.md).
A fixture policy test alone does not prove the model lost native execution tools.

Version updates should change the exact agent version defaults and their
documentation together, rebuild all used descendants and repeat protocol
checks against the installed Paseo SDK. Keep credentials, generated daemon
config, private handoffs and personal deployment transcripts out of commits.

Use synthetic fixtures and example domains/addresses. Do not copy a live
platform file, model login, CA private key, WireGuard profile or runtime database
into the repository. Before publishing, review `git diff --cached`, scan the
candidate files and Git history with Gitleaks, and inspect the exact archive:

```bash
gitleaks dir . --redact=100
gitleaks git --redact=100 --log-opts='--all'
git archive HEAD | tar -tf -
```

CI scans history with a pinned, checksum-verified Gitleaks binary. Do not blanket
allowlist the tests directory; fixture code can leak real credentials too.
