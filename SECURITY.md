# Security model

Agentbox is an experimental development wrapper around Docker and native
coding CLIs. Treat every profile and every selected image as trusted code.

- A host manager with shell/Docker access can bypass profiles. Docker access
  is powerful; this project does not restrict that manager.
- Workers can modify writable mounts, read their selected auth directory and
  use credentials injected into them. Shared auth/history is a deliberate
  compatibility trade-off, not per-worker identity isolation.
- The provider wrapper forwards provider-related environment variables such
  as `ANTHROPIC_*`, `OPENAI_*`, `CLAUDE_*` and `CODEX_*`, as well as explicitly
  configured profile variables. Minimize the daemon's environment.
- Bridge networking permits outbound connectivity by default. There is no
  egress allowlist, network-policy controller or exfiltration prevention here.
- Vault secrets are resolved on the host at process launch and supplied via
  Docker environment variables. Secret values are kept out of static Paseo
  configuration and profile-secret argv; they remain readable by workers and
  Docker/host administrators. No token broker, TTL issuance or automatic
  revocation/rotation is implemented.
- MCP connectivity must preserve Paseo's per-agent capability authentication.
  Keep the bridge proxy off public interfaces and expose only the MCP path.
  Its capability value can be present in native process/protocol arguments;
  avoid dumping process commands or full Docker inspect output into reports.
- CLI-only `run` bypasses interactive provider approvals. Provider-mode
  permission handling is different and remains controlled by Paseo.
- Normal runtime teardown removes the worker. An uncatchable process kill or
  host crash can leave a container; inspect ownership before cleanup.
- Agent-version pins do not pin every OS/tool dependency. Rebuild and review
  images regularly; upstream licenses and service terms still apply.

Choose minimal mounts and token scopes. Do not mount the Docker socket,
private signing keys or unrelated credential directories into workers. Test
against disposable repositories before using privileged tools.

For a suspected vulnerability, use GitHub's private vulnerability reporting
for this repository when available. Do not put tokens or private infrastructure
information in a public issue. General limitations above are intentional and
should be accounted for when choosing where to deploy this experiment.
