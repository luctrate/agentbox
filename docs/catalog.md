# Declarative agent catalogs

The catalog uses `apiVersion: asp.now/v1alpha1` and `kind: AgentCatalog`.
It describes agent definitions; each Paseo session is a separately identified
runtime of a definition. The CLI, broker and launcher use the same compiled
policy. Catalog content is data, never sourced shell code.

This release implements the Docker/CLI/Vault/IP-policy foundation. It does
not silently accept future security features that cannot yet be enforced.

For protected installation, authentication, systemd services and first activation,
follow the [installation guide](installation.md).

## Supported settings

- Claude Code and Codex, with exact harness versions and immutable image IDs
  or registry digests. The operator verifies actual harness versions and sudo
  availability in isolated image probes before activation.
- Named manager/worker definitions, preserving normal native Claude/Codex as
  separate unmanaged entries.
- Unshared research profiles and project-only workers with ephemeral model
  login, plus an internal Docker network and exact-host HTTPS model proxy.
  See [research workers](research-workers.md) for the image and proxy requirements.
- Non-root execution; CPU/memory/PID limits; explicit read-only root/project
  controls; capability dropping and privilege-escalation policy.
- `vaultPathToEnv` and static tool configuration. Vault reads happen only when
  a real worker starts; validation, planning and image probes read no secrets.
- Per-definition `tools.launchAgent.allowedWorkers` and concurrent limits,
  with bounded, cycle-free delegation and parent-bound runtime capabilities.
  CLI clients cannot choose extra Docker flags,
  mounts, Vault paths, environment overrides or native host providers.
- Named IPv4 network policies: `publicExceptPrivate` or `denyAll`, explicit
  CIDR/protocol/port exceptions, selected DNS and broker access. Rules are
  enforced through Docker bridges and host firewall policy.

`tools.cli.mode: unrestrictedWithinContainer` is the supported command mode.
Mediated commands, CLI-disabled/MCP-only agents, remote MCP tool policies,
reviewer-agent approvals, arbitrary domain egress policies and workspace creation
are rejected until the corresponding adapters exist. The supported domain
restriction is the dedicated internal-network HTTPS proxy described above.
An empty `tools.mcp: []` declares no configured MCP integrations; it does not
claim an unrestricted shell could never run an MCP client itself.

## Files and trust

Start from [examples/catalog.yaml](../examples/catalog.yaml) and
[examples/platform.json](../examples/platform.json). Replace the example zero
image digest with an actual immutable image ID from your build.

The YAML describes agent policy. A separate **administrator-controlled**
platform JSON binds auth references to host directories, definition IDs to
Paseo provider IDs, network policies to physical bridges/subnets, and supplies
trusted runtime/service paths. Neither file contains credential values.
Platform paths must stay outside agent workspace mounts; auth directories
must be distinct. Apply checks real symlink resolution on the host too.

Agents may propose catalog changes in a development repository. They cannot
activate those proposals. Only an operator installs a reviewed revision into
the protected policy store. Never run an agent-writable operator script as
root: install reviewed source and dependencies under a protected prefix first.
The original `deploy/configure.py` remains the legacy setup helper and refuses
to apply over restricted/catalog providers.

## Validate and plan

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt

.venv/bin/python deploy/catalog.py validate examples/catalog.yaml \
  --platform examples/platform.json

.venv/bin/python deploy/catalog.py plan YOUR_CATALOG.yaml \
  --platform YOUR_PLATFORM.json --paseo-config /home/paseo/.paseo/config.json
```

You can also use `agentbox catalog ...` from the host CLI, selecting its
interpreter with `AGENTBOX_CATALOG_PYTHON` when dependencies live in a venv.
The restricted container-side client intentionally has no catalog-apply command.

Plan produces a catalog revision, deployment revision, provider changes and
secret-free runtime policy. The catalog revision covers normalized definitions
and permission-relevant bindings. The deployment revision additionally covers
operational bindings. Generation paths are excluded from the identity to avoid
a circular hash. Defaults merge objects, but permission lists **replace**;
empty lists explicitly remove grants.

The loader rejects duplicate YAML keys, aliases/merge keys, custom tags,
multiple documents, unknown fields, invalid references, unsupported settings
and oversized/invalid input. Native provider IDs and provider/model shortcuts
cannot become delegated worker targets. The checked-in schema is an identifier
under asp.now; this repository does not publish a schema endpoint on the domain.

## Apply

Use a root-owned installed operator, not an agent-writable development checkout:

```bash
sudo /opt/agentbox/.venv/bin/python /opt/agentbox/deploy/catalog.py apply YOUR_CATALOG.yaml \
  --platform YOUR_PLATFORM.json \
  --paseo-config /home/paseo/.paseo/config.json \
  --expect-revision REVIEWED_CATALOG_HASH \
  --expect-deployment REVIEWED_DEPLOYMENT_HASH
```

Adapt the prefix to your installation. The default generation store is
`/etc/agentbox/catalog/generations/`, policy link `/etc/agentbox/security.json`,
and managed manifest `/etc/agentbox/catalog/managed.json`. Override them with
`--generations`, `--policy-link` and `--manifest` if needed.

First migration over existing compatible restricted provider entries requires
`--adopt-existing` after reviewing the plan. Arbitrary custom providers are
never adopted just because their IDs happen to match. Later applies use a
three-way managed manifest and refuse unreviewed out-of-band changes. Removed
definitions are disabled, not deleted, so their history bindings remain.
Native Claude/Codex, plugins, daemon auth and MCP settings are preserved.

Apply is serialized with an exclusive operator lock. It checks bindings,
images/auth, provider conflicts and generation consistency before draining.
An active normal host-agent turn blocks apply. Existing managed containers
block it unless an operator explicitly supplies `--drain`, which archives
those sessions. Unscoped model/auth probes carry no workspace/tool-secret/
delegation authority and are not counted as active agent sessions.

Activation briefly stops Paseo/broker, atomically installs a complete network
ruleset, switches the protected policy link/provider config, starts services
and checks readiness before committing the managed manifest. Backups include
previous config/policy and registry files. Failure restores previous policy,
network and config; if rollback cannot be verified, services stay stopped.
An idempotent apply of the same deployment makes no service changes.

This is a controller for an existing native Linux Paseo/Docker installation,
not a fresh-server bootstrap. The trusted broker/network/Paseo systemd units,
model authentication directories and CA trust must already be installed as
described in [the restricted manager reference](../security/README.md).

## Delegation and recovery

```bash
agentbox profiles
agentbox spawn --detach codex "Review this checkout"
agentbox status AGENT_ID
agentbox logs AGENT_ID --json
agentbox send AGENT_ID "Use the existing API; add regression tests too."
agentbox questions AGENT_ID
agentbox answer AGENT_ID QUESTION_REQUEST_ID --answers '{"Color":"Blue"}'
agentbox archive AGENT_ID
```

The container client has only a runtime capability. Replacing it, using curl,
or changing local tool configuration cannot widen backend authorization.
The broker stores capability hashes and launch ownership in SQLite. Existing
legacy `state.json` registries use a `state.sqlite3` sidecar; keep the whole
state directory private and writable by the trusted broker for SQLite journals.

Creation reserves quota durably before calling Paseo. Each launch has a
server-generated label used for recovery. Retry an uncertain HTTP request
with the **same** client request ID:

```bash
agentbox spawn --detach --request-id REQUEST_UUID codex "The exact same task"
```

A pending reconciliation response is not a completed launch. The broker never
blindly creates another worker after an ambiguous timeout; uncertain requests
keep their reservation until positively recovered/resolved. UI-side archival
or confirmed deletion is reconciled and releases quota. An unavailable daemon
is not treated as proof that a worker was deleted. Capability revocation is
attempted even if Docker cleanup fails.

### Worker clarification and follow-up

Workers are persistent Paseo conversations. Ordinary assistant questions appear
in `agentbox logs` and the worker's conversation in Paseo. The manager can use
`agentbox send ID "ANSWER"` to continue that same worker with its existing
context. Delivery uses Paseo's `steer` behavior and returns immediately; it does
not interrupt an active turn. Use `wait` and `logs` to collect the response.
Manager messages carry the manager's Paseo agent ID as their source.
If delivery is `queued`, an immediate `wait` can still see the old idle state;
confirm the new message/response in logs before treating the follow-up as done.

Structured Claude `AskUserQuestion` and Codex `request_user_input` requests
appear as question cards in Paseo. `agentbox questions ID` returns their exact
request IDs and answer keys. Use `agentbox answer ID REQUEST_ID --answers JSON`
with a JSON object mapping **every returned key** to a non-empty answer string.
Claude keys are full question text; Codex keys are question headers. For a
multi-select question, use the harness's comma-separated answer convention.
Inspect `questions` rather than guessing keys or using request-ID prefixes.

The trusted host adapter re-fetches the worker, checks its exact identity,
parent, provider and workspace, and permits only those two question tools with
`kind: question`. It never grants command/file approvals, accepts `ExitPlanMode`,
changes a worker's policy or forwards arbitrary permission input. Other pending
requests appear under `blockedPermissions` and need human review. `send` refuses
workers with any pending requests; use the question-specific route when needed.
The adapter uses the installed Paseo CLI's native client module (tested with
0.16.2); upgrading Paseo requires checking this private module integration.

These operations are restricted to the manager's own live, unarchived workers.
They do not automatically notify or wake the manager: the manager must poll
`wait` / `logs` / `questions`, decide an answer from its task, or ask the user.
An answer can direct actions already allowed by the worker's profile; it does
not itself expand the sandbox's access.

`send` and `answer` use generated delivery request UUIDs and durable receipts.
Reuse `--request-id UUID` with the **identical** request after a connection
failure to avoid sending it twice. `delivery_unconfirmed` means delivery may
have happened; replaying that UUID reports the uncertainty and never resends.
Inspect logs/questions before deciding whether a new request is needed. No
exactly-once guarantee is claimed across an uncertain upstream failure.

## Security boundaries

Credentials intentionally delivered through `vaultPathToEnv` remain readable
by their worker and Docker/host administrators. Reserved environment names
cannot change the host Docker client's loader/context/runtime settings.
Multiline values, CRLF and trailing newlines are preserved; NUL is rejected.
Ending a container does not revoke an already copied static service token.

`publicExceptPrivate` allows general public egress, not just model APIs.
`denyAll` allows only its explicit IP/port and DNS exceptions. Domain filters
need a separately enforced proxy/resolver and are not implemented here. The
runtime disables IPv6 and checks a root-owned network-readiness revision/hash.
A firewall rule update preserves established connections; apply requires
managed runtimes to close/drain before adopting changed policy. Unrelated
manual firewall changes require revalidation; a readiness file is not proof
against a privileged host administrator changing rules afterward.

The host Paseo daemon/plugins/Git operations, Docker/kernel, operator and
launcher remain trusted. Normal host agents deliberately retain their normal
host-account access. Workspace path checks are not FD-pinned protection
against hostile concurrent mount-source replacement. Worktree metadata can
expose shared Git refs/objects within the mounted repository. This release
is a personal development-lab integration, not multi-tenant hostile-code isolation.
