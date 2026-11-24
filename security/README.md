# Restricted managers

The recommended configuration path is now the [ASP catalog controller](../docs/catalog.md).
Use the [installation guide](../docs/installation.md) for the complete setup.
The catalog compiles protected role/network/delegation plans; the architecture
and bootstrap requirements below still apply.

The optional [research/model-only profiles](../docs/research-workers.md) add
ephemeral authentication without host auth mounts, unshared research containers,
a dedicated HTTPS egress proxy and bounded worker-to-research delegation.

The original `bin/agentbox-provider` integration provides scoped development
containers. It leaves the native manager running on its host account. The
optional implementation in this directory adds a different deployment mode:
**every manager runs in a container, without the Docker socket or Vault access**.
It is not enabled by `deploy/configure.py`. That helper remains the original
integration recipe. A restricted deployment requires a trusted administrator
to install the policy, system services, role authentication and firewall.

## Components

- `provider.py`: trusted, fixed-role launcher. It reads an administrator-owned
  `/etc/agentbox/security.json`, constructs Docker arguments itself, discards
  request-supplied host environment, and mounts only an allowed workspace and
  any validated worktree Git common directory. Managers get read-only project
  mounts, a read-only root filesystem, dropped capabilities and no-new-privileges.
- `broker.py`: authenticated, narrow HTTP service for manager delegation. A
  private Unix socket registers runtime capabilities; registration is never
  exposed over HTTP. Manager capabilities expire after 24 hours and are revoked
  when the runtime closes. A new runtime invalidates that manager's old token.
  Child ownership survives broker restarts. Tokens are stored as hashes.
- `client.py`: container-side `agentbox` command. Supports `profiles`, `spawn`,
  `status`, `logs`, `wait`, `send`, `questions`, `answer`, `stop` and `archive`. It cannot change profiles,
  choose arbitrary mounts/env/commands, request arbitrary Vault paths or
  approve a worker's permissions.
- `paseo-messaging.mjs`: trusted host adapter for follow-ups and structured
  clarification answers. It uses the installed Paseo CLI's native client,
  validates exact ownership/context and pending request type, and never
  exposes general permission approvals. See [worker clarification](../docs/catalog.md#worker-clarification-and-follow-up).
- `network.py`: administrator-run Docker bridge and IPv4 firewall setup.
  Managers can reach the broker and public destinations, but not private,
  loopback, link-local/metadata or configured host-public destinations. Workers
  get an explicit private-service allowlist. IPv6 is disabled in containers.

The broker starts children through the native Paseo CLI with fixed provider
IDs and the manager's parent/workspace context. Workers remain visible in Paseo.
Paseo itself stays trusted; managers do not receive the daemon password or its
unrestricted MCP capability. Disable automatic Paseo MCP injection for this
mode and block direct container access to the daemon/UI.

## Deployment requirements

This directory is a reference implementation, not a fresh-host installer.
The current `Backend` expects `/usr/bin/paseo`, the host home `/home/paseo`,
and local daemon access for that account. Adapt these administrator-controlled
paths if deploying elsewhere. The launcher can use policy `host_home`, `uid`
and `gid`; Vault is invoked at `/usr/local/bin/vault`.

1. Copy the runtime code to a root-owned, agent-immutable directory outside
   all workspace mounts. Protect its parents, policy, services and auth seeds.
   A development checkout can remain writable; it must not be the live launcher.
2. Create separate model-auth/history directories for manager and worker
   roles. Seed only the required model login file, not the host's complete
   Claude/Codex config, settings, plugins, instructions or session history.
   Set each Paseo provider's `CLAUDE_CONFIG_DIR` / `CODEX_HOME` to its role path.
   The role auth directory is writable inside that role's container so upstream
   CLIs can refresh tokens and persist history. Keep it separate from Vault
   credentials and the host's native CLI configuration.
3. Define immutable roles: agent, image digest, auth path, network, manager flag,
   optional container-local sudo, fixed environment/host mappings and optional
   Vault references. The manager roles must contain no Vault secret references.
4. Install bridges/firewall using a root-only oneshot service after Docker,
   then run the broker under a trusted host account with its state directory
   and private control socket. Order the Paseo service after these services.
   Treat a firewall reload or Docker networking change as a policy change and
   reverify the chains. Do not silently fall back to unrestricted networking.
5. Expose fixed container-role providers. For a fully restricted deployment,
   override or disable the built-in native `claude` and `codex` providers too.
   In mixed mode, retain those native providers only for trusted host work;
   they are outside this boundary. Apply restrictions to API launches too;
   hiding a provider in the UI is insufficient.
6. Turn off `daemon.mcp.injectIntoAgents` for these containers. Do not pass a
   full Paseo CLI login/password or an unrestricted agent MCP capability into
   managers. Their only delegation interface is the scoped broker client.
7. Archive any existing native host-manager runtimes and restart Paseo after
   the configuration cutover. A previously started host process does not become
   sandboxed merely because a config file changed. Preserve its history.

Paseo 0.16.2 starts unscoped model/auth probes before dedicated agent processes.
Those probes are handled without project mounts, worker secrets or broker
capabilities. Dedicated processes receive their scope from `PASEO_AGENT_ID`
and `PASEO_AGENT_CWD`, not from the server process's current directory.

The policy must define `roots`, `roles`, `networks`, `control_socket`, broker
`listen`/`port`/`broker_url`, `client`, `state`, Vault connection/CA fields,
optional CA mounts/environment, `worker_private_access`, `deny_public_ips` and
`max_workers`. Read the source before adapting this mode. Keep real deployment
policies and all generated credentials out of Git. Existing model logins may
need refresh/re-authentication when seeding separate role directories; do not
assume copied OAuth refresh state can be shared indefinitely without care.

## Mixed normal and restricted providers

You can retain native `claude` and `codex` providers for trusted host work and
expose custom `manager-claude` / `manager-codex` providers extending those
engines, each with the fixed restricted launcher command and its own role auth
path. In that mode the normal agents intentionally retain host-account access;
the container restrictions apply only to the explicitly selected managers.
Keep the broker's profile mapping restricted to container workers. Do not add
native host providers to its allowlist or give boxed managers full daemon
credentials. Provider restrictions must be enforced on API creation paths too.

## Behavior and limits

Managers orchestrate; workers edit. A manager sees only its current workspace,
read-only. Worker profiles receive that workspace read-write. Separate
worktrees must already exist for concurrent edits: this broker does not offer
host-side Git checkout/worktree commands.

The broker accepts only fixed profile names and a task. Status/logs/stop/archive
are scoped to its recorded children. It does not accept environment variables,
Docker flags, provider overrides, cwd overrides, Vault paths or permission grants.
The default limit is eight unarchived workers across managers. Archive completed
workers to release both their container and quota.

Model-provider credentials still exist inside a manager's role auth directory;
this mode hides Vault/host credentials, not the model login needed to run it.
The basic manager/worker networks allow public internet egress. The optional
model-only profiles instead require the dedicated HTTPS proxy described in
[research workers](../docs/research-workers.md). Docker remains the isolation
boundary; this is not a microVM or production multi-tenant platform.

A manager allowed to delegate to a credential-bearing worker has that worker's
operational authority. It could ask the worker to reveal a credential and read
its response. This broker **does not guarantee secret values remain unknown
to that manager**. Use a tool gateway that retains credentials outside every
agent if that stronger requirement matters.

The trusted host daemon, plugins, Docker/kernel and launcher still form part
of the trusted computing base. This mode does not move all Paseo host operations
into an independently sandboxed control plane. In particular, do not treat
writable repositories, Git metadata or native host Git/plugin processing as
safe for hostile multi-tenant input. Keep the trusted host account and its
operations within the trust assumptions of a personal development lab.

## Verify changes

```bash
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Fixture tests cover disallowed overrides, worker ownership, capability
revocation, persistent state/quota, symlink/worktree escapes and manager mount
and environment restrictions. They do not prove a deployed firewall works.
For a deployment, test actual manager containers for denied host/Docker/Vault
access, read-only project mounts, private-network denial, rejected arbitrary
broker fields, permitted model calls, and successful delegation by both
providers. Repeat those checks after a service restart. Never print secrets
or dump container environments into transcripts while testing.
