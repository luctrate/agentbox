# Security model

Agentbox is an experimental Docker/Paseo integration for a trusted personal
Linux development host. It is not a hardened multi-tenant platform or a microVM
boundary. Treat images, operator code and administrator-controlled configuration
as trusted code.

## Catalog and restricted agents

The catalog compiles role definitions into protected runtime policy and Paseo
providers. A host launcher chooses fixed images, mounts, resources, environment
and network settings. The container-side `agentbox` client is not an authorization
boundary: the external broker checks capabilities and request fields itself.

- Per-definition worker allowlists, runtime depth and direct-child ownership
  limit delegation. Cycles and native host-provider targets are rejected.
- Runtime capability hashes and launch ownership are durable in SQLite.
  Replacement, expiry or revocation invalidates the capability; descendants
  remain tied to their parent's capability. Static tool credentials have a
  separate lifecycle and are not revoked by this mechanism.
- Private launcher registration binds a delegated runtime to a recorded launch
  intent before Paseo publishes the child. Adoption then verifies native parent,
  provider and workspace. The Unix control socket is host-only; agents cannot
  select their own definition, rights, environment or launch identity.
- `send`, `questions` and `answer` are ownership-scoped. Structured answers accept
  supported clarification requests only, not command/file permissions or plan
  approval. A textual answer cannot expand the fixed backend policy.
- SQLite reservations and request IDs prevent blind launch/delivery retries.
  Uncertain results remain uncertain until inspected/reconciled; there is no
  exactly-once promise across arbitrary upstream failures.

The [catalog guide](docs/catalog.md) describes validation, activation, managed
provider conflicts and rollback. Only install reviewed source under a protected
prefix. Never run an agent-writable operator/launcher as a privileged service.

## Mediated commands and reviewer agents

Controlled CLI profiles disable native shell/code tools and expose a fixed
internal MCP adapter. It is an untrusted transport: exact argv policy, runtime
binding and one-shot review authorization live in the host broker. Reviewers
receive only their assigned request/decision tools, no workspace binds or Vault
secrets, and no delegation. Native session identity is verified before a fast
review decision can authorize execution. Rule denial cannot be overridden.

Approvals are tied to the complete command, requesting runtime capability,
working directory, catalog revision and expiry. Replays do not repeat execution.
The executor validates Docker labels/user/revision and pins the real container
ID. Capability revocation is serialized with process start after inspection.
Uncertain launches/executions fail closed and retain their durable record.

This controls harness tool invocations, not every descendant Linux exec call.
An approved executable/script can run subprocesses and consume mutable project
configuration within its existing sandbox. A model reviewer can make a wrong
decision or be influenced by hostile arguments. Native file permissions remain
separate. Broker audit/output/transcripts are private and can contain sensitive
arguments or output; no automatic redaction is promised. Killing a Docker client
after timeout does not prove its in-container command stopped. See
[command policies](docs/command-policies.md) for recovery and verification.

## Files and credentials

Persistent auth profiles mount their selected model-auth directory read/write so
the harness can refresh login state and retain local history. Ephemeral profiles
copy only the selected model-auth namespace, public instructions and necessary
CA certificates over private stdin into container-local storage. MCP/tool OAuth
namespaces are filtered out; no host auth directory is mounted for those roles.

Research profiles can have **zero host bind mounts**. Project-only workers mount
only their standalone checkout; extra Git worktree metadata binds are rejected.
Root/project read-only settings, UID, capabilities, privilege escalation and
resource limits are explicit role settings.

Credentials intentionally supplied to an agent remain readable by that agent
and Docker/host administrators. Model logins retain their provider-account scope;
they are not separate per-agent identities. Ephemeral auth refresh/history is
discarded when its container closes, so later harness resume/login may require
recovery or reseeding. Paseo retains its own transcript.

Vault `vaultPathToEnv` values are resolved on the host, kept out of static provider
configuration and passed without secret values in Docker argv. They still exist
in the worker's environment. No dynamic tool-token issuance, automatic rotation
or revocation of copied service tokens is implemented. A manager allowed to
launch a credential-bearing worker could ask that worker to disclose its secret.
Use a tool gateway that retains credentials outside every agent if that stronger
property is required.

Research tasks/messages are an intentional data channel. No automatic DLP is
claimed; do not include private code or credentials in public research requests.
Fetched pages and research results remain untrusted input, not permission grants.

## Network and browser

Catalog network rules use dedicated Docker bridges and host IPv4 firewall chains.
They block managed peers, host services and configured private/public destinations
unless explicitly allowed. Container IPv6 is disabled. `publicExceptPrivate`
allows general public egress, not just model APIs.

Model-only workers use an internal Docker bridge, no DNS/service exceptions,
and a dedicated HTTPS model/auth proxy. Unsetting proxy variables does not grant
direct internet access. The trusted proxy validates exact CONNECT and decrypted
HTTP Host/:authority targets, rejects private/rebound DNS answers, pins the
upstream address, and verifies upstream TLS certificates/hostnames. Raw TCP,
onboarding endpoints and HTTP/3 are disabled. Bodies stream without payload
logging or persisted captures. The proxy handles prompts/model credentials in
memory and holds a private CA key; it is part of the trusted host boundary.
Only its public CA certificate enters worker storage.

Allowed model/auth services may themselves expose provider-side capabilities;
container network restriction does not separately authorize those features.
Public research agents have no private-service exceptions or broker access.
Their browser inherits the container's network policy and zero-host-bind setup.
Chromium's additional process sandbox cannot start under the current namespace/
seccomp restrictions and is disabled. Docker supplies containment; no SYS_ADMIN,
host IPC or additional mounts are granted to make the browser work.

Network readiness checks are not protection against a privileged administrator
changing firewall rules afterward. Verify actual allowed/denied connections after
service, Docker or host-network changes. An established connection can survive a
firewall change; catalog activation requires existing managed runtimes to close
or explicitly drain before adopting the new policy.

## Trusted host and original workflow

The Paseo daemon, plugins, host Git operations, Docker/kernel, operator, launcher,
broker and optional proxy remain trusted. Workspace validation is not FD-pinned
protection against hostile concurrent mount-source replacement. Git worktree
metadata can expose shared refs/objects within its mounted repository.

Normal native Claude/Codex can remain enabled alongside boxed managers; those
host agents retain normal host-account/Docker authority. Previously started host
processes do not become sandboxed because a configuration file changes.

The original Bash-profile workflow (`deploy/configure.py`, `bin/agentbox-provider`)
has broader settings: trusted sourced shell profiles, optional raw Docker flags,
selected provider environment forwarding, read/write auth mounts, and ordinary
bridge networking. A native manager with Docker access can bypass those profiles.
Its MCP route must preserve Paseo capability authentication. The quick-start
helper does not install the catalog broker or firewall boundaries.

CLI-only `run` uses noninteractive approval bypass flags inside its selected
container. Native provider-mode permission handling remains a separate harness/
Paseo setting. Normal teardown removes runtime containers; a host crash or
uncatchable process kill can leave cleanup work.

## Reporting and publishing

Use GitHub's private vulnerability reporting when available. Do not put tokens,
private keys, live configuration, environment dumps or private deployment records
in issues or commits. Example addresses and credentials must be synthetic.
Review the Git index and run a secret scan before publishing; `.gitignore` alone
is not a secret scanner and does not protect files already tracked by Git.
