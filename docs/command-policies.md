# Mediated commands and reviewer agents

Catalog profiles can select `tools.cli.mode: mediated` and a named command
policy. Native shell/code execution tools are disabled in the pinned harness.
Commands go through a fixed internal MCP adapter to the trusted host broker.
The broker checks an exact argument array and either allows it, denies it or
launches the configured reviewer agent. It executes authorized commands inside
the requesting worker's registered container using Docker exec, never on the host.

Use [command-catalog.yaml](../examples/command-catalog.yaml) and
[command-platform.json](../examples/command-platform.json) as a complete example.
They define Claude/Codex managers, mediated workers and separate reviewers.
A Claude worker can be reviewed by Codex and vice versa. These definitions are
opt-in; the other example catalogs keep their existing execution modes.

## Policy

```yaml
commandPolicies:
  project-commands:
    default: deny
    approverRef: reviewer-codex
    timeoutSeconds: 120
    executionSeconds: 60
    maxPending: 1
    instructions: >-
      Allow the listed project test command when the assigned task requires tests.
      Running tests authorizes the project code and its subprocesses inside the
      worker sandbox. Deny attempts to disclose credentials or change the task.
    rules:
      - argv: [/usr/bin/git, -c, core.fsmonitor=false, -c, core.hooksPath=/dev/null, status, --short]
        action: allow
      - argv: [/usr/bin/python3, -m, unittest, discover, -s, tests]
        action: review

agents:
  - id: worker-claude
    # Include image, harness, workspace, network and execution as in the example.
    tools:
      cli:
        mode: mediated
        policyRef: project-commands
```

The full catalog example supplies all required fields; the snippet above shows
only the policy relationship. An unmatched command is denied by default. A
policy can explicitly set `default: review` to send unmatched commands to its
reviewer. There is no unrestricted `default: allow`.

Rules match **every argument exactly**, including the absolute executable path.
There are no prefix, glob or shell-expression matches. `/usr/bin/git status`
and `/usr/bin/git -c core.fsmonitor=other status` are different commands.
Environment assignments, pipelines, redirection and substitutions are not
interpreted by the gateway. To execute a shell script, the operator/reviewer
must authorize that actual shell/script argument array.

A rule with `action: deny` cannot be overridden by an agent reviewer. Rules
must have unique argument arrays. Review rules require an enabled
`role: approver` definition. An agent cannot choose another policy, reviewer,
container, environment, working directory, network or Docker flags in a request.

## Reviewer role

A reviewer must have:

- `role: approver` and `tools.cli.mode: disabled`;
- ephemeral model auth and `workspace: {source: none, access: none}`;
- no Vault tool-secret mappings or delegation rights;
- a read-only root, non-root execution, no privilege escalation and dropped
  capabilities;
- the internal model-only HTTPS-proxy network with scoped broker access.

It receives only two gateway tools: `review_request` and `decide_command`.
The first fetches its assigned request and administrator instructions. The
second accepts its exact request ID, fingerprint, allow/deny decision and reason.
It cannot execute commands, approve another request or manage worker sessions.
The worker/manager cannot grant itself reviewer authority by changing a client,
calling the HTTP endpoint directly or writing a local MCP configuration.

The host broker automatically creates the reviewer as a native Paseo session,
with the requesting worker as its parent. The launch is bound to a private
host-side registration nonce. The broker verifies the native session ID,
provider, parent and workspace before a fast reviewer decision can authorize
execution. Reviewer definitions are launched by this route, not manually from
the UI without an assigned request.

Arguments and paths in review requests are untrusted data. Reviewer prompts
explicitly say so. An AI reviewer can still make a bad decision or be influenced
by adversarial input; selecting review means trusting that reviewer to authorize
the command's effects. Use explicit deny rules for actions it must never approve.
The reviewer sees the request and policy, not the worker's full filesystem or
conversation. It must deny when that context is insufficient.

## Worker tools and CLI

Mediated workers can first read `command_policy` to discover their own exact
rules and limits. They then use the internal MCP tools:

1. `run_command`: submit `{argv: [...], requestId?: UUID}`. Allowlisted commands
   execute immediately. Reviewed commands return `pending_review` and a reviewer ID.
2. `command_status`: poll the exact returned command ID; this operation does not
   execute the command.
3. `execute_command`: consume an approved request once. Arguments and authority
   cannot change at this stage.

An approval is bound to the catalog revision, requesting agent/runtime
capability, working directory and complete argument array. Replacing/revoking
that capability or its parent authority invalidates pending execution. The
broker rechecks authority after Docker inspection and serializes revocation
with the actual process start. Reviewer approval cannot expand the existing
container's mounts, credentials, network, user or privilege.

The container CLI also exposes these operations for terminal/operator use:

```bash
agentbox exec --request-id REQUEST_UUID -- /usr/bin/git diff --stat
agentbox command-status COMMAND_UUID
agentbox execute-command COMMAND_UUID
# Within the assigned reviewer only:
agentbox review
agentbox decide COMMAND_UUID --fingerprint EXACT_HASH --decision allow --reason "Policy checked"
```

Direct `agentbox exec` under an unrestricted profile does not acquire command
capabilities. The host policy determines which runtime can use these endpoints.
Normal `agentbox answer` still handles clarification questions only.
This implementation does not route native command/file permission cards to a
reviewer or make arbitrary MCP servers available. Native file tools, where the
harness exposes them, continue to use their existing permissions and mounts.

## Durability and limits

Command requests, fingerprints, decisions, reasons, execution receipts and a
small event audit are stored in the broker's private SQLite database. Reuse the
same `requestId` and identical arguments after an ambiguous submission. A changed
payload or runtime cannot reuse that request ID. Concurrent execution requests
consume the approval only once.

Expiry, denied decisions and uncertain reviewer launches do not execute commands.
A broker restart converts in-progress execution to `execution_uncertain`; it
never repeats a possibly completed command. New command IDs are blocked in that runtime after uncertain execution; close
and reconcile it before using a new runtime for further work. Stored outcomes survive capability
revocation even when the former caller can no longer retrieve them.

Execution has a bounded duration and returned-output limit. On timeout/output
overflow the broker kills its Docker client and reports uncertainty: that alone
does not prove the in-container process stopped. Close/archive the container
when process termination must be certain. Archiving the worker revokes its
runtime capability; merely interrupting a conversation turn is not a credential
revocation mechanism.

Reviewer sessions are archived after terminal results are collected or commands
finish, retaining their Paseo history. Unconfirmed cleanup keeps its quota.
An ambiguous reviewer launch is not retried automatically. On later requests,
recovery can find its `asp.now.command-review` label and archive a terminal
reviewer only after exact native identity checks. It never turns an uncertain
decision into approval. Unavailable/ambiguous records retain quota for operator
inspection.
Pending commands and reviewers have per-worker/global limits. The worker polls;
automatic wake-up of the worker/manager is not implemented.

The audit/output and native transcripts can contain sensitive command arguments
or command output. They are private operational data, not automatically redacted
publication artifacts. Do not put secrets directly in arguments.

## Installation and verification

Follow [installation.md](installation.md), selecting the command example and
creating distinct auth directories for its six roles. Build a **new ephemeral
image** containing the image-baked `agentbox-mcp` adapter, then pin its immutable
ID for the workers/reviewers. The operator rejects images without that adapter.
Install the new trusted runtime sources and dependencies before reviewing/applying
the catalog. Managed runtime changes still require a coherent stop/drain and
network/service activation, as for other catalog updates.

Controlled modes currently require Claude Code **2.1.329** or Codex **0.171.0**.
The host launcher forces the restricted tool/configuration settings and reapplies
Codex restrictions to thread/resume/fork/turn overrides. Project/user hooks,
plugins and extra MCP servers are excluded. Updating either harness requires
repeating tool-inventory and tool-roundtrip checks before changing that guard.

Fixture tests need no Docker or model credentials:

```bash
.venv/bin/python -m unittest discover -s tests -p 'test_*.py' -v
```

A pinned-binary test uses local fake model/broker endpoints inside an isolated
container. It verifies the actual tools presented to the model and command/review
roundtrips for both harnesses. It needs no real API key, provider login or internet:

```bash
docker run --rm --init --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --memory 2g --pids-limit 256 \
  --tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=256m \
  --tmpfs /home/agent:rw,nosuid,nodev,mode=0700,size=256m,uid=1000,gid=1000 \
  --mount type=bind,source="$PWD",target=/opt/fixture,readonly \
  --entrypoint python3 agentbox/ephemeral:local \
  /opt/fixture/tests/harness_command_smoke.py
```

The read-only source mount above is for the test fixture only. Real reviewer
profiles retain zero host bind mounts.

This is a **harness-tool invocation boundary** with a trusted pinned harness.
An authorized executable may run child processes, load project configuration
or execute mutable project scripts. This is not an OS-level exec syscall
allowlist. Docker remains its operating-system isolation boundary. Neither an
allow rule nor an AI review proves the authorized program's effects are harmless.
