# Profiles, tools and secrets

Profiles are trusted Bash files loaded by name. Search order: explicit
`AGENTBOX_PROFILE_DIR`, existing `${XDG_CONFIG_HOME:-$HOME/.config}/agentbox/profiles`,
then this repository's `profiles/`. A name selects a fixed file, not an arbitrary
caller-supplied Docker command. This is a configuration convention, not a
security boundary against a host-shell manager.

```bash
DESC="Codex project worker"
IMAGE=agentbox/base:latest
AGENT=codex                 # claude | codex
PRIVILEGE=none             # none | sudo | root
NETWORK=bridge
PASEO_PROVIDER=codex-box    # required by spawn; must match Paseo config
MOUNTS=("$HOME/projects" "$HOME/worktrees")
RO_MOUNTS=()
WORKDIR=""                 # run: defaults to first mount; spawn: caller cwd
AUTH_VOLUME=""             # CLI-only auth mount; default agentbox-<agent>-shared
VAULT_SECRETS=()            # e.g. "GITLAB_TOKEN=secret/agentbox/gitlab#token"
PASS_ENV=()                 # explicitly inherited host environment names
STATIC_ENV=()               # e.g. "GITLAB_HOST=gitlab.example.com"
DOCKER_EXTRA=()             # trusted raw Docker flags
```

Provider mode uses `CLAUDE_CONFIG_DIR` or `CODEX_HOME` from the provider's
environment and mounts it at the same absolute path. CLI-only mode uses
`AUTH_VOLUME` mounted under `/home/agent` instead. The setup helper sets an
auth directory suitable for each profile; do not mistake the two modes.

## Privilege

| Tier | Runtime |
| --- | --- |
| `none` | Non-root image user; no sudo in base |
| `sudo` | Non-root with passwordless sudo inside an appropriate sudo image |
| `root` | UID 0; Claude receives `IS_SANDBOX=1` |

Prefer `none`; select `sudo` when installing a missing build dependency is
part of the task. Root provider mode is not live-verified and is not generated
by the setup helper. Container UID 0 and Docker host privileges are different;
raw flags such as `--privileged` or mounting the Docker socket can undermine
that separation. Do not add them by default.

## Vault and GitLab

Authenticate the **host's** Vault CLI using a suitably scoped token/AppRole.
The provider wrapper resolves `VAULT_SECRETS` before each container launch;
no Vault root token or Vault CLI is required inside workers.

```bash
python3 deploy/configure.py \
  --mount "$HOME/projects" --mount "$HOME/worktrees" \
  --gitlab-host gitlab.example.com \
  --gitlab-vault-ref 'secret/agentbox/gitlab#token' --apply
paseo reload
agentbox spawn --detach gitlab-codex "Inspect the project's open issues"
```

The referenced Vault field must already exist and contain an appropriately
scoped GitLab token. The helper never creates a token or writes a secret.
The generated GitLab profiles include `glab`, `git` and `GITLAB_TOKEN` at
launch. `glab api user | jq -r .username` works with the Debian version that
lacks `--jq`. Git HTTPS uses a credential helper restricted to the configured
HTTPS hostname; it does not return that token for another host.

Vault reads fail closed: no container starts if a required read fails.
Multiline values are supported. Values are exported in the Docker client's
environment and Docker gets `--env NAME`, not `--env NAME=value`, for profile
secrets. This avoids putting those values into argv and static Paseo config;
it does not hide them from the worker, a host administrator or Docker inspect.
Do not enable shell tracing or ask a worker to dump its environment.

## Networks

`NETWORK=bridge` normally permits outbound Internet access, including provider
APIs, subject to host routing/firewalls. `none`, `host`, or a named network
are accepted Docker network choices. `none` prevents normal model API and
Paseo MCP access, so it is not a usable default for these provider sessions.
Network policy/egress filtering and separation of research versus internal
tools are outside this implementation.

## CLI-only mode

This mode does not require Paseo and does not create UI sessions:

```bash
export PATH="$PWD/bin:$PATH"
# Select the repository examples instead of previously generated profiles.
export AGENTBOX_PROFILE_DIR="$PWD/profiles"
agentbox build base
agentbox login scratch
agentbox login scratch-codex
agentbox run scratch "Explain what tools are installed"
agentbox run --detach scratch-codex "Review the available tools"
agentbox logs CONTAINER_NAME
agentbox clean
```

The final answer is stdout and diagnostics/transcript are stderr. CLI-only
runs deliberately bypass the CLIs' interactive approval/sandbox checks and
rely on Docker and the profile's scope: use them only for tasks that have
already been authorized. Provider mode retains Paseo permission handling.
Detached CLI-only runs keep exited containers so their logs remain available;
`clean` removes finished `agentbox-*` containers. Provider containers are
removed on normal runtime teardown instead.

The included `node` example expects `$HOME/projects`; the DNS example has
placeholder Vault and GCP references. Adapt them before use. The gcloud init
hook writes a credential file with mode 0600 and unsets the raw JSON env var;
the worker can still read that file.

## Image versions

The base Dockerfile pins `CLAUDE_VERSION` and `CODEX_VERSION` as exact npm
versions. All derived images inherit them and their image labels. Claude's
auto-updater is disabled; explicit manual changes inside a writable running
container are still possible. Rebuilding updates future sessions, not already
running containers.

Change the defaults in `images/base/Dockerfile`, then rebuild the base and
all child images you use. For an experimental version, build the base with
explicit `--build-arg CLAUDE_VERSION=... --build-arg CODEX_VERSION=...` and the
correct `AGENT_UID`/`AGENT_GID`, then rebuild its children. Verify compatibility
with Paseo's installed SDK before adopting new versions.

These are agent-version pins, not fully reproducible OS images: the Node
base tag, apt packages, gcloud and optional nvm/Node installation can change.
