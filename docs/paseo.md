# Integrating with Paseo

## Host requirements

Use a native Linux Paseo daemon and Docker on the same host, running as the
same regular user. Do not run the daemon inside a container for this recipe:
that would additionally require Docker access and path translation, neither
of which is configured by this project.

Authenticate the native Claude and Codex CLIs first. The provider wrapper
uses `~/.claude` or `~/.codex` at the identical path inside its container.
Paseo needs to see the history those CLIs write. It must be able to execute
Docker, Python 3 and `bin/agentbox-provider`.

Build images using the Paseo user's UID/GID (`agentbox build base` handles
this on Linux). The image's default user is UID 1000. If you use another UID,
rebuild rather than assuming a runtime UID override creates a matching home
or sudo-group membership. Run the build as a regular user, not through sudo.

## Generate profiles and providers

From the repository:

```bash
python3 deploy/configure.py \
  --mount "$HOME/projects" --mount "$HOME/worktrees"
cat "$HOME/.config/agentbox/providers.json"
```

The paths must already exist. This writes `claude.sh`, `codex.sh` and
`providers.json` under `~/.config/agentbox`, with owner-only permissions.
Other options include `--with-node`, `--gitlab-host`, `--gitlab-vault-ref`,
`--claude-config`, `--codex-home`, `--output`, `--mcp-host`, and `--paseo-config`.
Use `--help` for details. No secret values are read by this helper.

When ready, repeat with `--apply`. The helper backs up the existing config,
merges generated providers, preserves other fields and enables
`daemon.mcp.injectIntoAgents`. It refuses to replace an unrelated custom
profile or provider. Backups may include existing credentials; keep them
private. Run `paseo reload` afterward; no automatic restart is performed.

For manual configuration, merge a provider like this into your existing
config. Replace all paths with your own absolute paths, then add an analogous
`claude-box` entry with `extends: "claude"` and profile `claude`.

```json
{
  "daemon": { "mcp": { "injectIntoAgents": true } },
  "agents": {
    "providers": {
      "codex-box": {
        "extends": "codex",
        "label": "Codex (container)",
        "command": ["/home/you/agentbox/bin/agentbox-provider", "--profile", "codex"],
        "env": {
          "AGENTBOX_PROFILE_DIR": "/home/you/.config/agentbox/profiles",
          "AGENTBOX_DAEMON_HOST": "host.docker.internal",
          "CODEX_HOME": "/home/you/.codex"
        },
        "options": {
          "sandbox_mode": "danger-full-access",
          "approval_policy": "on-request"
        }
      }
    }
  }
}
```

Codex's setting uses Docker as the outer process/filesystem boundary instead
of requiring nested bubblewrap. Provider permission requests still flow
through Paseo. It does not make Docker a hardened security boundary.

## Make Paseo's MCP endpoint reachable

The provider wrapper rewrites loopback `/mcp/agents` URLs to
`host.docker.internal`, preserving their capability headers. On Linux it adds
Docker's `host-gateway` mapping. This **does not make a host loopback listener
reachable by itself**: a proxy or a suitable existing listener is required.

A narrow setup keeps Paseo on `127.0.0.1:6767` and proxies only its MCP route
on the Docker bridge gateway. Find that address on your host:

```bash
docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}'
```

For example, if the result is `172.17.0.1`, add this to your existing Caddy
configuration. Replace both the bridge IP and daemon port when necessary.
Do not replace your existing UI routes or authentication configuration.

```caddyfile
http://host.docker.internal:6767 {
    bind 172.17.0.1
    handle /mcp/agents* {
        reverse_proxy 127.0.0.1:6767 {
            header_up Host 127.0.0.1:6767
        }
    }
    handle {
        respond "Not found" 404
    }
}
```

Validate and reload Caddy using your installation's normal process. If Caddy
starts before Docker creates the bridge, give its service an `After=` and
`Requires=docker.service` dependency or otherwise ensure that address exists
before Caddy binds it. Your host firewall must permit container access to this
bridge listener; keep it off public interfaces. Custom networks and rootless
Docker may require a different host route/address.

An unauthenticated request to `/mcp/agents` should receive `401`; an unrelated
path should receive `404`. Never remove capability authentication to make a
worker connect. If a different proxy port is used, generate providers with
`--mcp-host host.docker.internal:YOUR_PORT`. The wrapper rewrites Claude's MCP
config in argv and Codex's MCP URLs in stdin JSON-RPC without changing prose.

## Expose the command to manager agents

Add this repository's `bin` to the **daemon's** `PATH`, not just your interactive
shell's PATH, or install a wrapper in a directory already on that PATH. A
systemd environment change generally needs a service restart; plan around
active sessions. Provider definitions use absolute wrapper paths already.

If you use the default generated profile directory, `agentbox` discovers it.
For a custom `--output`, set `AGENTBOX_PROFILE_DIR=/absolute/output/profiles`
in the daemon environment too. Copy the guidance in
[manager-instructions.md](manager-instructions.md) into your existing
`~/.claude/CLAUDE.md` and `~/.codex/AGENTS.md`, preserving their other content.
New sessions may be needed to pick up those instructions.

```bash
cd "$HOME/projects/YOUR_REPOSITORY"
agentbox spawn --detach claude "Read README.md and explain the project"
agentbox spawn --detach codex "Review the tests without changing files"
agentbox ps
```

Workers should appear with `[box:PROFILE]` titles. Manager launches inherit
the caller's workspace and parent context. Use `status`, `logs`, or the UI
for permission requests. `stop` interrupts; `archive` releases the runtime.

## Worktrees and parallel edits

Mount both the main checkout's parent and the worktree parent at their exact
host paths. A worktree's `.git` file contains an absolute pointer into the
main checkout. Mounting only the worktree will break Git.

Use a separate worktree per concurrent editing task. `agentbox spawn` reuses
the caller's workspace; it does **not** automatically create an isolated branch.
You can create a dedicated worktree through Paseo or its CLI:

```bash
paseo run --provider codex-box --new-workspace worktree \
  --new-branch agentbox/example --cwd "$HOME/projects/YOUR_REPOSITORY" \
  "Implement the requested change in this worktree"
```

## Private certificate authorities

If your GitLab, Vault or other tools use a private CA, trust it on the host
first. Add read-only CA mounts to the relevant profiles. One Linux example:

```bash
STATIC_ENV+=("NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/internal-ca.crt"
             "REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt")
DOCKER_EXTRA+=(--volume /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro
               --volume /usr/local/share/ca-certificates:/usr/local/share/ca-certificates:ro)
```

Adjust paths for your distribution. Do not mount private CA signing keys and
do not disable TLS verification. The host Vault CLI needs its own CA trust.

## Troubleshooting

- **No visible worker:** `agentbox run` is CLI-only. Use `spawn` with a profile
  whose `PASEO_PROVIDER` matches a configured provider.
- **Unknown profile/provider:** check generated paths, the daemon's environment
  and the result of `paseo reload`.
- **MCP connection refused:** check the bridge proxy, host-gateway mapping,
  port and firewall. A daemon bound only to loopback cannot be reached directly.
- **Missing history or invalid Git repo:** check identical absolute auth/repo
  paths and both sides of a worktree's pointer.
- **No GitLab authentication:** check host Vault access and run `agentbox doctor
  gitlab`. Never print the token while troubleshooting.
- **Idle container remains:** expected for resumable sessions. Archive it to
  release the runtime. `agentbox ps` maps containers to Paseo IDs.
- **Orphan after SIGKILL/crash:** normal teardown handles cleanup; an
  uncatchable kill may not. Inspect `agentbox ps` and remove only containers
  whose owning sessions are no longer in use.
- **New upstream CLI/Paseo version:** update deliberately and repeat native
  protocol, permissions, MCP, history and lifecycle checks. See CONTRIBUTING.
