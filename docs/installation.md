# Install the catalog runtime

This runbook targets an **existing native Linux Paseo/Docker host**. It does not
provision a VM, install Docker/Paseo, or authenticate provider accounts for you.
The original Bash workflow is documented separately in [paseo.md](paseo.md).

All paths below are examples, not a live deployment. Review the source and
bindings before running administrator commands. The service account is `paseo`
(UID/GID 1000 in the examples); adapt it, binary paths and unit names to your host.
Do not install trusted runtime code beneath any agent workspace mount.

## Prerequisites

- Native Paseo 0.16.2, Node 22 and working Claude/Codex authentication under the
  service account. A private/local Paseo endpoint and initialized CLI credentials
  must already work: run `paseo status --json` as that account.
- Docker with the iptables backend and `DOCKER-USER` chain, Python 3.12+ with venv,
  `iptables-save` / `iptables-restore`, and systemd system units. Docker access
  makes the host account trusted; never add agent containers to a host Docker socket.
- An existing `paseo.service` running as that account. If needed, adapt
  [paseo.service.example](../security/paseo.service.example), which uses the
  supported `paseo daemon run` foreground command. Do not run a competing user
  daemon and system service against the same Paseo home.
- Existing standalone project checkouts under your selected workspace roots.
  Ephemeral-auth project-only profiles reject extra Git worktree metadata binds.

Paseo stores daemon credentials/configuration outside this repository. Keep its
endpoint private and authenticated. Set `daemon.mcp.injectIntoAgents` to `false`
for the restricted/catalog workflow; the catalog operator preserves that setting
rather than changing it. The scoped delegation interface is the broker CLI.
Native host providers can remain enabled only when you intend their full host
account authority. Close active native turns before applying a catalog.

## Build images

Run Docker builds as the trusted host account from the reviewed repository root:

```bash
./bin/agentbox build base
docker build -f images/ephemeral/Dockerfile \
  --build-arg BASE=agentbox/base:latest -t agentbox/ephemeral:local .
docker build -f images/research-browser/Dockerfile \
  --build-arg BASE=agentbox/ephemeral:local -t agentbox/research-browser:local .

docker image inspect agentbox/base:latest --format '{{.Id}}'
docker image inspect agentbox/ephemeral:local --format '{{.Id}}'
docker image inspect agentbox/research-browser:local --format '{{.Id}}'
```

The harness versions are fixed in the base Dockerfile; Playwright and its core
package are pinned in the browser package lockfile. Record actual immutable image
IDs in your catalog: managers use base, offline workers use ephemeral, research
uses research-browser. The operator verifies harness versions and sudo metadata.
Building only the basic catalog does not require the two additional images.

## Install protected source and operator

After reviewing the repository, copy only the runtime source into a root-owned
prefix. These commands do not copy a Git history, workspace, login or private key:

```bash
sudo install -d -m 0755 /opt/agentbox
sudo cp -R agentbox_config deploy schemas security /opt/agentbox/
sudo install -m 0644 requirements.txt requirements-egress.txt /opt/agentbox/
sudo chown -R root:root /opt/agentbox
sudo chmod -R go-w /opt/agentbox
sudo chmod 0755 /opt/agentbox/security/*.py /opt/agentbox/deploy/catalog.py
sudo python3 -m venv /opt/agentbox/.venv
sudo /opt/agentbox/.venv/bin/pip install -r /opt/agentbox/requirements.txt
sudo install -m 0755 bin/agentbox-catalog /usr/local/sbin/agentbox-catalog
```

The wrapper has a fixed protected `/opt/agentbox` prefix. Adapt it before
installation if necessary. Use that installed operator for privileged apply;
`bin/agentbox catalog` in a development checkout is useful for validation/plan,
but an agent-writable checkout must not become a root execution path.

## Configure the catalog and host bindings

The research example defines both managers, both project-only workers and both
research workers. It exercises all current security/execution features without
injecting external-tool credentials:

```bash
sudo install -d -m 0755 /etc/agentbox/catalog
sudo install -m 0644 examples/research-catalog.yaml /etc/agentbox/catalog/agents.yaml
sudo install -m 0644 examples/research-platform.json /etc/agentbox/catalog/platform.json
```

Edit the installed copies to supply the image IDs from your builds and correct
UID/GID, service HOME, native Paseo binary, roots, auth references and service
paths. Never put credential values in either file. The source examples use zero
image IDs deliberately; replace every zero ID before activation.

Alternatively use `examples/catalog.yaml` and `examples/platform.json` for the
basic manager/worker/Vault example. Remove or adapt optional tool-secret mappings
before using it. Unlike the research example, its ordinary workers have general
public internet and its GitLab profile has an explicit private-service exception.

The research platform uses an internal model-only bridge at `172.29.42.0/24`.
Match the egress service listener to that binding. Choose non-overlapping bridges
and subnets that do not conflict with your existing host/VPN/container routes.
If containers could reach this host's public address, add it to `deny_public_ips`.

Create the broker's complete writable state directory, including SQLite journal
space, and the auth directories referenced by the selected research example:

```bash
sudo install -d -o paseo -g paseo -m 0700 /var/lib/agentbox-broker
sudo install -d -m 0755 /var/lib/agentbox-auth
for role in manager-claude manager-codex offline-claude offline-codex research-claude research-codex; do
  sudo install -d -o paseo -g paseo -m 0700 "/var/lib/agentbox-auth/$role"
done
sudo install -d -o paseo -g paseo -m 0755 /srv/agentbox/workspaces /srv/agentbox/worktrees
```

Adapt that directory list if using another catalog. Authentication directories
must be distinct, outside workspace roots, and accessible to the runtime UID.
Protect their parent directories and never commit the resulting state.

## Model login and instructions

Authenticate each role using its selected host auth directory. For example,
using already installed native model CLIs as the trusted account:

```bash
sudo -u paseo -H env CLAUDE_CONFIG_DIR=/var/lib/agentbox-auth/research-claude claude auth login
sudo -u paseo -H env CODEX_HOME=/var/lib/agentbox-auth/research-codex codex login
```

Repeat for every role with the matching engine and auth reference. Complete any
provider browser/device login interactively. The container CLI versions remain
those pinned in their image. If seeding from an existing login instead, copy only
its model-auth namespace, not the entire native configuration, hooks, plugins,
MCP credentials, history or unrelated secrets. Copied subscription refresh state
is not an independent identity and can require reseeding/reauthentication.

Persistent roles use their auth directory as a read/write bind. Ephemeral roles
read a host `.credentials.json` (Claude) or `auth.json` (Codex) and privately
bootstrap filtered model fields into temporary container storage. Refreshed
credentials/history are discarded when that container ends. Paseo retains its
transcript, but a later harness resume can lack local state.

Put non-secret role instructions in each auth reference's `CLAUDE.md` / `AGENTS.md`:
managers delegate via `agentbox`; offline workers use only their research
allowlist; research handles public questions and cites sources. See
[manager instructions](manager-instructions.md) and [research workers](research-workers.md).
The launcher also supplies the authenticated parent identity for delegated
new ephemeral roles. Fetched content/results remain untrusted data.

## Optional model HTTPS gateway

Skip this section for a catalog with no `httpsProxy`. The model-only example
requires the gateway and an extra system account, venv and private CA state:

```bash
sudo useradd --system --home-dir /var/lib/agentbox-egress --shell /usr/sbin/nologin agentbox-egress
sudo install -d -o agentbox-egress -g agentbox-egress -m 0700 /var/lib/agentbox-egress
sudo python3 -m venv /opt/agentbox-egress-venv
sudo /opt/agentbox-egress-venv/bin/pip install -r /opt/agentbox/requirements-egress.txt
sudo -u agentbox-egress /opt/agentbox-egress-venv/bin/python -c \
  'from mitmproxy.certs import CertStore; CertStore.from_store("/var/lib/agentbox-egress", "mitmproxy", 2048)'
sudo install -m 0644 /var/lib/agentbox-egress/mitmproxy-ca-cert.pem /etc/agentbox/model-egress-ca.pem
```

Run account creation only if it does not already exist. Never replace an existing
CA casually: active clients trust its public certificate. **Only copy the public
`mitmproxy-ca-cert.pem`; `mitmproxy-ca.pem` contains the private key.** The private
state directory stays accessible only to the proxy account/root.

The trusted proxy terminates TLS and handles model credentials/prompts in memory.
Its addon validates exact CONNECT and decrypted HTTP Host/:authority targets,
rejects private/rebound upstream addresses, and verifies upstream TLS. No request
payload capture/logging is configured. Model and authentication services must be
allowlisted; this does not separately restrict provider-side capabilities.

## Install systemd templates

Review/adapt the account, paths, state directory and bridge address in each
[service template](../security). Do not overwrite a customized Paseo unit:

```bash
sudo install -m 0644 security/agentbox-network.service.example /etc/systemd/system/agentbox-network.service
sudo install -m 0644 security/agentbox-broker.service.example /etc/systemd/system/agentbox-broker.service
sudo install -d -m 0755 /etc/systemd/system/paseo.service.d
sudo install -m 0644 security/paseo-agentbox.conf.example /etc/systemd/system/paseo.service.d/agentbox.conf
# For a model-only catalog:
sudo install -m 0644 security/agentbox-egress.service.example /etc/systemd/system/agentbox-egress.service
sudo systemctl daemon-reload
```

Keep the new services stopped until the first apply. The operator creates the
bridges/firewall, writes the protected policy link, then starts the services.
The broker binds only explicit bridge gateways. Its HTTP interface exposes
scoped operations; private launcher registration uses a mode-0600 Unix socket.
The broker's `ReadWritePaths` must include its whole SQLite state directory.

## Review and activate

```bash
/usr/local/sbin/agentbox-catalog validate /etc/agentbox/catalog/agents.yaml \
  --platform /etc/agentbox/catalog/platform.json
/usr/local/sbin/agentbox-catalog plan /etc/agentbox/catalog/agents.yaml \
  --platform /etc/agentbox/catalog/platform.json

sudo /usr/local/sbin/agentbox-catalog apply /etc/agentbox/catalog/agents.yaml \
  --platform /etc/agentbox/catalog/platform.json \
  --expect-revision REVIEWED_CATALOG_HASH \
  --expect-deployment REVIEWED_DEPLOYMENT_HASH
```

Use the hashes from the reviewed plan. There must be no active native host turn;
close managed runtimes too, or explicitly use `--drain` to archive their sessions.
Compatible existing restricted providers require an explicit, reviewed
`--adopt-existing` on first migration; arbitrary provider definitions are not
silently replaced. Apply preserves unmanaged native providers, plugins and daemon
MCP/auth settings, so review those separately before first cutover.

On success, enable the installed dependencies for the next boot:

```bash
sudo systemctl enable agentbox-network agentbox-broker paseo
# If configured:
sudo systemctl enable agentbox-egress
```

Use the protected source/operator for updates. Rebuild images when changing
image-baked bootstrap/client/browser code and pin the new image IDs. Do not
point privileged services at an agent-writable development checkout. Back up
Paseo configuration, policy generations and the complete private broker state
directory; those backups are private and must not enter this repository.

## Verification

```bash
systemctl is-active paseo agentbox-broker agentbox-network
# If configured:
systemctl is-active agentbox-egress
paseo provider ls --json
```

From an isolated manager, verify the profile list and a real delegation. Check
actual containers for expected UID/resources, exact binds, denied host/private
access, successful model traffic, allowed/denied worker profiles and teardown.
Do not dump full Docker environments or credentials into the transcript.
An idle worker still consumes a runtime/quota until archived.

A browser-only smoke test needs no model credentials, host binds or public
network. It exercises delayed JavaScript, evaluation, clicks and screenshots:

```bash
docker run --rm --init -i --network none --user 1000:1000 \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --memory 4g --pids-limit 512 --workdir /tmp \
  --tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=1g \
  --tmpfs /home/agent:rw,nosuid,nodev,mode=0700,size=256m,uid=1000,gid=1000 \
  agentbox/research-browser:local node < tests/research_browser_smoke.cjs
```

Chromium's additional process sandbox is disabled with this Docker profile;
Docker supplies containment. No SYS_ADMIN, host IPC or extra host mounts are
needed. Browser profiles/screenshots are temporary. Check the research browser
against actual public and denied destinations after deployment; a local fixture
cannot prove the host firewall works.

If activation fails, inspect the protected generation's `before-activation`
backup and service health. The operator attempts rollback and leaves services
stopped if it cannot verify recovery. Do not work around a failure by disabling
the firewall, exposing daemon credentials, or granting agents Docker access.
