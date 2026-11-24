# Research and model-only workers

These optional profiles separate public research from a project workspace. They
extend the catalog runtime with bounded delegation, ephemeral model login, and
an internal Docker bridge served by a trusted HTTPS model proxy.

Follow the [installation guide](installation.md) for the protected runtime,
model logins and proxy CA/service bootstrap.

See [the example catalog](../examples/research-catalog.yaml) and
[platform bindings](../examples/research-platform.json). Replace placeholder
image IDs and adapt host paths/service bindings before applying.

| Profile | Host bind mounts | Network | Delegation |
|---|---|---|---|
| `offline-claude`, `offline-codex` | Assigned standalone project only, read/write | Internal Docker bridge; model proxy and scoped broker only | Research profiles only |
| `research-claude`, `research-codex` | None | Public internet; no private services or broker | None |

Both engines keep their exact catalog harness versions and immutable image IDs.
New profiles have no sudo, dropped capabilities, no privilege escalation, a
read-only root, 2 CPUs / 4 GiB RAM / 512 PIDs in the reference deployment, and no
Vault/GitLab tool credentials. Model login and the offline worker's scoped
broker capability remain necessary credentials.

## No host authentication mounts

Set `harness.authStorage: ephemeral`. The trusted launcher reads only the
selected model login file and profile instructions, sends a private bootstrap
header over stdin, and the image writes them into its temporary home. It does
not copy unrelated credential namespaces such as MCP OAuth tokens. It does
not mount the source auth directory, CA directories, broker client, Docker
socket, or other host directories. Research uses `workspace: {source: none,
access: none}`. Offline workers use callerWorkspace/readWrite; extra Git worktree
metadata binds are rejected for these profiles. Use a standalone checkout.

Build the supporting image from the repository root, supplying a reviewed local
base tag or registry digest, then record its resulting immutable image ID:

```bash
docker build -f images/ephemeral/Dockerfile --build-arg BASE=agentbox/base:latest \
  -t agentbox/ephemeral:local .
docker image inspect agentbox/ephemeral:local --format '{{.Id}}'
```

The bootstrap and capability client are image-baked. Rebuild and pin a new image
when changing them. No model tokens are in image layers, argv or bootstrap logs.
Auth refresh and harness history stay inside the temporary container filesystem;
closing its container discards them. Paseo retains its own transcript, but a
later harness-level resume may lack local state. Copied subscription OAuth
sessions can require reseeding/reauthentication; they are not independent logins.

## Headless JavaScript browser

Research profiles can use the dedicated `images/research-browser` image, based
on the ephemeral image above. It installs **Playwright 1.65.1** and its matching
Chromium headless shell with system libraries. Package versions/integrity are
locked, browser files are image-baked, and the catalog pins the resulting image
ID. Offline workers continue to use the smaller ephemeral image.

```bash
docker build -f images/research-browser/Dockerfile \
  --build-arg BASE=agentbox/ephemeral:local -t agentbox/research-browser:local .
docker image inspect agentbox/research-browser:local --format '{{.Id}}'
```

Inside a research agent:

```bash
research-browser https://example.com
research-browser https://example.com --wait-for body --screenshot /tmp/page.png
research-browser https://example.com --evaluate 'document.title'
research-browser --help
```

The helper returns JSON with the final URL, HTTP status, title and rendered text
(default maximum 20,000 characters). `--html` returns HTML instead, `--wait-for`
waits for a visible selector, and `--evaluate` evaluates a JavaScript expression
in the page. Screenshots and browser state stay in the ephemeral container.
Page content and JavaScript results remain untrusted research data.

For clicking, forms or multiple pages, use Playwright directly:

```javascript
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({
    headless: true, args: ['--disable-dev-shm-usage'],
  });
  try {
    const page = await browser.newPage();
    await page.goto('https://example.com');
    console.log(await page.title());
    // await page.getByRole('button', { name: 'Continue' }).click();
  } finally { await browser.close(); }
})();
```

`NODE_PATH` points to the image-baked modules for CommonJS scripts. Native ESM
scripts can use
`import { chromium } from "/opt/agentbox-browser/node_modules/playwright/index.mjs"`.

The browser runs with the same non-root user, read-only root, dropped
capabilities, no-new-privileges, private IPC, zero host bind mounts and research
network policy. Chromium's additional process sandbox is disabled under this
Docker profile (the namespace sandbox cannot start with these restrictions);
Docker supplies the containment boundary. No SYS_ADMIN, host IPC, extra mounts
or network exemptions are granted. `--disable-dev-shm-usage` uses temporary
storage rather than sharing the host IPC namespace.

## Model-only egress

The network uses Docker `internal: true` in its trusted binding, `mode: denyAll`,
no DNS/service exceptions, and `httpsProxy.allowedHosts` with exact domain names.
The runtime blocks direct internet/private/peer connections; the model proxy and
broker bind only explicit bridge gateways. Altering/unsetting HTTPS_PROXY does
not grant direct egress. The internal bridge also prevents external Docker DNS
forwarding. IPv6 is disabled in agent containers.

The reference allowlist is api.anthropic.com, platform.claude.com, api.openai.com,
auth.openai.com, and chatgpt.com. Authentication/refresh endpoints are needed
alongside inference. Changes require a reviewed policy revision. This allows the
listed services, not arbitrary web access; provider-side tools reachable through
those services are a separate control from this container network boundary.

`security/model_proxy.py` is an addon for **mitmproxy 12.3.1**, installed in a
separate protected environment. The trusted proxy terminates TLS so it can
check every decrypted HTTP Host/:authority against the allowed CONNECT target,
preventing a shared-CDN tunnel from hiding a different requested hostname. It
rejects private DNS answers, pins the chosen upstream IP, and retains upstream
hostname/certificate validation. Raw TCP and HTTP/3 are disabled. Requests and
responses stream without payload logging or persisted captures.

A dedicated proxy CA private key stays in the proxy service's private state
directory. Only its public certificate is copied into the worker's temporary
trust bundle. The proxy handles model credentials/prompts in memory and is part
of the trusted host boundary. Run it as a dedicated account with no home/Vault/
Docker access. `egress_service` binds it to catalog activation/rollback. This is
an adapter for an existing native Linux installation, not an automatic bootstrap.

Use the [service template](../security/agentbox-egress.service.example), adapting
its trusted runtime prefix and listener to your platform bindings. Install
[requirements-egress.txt](../requirements-egress.txt) in its separate root-owned
venv. Create a dedicated system account and a private state directory, then
generate its CA with the installed `mitmproxy.certs.CertStore.from_store` API.
Copy only `mitmproxy-ca-cert.pem` to the root-owned `proxyBindings.*.caFile`;
never copy `mitmproxy-ca.pem` (the private key) into an agent or workspace.
The template's disabled raw TCP/onboarding, lazy upstream connection, verified
TLS, private state and no-payload-log settings are part of this configuration.

## Delegation

Managers have `maxDepth: 2` and can launch the offline profiles. Each offline
profile allows only the two research profiles, with `maxDepth: 1` and a reference
concurrency limit of two. Research cannot delegate. Catalog validation rejects
cycles, manager targets, or a graph exceeding a definition's depth budget.

The broker derives child authority from its recorded launch and parent
capability. The trusted launcher supplies the launch identity; workers cannot
supply their own rights or reset depth. Parent expiry/revocation/replacement
invalidates descendant capabilities. Direct child ownership and global quotas
still apply; managers do not gain direct control of grandchildren.
The ephemeral startup instructions identify the authenticated parent, making its
task assignments explicit to the harness. That does not make web content or
research results instruction sources, and it cannot expand backend permissions.

```bash
agentbox spawn --detach offline-codex "Implement the change in this checkout"
# Inside that offline worker:
agentbox spawn --detach research-claude "Research the public API and cite sources"
agentbox logs RESEARCH_ID --json
agentbox send RESEARCH_ID "Check compatibility with version X too"
agentbox archive RESEARCH_ID
```

Research sees the supplied task/messages and can send them to the internet.
Delegation is an intentional data channel: no automatic DLP is claimed. Do not
include credentials or private project content in public research requests.
Research output is untrusted input. Managers/workers poll for results and
clarification questions; automatic wake-up is not implemented.
