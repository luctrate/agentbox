# agentbox base: claude + codex, non-root, no sudo.
#
# AGENT_UID/AGENT_GID must match the host user that owns any mounted worktree on
# a Linux host, otherwise the agent cannot write to it. On macOS Docker Desktop
# the uid is translated, so the default 1000 is fine.
FROM node:22-trixie-slim

ARG AGENT_UID=1000
ARG AGENT_GID=1000
ARG CLAUDE_VERSION=2.1.329
ARG CODEX_VERSION=0.171.0
LABEL org.agentbox.claude-version="${CLAUDE_VERSION}" \
      org.agentbox.codex-version="${CODEX_VERSION}"

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git glab jq less ripgrep python3 \
 && rm -rf /var/lib/apt/lists/*

RUN npm install -g "@anthropic-ai/claude-code@${CLAUDE_VERSION}" "@openai/codex@${CODEX_VERSION}" \
 && npm cache clean --force

# node:22-slim already owns uid 1000; drop it so AGENT_UID is free.
RUN userdel -r node 2>/dev/null || true \
 && groupadd -g "${AGENT_GID}" agent \
 && useradd -u "${AGENT_UID}" -g "${AGENT_GID}" -m -d /home/agent -s /bin/bash agent

# Per-image init hooks. Each image drops *.sh here; the entrypoint sources them
# in order before exec'ing the agent, so a profile's secrets can be turned into
# whatever on-disk shape a CLI expects.
RUN mkdir -p /etc/agentbox/init.d
COPY entrypoint.sh /usr/local/bin/agentbox-entrypoint
RUN chmod 0755 /usr/local/bin/agentbox-entrypoint
COPY git-credential-agentbox /usr/local/bin/git-credential-agentbox
RUN chmod 0755 /usr/local/bin/git-credential-agentbox \
 && git config --system credential.helper /usr/local/bin/git-credential-agentbox \
 && git config --system user.name Agentbox \
 && git config --system user.email agentbox@lab

ENV HOME=/home/agent \
    CLAUDE_CONFIG_DIR=/home/agent/.claude \
    CODEX_HOME=/home/agent/.codex \
    DISABLE_AUTOUPDATER=1 \
    npm_config_update_notifier=false

# Both CLIs refuse to start if their home is missing, and the auth volumes mount
# over these paths, so create them owned by the agent.
RUN mkdir -p /home/agent/.claude /home/agent/.codex /home/agent/work \
 && chown -R "${AGENT_UID}:${AGENT_GID}" /home/agent

USER agent
WORKDIR /home/agent/work
ENTRYPOINT ["/usr/local/bin/agentbox-entrypoint"]
CMD ["bash"]
