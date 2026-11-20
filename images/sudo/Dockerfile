# agentbox sudo: base + passwordless escalation, still running as uid 1000.
#
# This is the escalation tier to prefer over PRIVILEGE=root: Claude Code checks
# the effective uid, not whether sudo exists, so --dangerously-skip-permissions
# is accepted here with no IS_SANDBOX override.
ARG BASE=agentbox/base:latest
FROM ${BASE}

USER root
RUN apt-get update && apt-get install -y --no-install-recommends sudo \
 && rm -rf /var/lib/apt/lists/*

# Keyed on the group, not the user: on a Linux host agentbox passes
# -u $(id -u):$(id -g), and a user-keyed rule silently stops matching when the
# host uid is not the one baked into the image.
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/agentbox \
 && chmod 0440 /etc/sudoers.d/agentbox \
 && usermod -aG sudo agent

USER agent
