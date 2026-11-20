# agentbox nvm: base (or sudo) + nvm for agents that must switch Node versions.
#
# nvm lives in /opt/nvm rather than $HOME so it is unaffected by the auth volumes
# mounted under /home/agent, and so a version cache volume can be mounted at a
# stable path.
ARG BASE=agentbox/base:latest
FROM ${BASE}

ARG NODE_VERSIONS="lts/*"

USER root
# node:*-slim omits libatomic1, which the prebuilt Node tarballs nvm downloads
# link against: without it every nvm-installed node dies with
# "error while loading shared libraries: libatomic.so.1".
RUN apt-get update && apt-get install -y --no-install-recommends libatomic1 \
 && rm -rf /var/lib/apt/lists/*

ENV NVM_DIR=/opt/nvm
RUN mkdir -p "$NVM_DIR" && chown agent:agent "$NVM_DIR"

USER agent
# Cloned rather than piped through the install script so nothing is written to
# $HOME/.bashrc, which the init hook replaces.
RUN git clone --depth 1 https://github.com/nvm-sh/nvm.git "$NVM_DIR" \
 && . "$NVM_DIR/nvm.sh" \
 && for v in $NODE_VERSIONS; do nvm install "$v"; done \
 && nvm cache clear

USER root
COPY init-nvm.sh /etc/agentbox/init.d/20-nvm.sh
RUN chmod 0644 /etc/agentbox/init.d/20-nvm.sh

USER agent
