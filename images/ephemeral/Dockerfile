# Same pinned harnesses as base; runtime support is baked in, never host-mounted.
ARG BASE=agentbox/base:latest
FROM ${BASE}
USER root
COPY security/bootstrap.py /usr/local/bin/agentbox-bootstrap
COPY security/client.py /usr/local/bin/agentbox
RUN chmod 0755 /usr/local/bin/agentbox-bootstrap /usr/local/bin/agentbox
USER agent
