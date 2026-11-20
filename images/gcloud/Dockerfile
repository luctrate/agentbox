# agentbox gcloud: base (or sudo) + Google Cloud CLI.
#
# Build on either tier:
#   --build-arg BASE=agentbox/base:latest  -> agentbox/gcloud
#   --build-arg BASE=agentbox/sudo:latest  -> agentbox/gcloud-sudo
ARG BASE=agentbox/base:latest
FROM ${BASE}

USER root
RUN apt-get update && apt-get install -y --no-install-recommends gnupg \
 && curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg \
      | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
      > /etc/apt/sources.list.d/google-cloud-sdk.list \
 && apt-get update && apt-get install -y --no-install-recommends google-cloud-cli \
 && rm -rf /var/lib/apt/lists/*

COPY init-gcloud.sh /etc/agentbox/init.d/20-gcloud.sh
RUN chmod 0644 /etc/agentbox/init.d/20-gcloud.sh

# gcloud writes logs and an active-config file on every invocation, so its config
# dir has to live somewhere the agent owns.
ENV CLOUDSDK_CONFIG=/home/agent/.config/gcloud \
    CLOUDSDK_CORE_DISABLE_PROMPTS=1
RUN mkdir -p /home/agent/.config/gcloud && chown -R agent:agent /home/agent/.config

USER agent
