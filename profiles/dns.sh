# Cloud DNS changes. No repo access, no escalation: the agent only needs gcloud
# and a service-account key, both already in the image/env.
DESC="Cloud DNS via gcloud, no repo access"
IMAGE=agentbox/gcloud:latest
AGENT=claude
PRIVILEGE=none
NETWORK=bridge
MOUNTS=()

VAULT_SECRETS=(
  "GOOGLE_APPLICATION_CREDENTIALS_JSON=secret/gcp/dns-admin#key"
)
STATIC_ENV=(
  "GOOGLE_CLOUD_PROJECT=your-project-id"
)
