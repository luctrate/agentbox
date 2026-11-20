# Smallest possible box: no mounts, no secrets, no escalation, no network needed
# beyond the API call. Use it to prove the plumbing before touching a real
# profile, and as the template for new ones.
DESC="No repo, no secrets - plumbing test"
IMAGE=agentbox/base:latest
AGENT=claude
PRIVILEGE=none
NETWORK=bridge
MOUNTS=()
