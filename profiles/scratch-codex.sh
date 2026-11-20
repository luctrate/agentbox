# Same as scratch but on codex, to exercise the other agent's argv path:
# codex's transcript goes to stderr and only its last message to stdout, so a
# caller reads both agents the same way.
DESC="No repo, no secrets - codex plumbing test"
IMAGE=agentbox/base:latest
AGENT=codex
PRIVILEGE=none
NETWORK=bridge
MOUNTS=()
