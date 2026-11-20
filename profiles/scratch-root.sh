# The root tier, kept as a profile so it is demonstrable and reviewable.
# Prefer PRIVILEGE=sudo over this: root is only for images that must own uid 0
# from the first instruction. agentbox adds IS_SANDBOX=1 for Claude here, since
# Claude Code otherwise refuses --dangerously-skip-permissions as root.
DESC="Runs as uid 0 - last resort tier"
IMAGE=agentbox/base:latest
AGENT=claude
PRIVILEGE=root
NETWORK=bridge
MOUNTS=()
