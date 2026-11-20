# Node work on one project tree. PRIVILEGE=sudo so the agent can apt-get a
# missing native build dependency without a round trip to you; it still runs as
# uid 1000, which is why Claude Code accepts --dangerously-skip-permissions here
# with no IS_SANDBOX override.
DESC="Node/JS work with nvm, can apt-get"
IMAGE=agentbox/nvm-sudo:latest
AGENT=claude
PRIVILEGE=sudo
NETWORK=bridge

# Mount the directory holding the main checkout AND its worktrees, at the same
# absolute path: a worktree's .git is an absolute gitdir pointer into the parent.
MOUNTS=(
  "$HOME/projects"
)
WORKDIR="$HOME/projects"

STATIC_ENV=(
  "AGENTBOX_NODE_VERSION=default"
)
