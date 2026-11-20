#!/usr/bin/env bash
# Runs as the agent user. Sources each image's init hooks, then execs the agent.
# Hooks are sourced (not run) so they can export into the agent's environment.
set -euo pipefail

if [ -d /etc/agentbox/init.d ]; then
  for hook in /etc/agentbox/init.d/*.sh; do
    [ -e "$hook" ] || continue
    # shellcheck source=/dev/null
    . "$hook"
  done
fi

exec "$@"
