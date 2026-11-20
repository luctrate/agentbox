# Sourced by agentbox-entrypoint.
#
# Puts the default nvm Node on PATH for the agent and any shell it spawns. The
# agent's own Bash tool starts non-interactive shells that never read .bashrc,
# so exporting PATH here is what actually makes `node`/`npm` resolve.
if [ -s "${NVM_DIR:-/opt/nvm}/nvm.sh" ]; then
  export NVM_DIR="${NVM_DIR:-/opt/nvm}"
  # shellcheck source=/dev/null
  . "$NVM_DIR/nvm.sh"
  nvm use "${AGENTBOX_NODE_VERSION:-default}" >/dev/null 2>&1 || true
  # Make the selection stick for child processes.
  if _nvm_bin="$(nvm which current 2>/dev/null)"; then
    PATH="$(dirname "$_nvm_bin"):$PATH"
    export PATH
    unset _nvm_bin
  fi
fi
