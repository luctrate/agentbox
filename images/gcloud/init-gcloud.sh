# Sourced by agentbox-entrypoint.
#
# A service-account key arrives as an env var (GOOGLE_APPLICATION_CREDENTIALS_JSON)
# so it never touches the host filesystem. gcloud wants a file, so materialize it
# here, inside the container, and activate it.
if [ -n "${GOOGLE_APPLICATION_CREDENTIALS_JSON:-}" ]; then
  _sa_dir="${HOME}/.config/agentbox"
  _sa_file="${_sa_dir}/gcp-sa.json"
  mkdir -p "$_sa_dir"
  ( umask 077; printf '%s' "$GOOGLE_APPLICATION_CREDENTIALS_JSON" > "$_sa_file" )

  export GOOGLE_APPLICATION_CREDENTIALS="$_sa_file"
  # Drop the secret from the environment the agent inherits: the file is the
  # interface from here on, and the agent has no reason to read the raw key.
  unset GOOGLE_APPLICATION_CREDENTIALS_JSON

  if ! gcloud auth activate-service-account --key-file="$_sa_file" --quiet 2>/dev/null; then
    echo "agentbox: gcloud could not activate the service account key" >&2
  fi

  if [ -n "${GOOGLE_CLOUD_PROJECT:-}" ]; then
    gcloud config set project "$GOOGLE_CLOUD_PROJECT" --quiet 2>/dev/null || true
  fi

  unset _sa_dir _sa_file
fi
