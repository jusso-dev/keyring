#!/usr/bin/env bash
# Fetch Keyring's startup secrets from its own config Key Vault into RAM
# (/run/keyring/secrets.env, tmpfs) using the VM's user-assigned managed
# identity via Azure IMDS. Never writes secrets to persistent disk and never
# prints secret values to stdout/stderr.
set -euo pipefail
umask 077

OUT_FILE="/run/keyring/secrets.env"
IMDS_URL="http://169.254.169.254/metadata/identity/oauth2/token"

: "${KEYRING_CONFIG_VAULT_URI:?KEYRING_CONFIG_VAULT_URI must be set in /etc/keyring/keyring.env}"
: "${KEYRING_MANAGED_IDENTITY_CLIENT_ID:?KEYRING_MANAGED_IDENTITY_CLIENT_ID must be set in /etc/keyring/keyring.env}"

vault_uri="${KEYRING_CONFIG_VAULT_URI%/}"
if [[ ! "$vault_uri" =~ ^https://[a-zA-Z0-9-]+\.vault\.azure\.net$ ]]; then
  echo "KEYRING_CONFIG_VAULT_URI must be an https://<name>.vault.azure.net URI" >&2
  exit 1
fi

token_json="$(curl -fsS --max-time 10 -H "Metadata: true" \
  "${IMDS_URL}?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net&client_id=${KEYRING_MANAGED_IDENTITY_CLIENT_ID}")"

kv_token="$(printf '%s' "$token_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')"
unset token_json

fetch_secret() {
  local name="$1"
  local body
  body="$(curl -fsS --max-time 10 \
    -H "Authorization: Bearer ${kv_token}" \
    "${vault_uri}/secrets/${name}?api-version=7.5")"
  printf '%s' "$body" | python3 -c 'import json,sys; v=json.load(sys.stdin)["value"]; assert "\n" not in v and "\r" not in v; print(v, end="")'
}

tmp_file="${OUT_FILE}.tmp.$$"
trap 'rm -f "$tmp_file"' EXIT

session_secret="$(fetch_secret "session-secret")"
printf 'SESSION_SECRET=%s\n' "$session_secret" > "$tmp_file"
unset session_secret

if [[ "${KEYRING_USE_FEDERATED_CREDENTIAL:-false}" != "true" ]]; then
  client_secret="$(fetch_secret "entra-client-secret")"
  printf 'ENTRA_CLIENT_SECRET=%s\n' "$client_secret" >> "$tmp_file"
  unset client_secret
fi

unset kv_token
chmod 0600 "$tmp_file"
mv -f "$tmp_file" "$OUT_FILE"
trap - EXIT
