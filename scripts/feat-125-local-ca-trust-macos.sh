#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ca_file="$repo_dir/environments/local/generated/feat-125-caddy-root.crt"
action="${1:-}"

if [[ "$action" != "install" && "$action" != "remove" && "$action" != "status" ]]; then
  echo "usage: feat-125-local-ca-trust-macos.sh install|remove|status" >&2
  exit 2
fi
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This trust helper is intentionally limited to the macOS user login Keychain" >&2
  exit 1
fi
node "$repo_dir/scripts/validate-feat-125-local-ca-binding.mjs"

keychain="$(security default-keychain -d user | tr -d '"')"
fingerprint="$(openssl x509 -in "$ca_file" -noout -fingerprint -sha1 | sed 's/^.*=//' | tr -d ':')"
is_installed() {
  security find-certificate -Z -a "$keychain" 2>/dev/null | grep "$fingerprint" >/dev/null
}

case "$action" in
  status)
    if is_installed; then
      echo "FEAT-125 Caddy root CA is trusted in $keychain (SHA-1 $fingerprint)"
    else
      echo "FEAT-125 Caddy root CA is not trusted in $keychain (SHA-1 $fingerprint)"
      exit 1
    fi
    ;;
  install)
    if is_installed; then
      echo "FEAT-125 Caddy root CA is already trusted (SHA-1 $fingerprint)"
      exit 0
    fi
    security add-trusted-cert -d -r trustRoot -k "$keychain" "$ca_file"
    echo "Trusted only the exported FEAT-125 public root CA (SHA-1 $fingerprint)"
    ;;
  remove)
    if [[ "${FEAT125_CONFIRM_CA_FINGERPRINT:-}" != "$fingerprint" ]]; then
      echo "Refusing removal. Set FEAT125_CONFIRM_CA_FINGERPRINT=$fingerprint and run again." >&2
      exit 1
    fi
    if ! is_installed; then
      echo "FEAT-125 Caddy root CA is already absent (SHA-1 $fingerprint)"
      exit 0
    fi
    security delete-certificate -t -Z "$fingerprint" "$keychain"
    echo "Removed the exact FEAT-125 Caddy root CA trust entry (SHA-1 $fingerprint)"
    ;;
esac
