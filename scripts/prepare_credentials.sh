#!/bin/bash
set -euo pipefail
for name in APPLE_API_KEY APPLE_API_ISSUER APPLE_API_KEY_CONTENT APPLE_CERTIFICATE APPLE_SIGNING_IDENTITY; do
  [[ -n "${!name:-}" ]] || { echo "Central credential ${name} is missing; use the secure setup handoff." >&2; exit 1; }
done
# An existing PKCS12 export can legitimately use an empty password. GitHub
# resolves both an empty and absent secret to an empty string; the owner setup
# verifies the secret name, and security import still authenticates the P12.
APPLE_CERTIFICATE_PASSWORD="${APPLE_CERTIFICATE_PASSWORD-}"
umask 077
key_path="$RUNNER_TEMP/applerelease-notary.p8"
certificate_path="$RUNNER_TEMP/applerelease-certificate.p12"
keychain_path="$RUNNER_TEMP/applerelease-signing.keychain-db"
keychain_password="$(openssl rand -hex 32)"
echo "::add-mask::$keychain_password"
echo "APPLE_API_KEY_PATH=$key_path" >> "$GITHUB_ENV"
echo "APPLE_CERTIFICATE_PATH=$certificate_path" >> "$GITHUB_ENV"
echo "APPLE_KEYCHAIN_PATH=$keychain_path" >> "$GITHUB_ENV"
printf '%s' "$APPLE_API_KEY_CONTENT" > "$key_path"
printf '%s' "$APPLE_CERTIFICATE" | openssl base64 -d -A -out "$certificate_path"
security create-keychain -p "$keychain_password" "$keychain_path"
security set-keychain-settings -lut 3600 "$keychain_path"
security unlock-keychain -p "$keychain_password" "$keychain_path"
security import "$certificate_path" -k "$keychain_path" -P "$APPLE_CERTIFICATE_PASSWORD" -T /usr/bin/codesign >/dev/null
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$keychain_password" "$keychain_path" >/dev/null
existing_keychains=()
while IFS= read -r item; do existing_keychains+=("$item"); done < <(security list-keychains -d user | tr -d '"' | sed 's/^[[:space:]]*//')
security list-keychains -d user -s "$keychain_path" "${existing_keychains[@]}"
security default-keychain -d user -s "$keychain_path"
