# Speakerdesk updater setup and next-version registration

The updater path is disabled for all existing registered builds, including 0.6.1. A new approved build opts in with `"updater": true`; it retains the exact original producer run, artifact, source and unsigned DMG/ZIP checks. Register the new source-bound build only after the ordinary candidate verification. Do not invent producer identities, payload hashes or a 0.6.2 registration ahead of that build.

Before opting in, set `apps.speakerdesk.updater_public_key` in `policy/apps.json` to Speakerdesk's Tauri-encoded public key, and embed that exact public key in Speakerdesk's trusted native configuration. Missing, malformed or mismatched keys fail closed. An updater-enabled client uses `requireSignedVersion: true` and disables downgrades.

AppleRelease alone needs repository Actions secrets `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` for the new app-specific key. Do not reuse BatCave's key. Existing Apple certificates/API credentials and artifact-reader access remain sufficient. No website or R2 credential change is needed.

## User-run one-time script — source review only

The prepared [setup script](../scripts/setup_updater_key.sh) has **not been run**. Only Albert should run it after reviewing it and choosing to provision the credential. It requires macOS, Python 3.9+, Node, Cargo and `gh` already authenticated as `TheGreenCedar` through its normal local authentication. It checks existing secret names and refuses key rotation. It creates a new persistent 0700 directory outside the repository, saves the encrypted key as 0600, prompts interactively using official Tauri tooling, and submits secrets directly to `TheGreenCedar/AppleRelease` through `gh secret set` stdin. It emits only the public key to stdout. Private values never appear in arguments, logs or temporary plaintext files.

Prepare the trusted tools **before** generating or entering credentials:

```sh
npm ci --prefix tooling/updater --ignore-scripts --no-audit --no-fund
cargo build --release --locked --manifest-path tooling/updater/verifier/Cargo.toml
```

Then, from a private interactive terminal, Albert can run:

```sh
bash scripts/setup_updater_key.sh "$HOME/.speakerdesk-updater"
```

Choose a strong nonempty password and keep it in a password manager. The script prompts to re-enter that password, signs and verifies a disposable **public** probe before uploading, then uploads the encrypted private key and matching password. The probe/signature temporary files contain no private key or password. The persistent encrypted key and password must be backed up separately by Albert. Uploads are two API operations: if the second fails, the first secret may already exist; finish the password submission manually rather than deleting/rotating the generated key. No release is dispatched by the script. Share only its emitted public key for source configuration.

The official [CLI generate implementation](https://github.com/tauri-apps/tauri/blob/30da1fd6e17de6107ecc850c95dfb16b5729f2dd/crates/tauri-cli/src/signer/generate.rs) prints private key contents if `--write-keys` is omitted. This script always supplies that argument, never `--ci`, `--force` or a password argument, and suppresses captured stdout from the generator. Tauri's [key writer](https://github.com/tauri-apps/tauri/blob/30da1fd6e17de6107ecc850c95dfb16b5729f2dd/crates/tauri-cli/src/helpers/updater_signature.rs) enforces 0600 on the private file.

## Trusted tooling and signer output

`tooling/updater/package-lock.json` locks official Tauri CLI 2.12.1 archives by registry URL and SHA-512 integrity, including both macOS runner architectures. The official NPM version-list metadata initially rejected the exact version, but the exact 2.12.1 archives were available; a clean `npm ci --ignore-scripts` succeeded and the installed CLI reports 2.12.1 and `--app-version` support. Its source is official tag commit `30da1fd6e17de6107ecc850c95dfb16b5729f2dd`. This directory is independent of producer tooling and contains no uploaded executable.

The Rust verifier locks `minisign-verify=0.3.0` and `base64=0.22.1`. It authenticates archive bytes and the trusted comment before requiring exactly one matching signed version. It consumes only public archive/signature/key files. Raw signer output and unrelated credential environments are excluded from durable diagnostics. The signing workflow prepares/tests these tools after trusted registration preflight and before loading Apple/signing credentials, only for an opted-in build; legacy candidates skip the added tools entirely.

After final app signing, notarization, stapling, ZIP/DMG read-back verification, the signer creates `Speakerdesk_<version>_AppleSilicon.app.tar.gz` with one canonical `Speakerdesk.app` root. It performs bounded extraction, compares every member's bytes/mode/link with the final signed app, and runs codesign/stapler/Gatekeeper assessment against the extracted app. These tools inspect the candidate; they never launch it. Only then does the trusted CLI sign with `--app-version <version>`, and the verifier authenticate the payload and version.

An opted-in signer artifact contains exactly six top-level members: DMG, app ZIP, final app tar.gz, tar.gz.sig, `artifact-manifest.json`, and `SHA256SUMS`. The latter lists the four payloads with their exact bytes/SHA-256 recorded in manifest.files. Additional `manifest.updater` metadata is emitted only after successful signature verification:

```json
{
  "platform": "darwin-aarch64",
  "filename": "Speakerdesk_0.6.2_AppleSilicon.app.tar.gz",
  "signature_filename": "Speakerdesk_0.6.2_AppleSilicon.app.tar.gz.sig",
  "signature": "<exact generated base64 .sig text>",
  "public_key": "<same app-specific public key as native config>",
  "require_signed_version": true
}
```

These placeholders are documentation only. Existing signing/provenance/notary receipts and `public_ready: false` remain required. Speakerdesk promotion must verify the authenticated original six-member inventory, exact archive/signature hashes and metadata, signature text equality, and native public key equality. Website approval projects only approved updater metadata to its separate manifest; promotion/deployment remains with its existing owners.

CPU tests cover final archive preservation, tampered bytes/modes/links/ticket removal, canonical root restrictions, special files/permissions and escaping links, legacy opt-out, missing public key, safe diagnostics and failed-verification rejection. Public signature vectors test real cryptographic tampering and forged trusted comments without a private key. These tests do not claim a real Apple signing run, app installation or end-to-end updater validation. Key setup remains unexecuted; native signing and next-version release validation follow only when the combined candidate is ready.
