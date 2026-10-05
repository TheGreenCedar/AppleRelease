# AppleRelease

Central private Developer ID signing and Apple notarization for approved RootandRuntime app artifacts. Apple credentials are entered once here and are not copied to producer repositories. The GitHub App reads Actions artifacts from Speakerdesk only, with automatic metadata read access. It has no source/content/write permission.

[One-time secure setup](setup/README.md) describes registration, selected-repository installation, permission verification and direct private credential entry. No credentials are included in this repository.

The signing workflow runs only for owner dispatches on this repository's `main`. Its fixed policy accepts an exact registered repository, workflow, branch, successful run, source commit, artifact ID, artifact digest, file hashes and app bundle identity. It never checks out producer source, runs producer scripts or launches the application. API credentials are not forwarded to signed blob-storage URLs. Archive extraction rejects traversal, external symlinks, special files, excess size and substituted payloads.

Before loading Apple credentials, the runner verifies the existing GitHub App's exact Actions/Metadata read permissions, empty event subscriptions, and its complete selected installation containing private Speakerdesk only. Verification credentials stay in memory, API redirects are rejected, and the temporary metadata token is revoked. Errors report sanitized categories. The later artifact-read token remains restricted to Speakerdesk.

Speakerdesk's PyInstaller one-file runtime needs embedded library signatures updated as well as its outer signature. The pinned adapter reads/rebuilds its archive without loading marshaled scripts or PYZ code. It preserves unchanged payload entries, signs embedded arm64 libraries and verifies their signatures after reassembly. Native signing, app/DMG notarization and packaged-ticket checks require the secure setup and a real signing run; CPU policy tests do not claim that validation has happened.

Outputs are private workflow artifacts with source/signer commits, input digest, notarization receipts, SHA-256 checksums and `public_ready: false`. Native meeting QA and public publication are separate readiness steps. No workflow publishes a release, changes repository visibility or uses paid transcription APIs.

Run policy tests without keys or model downloads:

```sh
python -m pip install pyinstaller==6.22.3
python -m unittest discover -s tests -v
node --test tests/app-installation.test.mjs
```

Future apps are individually registered in `policy/apps.json` and the artifact-reader installation; they need no Apple credential copies. Existing keys are reused until renewal/rotation is necessary. The initial source allowlist is deliberately limited to the tested Speakerdesk build recorded in policy.
