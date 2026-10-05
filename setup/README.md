# One-time private setup

Authorized destination: private `TheGreenCedar/AppleRelease`. Speakerdesk remains private. No organization, paid plan, personal access token, additional app repository or source write permission is required.

## Register and install the artifact reader

Open https://github.com/settings/apps/new while signed in as `TheGreenCedar`.

Use [github-app-registration.json](github-app-registration.json) as the exact registration specification:

- Name: `RootandRuntime Artifact Reader` (GitHub names are globally unique; if unavailable, use an owner-specific suffix and record the resulting slug).
- Homepage: `https://github.com/TheGreenCedar`.
- Webhooks: inactive; no webhook URL or subscribed events.
- User authorization/OAuth and device flow: disabled; no callback URL required.
- Repository permissions: **Actions: Read-only** and automatic **Metadata: Read-only**. Every other permission: No access.
- Organization/account permissions: none.
- Installation availability: **Only on this account**.

Create the app, then use **Install App**. Choose the `TheGreenCedar` account, **Only select repositories**, and select **Speakerdesk only**. Do not select AppleRelease, BatCave or CodeStory.

The App ID and installation ID are public identifiers. The App private key is a credential: generate/download it privately in GitHub's app settings, then enter its entire PEM text directly into AppleRelease's `ARTIFACT_READER_PRIVATE_KEY` Actions secret. Do not send it through chat, commit it, or put it in command-line arguments. No OAuth client secret is used.

## Verify public permission metadata

After registration, an authorized owner session can run:

```sh
python scripts/verify_registration.py ACTUAL_APP_SLUG
```

This reads metadata only. It requires exact Actions/Metadata read permissions and one selected installation repository, Speakerdesk. GitHub's owner UI must also show private installation availability and inactive webhooks. It does not read the App private key or create credentials. After successful verification, set the non-secret repository variable `ARTIFACT_READER_APP_ID` to the verified numeric App ID.

## Enter existing Apple credentials once

Open https://github.com/TheGreenCedar/AppleRelease/settings/secrets/actions and create these **repository Actions secrets** using original secure backups. GitHub cannot recover values previously stored in BatCave.

| Name | Private value to enter |
| --- | --- |
| `ARTIFACT_READER_PRIVATE_KEY` | New artifact-reader App PEM private key |
| `APPLE_CERTIFICATE` | Single-line base64 of the existing Developer ID P12 containing its certificate and private key |
| `APPLE_CERTIFICATE_PASSWORD` | Existing P12 password |
| `APPLE_SIGNING_IDENTITY` | Existing Developer ID Application identity |
| `APPLE_API_KEY` | Existing notarization API key ID |
| `APPLE_API_ISSUER` | Existing notarization issuer ID |
| `APPLE_API_KEY_CONTENT` | Existing raw multiline P8 key, not base64 |

Use GitHub's private entry fields or the owner-controlled interactive `gh secret set NAME --repo TheGreenCedar/AppleRelease --app actions` prompt. No secret values should enter chat, logs or files in this repository. The assistant can verify names afterward; it does not need their values.

## Verify a candidate

The initial allowlist approves only Speakerdesk source `88b311dea8c1bc606c06ffc05b84fdd5c6ed4fc1`, build run `37340319762`, artifact `11357848842`, archive SHA-256 `ef377e4e29765106436b398119793f82e342b6ffb371899f2519abc717d5ed9c`. Its current unsigned artifact expires on 2026-10-12. No signing job has been run as part of source preparation.

After permission metadata and all central secret names are verified, dispatch **Sign approved Apple candidate** on `main`, using its prefilled exact identifiers. The owner can use the GitHub UI or existing authenticated CLI. The workflow downloads only an approved artifact; it cannot fetch producer source or execute producer scripts or the app.

Outputs remain private, notarized **candidates**. Both the ZIP's app and the DMG's app must pass signature/ticket verification. Native first launch and meeting capture QA remain required before the RootandRuntime website publishes the exact approved bytes.

## Future apps and maintenance

New apps need a trusted producer workflow and a centrally reviewed repository/bundle/build registration. Future repository access must be individually authorized and added to this GitHub App's selected installation list. Their repositories need no Apple secret copies. The initial token minting step is fixed to Speakerdesk; onboarding another app requires a reviewed central change.

Rotate or renew Apple credentials centrally when necessary. GitHub App installation tokens are short-lived and the token action revokes its token after the job. The App private key and Apple credentials stay exclusively in this repository's private secret store. Publication credentials and source-write access are outside this setup.

Official references: [App registration](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app), [artifact API permissions](https://docs.github.com/en/rest/actions/artifacts), [GitHub CLI secret entry](https://cli.github.com/manual/gh_secret_set).
