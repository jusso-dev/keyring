# Security

Keyring handles secrets, so security reports are welcome and taken seriously.

## Reporting a vulnerability

Please **don't open a public issue** for a security problem.

Use GitHub's private reporting instead: go to the repository's **Security** tab and select **Report a vulnerability**. Include:

- what you found and where (file, route or page)
- how to reproduce it
- what an attacker could do with it

If the **Report a vulnerability** button isn't there, open a public issue titled "Security contact request" with **no details** of the problem. A maintainer will reply with a private way to send them.

You'll get an acknowledgement within five working days. We'll agree a fix and a disclosure date with you, and credit you in the fix's pull request and in [CHANGELOG.md](CHANGELOG.md) unless you'd rather not be named.

## Supported versions

Security fixes apply to the latest `1.x` release and `main`. To check whether a running copy has a fix, compare its image's `org.opencontainers.image.version` and `org.opencontainers.image.revision` labels with the release or fix commit (see the README, "Which version am I running?").

## Verifying an image

Each version tag's image is built by [`.github/workflows/release.yml`](.github/workflows/release.yml) and carries a signed build provenance attestation (published to `ghcr.io` when `KEYRING_PUBLISH_IMAGE=true`, or attached as an attested workflow archive). To check that a published image came from this repository's workflow, run:

```sh
gh attestation verify oci://ghcr.io/jusso-dev/keyring@sha256:<digest> --repo jusso-dev/keyring
```

If the command fails, don't deploy that image.

## What's in scope

- The Keyring application in `src/`, `templates/` and `static/`
- The container image built from `Dockerfile`
- The Bicep, VM/Packer, Azure Policy and Terraform packaging in `infra/` and the Microsoft Sentinel Content Hub package in `Solutions/Keyring/`
- Automated supply-chain checks in [`.github/workflows/ci.yml`](.github/workflows/ci.yml) and [`.github/workflows/scorecard.yml`](.github/workflows/scorecard.yml) (OpenSSF Scorecard)

Out of scope: Azure Key Vault, Entra ID and other Microsoft services themselves (report those to the [Microsoft Security Response Center](https://msrc.microsoft.com/)), and problems that need an attacker to already control a signed-in person's browser or the server.

## How Keyring is built to be safe

See the [threat model](docs/threat-model.md): trust boundaries, a diagram and every STRIDE threat with what stops it. The engineering detail is in [docs/architecture.md](docs/architecture.md#threat-model).
