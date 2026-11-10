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

Keyring is in early development and has no releases yet. Only the latest commit on `main` gets security fixes. To check whether a running copy has a fix, compare its image's `org.opencontainers.image.revision` label with the fix's commit (see the README, "Which version am I running?").

## What's in scope

- The Keyring application in `src/`, `templates/` and `static/`
- The container image built from `Dockerfile`
- The Bicep templates in `infra/`

Out of scope: Azure Key Vault, Entra ID and other Microsoft services themselves (report those to the [Microsoft Security Response Center](https://msrc.microsoft.com/)), and problems that need an attacker to already control a signed-in person's browser or the server.

## How Keyring is built to be safe

See the threat model in [docs/architecture.md](docs/architecture.md#threat-model).
