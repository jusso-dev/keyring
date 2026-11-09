# Security

Keyring handles secrets, so security reports are welcome and taken seriously.

## Reporting a vulnerability

Please **don't open a public issue** for a security problem.

Use GitHub's private reporting instead: go to the repository's **Security** tab and select **Report a vulnerability**. Include:

- what you found and where (file, route or page)
- how to reproduce it
- what an attacker could do with it

You'll get an acknowledgement within five working days. We'll agree a fix and a disclosure date with you, and credit you in the release notes unless you'd rather not be named.

## Supported versions

Keyring is in early development. Only the latest commit on `main` gets security fixes.

## What's in scope

- The Keyring application in `src/`, `templates/` and `static/`
- The container image built from `Dockerfile`
- The Bicep templates in `infra/`

Out of scope: Azure Key Vault, Entra ID and other Microsoft services themselves (report those to the [Microsoft Security Response Center](https://msrc.microsoft.com/)), and problems that need an attacker to already control a signed-in person's browser or the server.

## How Keyring is built to be safe

See the threat model in [docs/architecture.md](docs/architecture.md#threat-model).
