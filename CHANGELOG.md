# Changelog

Notable changes to Keyring. Keyring has no releases yet, so everything is under Unreleased. Each entry names the pull request it came from. To see which commit an image was built from, read its `org.opencontainers.image.revision` label.

## Unreleased

### Security

- `deny.toml` also bans `aws-lc-rs` and `aws-lc-sys`, so a dependency change can't quietly swap rustls's ring provider for aws-lc.
- CI installs its tools only from pinned, checksummed binaries (no fallback download), pins the Bicep CLI, and pins the Dockerfile build frontend by digest.

### Deployment

- Container Apps with `ingress = 'internal'` is reachable from the VNet. The template outputs `defaultDomain` and `staticIp` and can create the private DNS zone (`privateDnsVnetId`).
- Both templates take `apiScope` and `logLevel`.
- App Service can send Keyring's output to Log Analytics (`logAnalyticsWorkspaceId`), and otherwise keeps a 7 day local log.
- The alerts template puts the system topic in the vault's region and can use a topic the vault already has (`existingSystemTopicName`).
- Images carry `org.opencontainers.image.version` and `org.opencontainers.image.revision` labels.

### Documentation

- App registration: the Log Analytics API permission and the sign-out redirect URI.
- Role table: the smallest role first, and which roles can read secret values.
- Rotating the client secret and `SESSION_SECRET`, logs on each platform, proxies and private CAs, and more troubleshooting rows.
