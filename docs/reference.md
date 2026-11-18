# Reference

Where to find each list. Each one is kept in one place, next to the code or the deployment it describes, so it is linked here rather than copied.

| What | Where |
| --- | --- |
| Every environment variable Keyring reads | README, [Configuration](https://github.com/jusso-dev/keyring#configuration) |
| Every setting, with its Bicep parameter | The [design document](design-overview.md), Appendix A |
| Bicep parameters for App Service and Container Apps | [Deploy, Parameters](deploy.md#parameters) |
| Audit event fields, actions and reason codes | [Deploy, Audit event fields](deploy.md#audit-event-fields) |
| Keyring's audit table in Log Analytics | [Microsoft Sentinel](sentinel.md) and [Deploy, Audit sink](deploy.md#audit-sink) |
| Reserved tags (`description`, `owner`, `notify`, `keyring-owners`, the rotation tags) | [Architecture, Well-known tags](architecture.md#well-known-tags) and [Rotation](rotation.md) |
| Key Vault and Azure roles each page needs | README, [Give people access to vaults](https://github.com/jusso-dev/keyring#5-give-people-access-to-vaults) |
| What Keyring checks in vault health | [Vault health walkthrough](guides/09-vault-health.md) |
| Limits on connections, forms and sessions | [Architecture](architecture.md) |
| Error messages and what to do | [Troubleshooting](troubleshooting.md) |
| Changes in each release | [CHANGELOG](https://github.com/jusso-dev/keyring/blob/main/CHANGELOG.md) |
