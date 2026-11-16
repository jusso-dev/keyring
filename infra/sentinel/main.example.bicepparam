// Example parameters. Copy next to main.bicep (infra/sentinel/main.bicepparam),
// fill in, and keep out of source control (.gitignore skips *.bicepparam
// except the examples). Every rule is off until its enable parameter is
// true. See docs/sentinel.md.
using './main.bicep'

param workspaceName = 'law-sentinel'

// Whichever table the vaults' diagnostic settings write to.
param keyVaultTable = 'AzureDiagnostics'

// Keyring's outbound addresses, as Key Vault sees them. Empty leaves out the
// audit gap and unmatched SecretGet rules.
param keyringOutboundIps = [
  '203.0.113.10'
]

param enableManyReveals = true
param revealThreshold = 20
param revealWindowMinutes = 60

param enableAppAttack = true

param enableOffHours = false
param utcOffsetMinutes = 600

param enableAuditGap = false

// Leave off until the real-vault checklist row passes.
param enableUnmatchedSecretGet = false
