# Running checklist rows against a real vault

A few rows of the [real-vault checklist](real-vault-checklist.md) can run as a Rust test target, `tests/real_vault.rs`, against a throwaway vault. It covers nine rows, and it is not full coverage.

Why it exists: every other test runs against the mock Key Vault in `tests/support/`, and the first real run found two places where the mock was wrong. A row that runs on demand checks the mock against Key Vault again, for example before moving off API version 7.5.

## What is automated

| Row | Test name (after `mock_` or `real_`) |
| --- | --- |
| Secrets: Versions of a name that doesn't exist | `versions_of_a_name_that_doesnt_exist` |
| Secrets: Clearing an expiry date | `clearing_an_expiry_date` |
| Secrets: Recover then read | `recover_then_read` |
| Secrets: 409 for a soft-deleted name | `409_for_a_soft_deleted_name` |
| Keys: HSM key on a Standard vault | `hsm_key_on_a_standard_vault` |
| Certificates: Self-signed create | `self_signed_create` |
| Certificates: Change renewal | `change_renewal` |
| Certificates: Import onto a soft-deleted name | `import_onto_a_soft_deleted_name` |
| Certificates: BER-encoded PFX | `ber_encoded_pfx` |

Each row has two tests:

- `mock_<row>` runs the steps against the mock and checks the answer Key Vault gave in the recorded run. It runs in a normal `cargo test` and calls nothing outside your machine.
- `real_<row>` is ignored by default. It runs the same steps against the real vault, then against the mock, and fails if the real answer differs from the recorded one, or if the mock and the real vault disagree. The failure message names the checklist row and the mock file to fix.

Three of the certificate rows have no recorded run yet, so their expected answers are what Microsoft documents. Change renewal expects an empty `lifetime_actions` list to clear the actions, and a day count above 27 times the validity to get 400 `BadParameter`. Import onto a soft-deleted name expects the same 409 as for secrets, with inner code `ObjectIsDeletedButRecoverable`. BER-encoded PFX expects Key Vault to import `tests/fixtures/test-ber.pfx`, which has indefinite lengths (see `tests/fixtures/README.md`). If a real run answers differently, change the mock and the expected value together.

The steps call Keyring's own clients in `src/azure/` (`SecretsApi`, `KeysApi`, `CertsApi`), so the code that was checked is the code that ships.

## What is not automated, and why

- Sign-in, on-behalf-of, `oid` and `tid`, consent and conditional access rows need a signed-in person. The test has no user.
- RBAC role rows (the smallest role for listing, reading or downloading) need an identity limited to that role. See the open questions.
- Browser, accessibility and deployment rows need a browser or an Azure deployment.
- The test does not create vaults. You make the vault, and the test only creates and deletes items inside it.

## How it gets a token

Keyring has no app-only path to Azure, and this does not add one. The test takes a Key Vault token from a file and puts it into a test session's token cache, through one hidden hook, `TokenCache::seed_token_for_tests` in `src/azure/token.rs`. The hook only stores a token. It does not fetch, exchange or refresh anything, and nothing in the app calls it.

The seeded token is treated as valid for 50 minutes. Nothing can refresh it: the test session's user token is already expired and has no refresh token. If Key Vault rejects the token, the test stops with "token expired, get a new one" and makes no call to Entra.

## Running it

1. Make a Standard vault named `kr-test-<something>` (at most 24 characters in all) with soft delete on, in a subscription you can delete from. Give your identity rights over secrets, keys and certificates in it (for example Key Vault Administrator).
2. Get a token and keep it outside the repository. Do not print it.

   ```sh
   TOKEN_FILE=$(mktemp)   # a new file only you can read
   az account get-access-token --resource https://vault.azure.net \
     --query accessToken -o tsv > "$TOKEN_FILE"
   ```

3. Run the real half.

   ```sh
   KEYRING_REAL_VAULT=kr-test-<something> \
   KEYRING_REAL_TOKEN_FILE="$TOKEN_FILE" \
   cargo test --test real_vault -- --ignored --test-threads=1
   ```

4. Delete the token file (`rm "$TOKEN_FILE"`). Add what you saw to "Record of runs" in the checklist, with no tenant-identifying values.

### Guard rails

- The vault name must be valid and start with `kr-test-`. Anything else fails before any request is sent. Name throwaway vaults that way, and never give a vault that name if it holds anything that matters.
- Items get random names (`kr-real-` and 8 hex digits) and values are fixed dummy strings.
- Every test deletes what it made, including when a step panics. It purges too, unless the vault has purge protection, in which case the items stay soft-deleted until retention ends and the test says so on stderr.
- If a cleanup step fails, the test says what was left behind, so you can remove it by hand.

## Adding a row

1. Write the steps as an `async fn` that takes a `&Target` and returns a small struct of what Key Vault did (status, code, or whether a field changed). Make names with `unique_name()` and register them with `t.cleanup.track(...)` before creating anything.
2. Write the answer from the real run as the expected value.
3. Add a `mock_` test that calls `mock_row`, and an ignored `real_` test that calls `real_row` with the mock file to fix on a mismatch.

A disagreement between a real answer and the mock is a finding. Change the mock to match Key Vault, with a test, as the checklist says, and record it.

## Open questions

- Should this run before every bump of the Key Vault API version?
- Should recorded replies be kept as fixtures? A scrubber that refuses any body with a secret value is part of the plan, but this spike does not record anything.
- Should it also run as an identity limited to a small role, to cover the smallest-role rows of issue #170?
