# Get started

Three ways in, from quickest to most real.

## Try the demo locally

The demo runs the real Keyring over the mock Azure services from the test suite, signed in as a made-up person with made-up vaults. It needs Rust and nothing from Azure.

```sh
cargo test --test screenshots -- --ignored --nocapture
```

It listens on `127.0.0.1:3999` (or `KEYRING_DEMO_PORT`) and prints a line `KEYRING_DEMO_COOKIE=keyring_session=...` once it is ready. Set that cookie for `127.0.0.1` in your browser, then open `http://127.0.0.1:3999`. Stop it with Ctrl+C. Nothing in the demo talks to Azure, and every value is fake.

## Run against a real tenant

1. Register the app in Entra ID, with the redirect URI `http://localhost:3000/auth/callback`. The README has the steps under [Entra app registration](https://github.com/jusso-dev/keyring#entra-app-registration).
2. Copy the example settings and fill them in:

   ```sh
   cp .env.example .env
   ```

   Set `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET` and `SESSION_SECRET`. Leave `APP_BASE_URL=http://localhost:3000`.

3. Start Keyring, with Rust or Docker:

   ```sh
   set -a; . ./.env; set +a
   cargo run
   ```

   ```sh
   docker build -t keyring .
   docker run --rm -p 3000:3000 --env-file .env --read-only --cap-drop ALL --security-opt no-new-privileges keyring
   ```

4. Open `http://localhost:3000`.

Use a test vault first. Keyring acts as you, so it can change anything your roles allow.

## First sign-in

Select **Sign in with Microsoft** and sign in with your work account. You see the vaults your Azure roles let you see. If the list is empty, or a page says you don't have access, the roles each page needs are in the README under [Give people access to vaults](https://github.com/jusso-dev/keyring#5-give-people-access-to-vaults).

The [Getting started walkthrough](guides/01-getting-started.md) tours the pages from there. To run Keyring for other people, go to [Deploy](deploy.md), and after the first deployment work through the [real-tenant checklist](real-vault-checklist.md).
