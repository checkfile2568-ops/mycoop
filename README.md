# MyCoop

Thai-language cooperative loan planner for one owner across multiple devices.

Live app: https://checkfile2568-ops.github.io/mycoop/

## Features

- Single passphrase field; no email login.
- Equal-principal repayment forecasts, project sorting, monthly totals and contract-expiry discrepancies.
- Encrypted shared vault in Supabase. Edits sync on page focus and every 20 seconds while the page is visible.
- Revision checks reject stale writes from another device rather than silently overwriting them.
- Encrypted backups and explicit recovery; global passphrase rotation invalidates other device sessions.
- Inactivity lock after 10 minutes. Internet is required to sign in and save changes.

## Privacy and authentication

This public repository contains application code only: no personal financial records, plaintext passphrases, password verifier, database seed or service-role secret.

The browser encrypts the vault with Web Crypto AES-GCM (256-bit), PBKDF2 SHA-256 (600,000 iterations), a random salt and a fresh IV for each save. Passphrases are sent over HTTPS for server authentication; only a separately salted verifier is retained on the server. Sessions use random 256-bit tokens, are stored hashed on the server, remain in browser memory, and expire after 12 hours. Login attempts are rate limited. A single-field passphrase is the sole identity factor; there is no forgotten-password reset.

Direct database access is revoked for both `anon` and `authenticated`. RLS explicitly denies direct client access. Only the edge function uses the service-role secret from its server environment, with custom authentication and revision checks on every data request. `verify_jwt=false` is intentional because the function validates its own sessions, not Supabase Auth JWTs.

## Deployment and operation

GitHub Pages serves the static application. Supabase hosts the database and `mycoop-api` edge function. `supabase/schema.sql` is a reference snapshot of the schema applied through managed migrations. It contains no data seed. Credentials and encrypted financial data are provisioned separately and must never be committed here.

The current deployment uses the Supabase Free plan. Free projects may pause after a week without activity; no keep-alive workaround is used. Keep encrypted backups. Plan changes must be reviewed separately; paid upgrades are not performed by the application.

## Calculation assumptions

Monthly interest is estimated from opening principal × annual rate ÷ 12, rounded per contract. The final principal installment is capped at the remaining balance. Forecasts assume unchanged rates and on-time payments, and exclude other cooperative deductions. Results are estimates, not a lender statement.

## Verification

Pure calculation and encryption tests passed. Live integration tests verified two independent clients, correct-password login, wrong-password and forged-session rejection, revision conflict handling, synchronization and logout. Database grants were inspected and the Supabase security advisor returned no findings. Integration tests are run against a private seed outside this repository.

Documentation: [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages), [Supabase pricing](https://supabase.com/pricing), [Edge Function configuration](https://supabase.com/docs/guides/functions/function-configuration).
