# MyCoop

A Thai-language, single-user cooperative loan planner.

- Equal-principal monthly repayment forecasts, project sorting and payment schedules.
- Single-field passphrase unlock, encrypted browser storage and encrypted backups.
- No personal loan records or plaintext passwords are included in this repository.
- The bootstrap vault is empty. Restore a separately held encrypted backup on first use.
- Browser-local storage; no cloud sync. Changing the passphrase only re-encrypts the current browser vault.
- Estimates use monthly interest and are not a lender statement.

Published with [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages).

Encryption: Web Crypto AES-GCM (256-bit), PBKDF2 SHA-256 (600,000 iterations), random salt and per-save IV. The deployment bootstrap only unlocks an empty local workspace.
