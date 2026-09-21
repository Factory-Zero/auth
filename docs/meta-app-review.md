# Meta app review runbook (issue #18)

Values below assume production. Staging uses the same paths on its own origin.

## URLs to enter in the Meta App Dashboard

| Field | Value |
|---|---|
| Production base | `https://auth.factory0.ventures` (custom domain, `wrangler.toml`; `docs/ARCHITECTURE.md:7`) |
| Data deletion callback | `https://auth.factory0.ventures/v1/auth-meta/data-deletion` — POST `signed_request`; routes in `crates/auth-meta/src/handlers.rs:54-55` |
| Deletion status page | `https://auth.factory0.ventures/v1/auth-meta/deletion-status?code=…` — returned as `url` with `confirmation_code` (`handlers.rs:549-556`) |
| Valid OAuth Redirect URI | `https://auth.factory0.ventures/v1/auth-meta/callback` — `<AUTH_META_REDIRECT_BASE>/v1/auth-meta/callback`, must match exactly (`crates/auth-meta/README.md:26`) |
| Privacy Policy URL | TODO / needs-human — no value exists in the repo (`grep -ri privacy` = zero hits). Write the policy, add its URL here and in the App Dashboard. |

## How the deletion callback works

1. **Verify first.** `signed_request::verify` checks the HMAC against `AUTH_META_CLIENT_SECRET` before anything is read; every refusal answers the same generic `400` (`handlers.rs:528-534`).
2. **Record a job row**, not the deletion itself. Returns `{url, confirmation_code}` for the status page (`deletion.rs:51-73`).
3. **Scheduled drain.** `Module::scheduled` calls `deletion::run_pending`, which drains up to 50 pending jobs per run (`lib.rs:260-266`, `deletion.rs:130-166`).
4. **Unlink vs purge.** The Meta identity row is always deleted first; the account is purged only when no other identity or credential remains, otherwise the outcome is `unlinked` (`deletion.rs:89-121`). Replays are harmless: an already-gone subject completes as `nothing_to_do`.
5. **Status page.** Unknown and missing codes answer identically; known jobs say pending ("received and is being carried out") or done ("has been carried out") with no account details (`handlers.rs:570-602`).

## Reviewer walkthrough

1. Submit a deletion request for a test user via the callback URL.
2. Confirm the answer contains `url` + `confirmation_code`.
3. Open the status URL: expect the pending message, then the done message after the next scheduled run.
4. Confirm the Meta identity row is gone, and the account only if it had no other login method.
