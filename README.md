<p align="center">
  <img src="assets/readme-banner.png" alt="Factory Zero Auth. One login. Every venture. Six ways in, one session." width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/STATUS-SPIKES-FF5A36?style=flat-square&labelColor=0A0A0B" alt="Status: spikes">
  <img src="https://img.shields.io/badge/LANGUAGE-RUST-EDEBE6?style=flat-square&labelColor=0A0A0B" alt="Language: Rust">
  <img src="https://img.shields.io/badge/RUNS%20ON-THE%20HARNESS-EDEBE6?style=flat-square&labelColor=0A0A0B" alt="Runs on the harness">
  <img src="https://img.shields.io/badge/LOGIN-PASSKEYS%20%C2%B7%20GOOGLE%20%C2%B7%20APPLE%20%C2%B7%20META%20%C2%B7%20PASSWORD%20%C2%B7%20MAGIC%20LINK-EDEBE6?style=flat-square&labelColor=0A0A0B" alt="Six login methods">
  <img src="https://img.shields.io/badge/TOKENS-ES256%20JWT%20%2B%20JWKS-EDEBE6?style=flat-square&labelColor=0A0A0B" alt="Tokens: ES256 JWT with JWKS">
  <img src="https://img.shields.io/badge/LICENSE-MIT-FF5A36?style=flat-square&labelColor=0A0A0B" alt="License: MIT">
</p>

<p align="center">
  <b>auth.factory0.ventures</b> · SHARED INFRASTRUCTURE
</p>

---

# The login

Every Factory Zero venture needs people to sign in, and none of them should
own a password table. This service is the one place logins happen. A venture
registers as a client, sends people here, and gets back a token it can verify
on its own.

> **Six ways in, one session.**
> Passkeys, Google, Apple, Meta, email and password, magic links. Whichever a
> person picks, the result is the same session, and one person can use all
> six on one account.

Built as a consumer of the
[Factory Zero harness](https://github.com/Factory-Zero/harness): one Worker,
one D1 database, modules that see only ports. Read
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how it fits, what was
validated before the issues were written, and what is deferred.

## How a venture uses it

1. Register the venture as a client: it gets an id, a secret, and an exact
   list of redirect URIs. No wildcards.
2. Send people to `/authorize` with PKCE. They log in here, on
   `auth.factory0.ventures`, by any method.
3. Exchange the code at `/token` for a short-lived ES256 access token and a
   single-use refresh token.
4. Verify tokens locally with `factory0-auth-client`, which fetches and caches
   the published JWKS and checks the audience so nobody has to remember to.

## Modules

| Module | What it owns |
|---|---|
| `auth-core` | schema, clients, sessions, tokens, the authorization flow, account linking |
| `auth-passkeys` | WebAuthn registration and login |
| `auth-oidc` | Google and Apple: discovery, PKCE, ID tokens, minted Apple client secret, form_post callback |
| `auth-meta` | Facebook Login: OAuth 2.0 plus a Graph profile call, with no OpenID Connect anywhere. The data deletion callback is #18 |
| `auth-password` | argon2id registration and login, breach check |
| `auth-magic-link` | request and single-use consume |

## The login chooser

`/v1/auth-core/authorize` renders a sign-in page whenever there is no session.
Which buttons it offers is configuration, not discovery:

```
AUTH_CORE_LOGIN_METHODS=passkey,google,apple,meta
```

Order is display order. An unknown slug fails `validate_config`, which today
means `cargo test` catches it: nothing on the production boot path calls that
check, so at runtime an unknown slug is silently dropped and simply renders no
button. Setting a provider's credentials does **not** by
itself put it on the chooser: which methods a deployment offers is a decision.

Redirect-shaped methods are plain links and work with script switched off. A
passkey cannot be: a WebAuthn credential is bound to a relying-party id, and a
browser only runs a ceremony on a page whose origin matches, so a passkey
registered here works on this service's own pages and nowhere else. That is why
the chooser ships one small inline script, and why it ships it only when a
passkey is enabled. See [ADR 0103](docs/adr/0103-the-login-chooser-and-browser-side-methods.md).

## Status

Design adopted 2026-09-06. Three spikes come first; everything else is
blocked on them. Enterprise SAML SSO is deliberately deferred. Progress is in
the [issues](../../issues) and [milestones](../../milestones).

## License

MIT. Built in the open by [Factory Zero](https://factory0.ventures).
