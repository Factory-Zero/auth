# ADR 0103: The login chooser, and where a browser-side method runs

Status: accepted, 2026-09-07

Resolves the decision issue #33 asked for: does this service ship a login page
with script, or does the chooser only ever list redirect-shaped methods?

## Context

`/v1/auth-core/authorize` renders a login chooser whenever there is no
session. Three login methods now work — passkeys (#13, #14), Google (#15) and
Apple (#16) — and the chooser offered none of them, because
`enabled_login_methods()` returned an empty `Vec`. Every method that landed
made that more wrong, and none could fix it alone: the chooser belongs to
`auth-core` and the methods live in other crates.

The two shapes are genuinely different, which is why this waited:

- **Google and Apple are links.** `GET /v1/auth-oidc/<provider>/start` is a
  redirect. A button needs nothing but an `href`.
- **A passkey is not.** `POST /login/options`, then a WebAuthn ceremony in the
  browser, then `POST /login/verify`. That is script, and there was no page in
  this service that ran any.

## Decision

### 1. This service ships the page, because nothing else can

Not a preference. A WebAuthn credential is bound to a **relying-party id**
(`AUTH_PASSKEYS_RP_ID`), and a browser will only run a ceremony when the RP id
matches the origin of the page asking. A passkey registered here can therefore
only ever be exercised on a page this service serves.

So the alternative — "browser-side methods are the consuming app's problem" —
is not a trade-off with a downside. It is impossible. A venture on
`undercoverrockstars.com` cannot run a ceremony for RP id
`auth.factory0.ventures` no matter what code it ships. Either this service
renders a page with script, or **passkeys are unreachable through the
authorization flow** and only usable by whatever calls the API directly.

The page is therefore ours. It is one `<script>` inline in the chooser
template, dependency-free, and emitted **only when a passkey is among the
enabled methods**. A chooser that offers only links ships no script at all.

This also settles the two questions #33 said it would. Passkey *registration*
(left hanging by #13) belongs on a page of this service's for the same reason,
and #31's step-up re-authentication has somewhere to happen.

### 2. Redirect-shaped methods stay plain links

They work with script switched off, and they should keep working. The passkey
button is the exception, not the pattern: it starts hidden and reveals itself
only once the browser has proved it has `PublicKeyCredential`, because a button
that cannot work should not be offered.

### 3. The enabled methods are configuration, not discovery

`AUTH_CORE_LOGIN_METHODS` is a comma-separated list of slugs, and the catalogue
of what each slug means — label, path, whether it is scripted — lives in
`auth-core`, because the chooser is `auth-core`'s page.

Deliberately **not** sniffed from the other modules' config keys
(`AUTH_OIDC_GOOGLE_CLIENT_ID` and friends). `auth-core` does not depend on the
login-method crates and should not learn their configuration either; and a
method whose module is not mounted would otherwise get a button that 404s.
An unknown slug fails `validate_config`, naming what the chooser does know, so
a typo is a build failure rather than a dead button.

The cost is that configuring Google is two settings rather than one. That is
the right way round: which methods a deployment *offers* is a decision, not a
consequence of which secrets happen to be set.

### 4. `return_to` carries the pending request, and never enters the script

Every button carries the `/authorize` that rendered the chooser, percent-encoded,
so a person lands back on the request they started rather than on the service
root with their sign-in lost. `OriginalUri` and not `Uri`, because the module is
nested under `/v1/auth-core` and a nested handler sees the prefix already
stripped.

That value holds the caller's own query parameters, so it reaches the page as a
**data attribute** and is read with `getAttribute`, never interpolated into the
script body. As it happens `http::Uri` refuses a raw `<`, so the HTTP path
cannot express the attack today — which is exactly why the escaping is proved
by rendering the template directly with a value no request could carry. The
defence should not rest on a property of the URI parser.

## Consequences

- The chooser works: with `passkey,google,apple` configured it offers three
  buttons and returns to the pending `/authorize`.
- With nothing configured the existing empty state still renders, and ships
  no script.
- Adding a redirect-shaped provider is one row in the catalogue.
- `auth-core` still depends on none of the login-method crates.

## What is not decided here

Passkey **registration** and account management still have no page. This ADR
says where they belong; it does not build them. The chooser also does not yet
offer a way to start a sign-up, only a sign-in, because every method here
either creates an account on first use or is added from an account page that
does not exist yet.
