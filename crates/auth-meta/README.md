# auth-meta

Facebook Login (issue #17). Mounted at `/v1/auth-meta`.

Its own crate rather than a provider on `auth-oidc`, because Meta is **not**
an OpenID Connect provider: no discovery document, no ID token, no nonce.
What comes back from the authorization code is a plain OAuth 2.0 access
token, and who the person is comes from a Graph call made with it.
See [ADR 0104](../../docs/adr/0104-facebook-login-without-openid-connect.md).

## Routes

| Route | What it does |
|---|---|
| `GET /start?return_to=/path` | Builds the authorization URL with PKCE, seals the flow into a signed cookie, redirects |
| `GET /callback?code&state` | Verifies the flow, exchanges the code, fetches the profile, applies the linking rules, issues a session |

## Configuration

| Key | Required | Notes |
|---|---|---|
| `AUTH_META_CLIENT_ID` | yes | The Meta app id |
| `AUTH_META_CLIENT_SECRET` | yes | The app secret. A Worker secret |
| `AUTH_META_REDIRECT_BASE` | yes | The public origin. The redirect URI is `<base>/v1/auth-meta/callback` and must match the app's registration exactly |
| `AUTH_META_GRAPH_VERSION` | no | Defaults to `v21.0`. **Check it before deploying** |
| `AUTH_META_DEFAULT_RETURN_TO` | no | Defaults to `/` |

Setting neither credential is a valid deployment: a venture that does not
offer Facebook simply leaves them unset. Setting one is a build failure.

The Graph version is configurable because Meta retires a version roughly two
years after release, and an expired one starts answering errors. The default
is the version this was written against, not a promise about today.

## The email is never stored as verified

The decision this module turns on. Meta returns `email` only when the person
granted the permission, and does not assert verification in a form this
service can rely on.

An address recorded as verified is a **key**: the linking rules auto-link an
incoming identity to an existing account when both sides have verified the
same address. Believing Meta would mean anyone who can get an address onto a
Facebook account walks into the matching account here. So `email_verified` is
hard-coded `false`.

The cost is accepted: a Meta sign-in whose address already belongs to an
account does not link, and the person is told to sign in the way they already
can and link from there.

## What guards what

**The flow cookie is the only thing that makes a callback ours.** Signed,
`__Host-` prefixed, ten minutes, holding the `state` to compare, the PKCE
verifier and where to go afterwards. `SameSite=Lax`, because Meta redirects
rather than posting — the `SameSite=None` that Apple's `form_post` needs
would be a widening with nothing asking for it.

**Nothing is cleared before the state matches.** An unverified request is not
evidence of anything.

**PKCE is used** even though Meta does not require it, so a leaked
authorization code is not enough on its own.

**No `debug_token` call.** The access token arrived on a back-channel
response to a request this service made, to Meta's own token endpoint,
authenticated with the app secret, so it is by construction a token issued to
this app. That reasoning does **not** extend to a token handed to us by a
browser or an app; this service never accepts one, and a path that did would
need `debug_token`.

**The profile token goes in a header**, never the query string: a URL reaches
proxy logs and referrers.

**Nothing Meta says is rendered.** It can put anything in
`error_description`; it is logged and never echoed.

## App-scoped ids

Meta's `id` identifies the person *to this app*. Changing the Meta app means
every Meta identity row stops matching and the people behind them cannot sign
in that way any more. Stored as returned, and said here rather than
discovered later.

## Known gaps

- **The data deletion callback is not built** (#18). Meta will not approve the
  app for public use without one. ADR 0104 decides what it deletes.
- **No manual run against a real Meta app.** Everything here is exercised
  against a fake that serves the token endpoint and the Graph profile shape,
  which covers this module's logic but not Meta's own behaviour: whether the
  dialog accepts these parameters, whether the redirect URI matches, the real
  shape of a Graph error, and whether `v21.0` is still served.
