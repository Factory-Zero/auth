# ADR 0104: Facebook Login, which is OAuth 2.0 and nothing else

Status: accepted, 2026-09-07

Resolves the spike in issue #4 and records the decisions issue #17 was built
on. The data deletion callback is #18 and is decided here but not built.

## Context

Every other provider this service speaks to is an OpenID Connect provider:
there is a discovery document, an ID token, a JWKS, and a nonce that binds
the token to the flow. Meta has none of them. Facebook Login is plain
OAuth 2.0, and who the person is comes from a Graph API call made with the
resulting access token.

That is a real difference, not a quirk to absorb: the thing that makes an
identity is no longer a signed assertion we verify, but an answer to a call
we make. So `openidconnect` does not fit and neither does the provider
descriptor in `auth-oidc`, which is written around discovery and ID tokens.

## Decision

### 1. Its own crate, on `oauth2`

`factory0-auth-meta`, using `oauth2` directly — the crate `openidconnect` is
built on, already in the tree and already proven to reach wasm32 with default
features off (ADR 0100).

The endpoints are constants rather than discovery, built from one configured
Graph version:

| Step | Endpoint |
| :--- | :--- |
| Authorize | `https://www.facebook.com/<version>/dialog/oauth` |
| Token | `https://graph.facebook.com/<version>/oauth/access_token` |
| Profile | `https://graph.facebook.com/<version>/me?fields=id,name,email` |

**The Graph version is configuration** (`AUTH_META_GRAPH_VERSION`, default
`v21.0`). Meta retires a version roughly two years after release and an
expired one starts answering errors, so an operator must be able to move it
without waiting for a release. The default is the version this was written
against, not a claim about today; check it before a deployment.

PKCE is used even though Meta does not require it, so a leaked authorization
code is not enough on its own. The app secret goes in the request body
(`client_secret_post`), pinned in the client rather than left to a default,
because Meta does not accept HTTP Basic.

### 2. The email is **never** stored as verified

This is the decision that matters. Meta returns `email` only when the person
granted the permission, and does not assert verification in a form this
service can rely on.

An address recorded as verified is a key, not a label: the linking rules
(#22) auto-link an incoming identity to an existing account when both sides
have verified the same address. So believing Meta here would mean that
anyone who can get an address onto a Facebook account can walk into the
matching account on this service. The address is stored, unverified, and
`email_verified` is hard-coded `false` rather than read from anything.

The cost is real and accepted: a Meta sign-in whose address already belongs
to an account does not link. The person is told to sign in the way they
already can and link from there — the same answer any unverified provider
gets, and the same answer they would get from a provider that simply did not
send an address.

### 3. No `debug_token` call

The spike asked whether to verify the token belongs to our app with
`debug_token` or to rely on the exchange. **Rely on the exchange.** The
access token arrived on a back-channel response, to a request this service
made, to Meta's own token endpoint, authenticated with the app secret. It is
by construction a token issued to this app. `debug_token` would re-ask a
question the exchange already answered, and would put a second round trip on
every sign-in.

The confused-deputy problem `debug_token` exists to solve is real for a
*client-side* token — one handed to us by a browser or an app, where we have
no idea who obtained it. This service never accepts one of those. If it ever
does, that path needs `debug_token` and this decision does not cover it.

### 4. App-scoped ids are the subject, and are not portable

Meta's `id` identifies the person **to this app**. The same human on a
different Meta app has a different id. It is stored as returned, and the
consequence is written down here rather than discovered later: changing the
Meta app means every Meta identity row stops matching, and the people behind
them cannot sign in that way any more.

### 5. Data deletion, decided here and built in #18

Meta requires a data deletion callback before an app leaves development mode.
`POST /meta/data-deletion` receives a `signed_request`: base64url payload plus
an HMAC-SHA256 over it with the app secret, verified in constant time before
anything is read.

**What "deletion" means here:** unlink the Meta identity; delete the user
entirely only when no other identity and no other credential remains.
Anything else would let a deletion request from one provider destroy an
account somebody still reaches another way — and Meta's request is about
Meta's data, not about the account.

Not built in #17. It needs a job row and a status page, which is #18.

## Consequences

- `auth-meta` owns no tables and adds no migrations, like every other login
  method. `auth-core` owns the schema and the linking rules.
- The step that turns a verified identity into a session moved to
  `auth-core::federated` in this change, so Google, Apple and Meta share one
  copy. It had been duplicated once; a third copy would have made it a
  pattern, and issue #37 is a bug that would need fixing in each.
- The workspace gains `oauth2` as a direct dependency. It was already in the
  tree under `openidconnect`.

## What is not proven

Everything here runs against a fake Meta: a real token-endpoint shape, a
real Graph profile shape, and the real `oauth2` client making the request.
**Nothing has talked to Meta.** There is no Meta app, no app secret and no
test user on this machine, so these are untested against the live provider:

- that the authorization dialog accepts these parameters as sent,
- that the registered redirect URI matches,
- the real shape of a Graph error,
- whether `v21.0` is a version Meta still serves.

Issue #17's last acceptance criterion, a manual run with a Meta test app,
stays open for whoever has the account.
