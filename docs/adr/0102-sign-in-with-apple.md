# ADR 0102: Sign in with Apple's three departures from OIDC

Status: accepted, 2026-09-07

Resolves the spike in issue #3 and records the decisions issue #16 was built on.

## Context

Apple is an OpenID Connect provider, and the flow written for Google (#15)
is written against a provider descriptor precisely so a second provider is
data rather than a second copy of the flow. Apple is that test, and it
mostly passes it: discovery, PKCE, the ID token, the nonce, the linking
rules and the session are all shared, unchanged.

Three things are not shared, and each one breaks a naive integration in a
way that is hard to diagnose from the outside:

1. **The client secret is not a string.** Apple issues a `.p8` private key,
   and the client secret is an ES256 JWT signed with it, valid at most six
   months. There is nothing to paste into `AUTH_OIDC_APPLE_CLIENT_SECRET`.
2. **The authorization response arrives as a cross-site `form_post`.** Once
   `name` or `email` is requested, Apple posts the response to the redirect
   URI instead of redirecting to it. A browser sends no `SameSite=Lax`
   cookie on a cross-site POST, so the flow cookie the Google path relies on
   simply does not arrive.
3. **The person's name arrives exactly once.** It is in the first
   authorization's form body, as JSON in a `user` field, and never in the ID
   token and never again. If it is not captured then, it is gone.

A fourth difference surfaced while building: Apple accepts only
`client_secret_post` at the token endpoint and answers HTTP Basic with
`invalid_client`, which names nothing and reads exactly like a bad key.

## Decision

### 1. The client secret is minted, never stored

`AUTH_OIDC_APPLE_CLIENT_SECRET` does not exist and is **refused** if set,
rather than ignored: someone who sets one has misunderstood the setup, and
silently ignoring it leaves them debugging Apple's error instead of ours.
Apple is configured with four values:

| Setting | What it is |
| :--- | :--- |
| `AUTH_OIDC_APPLE_CLIENT_ID` | The Services ID. Also the JWT's `sub`. |
| `AUTH_OIDC_APPLE_TEAM_ID` | The Team ID. The JWT's `iss`. |
| `AUTH_OIDC_APPLE_KEY_ID` | The key's id. The JWT header's `kid`. |
| `AUTH_OIDC_APPLE_PRIVATE_KEY` | The `.p8` contents. A **Worker secret**. |

The key is never in D1, never in a repository, and never in a log: the
`AppleConfig` `Debug` is hand-written to print the two identifiers and
withhold the key, and the one error type is deliberately vague, because
the ways a PKCS#8 parse can fail are a description of the bytes it was
given.

`Minter::mint` signs `{alg: ES256, kid}` over
`{iss: team, iat, exp, aud: https://appleid.apple.com, sub: services_id}`
with `p256`, the same crate that signs this service's own access tokens
(ADR 0101). **Lifetime is one hour, not six months.** Nothing here needs
more than a single token exchange, so the lifetime is set by clock skew
rather than by convenience, and a secret that somehow escapes a log is
worthless within the hour. A `const` assertion keeps the lifetime under
Apple's ceiling at build time rather than in a test, because a secret past
it fails at Apple on every sign-in and in no test that does not call Apple.

The minted secret is cached in memory until five minutes before it expires,
keyed by the client id it was minted for: configuration can change under a
live isolate, and a secret whose `sub` names the old Services ID is refused
by Apple in a way that looks like a key problem.

**Rotation is a secret swap.** Replace `AUTH_OIDC_APPLE_PRIVATE_KEY` and
`AUTH_OIDC_APPLE_KEY_ID` together and redeploy. There is no stored secret
to rotate and no window in which two are valid, because every secret this
service presents was minted seconds earlier.

The `.p8` is accepted armoured or bare. An operator moving a key through a
secret store often loses the `-----BEGIN-----` lines, and refusing that
costs an afternoon for no security gain.

### 2. The flow cookie is widened to `SameSite=None`, not moved to a row

The descriptor gains a `ResponseMode`, and `SameSite=None; Secure` is set
for `form_post` providers only. Google's cookie is untouched.

The spike weighed the alternative, a D1 row keyed by the `state` value, and
rejected it for the reason the cookie exists at all: **a row is spendable by
anyone who saw the state**, in a redirect chain or a referrer, while a
cookie is bound to the browser that started the flow. Widening `SameSite`
gives up cross-site request protection that this cookie was never providing
on its own: it is signed so it cannot be forged, `__Host-` keeps it
origin-locked, it lives ten minutes, and the only thing a holder can do
with it is finish the flow it belongs to, which also needs Apple's own code
and a `state` that matches. The `state` comparison is what defends the
callback, and it happens before anything else, on the error path too.

### 3. The name is taken from the form body, once

`user` is parsed on the callback and fills `Identity.name` **only when the
ID token did not carry one**, so a provider that does send a name is never
overwritten by a form field. A malformed or absent `user` is not an error:
that is what every sign-in after the first looks like. A name with a control
character or over 200 characters is dropped rather than stored, because it
is displayed and Apple promises nothing about the bytes.

Where the name goes is not this module's decision. It is handed to the
linking rules as `IncomingIdentity.name` and stored as `name_at_link`, the
same as every other provider.

### 4. The token-endpoint auth method is pinned, not discovered

`Provider::auth_type` says `client_secret_post` for Apple and HTTP Basic for
Google, pinned in the descriptor for the same reason the signing algorithms
are: the alternative is believing a document fetched over the network. This
is the same class of trap as the HS256 one fixed in #15, where a discovery
document listing HS256 would have turned our own client secret into the
signing key.

### 5. Private relay addresses were already handled

Apple may return a `@privaterelay.appleid.com` address. It is a per-app
alias, so two different people can hold relay addresses that look equally
plausible, and one can never be evidence that an incoming identity is an
existing account. This rule landed with the linking work (#22) and needed
nothing here; `apple.rs` adds a test that proves it end to end through a
real Apple flow rather than through the rules in isolation.

## Consequences

- Apple is `PROVIDERS[1]` and the flow did not fork. The only Apple-shaped
  code is `apple.rs`, two enum variants on the descriptor and one extra
  route method.
- A half-configured Apple block fails `validate_config`, naming the missing
  keys, so `fz doctor` and `Harness::build` refuse it rather than answering
  requests that will fail at Apple later.
- `p256` gains the `pkcs8` and `pem` features. Both are pure Rust and the
  workspace still builds to `wasm32` with no `openssl`, `reqwest` or `mio`
  in the tree.
- The token endpoint is reached with the credentials in the body for Apple
  and in the header for Google, which is now visible in the descriptor
  rather than implied by whatever each provider's document happens to say.

## What is not proven

Every test here runs against a fake Apple: real ES256 minting, a real
`form_post` body, a real RS256 ID token verified through the real
verification path, and Apple's own discovery shape. **Nothing has talked to
Apple.** No Apple Developer account, Services ID or `.p8` exists on this
machine, so these remain untested against the live provider:

- that Apple accepts a secret minted exactly this way,
- that the registered return URL matches byte for byte,
- the real `user` field's shape on a first authorization.

Issue #16's last acceptance criterion, a manual run against a staging
Services ID, stays open for whoever has the account. The runbook it needs
is in `docs/ARCHITECTURE.md`.
