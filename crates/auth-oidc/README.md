# auth-oidc

OpenID Connect login (issues #15, #16). Google and Apple. The flow is written
against a provider descriptor, so a provider arrives as data plus whatever
quirk it insists on, rather than as a second copy of the flow.

Mounted at `/v1/auth-oidc`.

## Routes

| Route | What it does |
|---|---|
| `GET /{provider}/start?return_to=/path` | Builds the authorization URL with PKCE, seals the flow into a signed cookie, redirects |
| `GET /{provider}/callback?code&state` | The redirect callback. Google. |
| `POST /{provider}/callback` | The `form_post` callback, form-encoded. Apple. |

All are public. An unknown provider is a 404; a known one whose credentials
are not configured says so rather than failing obscurely. Each provider
answers on exactly one callback method and 404s on the other, so an
authorization response cannot be delivered through a path its provider
never uses.

## Configuration

| Key | Required | Notes |
|---|---|---|
| `AUTH_OIDC_REDIRECT_BASE` | yes | The public origin. The redirect URI is `<base>/v1/auth-oidc/<provider>/callback` and must match what the provider has registered, exactly |
| `AUTH_OIDC_GOOGLE_CLIENT_ID` | per provider | |
| `AUTH_OIDC_GOOGLE_CLIENT_SECRET` | per provider | A Worker secret |
| `AUTH_OIDC_APPLE_CLIENT_ID` | for Apple | The **Services ID**, not the App ID |
| `AUTH_OIDC_APPLE_TEAM_ID` | for Apple | Ten characters, from the developer console |
| `AUTH_OIDC_APPLE_KEY_ID` | for Apple | The signing key's id |
| `AUTH_OIDC_APPLE_PRIVATE_KEY` | for Apple | The `.p8` contents. A Worker secret. Armoured or bare |
| `AUTH_OIDC_DEFAULT_RETURN_TO` | no | Defaults to `/` |

Half a credential is a configuration error rather than a runtime surprise:
a provider with an id and no secret would answer 503 with nothing to say why.
Apple has **no** `_CLIENT_SECRET`, and setting one is refused rather than
ignored, because the secret is minted from the signing key and a configured
one would be silently unused.

### Setting Apple up

1. In the Apple Developer console, create a **Services ID**. That string is
   `AUTH_OIDC_APPLE_CLIENT_ID`; the App ID is not.
2. Register the return URL on the Services ID **exactly**:
   `<AUTH_OIDC_REDIRECT_BASE>/v1/auth-oidc/apple/callback`. Apple matches it
   byte for byte, and the domain must be verified first.
3. Create a **Sign in with Apple** key and download the `.p8` **once**. Its
   key id is `AUTH_OIDC_APPLE_KEY_ID`; the file's contents are
   `AUTH_OIDC_APPLE_PRIVATE_KEY`, set with `wrangler secret put`.
4. Rotating the key is a secret swap: replace the `.p8` and the key id
   together and redeploy. There is no stored client secret to rotate.

Apple's button assets and their usage rules come from Apple and are the
consuming app's business, not this service's.

## What guards what

**The flow cookie is the only thing that makes a callback ours.** It is
signed, `__Host-` prefixed, and holds the `state` to compare, the `nonce` the
ID token must echo, the PKCE verifier and where to go afterwards. A callback
without it, with a tampered one, with one issued for another provider, or
with one older than ten minutes is refused before anything is exchanged.

It is `SameSite=Lax` rather than `Strict` for a redirect callback: that
callback arrives as a top-level navigation from the provider, and `Strict`
would withhold the cookie on exactly that request.

For a `form_post` provider it is `SameSite=None; Secure`, because a browser
sends **no** `Lax` cookie on a cross-site POST: with `Lax` there, the cookie
never arrives, every Apple sign-in reads as an expired flow, and nothing in
the logs says why. Widening it gives up little — the cookie is signed,
`__Host-` locked, ten minutes old at most, and useless without Apple's own
code and a matching `state` — and the alternative, a row keyed by the state,
is worse: a row is spendable by anyone who saw the state in a redirect chain
or a referrer, while a cookie is bound to the browser that started the flow.
See [ADR 0102](../../docs/adr/0102-sign-in-with-apple.md).

**The expiry lives in the signed payload**, not in the signer's own `exp`,
because `Signer::verify` compares against the wall clock rather than the
`Clock` port. Putting it in the payload is what makes it testable and what
keeps it agreeing with a test clock.

**`return_to` may only be a path on this service.** An absolute URL, a
protocol-relative `//`, or a backslash a browser may normalise into one would
each turn a login endpoint into an open redirect, which is how a login flow
becomes a phishing laundry.

**Nothing from the provider is rendered.** A provider can put anything in
`error_description`; it is logged and never echoed.

## Discovery

Cached per isolate for an hour, because it is two network calls that would
otherwise run on every login. The cache holds signing keys, so an ID token
naming a key the cached JWKS has never seen triggers exactly one forced
refresh: a provider rotating keys must not lock everyone out until the
isolate recycles. That path is only reachable after a genuine token
exchange, and it is throttled so a provider that is simply broken cannot
turn every login into a discovery request.

## Apple's three differences

The rest of Apple is ordinary OIDC. These are not, and each fails in its own
unhelpful way when it is got wrong. All three are in
[ADR 0102](../../docs/adr/0102-sign-in-with-apple.md).

1. **The client secret is minted, not configured.** An ES256 JWT over the
   `.p8`, one hour long, cached until five minutes before it expires and
   re-minted when the Services ID changes under a live isolate.
2. **The callback is a cross-site `POST`.** Hence the second route and the
   cookie policy above.
3. **The name arrives exactly once**, as JSON in the first authorization's
   `user` form field and never in the ID token. It is captured there, only
   when the ID token carried no name, and dropped if it holds a control
   character or runs past 200 characters.

A fourth, found while building: Apple accepts only `client_secret_post` and
answers HTTP Basic with `invalid_client`, which names nothing and reads like
a bad key. The token-endpoint auth method is pinned per provider in the
descriptor rather than read from the discovery document, the same way the
signing algorithms are.

Apple may also return a `@privaterelay.appleid.com` address. It is a per-app
alias, so it can never be evidence that an incoming identity is an existing
account; `auth-core::linking` has enforced that since #22.

## What this module does not decide

Which account an identity belongs to. `auth-core::linking` owns those rules
(#22) — they are the same for every method that arrives with an email — and
this module carries out what they return:

- a known identity signs in;
- a verified address on both sides links to the existing account, and an
  event carries the address that should be told;
- an address only one side has verified is **not** guessed: the person is
  told to sign in the way they already can and link from there;
- otherwise a new account, recording exactly what the provider vouched for.
  An unverified address is stored unverified, because storing it as verified
  would let the next provider auto-link a stranger's account to this one.

Confirming a link while signed in (`Outcome::ConfirmLink`) needs a page that
does not exist yet; the callback says so plainly rather than guessing.

## Known gaps

- The login chooser at `/v1/auth-core/authorize` does not offer this yet:
  `enabled_login_methods()` still returns nothing, and wiring it needs a
  decision about the methods that need a page rather than a link.
- No manual run against real Google or real Apple yet. Everything here is
  exercised against a fake provider that mints real RS256 ID tokens and
  serves each provider's own discovery shape, which covers the verification
  path but not the providers' own quirks. For Apple that specifically leaves
  untested: that it accepts a secret minted this way, that the registered
  return URL matches, and the real `user` field's shape.
