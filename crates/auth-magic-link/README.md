# auth-magic-link

Sign in by email (issue #21). Mounted at `/v1/auth-magic-link`.

A magic link is a **bearer credential sent over email** — a channel this
service does not control and cannot audit. Everything here follows from
that: 32 random bytes, stored only as a SHA-256, valid fifteen minutes,
single-use under concurrency rather than by convention.

It is also the answer to three things other modules leave undone:

- **Verifying an address.** Password registration creates an account with
  `primary_email_verified = 0`, because registering must not be a way to
  claim somebody else's address. Consuming a link sent to that address is
  the proof, and the linking rules only ever auto-link a verified one.
- **Getting back in.** A password lockout is deliberately not a dead end,
  and a passwordless account has no other way in at all.
- **Registration by mail**, for a venture that wants no passwords.

## Routes

| Route | What it does |
|---|---|
| `POST /request` | `{ email, return_to? }`. Always `202`, always the same body |
| `GET /consume?token=…` | The URL in the mail. Signs in, or shows a confirm button |
| `POST /consume` | The confirm button |

## Configuration

| Key | Required | Notes |
|---|---|---|
| `AUTH_MAGIC_LINK_PUBLIC_BASE` | yes | The origin the mailed link points at |
| `AUTH_MAGIC_LINK_MAIL_FROM` | yes | The `From` address. Its domain must be verified with the mailer |
| `AUTH_MAGIC_LINK_TTL_SECS` | no | Default 900. Accepted range 60–86400 |
| `AUTH_MAGIC_LINK_ALLOW_REGISTRATION` | no | Default **false** |
| `AUTH_MAGIC_LINK_DEFAULT_RETURN_TO` | no | Default `/` |

A link that lasts a day is a password with a long tail; one that lasts a
minute does not survive a slow mail queue. Hence the range.

**Registration is off by default and that is deliberate.** With it on,
anyone can create an account for any address they can type. A venture that
wants passwordless sign-up turns it on knowing that.

## Mail clients prefetch links

Outlook, corporate scanners and several mobile clients fetch every URL in a
message to check it for malware. A prefetch that consumed a single-use
token would sign nobody in and leave the person holding a link that has
already been used — the failure mode that makes people give up on magic
links entirely.

So `GET /consume` only signs somebody in when the request **looks like a
person clicking**: `Sec-Fetch-Mode: navigate` and `Sec-Fetch-Dest:
document`, which every current browser sends on a top-level navigation and
an out-of-band fetch does not. Anything else gets a confirm button.

**What the heuristic does not catch**, said plainly because it matters: a
scanner that copies a browser's headers, or one that renders the message in
a real browser engine. What it must never do is refuse a real person, so a
request with no fetch metadata at all — an old browser, a stripped proxy —
gets the button rather than a refusal. That costs one click and works
everywhere.

The prefetch page is also not an oracle: a real token and an invented one
get the same page, and nothing is read or spent to produce it.

## Single-use under concurrency

`consume_single_use_token` updates `where consumed_at is null and
expires_at > now` and checks the affected row count. Two simultaneous
consumes therefore produce **one session and one refusal**, rather than two
sessions or a lost update. Tested by driving both futures together;
replacing the statement with a read-then-write fails that test.

## What a caller can never learn

- A known and an unknown address get the same `202` and the same body.
- So does a disabled account, and so does a string that is not an address.
- An expired token, an already-used one, and one that was never issued all
  fail identically.
- A token of another kind — an authorization code, say — is refused here
  rather than turned into a session.
- The address is never written to a log. A log line naming who asked to
  sign in is exactly what this endpoint refuses to say out loud.

## The mail

Rendered through the harness template registry under
`auth-magic-link/sign-in`, so a venture can override the wording, with the
compiled default as the fallback. The **text part carries the raw link**,
because a client that shows only text must still be usable, and the HTML
part carries it twice — once as a button, once as copyable text — for
clients that strip anchors.

## Known gaps

- **Nothing rate-limits per address across deployments.** The `RateLimiter`
  port is per-isolate where the adapter is in-memory; a KV-backed limiter
  is the deployment's choice.
- **No "resend" throttle beyond the rate limiter.** Asking twice sends two
  mails, both valid until one is used.
- **The link does not carry the client's `state`.** A magic link that
  resumes a pending `/authorize` carries it as `return_to`, which is enough
  today because `/authorize` re-reads its own query.
