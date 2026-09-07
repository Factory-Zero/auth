# auth-password

Email and password (issues #12, #19, #20). Mounted at `/v1/auth-password`.

The oldest login method and the only one where a stranger can simply keep
guessing, which is what most of this crate is about.

## It requires the paid Workers plan

ADR 0100 measured Argon2id at the parameters this uses (m=19456, t=2, p=1)
at roughly **40 ms per hash or verify** on Workers. The free tier's 10 ms
CPU limit cannot fit one verify at any sane parameters.

That is a deployment fact rather than a tuning knob: lowering the
parameters to fit the free tier would make the stored hashes worth less
than not having them.

## Routes

| Route | What it does |
|---|---|
| `POST /register` | `{ email, password }`. Always `202`, always the same body |
| `POST /login` | `{ email, password }`. A session cookie, or one refusal |
| `POST /change` | `{ current_password, new_password }`, for a signed-in person |

## Configuration

| Key | Default | Notes |
|---|---|---|
| `AUTH_PASSWORD_BREACH_CHECK` | `true` | Ask the Pwned Passwords range API about a new password |
| `AUTH_PASSWORD_LOCKOUT_THRESHOLD` | `10` | Failures in the window before the password locks |
| `AUTH_PASSWORD_LOCKOUT_WINDOW_SECS` | `3600` | The window failures are counted in |
| `AUTH_PASSWORD_LOCKOUT_SECS` | `900` | How long a lock lasts |

Ten failures is far above a person mistyping and far below a useful
guessing rate. Fifteen minutes is long enough to make guessing pointless
and short enough that somebody whose only login method is a password is
not stuck for the day.

Nonsense in any of these is a `validate_config` failure rather than a
silent fall back to the default — though note that nothing on the
production boot path calls `validate_config`
([Cratefield/harness#101](https://github.com/Cratefield/harness/issues/101)),
so today that means `cargo test` catches it.

## Three defences, and they are not the same defence

**The `RateLimiter` port** is keyed on the request. It slows one attacker
down and does nothing about one with a botnet. Keys include the normalised
address as well as the caller, so a distributed guess against one account
is still limited.

**The lockout** is keyed on the credential, so it survives an attacker
rotating IP addresses. It locks the **password**, not the account:
somebody locked out here can still sign in with a passkey or a provider,
which is what keeps the lockout from being a denial of service an attacker
can aim at a person by guessing wrongly on purpose.

**The `Captcha` port**, where a deployment provides one, is what makes the
first two expensive to reach. Not required — a module that refused to
start without a captcha would take the whole service down — but `fz
doctor` refuses a production venture with public writes and no captcha.

## Nothing here says whether an address has an account

- **Registration** answers `202` and the same body whether it created an
  account, found the address already registered, or was handed something
  that is not an address. The owner of an already-registered address is
  told by mail, through the `auth-password.duplicate_registration` event;
  the person at the keyboard learns nothing.
- **Login** answers identically for a wrong password, an unknown address,
  a disabled account and a locked one.
- **The timing does not answer either.** An unknown address is verified
  against a fixed dummy hash, so it costs the same Argon2id verify a real
  one does. Skipping that is how a "constant-time" login leaks anyway.

The one thing registration *does* say is that a password is unusable, and
only ever about the password in front of it: too short, too long, or in a
breach corpus. Refusing silently would leave somebody unable to sign in
later, and none of it reveals anything about anybody else.

## The breach check

Pwned Passwords k-anonymity: the first five hex characters of the SHA-1 go
to the range API, every suffix sharing that prefix comes back, and the
comparison happens here. **The password and its full hash never leave.**
SHA-1 is the corpus's index, not a security choice.

**Fail-open, deliberately.** A corpus that is unreachable is not a reason
to stop people registering: the alternative turns somebody else's outage
into ours, and the check is advice rather than authentication.

## Rehash on login

Login is the only moment the plaintext exists, so it is the only moment a
stored hash written at older parameters can be upgraded. A hash that
cannot be parsed is left alone: it will fail verification anyway, and
rehashing on the strength of an unreadable value would be guessing.

## Known gaps

- **The address is never verified here.** A new account is
  `primary_email_verified = 0`, and only a magic link (#21) can change
  that. The linking rules only auto-link a verified address, so registering
  must not be a way to claim one.
- **No account recovery.** Somebody who forgets their password has no way
  back in through this module; that is the magic link's job.
- The `auth-password.duplicate_registration` event says a mail should be
  sent. **Nothing sends it yet** — no mail module subscribes.
