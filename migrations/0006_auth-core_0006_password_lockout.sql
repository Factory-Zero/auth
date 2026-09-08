-- Password login is the one method a stranger can attack by guessing, so
-- it needs a per-account counter the rate limiter cannot provide (issue
-- #12). The RateLimiter port is keyed on the request; this is keyed on the
-- account, and survives an attacker rotating IP addresses.
--
-- On the credential rather than on the user, because it is the password
-- that gets locked: a person locked out of their password can still sign
-- in with a passkey or a provider, which is exactly the escape hatch the
-- lockout depends on for not being a denial of service against them.
ALTER TABLE credentials ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0;

-- When the window the failures were counted in began. A count with no
-- window is a lifetime total, which locks out anyone who has ever
-- mistyped enough times across years.
ALTER TABLE credentials ADD COLUMN failed_window_started_at TEXT;

-- Set when the count crosses the threshold. Until it passes, a correct
-- password is refused too: that is the point.
ALTER TABLE credentials ADD COLUMN locked_until TEXT;
