-- A signature counter that goes backwards is the one signal WebAuthn gives a
-- relying party that an authenticator may have been cloned (issue #14). The
-- login refuses, and the credential is marked here so the refusal survives
-- the request and a person can see why on the account page.
ALTER TABLE credentials ADD COLUMN passkey_suspect_at TEXT;
