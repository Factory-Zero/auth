-- auth issue #9: token issuing. Two schema changes, both additive in
-- effect:
--
-- 1. sessions grows amr: the JSON array of authentication-method
--    references recorded at login (RFC 8176), read back into every
--    access token. NULL until the first login method exists (issues
--    #13-#22); the token claim is an empty array in that case.
-- 2. single_use_tokens grows the refresh_token kind: opaque
--    single-use refresh tokens are rows of this table, bound to a
--    session. SQLite cannot ALTER a CHECK constraint, so the table is
--    rebuilt with the extended kind list and the rows copied across,
--    inside one migration. Harness portable SQL subset (harness issue
--    #8): plain DDL, no dialect functions.

ALTER TABLE sessions ADD COLUMN amr TEXT;             -- JSON array of RFC 8176 method refs

CREATE TABLE IF NOT EXISTS single_use_tokens_rebuild (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('magic_link','webauthn_challenge','authorization_code','refresh_token')),
    token_hash BLOB NOT NULL UNIQUE,                 -- sha256 of the presented value; the value itself is never stored
    user_id TEXT,
    client_id TEXT,
    payload TEXT,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);

INSERT INTO single_use_tokens_rebuild (id, kind, token_hash, user_id, client_id, payload, expires_at, consumed_at)
    SELECT id, kind, token_hash, user_id, client_id, payload, expires_at, consumed_at
    FROM single_use_tokens;

DROP TABLE single_use_tokens;
ALTER TABLE single_use_tokens_rebuild RENAME TO single_use_tokens;

CREATE INDEX IF NOT EXISTS idx_single_use_tokens_expires_at ON single_use_tokens (expires_at);
