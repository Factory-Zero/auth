-- auth issue #5: the D1 schema. Column set, constraints and comments
-- follow the issue's DDL; the four indexes it names are at the bottom.
-- Harness portable SQL subset (harness issue #8): ULID text ids,
-- ISO-8601 text timestamps, no dialect functions.

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    display_name TEXT,
    primary_email TEXT,
    primary_email_verified INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL CHECK (status IN ('active','disabled')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS identities (            -- one row per linked provider
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    provider TEXT NOT NULL CHECK (provider IN ('google','apple','meta','password','magic_link','passkey')),
    provider_subject TEXT NOT NULL,                -- sub / Graph id / normalized email for password and magic link
    email TEXT,
    email_verified INTEGER NOT NULL DEFAULT 0,
    name_at_link TEXT,
    created_at TEXT NOT NULL,
    last_login_at TEXT,
    UNIQUE (provider, provider_subject)
);

CREATE TABLE IF NOT EXISTS credentials (           -- passkeys and password hashes
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    kind TEXT NOT NULL CHECK (kind IN ('passkey','password')),
    passkey_credential_id BLOB,
    passkey_public_key_cose BLOB,                  -- COSE key: public by design
    passkey_sign_count INTEGER,
    passkey_aaguid BLOB,
    passkey_transports TEXT,
    password_hash TEXT,                            -- argon2id PHC string
    label TEXT,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    UNIQUE (passkey_credential_id)
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    token_hash BLOB NOT NULL UNIQUE,               -- sha256 of the cookie value; the value itself is never stored
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    ip_hash TEXT,
    ua_family TEXT
);

CREATE TABLE IF NOT EXISTS single_use_tokens (     -- magic links, webauthn challenges, authorization codes
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('magic_link','webauthn_challenge','authorization_code')),
    token_hash BLOB NOT NULL UNIQUE,
    user_id TEXT,
    client_id TEXT,
    payload TEXT,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);

CREATE TABLE IF NOT EXISTS clients (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('confidential','public')),
    status TEXT NOT NULL CHECK (status IN ('active','disabled')),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS client_redirect_uris (
    client_id TEXT NOT NULL REFERENCES clients(id),
    uri TEXT NOT NULL,
    PRIMARY KEY (client_id, uri)
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_identities_user_id ON identities (user_id);
CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials (user_id);
CREATE INDEX IF NOT EXISTS idx_single_use_tokens_expires_at ON single_use_tokens (expires_at);
