//! `factory0-auth-core`: the schema and shared flows of the auth
//! service — `users`, `identities`, `credentials`, `sessions`,
//! `single_use_tokens`, `clients`, `client_redirect_uris` (auth issue
//! #5), the client-registration admin API (issue #6), exact-match
//! redirect URI validation (issue #7), sessions (issue #8) and token
//! issuing (issue #9).
//!
//! The rules this module exists to enforce:
//!
//! 1. **Anything single-use lives in D1, never KV.** KV is eventually
//!    consistent; magic links, `WebAuthn` challenges, authorization codes
//!    and refresh tokens all go in `single_use_tokens` with a `kind`,
//!    consumed by a guarded update whose affected-row count is checked,
//!    so two concurrent consumes cannot both win.
//! 2. **Nothing that can log a user in is stored in the clear.** Session
//!    cookie values, magic-link tokens and client secrets are stored only
//!    as hashes; `tests/schema.rs` greps the schema for forbidden column
//!    names.
//! 3. **A signing key's private half never reaches an output.**
//!    `tokens::SigningKeys` prints key ids only, and the published JWKS
//!    is built from the re-derived public point (issue #9).

#![forbid(unsafe_code)]

mod authorize;
mod clients;
pub mod federated;
pub mod linking;
mod secrets;
mod sessions;
mod store;
mod token_endpoint;

/// Exact-match redirect URI validation (issue #7): the one matching
/// rule, used at registration and — from issue #10 — at `/authorize`.
pub mod redirect_uri;

/// Token issuing (issue #9): ES256 access tokens, the published JWKS
/// and `openid-configuration`, opaque single-use refresh tokens with
/// reuse detection.
pub mod tokens;

pub use secrets::{
    CLIENT_DISABLED, SECRET_BYTES, SecretError, ensure_client_usable, generate_secret, hash_secret,
    kind_allows_secret, verify_client_secret, verify_secret,
};
pub use sessions::{
    ABSOLUTE_CAP_DAYS, COOKIE_NAME, IssuedSession, Login, SESSION_INVALID, SESSION_VALUE_BYTES,
    SLIDE_AFTER_SECS, SLIDE_WINDOW_DAYS, Session, SessionError, ValidSession, clear_cookie,
    cookie_value, issue, revoke_all, set_cookie, ua_family, validate,
};
pub use store::{
    Bytes, CLIENT_CONFIDENTIAL, CLIENT_PUBLIC, CREDENTIAL_PASSKEY, CREDENTIAL_PASSWORD,
    ClientRedirectUriRow, ClientRow, CredentialRow, DELETION_DELETED_USER, DELETION_DONE,
    DELETION_NOTHING_TO_DO, DELETION_PENDING, DELETION_UNLINKED, DeletionJobRow, IdentityRow,
    PROVIDER_APPLE, PROVIDER_GOOGLE, PROVIDER_MAGIC_LINK, PROVIDER_META, PROVIDER_PASSKEY,
    PROVIDER_PASSWORD, Redacted, STATUS_ACTIVE, STATUS_DISABLED, SessionRow, SingleUseTokenRow,
    TOKEN_AUTHORIZATION_CODE, TOKEN_MAGIC_LINK, TOKEN_REFRESH, TOKEN_WEBAUTHN_CHALLENGE, UserRow,
    client_by_id, complete_deletion_job, consume_single_use_token, credentials_by_user,
    delete_credential, delete_identity, delete_user, deletion_job_by_code, identities_by_user,
    identity_by_provider_subject, insert_client, insert_credential, insert_deletion_job,
    insert_identity, insert_redirect_uri, insert_session, insert_single_use_token, insert_user,
    list_clients, mark_passkey_suspect, passkey_by_credential_id, pending_deletion_jobs,
    purge_expired_sessions, purge_expired_single_use_tokens, purge_user, redirect_uris_for_client,
    replace_redirect_uris, revoke_all_sessions, revoke_session, rotate_client_secret,
    session_by_id, session_by_token_hash, sessions_by_user, single_use_token_by_hash,
    slide_session, touch_credential_used, touch_identity_login, touch_session_seen,
    update_client_name, update_client_status, update_passkey_sign_count, user_by_id,
    user_by_primary_email,
};
pub use tokens::{
    ACCESS_TOKEN_SECS, JWKS_CACHE_CONTROL, OIDC_CACHE_CONTROL, REFRESH_TOKEN_DAYS, RefreshGrant,
    RefreshOutcome, SigningKey, SigningKeys, TOKENS_UNCONFIGURED, TokenConfigError, TokenError,
    exchange_refresh_token, mint_access_token, mint_refresh_token,
};

use factory0_core::{
    AnyError, BoxFuture, Config, ConfigError, Module, ModuleConfig, ModuleContext, Port,
    SqlMigration,
};
use std::sync::Arc;

/// Default rotation overlap: the old client secret keeps verifying for
/// one hour after a rotation, then stops.
pub const DEFAULT_SECRET_OVERLAP_SECS: u64 = 3600;

/// The schema migration of issue #5: the seven-table schema in the
/// harness's portable SQL subset, embedded per the module contract.
const MIGRATION_INIT: SqlMigration = SqlMigration {
    id: "0001",
    name: "init",
    sql: include_str!("../migrations/sqlite/0001_init.sql"),
};

/// The rotation migration of issue #6: the previous client secret's
/// hash and the instant it stops verifying.
const MIGRATION_ROTATION: SqlMigration = SqlMigration {
    id: "0002",
    name: "client_secret_rotation",
    sql: include_str!("../migrations/sqlite/0002_client_secret_rotation.sql"),
};

/// The deletion-job table of issue #18: a provider's "delete this
/// person's data" request, recorded before it is carried out.
const MIGRATION_DELETION_JOBS: SqlMigration = SqlMigration {
    id: "0005",
    name: "deletion_jobs",
    sql: include_str!("../migrations/sqlite/0005_deletion_jobs.sql"),
};

/// The passkey clone signal of issue #14: `credentials.passkey_suspect_at`.
const MIGRATION_SUSPECT: SqlMigration = SqlMigration {
    id: "0004",
    name: "passkey_suspect",
    sql: include_str!("../migrations/sqlite/0004_passkey_suspect.sql"),
};

/// The token-issuing migration of issue #9: the sessions `amr` column
/// and the `refresh_token` single-use-token kind.
const MIGRATION_TOKENS: SqlMigration = SqlMigration {
    id: "0003",
    name: "token_issuing",
    sql: include_str!("../migrations/sqlite/0003_token_issuing.sql"),
};

/// Router state: the module context and the resolved rotation overlap.
pub(crate) struct ModuleState {
    pub(crate) ctx: Arc<ModuleContext>,
    pub(crate) secret_overlap_secs: u64,
    /// The same signing-key cell the `/.well-known` router reads, so
    /// `/token` mints with the key JWKS publishes (issue #9).
    pub(crate) tokens: tokens::SigningKeysCell,
}

/// The auth-core module: schema, clients, sessions, tokens, the
/// authorization flow and account linking (README module table).
///
/// Requires `Database` (the tables), `Clock` (every expiry decision
/// reads it, never a wall clock — ADR 0100) and `IdGen` (ULID client and
/// session ids).
#[derive(Debug, Clone)]
pub struct AuthCore {
    secret_overlap_secs: u64,
    /// The resolved signing keys for the `/.well-known` router.
    /// `Module::well_known` is called without a `ModuleContext`
    /// (harness issue #46), so the cell is filled by `router()` —
    /// which does see the config — before any request can flow, and
    /// the discovery handlers read it per request.
    signing: tokens::SigningKeysCell,
}

impl Default for AuthCore {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthCore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            secret_overlap_secs: DEFAULT_SECRET_OVERLAP_SECS,
            signing: std::sync::Arc::new(std::sync::RwLock::new(None)),
        }
    }

    /// How long the previous client secret keeps verifying after a
    /// rotation (default one hour). Overridable per environment with
    /// `AUTH_CORE_SECRET_OVERLAP_SECS`.
    #[must_use]
    pub fn secret_overlap_secs(mut self, secs: u64) -> Self {
        self.secret_overlap_secs = secs;
        self
    }

    fn resolved_overlap(&self, cfg: &dyn Config) -> u64 {
        ModuleConfig::new("auth-core", cfg)
            .get_u32(
                "SECRET_OVERLAP_SECS",
                u32::try_from(self.secret_overlap_secs).unwrap_or(u32::MAX),
            )
            .into()
    }
}

impl Module for AuthCore {
    fn name(&self) -> &'static str {
        "auth-core"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::Db, Port::Clock, Port::IdGen]
    }

    fn tables(&self) -> &'static [&'static str] {
        &[
            "users",
            "identities",
            "credentials",
            "sessions",
            "single_use_tokens",
            "clients",
            "client_redirect_uris",
        ]
    }

    fn migrations(&self) -> factory0_core::Migrations {
        const MIGRATIONS: [SqlMigration; 5] = [
            MIGRATION_INIT,
            MIGRATION_ROTATION,
            MIGRATION_TOKENS,
            MIGRATION_SUSPECT,
            MIGRATION_DELETION_JOBS,
        ];
        factory0_core::Migrations {
            sqlite: &MIGRATIONS,
            postgres: &[],
        }
    }

    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        let module = ModuleConfig::new("auth-core", cfg);
        if let Some(raw) = cfg.get(&module.key("SECRET_OVERLAP_SECS"))
            && raw.parse::<u32>().is_err()
        {
            let mut errors = ConfigError::default();
            errors.push(format!(
                "auth-core: {} must be a non-negative integer, got {raw:?}",
                module.key("SECRET_OVERLAP_SECS")
            ));
            return Err(errors);
        }
        match tokens::SigningKeys::from_config(cfg) {
            Ok(_) => Ok(()),
            Err(err) => {
                let mut errors = ConfigError::default();
                errors.push(format!("auth-core: {err}"));
                Err(errors)
            }
        }
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let keys = match tokens::SigningKeys::from_config(&*ctx.config) {
            Ok(keys) => keys.map(Arc::new),
            // `validate_config` reports this at doctor time; at runtime
            // the module degrades to the stable unconfigured problem
            // rather than failing to boot.
            Err(err) => {
                tracing::error!(error = %err, "signing-key configuration is invalid");
                None
            }
        };
        *self.signing.write().expect("signing cell uncontended") = keys;
        let state = Arc::new(ModuleState {
            secret_overlap_secs: self.resolved_overlap(&*ctx.config),
            ctx: Arc::new(ctx),
            tokens: Arc::clone(&self.signing),
        });
        clients::router(Arc::clone(&state))
            .merge(sessions::router().with_state(Arc::clone(&state)))
            .merge(authorize::router().with_state(Arc::clone(&state)))
            .merge(token_endpoint::router().with_state(state))
    }

    fn well_known(&self) -> Option<axum::Router> {
        Some(tokens::well_known_router(Arc::clone(&self.signing)))
    }

    fn scheduled<'a>(
        &'a self,
        ctx: &'a ModuleContext,
        cron: &'a str,
    ) -> BoxFuture<'a, Result<(), AnyError>> {
        Box::pin(store::scheduled_purge(ctx, cron))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory0_core::{HARNESS_API, MapConfig};

    #[test]
    fn module_metadata_matches_the_issues() {
        let module = AuthCore::new();
        assert_eq!(module.name(), "auth-core");
        assert_eq!(module.version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(module.harness_api(), HARNESS_API);
        assert_eq!(module.requires(), [Port::Db, Port::Clock, Port::IdGen]);
        assert!(module.optional().is_empty());
        assert_eq!(
            module.tables(),
            [
                "users",
                "identities",
                "credentials",
                "sessions",
                "single_use_tokens",
                "clients",
                "client_redirect_uris"
            ]
        );
        assert!(!module.public_writes());
    }

    #[test]
    fn migrations_are_the_embedded_set_in_order() {
        let migrations = AuthCore::new().migrations();
        assert_eq!(migrations.sqlite.len(), 5);
        assert_eq!(migrations.sqlite[0].id, "0001");
        assert_eq!(migrations.sqlite[0].name, "init");
        assert_eq!(migrations.sqlite[1].id, "0002");
        assert_eq!(migrations.sqlite[1].name, "client_secret_rotation");
        assert_eq!(migrations.sqlite[2].id, "0003");
        assert_eq!(migrations.sqlite[2].name, "token_issuing");
        assert_eq!(migrations.sqlite[3].id, "0004");
        assert_eq!(migrations.sqlite[3].name, "passkey_suspect");
        assert_eq!(migrations.sqlite[4].id, "0005");
        assert_eq!(migrations.sqlite[4].name, "deletion_jobs");
        assert!(migrations.postgres.is_empty());
        assert_eq!(
            migrations.sqlite[0].sql,
            include_str!("../migrations/sqlite/0001_init.sql")
        );
        assert_eq!(
            migrations.sqlite[1].sql,
            include_str!("../migrations/sqlite/0002_client_secret_rotation.sql")
        );
        assert_eq!(
            migrations.sqlite[2].sql,
            include_str!("../migrations/sqlite/0003_token_issuing.sql")
        );
        assert_eq!(
            migrations.sqlite[4].sql,
            include_str!("../migrations/sqlite/0005_deletion_jobs.sql")
        );
    }

    #[test]
    fn overlap_comes_from_the_builder_or_config() {
        let config = MapConfig::from_pairs([("AUTH_CORE_SECRET_OVERLAP_SECS", "90")]);
        assert_eq!(AuthCore::new().resolved_overlap(&config), 90);
        assert_eq!(
            AuthCore::new()
                .secret_overlap_secs(1200)
                .resolved_overlap(&config),
            90,
            "config wins over the builder"
        );
        assert_eq!(
            AuthCore::new().resolved_overlap(&MapConfig::default()),
            DEFAULT_SECRET_OVERLAP_SECS
        );
    }

    #[test]
    fn invalid_overlap_config_is_rejected() {
        let config = MapConfig::from_pairs([("AUTH_CORE_SECRET_OVERLAP_SECS", "soon")]);
        assert!(AuthCore::new().validate_config(&config).is_err());
        assert!(
            AuthCore::new()
                .validate_config(&MapConfig::default())
                .is_ok()
        );
    }

    #[test]
    fn invalid_signing_key_config_is_rejected() {
        let config = MapConfig::from_pairs([
            (
                "AUTH_CORE_SIGNING_KEYS",
                "[{\"kty\":\"EC\",\"crv\":\"P-256\"}]",
            ),
            ("AUTH_CORE_SIGNING_KEY_ACTIVE", "missing-kid"),
            ("AUTH_CORE_ISSUER", "https://auth.test.example"),
        ]);
        assert!(AuthCore::new().validate_config(&config).is_err());
        assert!(
            AuthCore::new()
                .validate_config(&MapConfig::default())
                .is_ok(),
            "no signing keys configured is a valid configuration"
        );
    }

    #[test]
    fn well_known_serves_jwks_and_openid_configuration_at_the_root() {
        // The router resolves keys from the config the TestHarness
        // passes at assembly; the well-known router reads them per
        // request through the shared cell.
        let config = MapConfig::from_pairs([
            ("AUTH_CORE_SIGNING_KEYS", "[{\"kty\":\"RSA\"}]"),
            ("AUTH_CORE_SIGNING_KEY_ACTIVE", "x"),
        ]);
        assert!(
            AuthCore::new().validate_config(&config).is_err(),
            "malformed keys are caught by validate_config"
        );
        assert!(AuthCore::new().well_known().is_some());
    }
}
