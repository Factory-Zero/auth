//! `factory0-auth-passkeys`: passkey registration and login (issues #13, #14).
//!
//! ```no_run
//! use factory0_auth_passkeys::Passkeys;
//!
//! let module = Passkeys::new();
//! ```
//!
//! The module owns no tables. `auth-core` owns the schema and publishes the
//! typed store API every login method writes through, so `credentials` and
//! `single_use_tokens` have exactly one definition and one migration history.
//!
//! Relying-party verification is implemented here rather than taken from
//! `webauthn-rs`, which cannot build for `wasm32-unknown-unknown` (ADR 0100).
//!
//! Two rules run through the whole module. A challenge is single-use and is
//! spent by a conditional update whose affected-row count decides the winner,
//! never by a read followed by a write. And every way a login can fail —
//! unknown credential, spent challenge, wrong origin, bad signature — answers
//! with one problem, because naming the failing check tells an attacker where
//! to aim.

#![forbid(unsafe_code)]

mod challenge;
mod login;
mod register;
mod request;
mod webauthn;

use cratefield_core::{
    Config, ConfigError, Migrations, Module, ModuleConfig, ModuleContext, Port, Problem, ProblemDef,
};
use http::StatusCode;
use std::sync::Arc;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub use webauthn::UserVerification;

/// The one answer every failed ceremony gets. Which check failed is logged,
/// never returned: an attacker learning "that credential is unknown" versus
/// "that signature is wrong" learns which half to work on.
pub const CEREMONY_FAILED: ProblemDef = ProblemDef {
    slug: "auth/passkey-ceremony-failed",
    status: StatusCode::UNAUTHORIZED,
    title: "The passkey ceremony could not be completed",
    description: "Unknown credential, spent or expired challenge, wrong origin, or a signature \
                  that does not verify — not distinguished",
};

/// Refusing to remove a user's only way back in.
pub const LAST_LOGIN_METHOD: ProblemDef = ProblemDef {
    slug: "auth/last-login-method",
    status: StatusCode::CONFLICT,
    title: "That is the account's only login method",
    description: "Add another passkey or link a provider before removing this one",
};

/// The module is mounted but its relying-party configuration is missing or
/// unusable; `fz doctor` reports the same thing at deploy time.
pub const PASSKEYS_UNCONFIGURED: ProblemDef = ProblemDef {
    slug: "auth/passkeys-unconfigured",
    status: StatusCode::SERVICE_UNAVAILABLE,
    title: "Passkeys are not configured",
    description: "AUTH_PASSKEYS_RP_ID and AUTH_PASSKEYS_ORIGINS must be set",
};

/// A credential id that is already registered, to any account.
pub const CREDENTIAL_ALREADY_REGISTERED: ProblemDef = ProblemDef {
    slug: "auth/passkey-already-registered",
    status: StatusCode::CONFLICT,
    title: "That authenticator is already registered",
    description: "The credential id is already stored for an account",
};

/// The algorithms offered at registration, best first: ES256 is what Apple,
/// Android and most security keys produce, RS256 is Windows Hello, EdDSA
/// appears on some keys. Anything else is refused at registration rather
/// than stored and failed at every login.
const COSE_ES256: i64 = -7;
const COSE_EDDSA: i64 = -8;
const COSE_RS256: i64 = -257;

/// Five minutes, per issue #13. Long enough for a person to find their
/// phone, short enough that a leaked challenge is not useful.
const DEFAULT_CHALLENGE_TTL_SECS: i64 = 300;
const MIN_CHALLENGE_TTL_SECS: i64 = 60;
const MAX_CHALLENGE_TTL_SECS: i64 = 900;

/// What the browser is told to wait, in milliseconds.
const DEFAULT_TIMEOUT_MS: u32 = 60_000;

pub(crate) fn iso(at: OffsetDateTime) -> String {
    at.replace_nanosecond(0)
        .unwrap_or(at)
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// The resolved relying-party configuration.
#[derive(Debug, Clone)]
pub(crate) struct RelyingParty {
    pub rp_id: String,
    pub rp_name: String,
    pub origins: Vec<url::Url>,
    pub challenge_ttl_secs: i64,
    pub user_verification: UserVerification,
    pub timeout_ms: u32,
}

impl RelyingParty {
    /// Reads and checks the configuration. The origin rule is WebAuthn's
    /// own: an origin may only be trusted for an RP id that is its host or
    /// a parent domain of it, so a misconfiguration cannot make this service
    /// accept ceremonies from somebody else's site.
    pub(crate) fn from_config(cfg: &dyn Config) -> Result<Self, Vec<String>> {
        let module = ModuleConfig::new("auth-passkeys", cfg);
        let mut problems = Vec::new();

        let rp_id = module.get_opt("RP_ID").unwrap_or_default();
        let rp_id = rp_id.trim().to_ascii_lowercase();
        if rp_id.is_empty() {
            problems.push(format!(
                "{} is required (the registrable domain passkeys are bound to)",
                module.key("RP_ID")
            ));
        } else if rp_id.contains("://") || rp_id.contains('/') || rp_id.contains(':') {
            problems.push(format!(
                "{} must be a bare domain, not a URL, got {rp_id:?}",
                module.key("RP_ID")
            ));
        }

        let configured = module
            .get_opt("ORIGINS")
            .unwrap_or_else(|| format!("https://{rp_id}"));
        let mut origins = Vec::new();
        for raw in configured
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            match url::Url::parse(raw) {
                Ok(url) => {
                    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
                    let localhost = host == "localhost" || host == "127.0.0.1";
                    if url.scheme() != "https" && !localhost {
                        problems.push(format!(
                            "{} must be https (localhost may be http), got {raw:?}",
                            module.key("ORIGINS")
                        ));
                    }
                    // WebAuthn's rule, enforced here so a typo cannot widen
                    // who this service will accept a ceremony from.
                    if !rp_id.is_empty()
                        && !localhost
                        && host != rp_id
                        && !host.ends_with(&format!(".{rp_id}"))
                    {
                        problems.push(format!(
                            "origin {raw:?} is not {rp_id} or a subdomain of it, so it can never \
                             produce a valid ceremony for this relying party"
                        ));
                    }
                    origins.push(url);
                }
                Err(err) => problems.push(format!(
                    "{} contains {raw:?}, which is not a URL: {err}",
                    module.key("ORIGINS")
                )),
            }
        }
        if origins.is_empty() {
            problems.push(format!(
                "{} must list at least one origin",
                module.key("ORIGINS")
            ));
        }

        let challenge_ttl_secs = match module.get_opt("CHALLENGE_TTL_SECS") {
            None => DEFAULT_CHALLENGE_TTL_SECS,
            Some(raw) => match raw.parse::<i64>() {
                Ok(secs) if (MIN_CHALLENGE_TTL_SECS..=MAX_CHALLENGE_TTL_SECS).contains(&secs) => {
                    secs
                }
                _ => {
                    problems.push(format!(
                        "{} must be between {MIN_CHALLENGE_TTL_SECS} and \
                         {MAX_CHALLENGE_TTL_SECS} seconds, got {raw:?}",
                        module.key("CHALLENGE_TTL_SECS")
                    ));
                    DEFAULT_CHALLENGE_TTL_SECS
                }
            },
        };

        let user_verification = match module.get_opt("USER_VERIFICATION") {
            None => UserVerification::Preferred,
            Some(raw) => {
                if let Some(policy) = UserVerification::parse(raw.trim()) {
                    policy
                } else {
                    problems.push(format!(
                        "{} must be required or preferred, got {raw:?}",
                        module.key("USER_VERIFICATION")
                    ));
                    UserVerification::Preferred
                }
            }
        };

        if problems.is_empty() {
            Ok(Self {
                rp_name: module.get_str("RP_NAME", &rp_id),
                rp_id,
                origins,
                challenge_ttl_secs,
                user_verification,
                timeout_ms: DEFAULT_TIMEOUT_MS,
            })
        } else {
            Err(problems)
        }
    }
}

pub(crate) struct ModuleState {
    pub ctx: Arc<ModuleContext>,
    pub rp: Option<RelyingParty>,
    /// How recent a login has to be to add or remove a passkey (issue #31).
    /// Resolved by `auth-core` so every login method reads one key.
    pub step_up_window_secs: i64,
}

impl ModuleState {
    pub(crate) fn rp(&self) -> Result<&RelyingParty, Problem> {
        self.rp
            .as_ref()
            .ok_or_else(|| Problem::new(&PASSKEYS_UNCONFIGURED))
    }
}

/// Passkey registration and login.
pub struct Passkeys;

impl Default for Passkeys {
    fn default() -> Self {
        Self::new()
    }
}

impl Passkeys {
    pub fn new() -> Self {
        Self
    }
}

impl Module for Passkeys {
    fn name(&self) -> &'static str {
        "auth-passkeys"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::Db, Port::Clock, Port::IdGen]
    }

    /// The two login endpoints are reachable by anyone and each one writes a
    /// challenge row, so they are rate limited where a limiter exists.
    fn optional(&self) -> &'static [Port] {
        &[Port::RateLimiter]
    }

    /// None. `auth-core` owns every table this module writes, so there is
    /// one schema and one migration history for `credentials` and
    /// `single_use_tokens` rather than two modules disagreeing about them.
    fn tables(&self) -> &'static [&'static str] {
        &[]
    }

    fn emits(&self) -> &'static [&'static str] {
        &[register::EVENT_REGISTERED, login::EVENT_LOGGED_IN]
    }

    fn public_writes(&self) -> bool {
        // The login endpoints are reachable without a session. They are
        // guarded by a single-use challenge this service issued, not by a
        // captcha, but they are public writes and the harness should know.
        true
    }

    fn migrations(&self) -> Migrations {
        Migrations::EMPTY
    }

    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        let mut errors = ConfigError::default();
        if let Err(problems) = RelyingParty::from_config(cfg) {
            for problem in problems {
                errors.push(format!("auth-passkeys: {problem}"));
            }
        }
        // The step-up window is auth-core's key, but a deployment that
        // mistypes it should hear about it from whichever module enforces
        // it rather than silently getting the default.
        if let Err(problem) = factory0_auth_core::step_up_window_secs(cfg) {
            errors.push(format!("auth-passkeys: {problem}"));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let rp = match RelyingParty::from_config(&*ctx.config) {
            Ok(rp) => Some(rp),
            // `validate_config` reports this at doctor time; at runtime the
            // module degrades to one stable problem rather than refusing to
            // boot and taking the rest of the service with it.
            Err(problems) => {
                tracing::error!(
                    problems = problems.join("; "),
                    "passkey relying-party configuration is unusable"
                );
                None
            }
        };
        // A bad value is reported by `validate_config`; here it degrades to
        // the default rather than taking the module down, and the default
        // is the stricter of the two outcomes anyway.
        let step_up_window_secs = factory0_auth_core::step_up_window_secs(&*ctx.config)
            .unwrap_or_else(|problem| {
                tracing::error!(problem, "the step-up window is unusable; using the default");
                factory0_auth_core::DEFAULT_STEP_UP_WINDOW_SECS
            });
        let state = Arc::new(ModuleState {
            ctx: Arc::new(ctx),
            rp,
            step_up_window_secs,
        });
        register::router().merge(login::router()).with_state(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cratefield_core::MapConfig;

    fn config(pairs: &[(&str, &str)]) -> MapConfig {
        MapConfig::from_pairs(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
        )
    }

    #[test]
    fn the_module_declares_no_tables_because_auth_core_owns_them() {
        let module = Passkeys::new();
        assert_eq!(module.name(), "auth-passkeys");
        assert!(module.tables().is_empty());
        assert!(module.migrations().sqlite.is_empty());
        assert_eq!(module.requires(), [Port::Db, Port::Clock, Port::IdGen]);
        assert!(module.public_writes());
    }

    #[test]
    fn a_relying_party_needs_an_rp_id() {
        let error = Passkeys::new()
            .validate_config(&config(&[]))
            .expect_err("no rp id is unusable");
        assert!(error.to_string().contains("AUTH_PASSKEYS_RP_ID"), "{error}");
    }

    #[test]
    fn an_origin_outside_the_rp_id_is_refused() {
        // The whole point of the RP id: a ceremony from somewhere else can
        // never be valid, so accepting the origin would only ever be a way
        // to get it wrong.
        let error = Passkeys::new()
            .validate_config(&config(&[
                ("AUTH_PASSKEYS_RP_ID", "auth.factory0.ventures"),
                ("AUTH_PASSKEYS_ORIGINS", "https://evil.example"),
            ]))
            .expect_err("a foreign origin is unusable");
        assert!(error.to_string().contains("evil.example"), "{error}");

        // A subdomain of the RP id is fine, and so is the RP id itself.
        assert!(
            Passkeys::new()
                .validate_config(&config(&[
                    ("AUTH_PASSKEYS_RP_ID", "factory0.ventures"),
                    (
                        "AUTH_PASSKEYS_ORIGINS",
                        "https://factory0.ventures,https://auth.factory0.ventures",
                    ),
                ]))
                .is_ok()
        );
    }

    #[test]
    fn plaintext_origins_are_refused_except_on_localhost() {
        assert!(
            Passkeys::new()
                .validate_config(&config(&[
                    ("AUTH_PASSKEYS_RP_ID", "auth.factory0.ventures"),
                    ("AUTH_PASSKEYS_ORIGINS", "http://auth.factory0.ventures"),
                ]))
                .is_err()
        );
        assert!(
            Passkeys::new()
                .validate_config(&config(&[
                    ("AUTH_PASSKEYS_RP_ID", "localhost"),
                    ("AUTH_PASSKEYS_ORIGINS", "http://localhost:8787"),
                ]))
                .is_ok(),
            "wrangler dev has to work"
        );
    }

    #[test]
    fn an_rp_id_that_is_a_url_is_a_configuration_error() {
        let error = Passkeys::new()
            .validate_config(&config(&[(
                "AUTH_PASSKEYS_RP_ID",
                "https://auth.factory0.ventures",
            )]))
            .expect_err("a URL is not an rp id");
        assert!(error.to_string().contains("bare domain"), "{error}");
    }

    #[test]
    fn the_challenge_lifetime_is_bounded_at_both_ends() {
        for bad in ["0", "10", "3600", "soon"] {
            assert!(
                Passkeys::new()
                    .validate_config(&config(&[
                        ("AUTH_PASSKEYS_RP_ID", "auth.factory0.ventures"),
                        ("AUTH_PASSKEYS_CHALLENGE_TTL_SECS", bad),
                    ]))
                    .is_err(),
                "{bad} was accepted"
            );
        }
        let rp = RelyingParty::from_config(&config(&[
            ("AUTH_PASSKEYS_RP_ID", "auth.factory0.ventures"),
            ("AUTH_PASSKEYS_CHALLENGE_TTL_SECS", "120"),
        ]))
        .expect("valid");
        assert_eq!(rp.challenge_ttl_secs, 120);
        assert_eq!(rp.user_verification, UserVerification::Preferred);
        assert_eq!(rp.origins.len(), 1);
        assert_eq!(rp.origins[0].as_str(), "https://auth.factory0.ventures/");
    }

    #[test]
    fn every_configuration_problem_is_reported_at_once() {
        let error = Passkeys::new()
            .validate_config(&config(&[
                ("AUTH_PASSKEYS_RP_ID", "auth.factory0.ventures"),
                ("AUTH_PASSKEYS_ORIGINS", "https://evil.example,not-a-url"),
                ("AUTH_PASSKEYS_USER_VERIFICATION", "whenever"),
            ]))
            .expect_err("three problems");
        assert_eq!(error.problems.len(), 3, "{error}");
    }
}
