//! `factory0-auth-password`: email and password (issues #12, #19, #20).
//!
//! ```no_run
//! use factory0_auth_password::Password;
//!
//! let module = Password::new();
//! ```
//!
//! The oldest login method and the only one where a stranger can simply
//! keep guessing, which is what most of this module is about.
//!
//! **It costs real CPU.** ADR 0100 measured Argon2id at the parameters
//! this uses (m=19456, t=2, p=1) at roughly 40 ms per hash or verify on
//! Workers. The free tier's 10 ms CPU limit cannot fit one verify at any
//! sane parameters, so **enabling this module requires the paid plan**.
//! That is a deployment fact, not a tuning knob: lowering the parameters
//! to fit would make the hashes worth less than not having them.
//!
//! **Three defences, and they are not the same defence.** The
//! `RateLimiter` port is keyed on the request, so it slows one attacker
//! down and does nothing about a distributed one. The account lockout is
//! keyed on the credential, so it survives an attacker rotating IP
//! addresses — and because it locks the *password* and not the account, a
//! person who is locked out can still sign in with a passkey or a
//! provider, which is what stops the lockout being a denial of service
//! against them. The `Captcha` port, where a deployment provides one, is
//! what makes the first two expensive to reach.
//!
//! **Nothing here says whether an address has an account.** Registration
//! answers identically whether it created one or not. Login answers
//! identically for a wrong password, an unknown address, a disabled
//! account and a locked one. An unknown address is verified against a
//! fixed dummy hash so the timing does not answer either.

#![forbid(unsafe_code)]

mod breach;
mod handlers;
mod lockout;

use factory0_core::{
    Config, ConfigError, Migrations, Module, ModuleConfig, ModuleContext, Port, ProblemDef,
};
use http::StatusCode;
use std::sync::Arc;

/// The one refusal every failed login answers with.
///
/// Wrong password, unknown address, disabled account, locked account: one
/// body, one status. A caller who can tell them apart has an oracle for
/// who holds an account here, and a lockout that announces itself is a
/// way to find out which addresses are worth attacking.
pub const LOGIN_REFUSED: ProblemDef = ProblemDef {
    slug: "auth/password-login-refused",
    status: StatusCode::UNAUTHORIZED,
    title: "That email address and password do not match",
    description: "Wrong password, unknown address, or the account cannot sign in this way",
};

/// A password that cannot be accepted, for a reason the person can act on.
///
/// Distinct from [`LOGIN_REFUSED`] on purpose: this is registration, where
/// telling somebody their password is too short reveals nothing about
/// anybody else.
pub const PASSWORD_UNSUITABLE: ProblemDef = ProblemDef {
    slug: "auth/password-unsuitable",
    status: StatusCode::BAD_REQUEST,
    title: "That password cannot be used",
    description: "Too short, too long, or found in a public breach corpus",
};

/// The module is mounted but cannot hash.
pub const NOT_READY: ProblemDef = ProblemDef {
    slug: "auth/password-not-ready",
    status: StatusCode::SERVICE_UNAVAILABLE,
    title: "Password sign-in is not available",
    description: "The module is missing a port it requires",
};

/// Shortest password accepted. Length is the only rule: composition rules
/// push people towards `Passw0rd!` and away from length, which is the
/// thing that actually helps.
pub const MIN_PASSWORD: usize = 8;

/// Longest password accepted. Not a security limit — Argon2id does not
/// care — but a bound on what an unauthenticated caller can make us hash,
/// because hashing is the expensive thing this module does.
pub const MAX_PASSWORD: usize = 256;

/// The resolved configuration.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    /// Whether to ask the Pwned Passwords range API about a new password.
    pub breach_check: bool,
    /// How many failures in the window lock the password.
    pub lockout_threshold: i64,
    /// The failure window, in seconds.
    pub lockout_window_secs: i64,
    /// How long a lock lasts, in seconds.
    pub lockout_secs: i64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            breach_check: true,
            // Ten failures in an hour, locked for fifteen minutes. Ten is
            // far above a person mistyping and far below a useful guessing
            // rate; fifteen minutes is long enough to make guessing
            // pointless and short enough that a locked-out person who has
            // no other login method is not stuck for the day.
            lockout_threshold: 10,
            lockout_window_secs: 3600,
            lockout_secs: 900,
        }
    }
}

fn resolve_settings(cfg: &dyn Config) -> Result<Settings, Vec<String>> {
    let module = ModuleConfig::new("auth-password", cfg);
    let mut problems = Vec::new();
    let defaults = Settings::default();

    let mut number = |key: &str, default: i64, min: i64| -> i64 {
        match module.get_opt(key) {
            None => default,
            Some(raw) => match raw.trim().parse::<i64>() {
                Ok(value) if value >= min => value,
                _ => {
                    problems.push(format!(
                        "{} must be an integer of at least {min}, got {raw:?}",
                        module.key(key)
                    ));
                    default
                }
            },
        }
    };

    let lockout_threshold = number("LOCKOUT_THRESHOLD", defaults.lockout_threshold, 1);
    let lockout_window_secs = number("LOCKOUT_WINDOW_SECS", defaults.lockout_window_secs, 1);
    let lockout_secs = number("LOCKOUT_SECS", defaults.lockout_secs, 1);

    let breach_check = match module.get_opt("BREACH_CHECK") {
        None => defaults.breach_check,
        Some(raw) => match raw.trim() {
            "true" | "1" => true,
            "false" | "0" => false,
            other => {
                problems.push(format!(
                    "{} must be true or false, got {other:?}",
                    module.key("BREACH_CHECK")
                ));
                defaults.breach_check
            }
        },
    };

    if problems.is_empty() {
        Ok(Settings {
            breach_check,
            lockout_threshold,
            lockout_window_secs,
            lockout_secs,
        })
    } else {
        Err(problems)
    }
}

pub(crate) struct ModuleState {
    pub ctx: Arc<ModuleContext>,
    pub settings: Settings,
}

/// Email and password.
pub struct Password;

impl Default for Password {
    fn default() -> Self {
        Self::new()
    }
}

impl Password {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Module for Password {
    fn name(&self) -> &'static str {
        "auth-password"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        &[Port::Db, Port::Clock, Port::IdGen]
    }

    /// `RateLimiter` and `Captcha` are the two defences a deployment can
    /// leave out, and `HttpClient` is only the breach check. None of them
    /// is required, because a module that refuses to start without a
    /// captcha would take the whole service down with it — the harness's
    /// own production rule (`fz doctor`) is what insists on one.
    fn optional(&self) -> &'static [Port] {
        &[Port::RateLimiter, Port::Captcha, Port::HttpClient]
    }

    /// None. `auth-core` owns every table this module touches, including
    /// the lockout columns on `credentials`.
    fn tables(&self) -> &'static [&'static str] {
        &[]
    }

    fn emits(&self) -> &'static [&'static str] {
        &[
            handlers::EVENT_REGISTERED,
            handlers::EVENT_LOGGED_IN,
            handlers::EVENT_LOCKED,
            handlers::EVENT_CHANGED,
            handlers::EVENT_DUPLICATE_REGISTRATION,
        ]
    }

    fn public_writes(&self) -> bool {
        true
    }

    fn migrations(&self) -> Migrations {
        Migrations::EMPTY
    }

    fn validate_config(&self, cfg: &dyn Config) -> Result<(), ConfigError> {
        match resolve_settings(cfg) {
            Ok(_) => Ok(()),
            Err(problems) => {
                let mut errors = ConfigError::default();
                for problem in problems {
                    errors.push(format!("auth-password: {problem}"));
                }
                Err(errors)
            }
        }
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let settings = resolve_settings(&*ctx.config).unwrap_or_else(|problems| {
            tracing::error!(
                problems = problems.join("; "),
                "auth-password configuration is unusable; falling back to defaults"
            );
            Settings::default()
        });
        handlers::router().with_state(Arc::new(ModuleState {
            ctx: Arc::new(ctx),
            settings,
        }))
    }
}

/// Whether a password is one this service will store.
///
/// Length only. Composition rules push people towards `Passw0rd!` and away
/// from length, which is the thing that actually helps, and every rule
/// added here is a rule an attacker can use to shrink the search space.
pub(crate) fn password_length_ok(password: &str) -> bool {
    let length = password.chars().count();
    (MIN_PASSWORD..=MAX_PASSWORD).contains(&length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory0_core::MapConfig;

    fn config(pairs: &[(&str, &str)]) -> MapConfig {
        MapConfig::from_pairs(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
        )
    }

    #[test]
    fn the_module_owns_no_tables_and_asks_for_what_it_needs() {
        let module = Password::new();
        assert_eq!(module.name(), "auth-password");
        assert!(
            module.tables().is_empty(),
            "auth-core owns the schema; a second owner is a build error"
        );
        assert!(module.requires().contains(&Port::Db));
        // Not required: a module that refused to start without a captcha
        // would take the whole service down with it.
        assert!(module.optional().contains(&Port::Captcha));
        assert!(module.optional().contains(&Port::RateLimiter));
        assert!(module.public_writes());
    }

    #[test]
    fn the_defaults_are_the_ones_the_docs_quote() {
        let settings = resolve_settings(&config(&[])).expect("valid");
        assert!(settings.breach_check, "the breach check is on by default");
        assert_eq!(settings.lockout_threshold, 10);
        assert_eq!(settings.lockout_window_secs, 3600);
        assert_eq!(settings.lockout_secs, 900);
    }

    #[test]
    fn nonsense_in_a_limit_is_a_build_failure_not_a_silent_default() {
        // A deployment that meant to raise the threshold and typed it
        // wrong would otherwise run with ten and never know.
        for (key, value) in [
            ("AUTH_PASSWORD_LOCKOUT_THRESHOLD", "lots"),
            ("AUTH_PASSWORD_LOCKOUT_THRESHOLD", "0"),
            ("AUTH_PASSWORD_LOCKOUT_WINDOW_SECS", "-1"),
            ("AUTH_PASSWORD_LOCKOUT_SECS", ""),
            ("AUTH_PASSWORD_BREACH_CHECK", "yes"),
        ] {
            assert!(
                resolve_settings(&config(&[(key, value)])).is_err(),
                "{key}={value:?} was accepted"
            );
        }
    }

    #[test]
    fn the_breach_check_can_be_switched_off_deliberately() {
        let settings =
            resolve_settings(&config(&[("AUTH_PASSWORD_BREACH_CHECK", "false")])).expect("valid");
        assert!(!settings.breach_check);
    }

    #[test]
    fn length_is_the_only_password_rule() {
        assert!(!password_length_ok(""));
        assert!(!password_length_ok("short"));
        assert!(password_length_ok("12345678"));
        assert!(password_length_ok("correct horse battery staple"));
        // No composition rules: this is a fine password.
        assert!(password_length_ok("aaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(password_length_ok(&"a".repeat(MAX_PASSWORD)));
        assert!(!password_length_ok(&"a".repeat(MAX_PASSWORD + 1)));
    }

    #[test]
    fn length_counts_characters_rather_than_bytes() {
        // Eight emoji is eight characters and thirty-two bytes. Counting
        // bytes would accept a two-character password of long runes and
        // reject a perfectly good short-rune one.
        assert!(password_length_ok("🔑🔑🔑🔑🔑🔑🔑🔑"));
        assert!(!password_length_ok("🔑🔑"));
        // And the maximum is a bound on hashing work, so it is characters
        // too rather than a byte count an attacker can inflate.
        assert!(!password_length_ok(&"🔑".repeat(MAX_PASSWORD + 1)));
    }
}
