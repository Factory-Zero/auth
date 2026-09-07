//! `factory0-auth-oidc`: OpenID Connect login (issues #15, #16).
//!
//! ```no_run
//! use factory0_auth_oidc::Oidc;
//!
//! let module = Oidc::new();
//! ```
//!
//! Google is the reference provider and the flow is written against a
//! [`provider::Provider`] descriptor, so a provider arrives as data plus
//! whatever quirk it insists on rather than as a second copy of the flow.
//! Apple is what proves that: it shares discovery, PKCE, ID-token
//! verification, the linking rules and the session, and differs in three
//! places, each carried by the descriptor (ADR 0102) — a client secret
//! minted per request from a `.p8` (`crate::apple`), a cross-site
//! `form_post` callback with the cookie policy that survives one, and a
//! name that arrives exactly once.
//!
//! The module owns no tables. `auth-core` owns the schema *and* the
//! account-linking rules (#22), which decide whether an incoming identity is
//! a known person, a link to a signed-in account, an automatic link on a
//! verified address, or a new user. This module's job is to establish who
//! the provider says is at the other end, and hand that over.
//!
//! Both routes are public, and both are guarded by the same thing: a signed,
//! origin-locked cookie that this service issued minutes earlier. It is not
//! server-side single-use — spending it is not recorded anywhere — so what
//! it gives is a browser binding and a ten-minute window, not a one-shot
//! token. That is enough because everything a holder could replay it for
//! needs the rest of the flow too: the PKCE verifier it carries only
//! matches the challenge the provider already holds, and the nonce only
//! matches one ID token.

#![forbid(unsafe_code)]

mod apple;
mod discovery;
mod flow;
mod handlers;
mod provider;
mod session;

use factory0_core::{
    Config, ConfigError, Migrations, Module, ModuleConfig, ModuleContext, Port, Problem, ProblemDef,
};
use http::StatusCode;
use std::sync::Arc;

pub use provider::{APPLE, GOOGLE, PROVIDERS, Provider, ResponseMode, SecretSource, TokenAuth};

/// A provider whose client id and secret are not both configured. Named
/// rather than hidden: the operator needs to know which key is missing, and
/// a caller needs to know the button they pressed is not wired up.
pub const PROVIDER_UNCONFIGURED: ProblemDef = ProblemDef {
    slug: "auth/oidc-provider-unconfigured",
    status: StatusCode::SERVICE_UNAVAILABLE,
    title: "That sign-in provider is not configured",
    description: "The provider's AUTH_OIDC_<PROVIDER>_* settings are missing or unusable",
};

/// The provider, or our request to it, failed in a way the person cannot
/// act on. Distinct from a refused sign-in.
pub const PROVIDER_UNAVAILABLE: ProblemDef = ProblemDef {
    slug: "auth/oidc-provider-unavailable",
    status: StatusCode::BAD_GATEWAY,
    title: "The sign-in provider could not be reached",
    description: "Discovery, the token exchange or the ID token failed; the detail is in the logs",
};

/// Every way a callback can be invalid answers with this, for the same
/// reason the passkey module has one refusal: telling a caller which check
/// failed tells an attacker which half to work on.
pub const CALLBACK_REFUSED: ProblemDef = ProblemDef {
    slug: "auth/oidc-callback-refused",
    status: StatusCode::BAD_REQUEST,
    title: "That sign-in link is no longer valid",
    description: "Missing, expired, replayed or mismatched authorization state",
};

pub(crate) const DEFAULT_RETURN_TO: &str = "/";

/// The one timestamp shape this service stores.
pub(crate) fn iso(at: time::OffsetDateTime) -> String {
    at.replace_nanosecond(0)
        .unwrap_or(at)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// One provider's credentials, ready for a request.
///
/// `client_secret` is a resolved string by the time anything holds this:
/// configured for Google, minted for Apple. The flow never learns which,
/// which is the point of the descriptor.
#[derive(Debug, Clone)]
pub(crate) struct ProviderConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

/// Where a provider's secret comes from, before it is resolved.
#[derive(Debug, Clone)]
pub(crate) enum ConfiguredSecret {
    /// The configured `_CLIENT_SECRET` string.
    Static(String),
    /// The Apple identifiers a secret is minted from, per request.
    Apple(apple::AppleConfig),
}

/// A provider's configuration as it sits in the environment.
#[derive(Debug, Clone)]
pub(crate) struct ProviderCredentials {
    pub client_id: String,
    pub secret: ConfiguredSecret,
    pub redirect_uri: String,
}

/// The module's configuration, resolved once per router build.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    /// The public origin this service answers on; the redirect URI is built
    /// from it, and it must match what the provider has registered.
    pub redirect_base: String,
    pub default_return_to: String,
}

impl Settings {
    pub(crate) fn provider_credentials(
        &self,
        cfg: &dyn Config,
        provider: &Provider,
    ) -> Option<ProviderCredentials> {
        let module = ModuleConfig::new("auth-oidc", cfg);
        let client_id = module.get_opt(&format!("{}_CLIENT_ID", provider.config))?;
        if client_id.trim().is_empty() {
            return None;
        }
        let secret = match provider.secret {
            SecretSource::Configured => {
                let value = module.get_opt(&format!("{}_CLIENT_SECRET", provider.config))?;
                if value.trim().is_empty() {
                    return None;
                }
                ConfiguredSecret::Static(value)
            }
            SecretSource::AppleMinted => ConfiguredSecret::Apple(apple_config(&module, provider)?),
        };
        Some(ProviderCredentials {
            client_id,
            secret,
            redirect_uri: format!(
                "{}/v1/auth-oidc/{}/callback",
                self.redirect_base.trim_end_matches('/'),
                provider.slug
            ),
        })
    }
}

/// The three Apple settings a minted secret needs, or `None` when any of
/// them is missing. All three or none: two out of three cannot mint.
fn apple_config(module: &ModuleConfig<'_>, provider: &Provider) -> Option<apple::AppleConfig> {
    let get = |suffix: &str| {
        module
            .get_opt(&format!("{}_{suffix}", provider.config))
            .filter(|value| !value.trim().is_empty())
    };
    Some(apple::AppleConfig {
        team_id: get("TEAM_ID")?,
        key_id: get("KEY_ID")?,
        private_key: get("PRIVATE_KEY")?,
    })
}

fn resolve_settings(cfg: &dyn Config) -> Result<Settings, Vec<String>> {
    let module = ModuleConfig::new("auth-oidc", cfg);
    let mut problems = Vec::new();

    let redirect_base = module.get_opt("REDIRECT_BASE").unwrap_or_default();
    let trimmed = redirect_base.trim().trim_end_matches('/').to_owned();
    if trimmed.is_empty() {
        problems.push(format!(
            "{} is required (the public origin this service answers on)",
            module.key("REDIRECT_BASE")
        ));
    } else if !(trimmed.starts_with("https://")
        || trimmed.starts_with("http://localhost")
        || trimmed.starts_with("http://127.0.0.1"))
    {
        problems.push(format!(
            "{} must be https (localhost may be http), got {trimmed:?}",
            module.key("REDIRECT_BASE")
        ));
    }

    let default_return_to = module.get_str("DEFAULT_RETURN_TO", DEFAULT_RETURN_TO);
    // The same rule the `return_to` parameter gets: a configured default
    // that could leave the site would be an open redirect with extra steps.
    if handlers::safe_return_to(Some(&default_return_to)).is_none() {
        problems.push(format!(
            "{} must be a path on this service beginning with a single /, got {default_return_to:?}",
            module.key("DEFAULT_RETURN_TO")
        ));
    }

    // A provider with half its credentials is a deployment mistake worth
    // naming: it answers 503 at runtime and nobody will know why.
    for provider in PROVIDERS {
        let present = |suffix: &str| {
            module
                .get_opt(&format!("{}_{suffix}", provider.config))
                .is_some_and(|value| !value.trim().is_empty())
        };
        let configured = present("CLIENT_ID");
        match provider.secret {
            SecretSource::Configured => {
                if configured != present("CLIENT_SECRET") {
                    problems.push(format!(
                        "{} needs both {}_CLIENT_ID and {}_CLIENT_SECRET, or neither",
                        provider.slug, provider.config, provider.config
                    ));
                }
            }
            SecretSource::AppleMinted => {
                // Apple has no client secret to configure: the secret is
                // minted from these three (#3). Naming them individually
                // matters because a missing `.p8` and a missing key id
                // fail identically at Apple, with an opaque error.
                let missing: Vec<String> = ["TEAM_ID", "KEY_ID", "PRIVATE_KEY"]
                    .into_iter()
                    .filter(|suffix| !present(suffix))
                    .map(|suffix| module.key(&format!("{}_{suffix}", provider.config)))
                    .collect();
                if configured && !missing.is_empty() {
                    problems.push(format!(
                        "{} mints its client secret and still needs {}",
                        provider.slug,
                        missing.join(", ")
                    ));
                }
                if !configured && missing.len() < 3 {
                    problems.push(format!(
                        "{} has signing settings but no {} (the Services ID)",
                        provider.slug,
                        module.key(&format!("{}_CLIENT_ID", provider.config))
                    ));
                }
                if present("CLIENT_SECRET") {
                    problems.push(format!(
                        "{} does not take a {}: the secret is minted from the signing key, and \
                         a configured one would be ignored",
                        provider.slug,
                        module.key(&format!("{}_CLIENT_SECRET", provider.config))
                    ));
                }
            }
        }
    }

    if problems.is_empty() {
        Ok(Settings {
            redirect_base: trimmed,
            default_return_to,
        })
    } else {
        Err(problems)
    }
}

pub(crate) struct ModuleState {
    pub ctx: Arc<ModuleContext>,
    pub settings: Option<Settings>,
    pub discovery: discovery::Cache,
    /// Apple's client-secret cache. Empty and untouched when Apple is not
    /// configured, which is why it costs nothing to hold here.
    pub apple: apple::Minter,
}

impl ModuleState {
    pub(crate) fn settings(&self) -> Result<&Settings, Problem> {
        self.settings
            .as_ref()
            .ok_or_else(|| Problem::not_ready("the auth-oidc module is not configured"))
    }

    /// The credentials for one provider, with the secret resolved: read
    /// from configuration for most providers, minted here for Apple.
    ///
    /// Minting is the only step that can fail, and it fails the way an
    /// unreachable provider does rather than the way a refused sign-in
    /// does: nobody at the browser can act on a bad `.p8`.
    pub(crate) fn provider_config(
        &self,
        provider: &Provider,
        clock: &dyn factory0_core::Clock,
    ) -> Result<ProviderConfig, Problem> {
        let credentials = self
            .settings()?
            .provider_credentials(&*self.ctx.config, provider)
            .ok_or_else(|| Problem::new(&PROVIDER_UNCONFIGURED))?;
        let client_secret = match &credentials.secret {
            ConfiguredSecret::Static(value) => value.clone(),
            ConfiguredSecret::Apple(config) => self
                .apple
                .mint(config, &credentials.client_id, clock)
                .map_err(|err| {
                    // The message names the setting, never the key.
                    tracing::error!(error = %err, provider = provider.slug, "could not mint the client secret");
                    Problem::new(&PROVIDER_UNCONFIGURED)
                })?,
        };
        Ok(ProviderConfig {
            client_id: credentials.client_id,
            client_secret,
            redirect_uri: credentials.redirect_uri,
        })
    }
}

/// OpenID Connect login.
pub struct Oidc;

impl Default for Oidc {
    fn default() -> Self {
        Self::new()
    }
}

impl Oidc {
    pub fn new() -> Self {
        Self
    }
}

impl Module for Oidc {
    fn name(&self) -> &'static str {
        "auth-oidc"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn requires(&self) -> &'static [Port] {
        &[
            Port::Db,
            Port::Clock,
            Port::IdGen,
            Port::Signer,
            Port::HttpClient,
        ]
    }

    /// Both routes are reachable by anyone, and `/start` makes the service
    /// talk to a third party, so they are rate limited where a limiter
    /// exists.
    fn optional(&self) -> &'static [Port] {
        &[Port::RateLimiter]
    }

    /// None. `auth-core` owns every table this module touches.
    fn tables(&self) -> &'static [&'static str] {
        &[]
    }

    fn emits(&self) -> &'static [&'static str] {
        &[session::EVENT_LOGGED_IN, session::EVENT_AUTO_LINKED]
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
                    errors.push(format!("auth-oidc: {problem}"));
                }
                Err(errors)
            }
        }
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let settings = match resolve_settings(&*ctx.config) {
            Ok(settings) => Some(settings),
            Err(problems) => {
                tracing::error!(
                    problems = problems.join("; "),
                    "auth-oidc configuration is unusable"
                );
                None
            }
        };
        handlers::router().with_state(Arc::new(ModuleState {
            ctx: Arc::new(ctx),
            settings,
            discovery: discovery::Cache::default(),
            apple: apple::Minter::new(),
        }))
    }
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
    fn the_module_owns_no_tables_and_needs_the_ports_the_flow_uses() {
        let module = Oidc::new();
        assert_eq!(module.name(), "auth-oidc");
        assert!(module.tables().is_empty());
        assert!(module.migrations().sqlite.is_empty());
        assert!(module.requires().contains(&Port::HttpClient));
        assert!(module.requires().contains(&Port::Signer));
        assert_eq!(module.optional(), [Port::RateLimiter]);
        assert!(module.public_writes());
    }

    #[test]
    fn a_redirect_base_is_required_and_must_be_https() {
        assert!(Oidc::new().validate_config(&config(&[])).is_err());
        assert!(
            Oidc::new()
                .validate_config(&config(&[(
                    "AUTH_OIDC_REDIRECT_BASE",
                    "http://auth.factory0.ventures"
                )]))
                .is_err()
        );
        assert!(
            Oidc::new()
                .validate_config(&config(&[(
                    "AUTH_OIDC_REDIRECT_BASE",
                    "https://auth.factory0.ventures"
                )]))
                .is_ok()
        );
        assert!(
            Oidc::new()
                .validate_config(&config(&[(
                    "AUTH_OIDC_REDIRECT_BASE",
                    "http://localhost:8787"
                )]))
                .is_ok(),
            "wrangler dev has to work"
        );
    }

    #[test]
    fn half_a_credential_is_a_configuration_error() {
        // It would otherwise answer 503 at runtime with nothing to say why.
        let error = Oidc::new()
            .validate_config(&config(&[
                ("AUTH_OIDC_REDIRECT_BASE", "https://auth.factory0.ventures"),
                ("AUTH_OIDC_GOOGLE_CLIENT_ID", "id"),
            ]))
            .expect_err("half a credential");
        assert!(
            error.to_string().contains("GOOGLE_CLIENT_SECRET"),
            "{error}"
        );
    }

    #[test]
    fn a_default_return_to_that_could_leave_the_site_is_refused() {
        for bad in ["https://evil.example", "//evil.example", "not-a-path"] {
            assert!(
                Oidc::new()
                    .validate_config(&config(&[
                        ("AUTH_OIDC_REDIRECT_BASE", "https://auth.factory0.ventures"),
                        ("AUTH_OIDC_DEFAULT_RETURN_TO", bad),
                    ]))
                    .is_err(),
                "{bad} was accepted"
            );
        }
    }

    #[test]
    fn the_redirect_uri_is_built_from_the_base_and_the_slug() {
        let cfg = config(&[
            ("AUTH_OIDC_REDIRECT_BASE", "https://auth.factory0.ventures/"),
            ("AUTH_OIDC_GOOGLE_CLIENT_ID", "id"),
            ("AUTH_OIDC_GOOGLE_CLIENT_SECRET", "secret"),
        ]);
        let settings = resolve_settings(&cfg).expect("valid");
        let provider = settings
            .provider_credentials(&cfg, &GOOGLE)
            .expect("configured");
        // The trailing slash on the base must not become a double slash: a
        // redirect URI is matched exactly by the provider.
        assert_eq!(
            provider.redirect_uri,
            "https://auth.factory0.ventures/v1/auth-oidc/google/callback"
        );
    }

    fn apple_cfg(pairs: &[(&str, &str)]) -> MapConfig {
        let mut all = vec![("AUTH_OIDC_REDIRECT_BASE", "https://auth.example.com")];
        all.extend_from_slice(pairs);
        config(&all)
    }

    /// A valid PKCS#8 P-256 key, derived rather than pasted. Worthless.
    fn test_p8() -> String {
        use p256::pkcs8::EncodePrivateKey as _;
        p256::SecretKey::from_slice(&[7u8; 32])
            .expect("a valid P-256 scalar")
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("encodes")
            .to_string()
    }

    #[test]
    fn apple_resolves_its_secret_from_the_signing_settings() {
        let p8 = test_p8();
        let cfg = apple_cfg(&[
            ("AUTH_OIDC_APPLE_CLIENT_ID", "com.example.service"),
            ("AUTH_OIDC_APPLE_TEAM_ID", "TEAM123456"),
            ("AUTH_OIDC_APPLE_KEY_ID", "KEY7890123"),
            ("AUTH_OIDC_APPLE_PRIVATE_KEY", &p8),
        ]);
        let settings = resolve_settings(&cfg).expect("valid");
        let credentials = settings
            .provider_credentials(&cfg, &APPLE)
            .expect("configured");
        assert!(matches!(credentials.secret, ConfiguredSecret::Apple(_)));
        assert_eq!(
            credentials.redirect_uri,
            "https://auth.example.com/v1/auth-oidc/apple/callback"
        );
    }

    #[test]
    fn apple_without_all_three_signing_settings_is_named_at_build() {
        // Two out of three cannot mint, and the runtime failure at Apple is
        // opaque, so the missing keys are named here instead.
        let cfg = apple_cfg(&[
            ("AUTH_OIDC_APPLE_CLIENT_ID", "com.example.service"),
            ("AUTH_OIDC_APPLE_TEAM_ID", "TEAM123456"),
        ]);
        let problems = resolve_settings(&cfg).expect_err("incomplete");
        let joined = problems.join("; ");
        assert!(joined.contains("AUTH_OIDC_APPLE_KEY_ID"), "{joined}");
        assert!(joined.contains("AUTH_OIDC_APPLE_PRIVATE_KEY"), "{joined}");
        assert!(!joined.contains("AUTH_OIDC_APPLE_TEAM_ID"), "{joined}");
    }

    #[test]
    fn a_configured_apple_client_secret_is_refused_rather_than_ignored() {
        // Somebody who pastes one has misunderstood the setup, and silently
        // ignoring it would leave them debugging Apple's error instead.
        let p8 = test_p8();
        let cfg = apple_cfg(&[
            ("AUTH_OIDC_APPLE_CLIENT_ID", "com.example.service"),
            ("AUTH_OIDC_APPLE_TEAM_ID", "TEAM123456"),
            ("AUTH_OIDC_APPLE_KEY_ID", "KEY7890123"),
            ("AUTH_OIDC_APPLE_PRIVATE_KEY", &p8),
            ("AUTH_OIDC_APPLE_CLIENT_SECRET", "not a thing Apple takes"),
        ]);
        let problems = resolve_settings(&cfg).expect_err("refused");
        assert!(
            problems.join("; ").contains("does not take a"),
            "{problems:?}"
        );
    }

    #[test]
    fn signing_settings_without_a_services_id_are_named_too() {
        let p8 = test_p8();
        let cfg = apple_cfg(&[
            ("AUTH_OIDC_APPLE_TEAM_ID", "TEAM123456"),
            ("AUTH_OIDC_APPLE_KEY_ID", "KEY7890123"),
            ("AUTH_OIDC_APPLE_PRIVATE_KEY", &p8),
        ]);
        let problems = resolve_settings(&cfg).expect_err("incomplete");
        assert!(
            problems.join("; ").contains("AUTH_OIDC_APPLE_CLIENT_ID"),
            "{problems:?}"
        );
    }

    #[test]
    fn a_deployment_with_no_apple_settings_at_all_is_valid() {
        // Apple is optional. A venture that only wants Google must not be
        // told about Team IDs.
        let cfg = apple_cfg(&[
            ("AUTH_OIDC_GOOGLE_CLIENT_ID", "id"),
            ("AUTH_OIDC_GOOGLE_CLIENT_SECRET", "secret"),
        ]);
        let settings = resolve_settings(&cfg).expect("valid");
        assert!(settings.provider_credentials(&cfg, &APPLE).is_none());
    }
}
