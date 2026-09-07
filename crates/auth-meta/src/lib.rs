//! `factory0-auth-meta`: Facebook Login (issue #17).
//!
//! ```no_run
//! use factory0_auth_meta::Meta;
//!
//! let module = Meta::new();
//! ```
//!
//! Meta is **not** an OpenID Connect provider, which is why this is its own
//! crate rather than a descriptor on `auth-oidc`: there is no discovery
//! document, no ID token and no nonce. What comes back from the
//! authorization code is a plain OAuth 2.0 access token, and who the person
//! is comes from a Graph call made with it (ADR 0104).
//!
//! That difference is the whole module. Everything after "Meta says this is
//! person X" — which account that is, whether it links, and the session —
//! belongs to `auth-core::federated`, exactly as it does for Google and
//! Apple. This module owns no tables.
//!
//! **The address Meta reports is never stored as verified.** Meta does not
//! assert verification in a form this service can rely on, and an address
//! recorded as verified is a key: the linking rules auto-link on a verified
//! match, so believing Meta here would let anyone who can get an address
//! onto a Facebook account walk into the matching account here. The cost is
//! that a Meta sign-in whose address already exists asks the person to sign
//! in the way they already can and link from there, which is the right
//! trade and is the same answer any unverified provider gets.

#![forbid(unsafe_code)]

mod flow;
mod graph;
mod handlers;
mod session;

use factory0_core::{
    Config, ConfigError, Migrations, Module, ModuleConfig, ModuleContext, Port, Problem, ProblemDef,
};
use http::StatusCode;
use std::sync::Arc;

/// Meta is mounted but not configured. Named rather than hidden: the
/// operator needs to know which key is missing, and a caller needs to know
/// the button they pressed is not wired up.
pub const NOT_CONFIGURED: ProblemDef = ProblemDef {
    slug: "auth/meta-not-configured",
    status: StatusCode::SERVICE_UNAVAILABLE,
    title: "Facebook sign-in is not configured",
    description: "AUTH_META_CLIENT_ID and AUTH_META_CLIENT_SECRET must both be set",
};

/// Meta, or our request to it, failed in a way the person cannot act on.
pub const META_UNAVAILABLE: ProblemDef = ProblemDef {
    slug: "auth/meta-unavailable",
    status: StatusCode::BAD_GATEWAY,
    title: "Facebook could not be reached",
    description: "The token exchange or the profile call failed; the detail is in the logs",
};

/// Every way a callback can be invalid answers with this, for the same
/// reason the other login methods have one refusal: telling a caller which
/// check failed tells an attacker which half to work on.
pub const CALLBACK_REFUSED: ProblemDef = ProblemDef {
    slug: "auth/meta-callback-refused",
    status: StatusCode::BAD_REQUEST,
    title: "That sign-in link is no longer valid",
    description: "Missing, expired, replayed or mismatched authorization state",
};

pub(crate) const DEFAULT_RETURN_TO: &str = "/";

/// The permissions this module asks for. `public_profile` is granted
/// automatically; `email` is the one a person can decline, and declining it
/// is not an error.
pub(crate) const SCOPES: &[&str] = &["public_profile", "email"];

/// The resolved configuration.
#[derive(Clone)]
pub(crate) struct Settings {
    pub client_id: String,
    pub client_secret: String,
    /// The public origin this service answers on. The redirect URI is built
    /// from it and must match what the Meta app has registered, exactly.
    pub redirect_base: String,
    pub default_return_to: String,
    pub graph_version: String,
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The app secret is a secret, and a derived `Debug` would put it in
        // any log line that formats a config.
        f.debug_struct("Settings")
            .field("client_id", &self.client_id)
            .field("redirect_base", &self.redirect_base)
            .field("graph_version", &self.graph_version)
            .finish_non_exhaustive()
    }
}

impl Settings {
    pub(crate) fn redirect_uri(&self) -> String {
        format!(
            "{}/v1/auth-meta/callback",
            self.redirect_base.trim_end_matches('/')
        )
    }
}

fn resolve_settings(cfg: &dyn Config) -> Result<Option<Settings>, Vec<String>> {
    let module = ModuleConfig::new("auth-meta", cfg);
    let mut problems = Vec::new();

    let get = |key: &str| module.get_opt(key).filter(|value| !value.trim().is_empty());
    let client_id = get("CLIENT_ID");
    let client_secret = get("CLIENT_SECRET");

    // Not configured at all is a valid deployment: a venture that does not
    // offer Facebook simply does not set these. Half of them is not.
    if client_id.is_none() && client_secret.is_none() {
        return Ok(None);
    }
    if client_id.is_none() || client_secret.is_none() {
        problems.push(format!(
            "both {} and {} must be set, or neither",
            module.key("CLIENT_ID"),
            module.key("CLIENT_SECRET")
        ));
    }

    let redirect_base = get("REDIRECT_BASE").unwrap_or_default();
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
    if handlers::safe_return_to(Some(&default_return_to)).is_none() {
        problems.push(format!(
            "{} must be a path on this service beginning with a single /, got {default_return_to:?}",
            module.key("DEFAULT_RETURN_TO")
        ));
    }

    let graph_version = module.get_str("GRAPH_VERSION", graph::DEFAULT_GRAPH_VERSION);
    // A version is `vNN.N`. A typo here fails every call to Meta with an
    // error that names the URL and not the setting.
    if !(graph_version.starts_with('v')
        && graph_version.len() >= 3
        && graph_version[1..]
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.'))
    {
        problems.push(format!(
            "{} must look like v21.0, got {graph_version:?}",
            module.key("GRAPH_VERSION")
        ));
    }

    if !problems.is_empty() {
        return Err(problems);
    }
    Ok(Some(Settings {
        client_id: client_id.unwrap_or_default(),
        client_secret: client_secret.unwrap_or_default(),
        redirect_base: trimmed,
        default_return_to,
        graph_version,
    }))
}

pub(crate) struct ModuleState {
    pub ctx: Arc<ModuleContext>,
    pub settings: Option<Settings>,
}

impl ModuleState {
    pub(crate) fn settings(&self) -> Result<&Settings, Problem> {
        self.settings
            .as_ref()
            .ok_or_else(|| Problem::new(&NOT_CONFIGURED))
    }
}

/// Facebook Login.
pub struct Meta;

impl Default for Meta {
    fn default() -> Self {
        Self::new()
    }
}

impl Meta {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Module for Meta {
    fn name(&self) -> &'static str {
        "auth-meta"
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
                    errors.push(format!("auth-meta: {problem}"));
                }
                Err(errors)
            }
        }
    }

    fn router(&self, ctx: ModuleContext) -> axum::Router {
        let settings = match resolve_settings(&*ctx.config) {
            Ok(settings) => settings,
            Err(problems) => {
                tracing::error!(
                    problems = problems.join("; "),
                    "auth-meta configuration is unusable"
                );
                None
            }
        };
        handlers::router().with_state(Arc::new(ModuleState {
            ctx: Arc::new(ctx),
            settings,
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
        let module = Meta::new();
        assert_eq!(module.name(), "auth-meta");
        assert!(
            module.tables().is_empty(),
            "auth-core owns the schema; a second owner is a build error"
        );
        assert!(module.requires().contains(&Port::HttpClient));
        assert!(module.requires().contains(&Port::Signer));
        assert!(module.optional().contains(&Port::RateLimiter));
        assert!(module.public_writes());
    }

    #[test]
    fn a_deployment_that_does_not_offer_facebook_is_valid() {
        let cfg = config(&[]);
        assert!(matches!(resolve_settings(&cfg), Ok(None)));
        assert!(Meta::new().validate_config(&cfg).is_ok());
    }

    #[test]
    fn half_a_credential_is_a_build_failure() {
        let cfg = config(&[
            ("AUTH_META_CLIENT_ID", "123"),
            ("AUTH_META_REDIRECT_BASE", "https://auth.example.com"),
        ]);
        let problems = resolve_settings(&cfg).expect_err("refused");
        assert!(
            problems.join("; ").contains("AUTH_META_CLIENT_SECRET"),
            "{problems:?}"
        );
    }

    #[test]
    fn the_redirect_uri_is_built_from_the_base() {
        let cfg = config(&[
            ("AUTH_META_CLIENT_ID", "123"),
            ("AUTH_META_CLIENT_SECRET", "shh"),
            ("AUTH_META_REDIRECT_BASE", "https://auth.factory0.ventures/"),
        ]);
        let settings = resolve_settings(&cfg).expect("valid").expect("configured");
        // The trailing slash must not become a double slash: Meta matches
        // the redirect URI exactly.
        assert_eq!(
            settings.redirect_uri(),
            "https://auth.factory0.ventures/v1/auth-meta/callback"
        );
    }

    #[test]
    fn a_plausible_graph_version_is_required() {
        let base = [
            ("AUTH_META_CLIENT_ID", "123"),
            ("AUTH_META_CLIENT_SECRET", "shh"),
            ("AUTH_META_REDIRECT_BASE", "https://auth.example.com"),
        ];
        for bad in ["21.0", "vTwentyOne", "", "v"] {
            let mut pairs = base.to_vec();
            pairs.push(("AUTH_META_GRAPH_VERSION", bad));
            assert!(
                resolve_settings(&config(&pairs)).is_err(),
                "{bad:?} was accepted as a Graph version"
            );
        }
        let mut pairs = base.to_vec();
        pairs.push(("AUTH_META_GRAPH_VERSION", "v23.0"));
        let settings = resolve_settings(&config(&pairs))
            .expect("valid")
            .expect("configured");
        assert_eq!(settings.graph_version, "v23.0");
    }

    #[test]
    fn the_debug_of_settings_never_carries_the_app_secret() {
        let cfg = config(&[
            ("AUTH_META_CLIENT_ID", "123"),
            ("AUTH_META_CLIENT_SECRET", "the-app-secret"),
            ("AUTH_META_REDIRECT_BASE", "https://auth.example.com"),
        ]);
        let settings = resolve_settings(&cfg).expect("valid").expect("configured");
        let rendered = format!("{settings:?}");
        assert!(rendered.contains("123"));
        assert!(
            !rendered.contains("the-app-secret"),
            "the app secret reached a log line: {rendered}"
        );
    }

    #[test]
    fn the_scopes_are_the_two_meta_documents() {
        assert!(SCOPES.contains(&"email"));
        assert!(SCOPES.contains(&"public_profile"));
        assert_eq!(SCOPES.len(), 2, "a new scope needs an app-review decision");
    }
}
