//! The provider descriptor (issue #15).
//!
//! Google is the reference implementation, and the flow is written against
//! this descriptor rather than against Google, so Apple (#16) and any other
//! compliant provider arrive as data plus whatever quirk they insist on.

use factory0_auth_core::{PROVIDER_APPLE, PROVIDER_GOOGLE};
use openidconnect::AuthType;
use openidconnect::core::CoreJwsSigningAlgorithm;

/// How the provider delivers the authorization response.
///
/// This is not cosmetic. A `form_post` arrives as a cross-site `POST`, and
/// a `SameSite=Lax` cookie is not sent on one, so the descriptor decides
/// both the route that answers and the cookie the flow is sealed into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseMode {
    /// A top-level `GET` redirect with the code in the query string.
    Query,
    /// A cross-site `POST` with a form-encoded body. Apple only.
    FormPost,
}

/// Where the client secret comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretSource {
    /// A string the operator configures: `AUTH_OIDC_<CONFIG>_CLIENT_SECRET`.
    Configured,
    /// Minted per request as an ES256 JWT over the configured `.p8`
    /// (`crate::apple`). There is no secret to store and none to rotate.
    AppleMinted,
}

/// One OpenID Connect provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Provider {
    /// The path segment and the `identities.provider` value. These are the
    /// same string on purpose: a route that says `google` writes `google`.
    pub slug: &'static str,
    /// The issuer, from which discovery finds everything else.
    pub issuer: &'static str,
    /// Requested scopes beyond `openid`, which openidconnect always sends.
    pub scopes: &'static [&'static str],
    /// Config-key infix: `AUTH_OIDC_<CONFIG>_CLIENT_ID`.
    pub config: &'static str,
    /// Human label, for the pages this module renders.
    pub label: &'static str,
    /// The signing algorithms an ID token from this provider may use.
    /// Policy, not discovery: see the comment where it is applied.
    pub signing_algorithms: &'static [CoreJwsSigningAlgorithm],
    /// How the authorization response comes back.
    pub response_mode: ResponseMode,
    /// Where the client secret comes from.
    pub secret: SecretSource,
    /// How the client authenticates at the token endpoint.
    ///
    /// Pinned here, like the signing algorithms and for the same reason:
    /// the alternative is believing the discovery document. Apple accepts
    /// only `client_secret_post`, and a client that sends HTTP Basic gets
    /// an `invalid_client` that names nothing.
    pub auth_type: TokenAuth,
}

/// How the client authenticates at the token endpoint.
///
/// A local enum rather than `oauth2::AuthType` because that one is not
/// `Copy`, and [`Provider`] is a `const` a route looks up by reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenAuth {
    /// HTTP Basic: `client_secret_basic`.
    Basic,
    /// Credentials in the form body: `client_secret_post`.
    RequestBody,
}

impl TokenAuth {
    pub(crate) fn as_oauth(self) -> AuthType {
        match self {
            Self::Basic => AuthType::BasicAuth,
            Self::RequestBody => AuthType::RequestBody,
        }
    }
}

impl Provider {
    /// Whether this provider answers on the cross-site `POST` callback.
    pub(crate) fn is_form_post(&self) -> bool {
        matches!(self.response_mode, ResponseMode::FormPost)
    }
}

pub const GOOGLE: Provider = Provider {
    slug: PROVIDER_GOOGLE,
    issuer: "https://accounts.google.com",
    scopes: &["email", "profile"],
    config: "GOOGLE",
    label: "Google",
    signing_algorithms: &[CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
    response_mode: ResponseMode::Query,
    secret: SecretSource::Configured,
    auth_type: TokenAuth::Basic,
};

/// Sign in with Apple (issues #3, #16).
///
/// The scopes are the reason the response mode is what it is: asking for
/// `name` or `email` makes Apple send the response as a `form_post`, and
/// Apple documents that as the only supported mode for those scopes.
pub const APPLE: Provider = Provider {
    slug: PROVIDER_APPLE,
    issuer: "https://appleid.apple.com",
    scopes: &["name", "email"],
    config: "APPLE",
    label: "Apple",
    // Apple signs ID tokens with RS256 and publishes only RSA keys.
    signing_algorithms: &[CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
    response_mode: ResponseMode::FormPost,
    secret: SecretSource::AppleMinted,
    // Apple documents `client_secret_post` and refuses HTTP Basic.
    auth_type: TokenAuth::RequestBody,
};

/// Every provider this module serves. Adding one is a line here plus its
/// config keys.
pub const PROVIDERS: &[Provider] = &[GOOGLE, APPLE];

/// The provider a request names, or `None` when the path segment is not one
/// we serve.
pub fn by_slug(slug: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|provider| provider.slug == slug)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_slug_is_the_identity_provider_value() {
        // The route segment and the row written into `identities` are the
        // same string; if they ever drift, a second login makes a second
        // account instead of matching the first.
        assert_eq!(GOOGLE.slug, PROVIDER_GOOGLE);
        assert_eq!(by_slug("google"), Some(&GOOGLE));
        assert_eq!(by_slug("Google"), None);
        assert_eq!(APPLE.slug, PROVIDER_APPLE);
        assert_eq!(by_slug("apple"), Some(&APPLE));
    }

    #[test]
    fn only_apple_uses_the_form_post_callback() {
        // The cross-site POST route and the `SameSite=None` cookie are both
        // driven off this, so widening it widens both.
        assert!(APPLE.is_form_post());
        assert!(!GOOGLE.is_form_post());
        assert_eq!(
            PROVIDERS.iter().filter(|p| p.is_form_post()).count(),
            1,
            "a new form_post provider must be a deliberate decision"
        );
    }

    #[test]
    fn apple_asks_for_the_scopes_that_force_form_post() {
        // These two are the reason Apple posts rather than redirects. If
        // they ever go, the response mode should be revisited rather than
        // left as a POST route nobody uses.
        assert!(APPLE.scopes.contains(&"name"));
        assert!(APPLE.scopes.contains(&"email"));
        assert!(!APPLE.scopes.contains(&"openid"));
    }

    #[test]
    fn apple_authenticates_in_the_request_body() {
        // Apple refuses HTTP Basic with `invalid_client`, which names
        // nothing and reads like a bad key.
        assert_eq!(APPLE.auth_type, TokenAuth::RequestBody);
        assert_eq!(GOOGLE.auth_type, TokenAuth::Basic);
    }

    #[test]
    fn only_apple_mints_its_own_secret() {
        assert_eq!(APPLE.secret, SecretSource::AppleMinted);
        assert_eq!(GOOGLE.secret, SecretSource::Configured);
    }

    #[test]
    fn every_provider_has_its_own_slug_and_config_infix() {
        // Two providers sharing either one would read each other's keys or
        // each other's identity rows.
        for (index, provider) in PROVIDERS.iter().enumerate() {
            for other in &PROVIDERS[index + 1..] {
                assert_ne!(provider.slug, other.slug);
                assert_ne!(provider.config, other.config);
                assert_ne!(provider.issuer, other.issuer);
            }
        }
    }

    #[test]
    fn only_rs256_is_accepted_from_google() {
        // A document that listed HS256 would otherwise be believed, and
        // openidconnect verifies HS256 with the client secret we hold.
        assert_eq!(
            GOOGLE.signing_algorithms,
            [CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256]
        );
    }

    #[test]
    fn openid_is_not_in_the_scope_list() {
        // openidconnect always sends `openid`; listing it again would ask
        // for it twice.
        assert!(!GOOGLE.scopes.contains(&"openid"));
        assert!(GOOGLE.scopes.contains(&"email"));
    }
}
