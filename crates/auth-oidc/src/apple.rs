//! Sign in with Apple's three departures from ordinary OIDC (issues #3, #16).
//!
//! Everything else about Apple is a compliant OpenID Connect provider and
//! is served by the same flow Google is. These three are not, and each one
//! breaks a naive integration in its own way:
//!
//! 1. **The client secret is not a string.** It is an ES256 JWT signed with
//!    a private key Apple issues as a `.p8` file, valid at most six months.
//!    There is nothing to paste into configuration and nothing stored to
//!    rotate: [`Minter`] mints one on demand and caches it well inside its
//!    own lifetime. Rotating the key is a secret swap and a key-id change.
//! 2. **The authorization response arrives as a cross-site `form_post`.**
//!    Handled in [`crate::flow`] and [`crate::handlers`], not here.
//! 3. **The person's name arrives exactly once**, as JSON in the first
//!    authorization's form body and never again. [`name_from_user_field`]
//!    reads it; the linking rules store it on the identity or lose it.
//!
//! The private key never leaves this module: it is parsed inside
//! [`Minter::mint`], used, and dropped. It is never logged, never written
//! to the database, and [`AppleKeyError`] is deliberately vague about what
//! was wrong with it so a misconfiguration cannot echo key material into a
//! log line.

use base64ct::{Base64UrlUnpadded, Encoding as _};
use factory0_core::Clock;
use p256::ecdsa::{self, signature::Signer as _};
use p256::pkcs8::DecodePrivateKey as _;
use serde_json::{Value, json};
use std::sync::RwLock;

/// The audience every Apple client secret is minted for.
pub(crate) const AUDIENCE: &str = "https://appleid.apple.com";

/// How long a minted secret claims to be good for. Apple's ceiling is six
/// months; nothing here needs more than one token exchange, so this is set
/// by clock skew rather than by convenience. Short lifetimes also mean a
/// secret that somehow escapes a log is worthless within the hour.
pub(crate) const LIFETIME_SECS: i64 = 3600;

/// Re-mint this long before expiry, so a cached secret can never be handed
/// out with only seconds left and expire in flight at Apple.
const REFRESH_MARGIN_SECS: i64 = 300;

/// Apple's own maximum, six months.
pub(crate) const APPLE_MAX_LIFETIME_SECS: i64 = 15_777_000;

// A secret claiming more than six months is refused by Apple with an error
// that does not say so, and it would be refused on every sign-in rather
// than in any test that does not talk to Apple. So this is a build failure,
// not a test failure.
const _: () = assert!(LIFETIME_SECS < APPLE_MAX_LIFETIME_SECS);
const _: () = assert!(REFRESH_MARGIN_SECS < LIFETIME_SECS);

/// The key, or the configuration around it, is unusable.
///
/// One variant on purpose. The operator learns that the Apple key is bad
/// from the message; nobody learns *how* it is bad, because the ways a
/// PKCS#8 parse can fail are a description of the bytes it was given.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the Apple signing key is not a usable PKCS#8 P-256 private key")]
pub(crate) struct AppleKeyError;

/// The configured Apple identifiers, resolved once per router build.
///
/// `private_key` is the contents of the `.p8` file Apple issues. It is a
/// Worker secret: never in the database, never in the repository.
#[derive(Clone)]
pub(crate) struct AppleConfig {
    /// The ten-character Apple Developer Team ID. Becomes `iss`.
    pub team_id: String,
    /// The key's own id, from the Apple Developer console. Becomes `kid`.
    pub key_id: String,
    /// The PKCS#8 PEM contents of the `.p8`.
    pub private_key: String,
}

impl std::fmt::Debug for AppleConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The identifiers are not secret; the key is. A derived `Debug`
        // would put a private key into any log line that formats a config.
        f.debug_struct("AppleConfig")
            .field("team_id", &self.team_id)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// A minted secret and the moment it stops being safe to reuse.
#[derive(Debug, Clone)]
struct Cached {
    secret: String,
    /// Unix seconds. Compared against the `Clock` port, never the wall
    /// clock, which is unreadable on wasm32 (ADR 0100) and untestable.
    good_until: i64,
    /// The client id the secret was minted for. Configuration can change
    /// between deploys within one isolate's life, and a secret minted for
    /// another `sub` is refused by Apple rather than being merely stale.
    client_id: String,
}

/// Mints and caches Apple client secrets.
///
/// One per module. The lock is held only to read or replace a small
/// struct, never across the signing itself.
#[derive(Debug, Default)]
pub(crate) struct Minter {
    cached: RwLock<Option<Cached>>,
}

impl Minter {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The client secret for a token exchange: the cached one when it has
    /// comfortable life left, a freshly minted one otherwise.
    ///
    /// # Errors
    ///
    /// [`AppleKeyError`] when the configured `.p8` is not a P-256 PKCS#8
    /// private key. Nothing else can fail: the claims are built from
    /// configuration and the clock.
    pub(crate) fn mint(
        &self,
        config: &AppleConfig,
        client_id: &str,
        clock: &dyn Clock,
    ) -> Result<String, AppleKeyError> {
        let now = clock.now().unix_timestamp();
        if let Some(hit) = self.cached_secret(client_id, now) {
            return Ok(hit);
        }
        let secret = sign_client_secret(config, client_id, now)?;
        if let Ok(mut slot) = self.cached.write() {
            *slot = Some(Cached {
                secret: secret.clone(),
                good_until: now + LIFETIME_SECS - REFRESH_MARGIN_SECS,
                client_id: client_id.to_owned(),
            });
        }
        Ok(secret)
    }

    fn cached_secret(&self, client_id: &str, now: i64) -> Option<String> {
        let slot = self.cached.read().ok()?;
        let cached = slot.as_ref()?;
        (cached.client_id == client_id && cached.good_until > now).then(|| cached.secret.clone())
    }
}

/// Builds and signs one client secret. Separate from the cache so the
/// claims can be tested without one.
fn sign_client_secret(
    config: &AppleConfig,
    client_id: &str,
    now: i64,
) -> Result<String, AppleKeyError> {
    let signing = signing_key(&config.private_key)?;
    let header = json!({ "alg": "ES256", "kid": config.key_id });
    let claims = json!({
        "iss": config.team_id,
        "iat": now,
        "exp": now + LIFETIME_SECS,
        "aud": AUDIENCE,
        // Apple wants the Services ID here, which is the same value that
        // goes in `client_id` on the token request. Passed in rather than
        // read from `AppleConfig` so the two can never disagree.
        "sub": client_id,
    });
    let signing_input = format!(
        "{}.{}",
        b64url(&serde_json::to_vec(&header).map_err(|_| AppleKeyError)?),
        b64url(&serde_json::to_vec(&claims).map_err(|_| AppleKeyError)?),
    );
    let signature: ecdsa::Signature = signing.sign(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", b64url(&signature.to_bytes())))
}

/// Parses the `.p8`.
///
/// Apple issues PKCS#8 PEM. Both the PEM and the bare base64 body are
/// accepted, because an operator moving a key through a secret store often
/// loses the armour lines, and refusing that costs an afternoon.
fn signing_key(private_key: &str) -> Result<ecdsa::SigningKey, AppleKeyError> {
    let trimmed = private_key.trim();
    if trimmed.contains("-----BEGIN") {
        return ecdsa::SigningKey::from_pkcs8_pem(trimmed).map_err(|_| AppleKeyError);
    }
    // No armour: re-armour it rather than hand-rolling a DER parse. The
    // whitespace strip is what makes a key pasted across several lines,
    // or through a YAML block, work.
    let body: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    if body.is_empty() {
        return Err(AppleKeyError);
    }
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in body.as_bytes().chunks(64) {
        // Every byte came from a `char` that is not whitespace, and the
        // base64 alphabet is ASCII, so a chunk boundary cannot split a
        // multi-byte character in a *valid* key. An invalid one fails the
        // parse below, which is where it should fail.
        let Ok(line) = std::str::from_utf8(chunk) else {
            return Err(AppleKeyError);
        };
        pem.push_str(line);
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    ecdsa::SigningKey::from_pkcs8_pem(&pem).map_err(|_| AppleKeyError)
}

fn b64url(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// The name from Apple's first-authorization `user` field, if it carried
/// one worth keeping.
///
/// Apple posts `user` as a JSON string in the form body, and only on the
/// very first authorization for a given Services ID. Every later sign-in
/// arrives without it, so this is the one chance to learn the name. A
/// malformed value is not an error: the sign-in is still valid, and a
/// missing name is the ordinary case.
pub(crate) fn name_from_user_field(user: &str) -> Option<String> {
    let parsed: Value = serde_json::from_str(user).ok()?;
    let name = parsed.get("name")?;
    let first = name.get("firstName").and_then(Value::as_str).unwrap_or("");
    let last = name.get("lastName").and_then(Value::as_str).unwrap_or("");
    let joined = format!("{first} {last}");
    let joined = joined.trim();
    if joined.is_empty() {
        return None;
    }
    // A name is displayed, and Apple does not promise anything about the
    // bytes. Control characters would let a name break a log line or a
    // rendered page open.
    if joined.chars().any(char::is_control) || joined.chars().count() > 200 {
        return None;
    }
    Some(joined.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::pkcs8::EncodePrivateKey as _;

    /// A clock the tests drive, so nothing here reads the wall clock.
    fn at(secs: i64) -> factory0_testing::FixedClock {
        factory0_testing::FixedClock(
            time::OffsetDateTime::from_unix_timestamp(secs).expect("in range"),
        )
    }

    /// A fixed P-256 key in the PEM shape Apple issues. Fixed rather than
    /// random so a failure is reproducible, and because ECDSA here is
    /// deterministic, which one test below relies on.
    fn test_key() -> String {
        let scalar = [7u8; 32];
        p256::SecretKey::from_slice(&scalar)
            .expect("a valid P-256 scalar")
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .expect("encodes")
            .to_string()
    }

    fn config() -> AppleConfig {
        AppleConfig {
            team_id: "TEAM123456".into(),
            key_id: "KEY7890123".into(),
            private_key: test_key(),
        }
    }

    fn part(token: &str, index: usize) -> Value {
        let raw = token.split('.').nth(index).expect("part");
        let bytes = Base64UrlUnpadded::decode_vec(raw).expect("base64url");
        serde_json::from_slice(&bytes).expect("json")
    }

    #[test]
    fn the_minted_secret_carries_apples_claims() {
        let clock = at(1_800_000_000);
        let token = Minter::new()
            .mint(&config(), "com.example.service", &clock)
            .expect("mints");

        let header = part(&token, 0);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "KEY7890123", "Apple selects the key by kid");
        assert!(
            header.get("typ").is_none(),
            "Apple does not want a typ, and sending one has broken before"
        );

        let claims = part(&token, 1);
        assert_eq!(claims["iss"], "TEAM123456", "iss is the Team ID");
        assert_eq!(
            claims["sub"], "com.example.service",
            "sub is the Services ID, the same value as client_id"
        );
        assert_eq!(claims["aud"], AUDIENCE);
        assert_eq!(claims["iat"], 1_800_000_000);
        assert_eq!(claims["exp"], 1_800_000_000 + LIFETIME_SECS);
        assert_eq!(token.split('.').count(), 3);
    }

    #[test]
    fn the_signature_verifies_under_the_configured_key() {
        let config = config();
        let token =
            sign_client_secret(&config, "com.example.service", 1_800_000_000).expect("mints");
        let signing = signing_key(&config.private_key).expect("parses");

        let (input, signature) = token.rsplit_once('.').expect("three parts");
        let raw = Base64UrlUnpadded::decode_vec(signature).expect("base64url");
        let parsed = ecdsa::Signature::from_slice(&raw).expect("signature");
        p256::ecdsa::signature::Verifier::verify(
            signing.verifying_key(),
            input.as_bytes(),
            &parsed,
        )
        .expect("the minted secret verifies under its own key");
    }

    #[test]
    fn a_cached_secret_is_reused_until_the_margin() {
        let minter = Minter::new();
        let config = config();
        let clock = at(1_800_000_000);
        let first = minter.mint(&config, "com.example.service", &clock).unwrap();
        let second = minter.mint(&config, "com.example.service", &clock).unwrap();
        assert_eq!(first, second, "the second call is a cache hit");

        // One second past the refresh margin, a new one is minted.
        let later = at(1_800_000_000 + LIFETIME_SECS - REFRESH_MARGIN_SECS + 1);
        let third = minter.mint(&config, "com.example.service", &later).unwrap();
        assert_ne!(third, first, "the cache expires before the secret does");
        assert_eq!(
            part(&third, 1)["exp"],
            later.now().unix_timestamp() + LIFETIME_SECS
        );
    }

    #[test]
    fn a_changed_client_id_is_not_served_from_the_cache() {
        // Configuration can change under a live isolate. A secret whose
        // `sub` names the old Services ID is refused by Apple, and the
        // failure looks like a key problem rather than a stale cache.
        let minter = Minter::new();
        let config = config();
        let clock = at(1_800_000_000);
        let first = minter.mint(&config, "com.example.one", &clock).unwrap();
        let second = minter.mint(&config, "com.example.two", &clock).unwrap();
        assert_ne!(first, second);
        assert_eq!(part(&second, 1)["sub"], "com.example.two");
    }

    #[test]
    fn a_key_without_its_armour_is_still_accepted() {
        let armoured = test_key();
        let bare: String = armoured
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        assert!(signing_key(&bare).is_ok(), "a de-armoured key must work");
        // And the same key both ways signs identically.
        let config_armoured = AppleConfig {
            private_key: armoured,
            ..config()
        };
        let config_bare = AppleConfig {
            private_key: bare,
            ..config_armoured.clone()
        };
        assert_eq!(
            sign_client_secret(&config_armoured, "x", 1).unwrap(),
            sign_client_secret(&config_bare, "x", 1).unwrap(),
            "ECDSA here is deterministic (RFC 6979), so the same key gives the same token"
        );
    }

    #[test]
    fn rubbish_where_a_key_should_be_is_refused_without_saying_why() {
        for bad in [
            "",
            "   ",
            "not a key",
            "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----",
            // An RSA key: valid PKCS#8, wrong curve.
            "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8=\n-----END PRIVATE KEY-----",
        ] {
            assert_eq!(signing_key(bad), Err(AppleKeyError), "{bad:?} was accepted");
        }
        // The message names the setting, never the bytes.
        let rendered = AppleKeyError.to_string();
        assert!(rendered.contains("Apple signing key"));
        assert!(!rendered.contains("BEGIN"));
    }

    #[test]
    fn the_debug_of_a_config_never_carries_the_key() {
        let rendered = format!("{:?}", config());
        assert!(rendered.contains("TEAM123456"));
        assert!(rendered.contains("KEY7890123"));
        assert!(
            !rendered.contains("PRIVATE KEY") && !rendered.contains("private_key"),
            "a config in a log line must not carry key material: {rendered}"
        );
    }

    #[test]
    fn the_first_authorization_name_is_read_and_joined() {
        assert_eq!(
            name_from_user_field(r#"{"name":{"firstName":"Ada","lastName":"Lovelace"}}"#)
                .as_deref(),
            Some("Ada Lovelace")
        );
        // Apple sends the halves independently; either alone is a name.
        assert_eq!(
            name_from_user_field(r#"{"name":{"firstName":"Ada"}}"#).as_deref(),
            Some("Ada")
        );
        assert_eq!(
            name_from_user_field(r#"{"name":{"lastName":"Lovelace"}}"#).as_deref(),
            Some("Lovelace")
        );
    }

    #[test]
    fn a_user_field_worth_nothing_is_not_a_failure() {
        // Every one of these is an ordinary second sign-in or a provider
        // change, not an error: the callback continues without a name.
        for empty in [
            "",
            "{}",
            "not json",
            r#"{"email":"someone@example.com"}"#,
            r#"{"name":{}}"#,
            r#"{"name":{"firstName":"","lastName":"  "}}"#,
            r#"{"name":"Ada"}"#,
        ] {
            assert_eq!(name_from_user_field(empty), None, "{empty:?}");
        }
    }

    #[test]
    fn a_name_that_could_break_a_log_or_a_page_is_dropped() {
        assert_eq!(
            name_from_user_field("{\"name\":{\"firstName\":\"Ada\\nSet-Cookie: x\"}}"),
            None,
            "a control character in a displayed name is not worth keeping"
        );
        let long = "a".repeat(300);
        assert_eq!(
            name_from_user_field(&format!(r#"{{"name":{{"firstName":"{long}"}}}}"#)),
            None
        );
    }
}
