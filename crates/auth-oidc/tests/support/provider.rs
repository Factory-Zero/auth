//! A fake OpenID Connect provider.
//!
//! It answers discovery, JWKS and the token endpoint, and mints real RS256
//! ID tokens with a test key, so the tests exercise the actual verification
//! path rather than a stub of it. Every claim a test needs to break — nonce,
//! audience, issuer, expiry, signing key — is a knob here.

#![allow(dead_code)]

use async_trait::async_trait;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use bytes::Bytes;
use factory0_core::{HttpClient, HttpError};
use http::{Request, Response};
use rsa::signature::{SignatureEncoding as _, Signer as _};
use serde_json::{Value, json};
use std::sync::{Arc, OnceLock, RwLock};

pub const ISSUER: &str = "https://accounts.google.com";
pub const JWKS_URI: &str = "https://www.googleapis.com/oauth2/v3/certs";
pub const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
pub const AUTHORIZATION_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const CLIENT_ID: &str = "test-client.apps.googleusercontent.com";
pub const KEY_ID: &str = "test-key-1";

// Apple (#16). Same machinery, different host: the issuer is checked for
// real, so a fake that answered every discovery with Google's issuer would
// make the Apple tests prove nothing.
pub const APPLE_ISSUER: &str = "https://appleid.apple.com";
pub const APPLE_JWKS_URI: &str = "https://appleid.apple.com/auth/keys";
pub const APPLE_TOKEN_ENDPOINT: &str = "https://appleid.apple.com/auth/token";
pub const APPLE_AUTHORIZATION_ENDPOINT: &str = "https://appleid.apple.com/auth/authorize";
/// Apple calls this the Services ID.
pub const APPLE_CLIENT_ID: &str = "com.example.service";

/// One 2048-bit key for the whole test binary; generating one per test would
/// dominate the run.
fn key() -> &'static rsa::RsaPrivateKey {
    static KEY: OnceLock<rsa::RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| {
        rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("rsa key generates")
    })
}

/// What the next ID token will claim. Defaults are a well-formed Google
/// token; a test changes one thing at a time.
#[derive(Debug, Clone)]
pub struct TokenClaims {
    pub issuer: String,
    pub audience: String,
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
    /// Overrides the nonce the flow asked for. `None` means "echo it",
    /// which is what a real provider does.
    pub nonce: Option<String>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub key_id: String,
    /// Send `email_verified` as the JSON string Apple sends rather than a
    /// boolean. Apple documents the claim as "a String or Boolean", and a
    /// fake that only ever mints a bool cannot catch a client that only
    /// accepts one.
    pub email_verified_as_string: bool,
}

impl Default for TokenClaims {
    fn default() -> Self {
        Self {
            issuer: ISSUER.to_owned(),
            audience: CLIENT_ID.to_owned(),
            subject: "google-subject-1".to_owned(),
            email: Some("nick@example.com".to_owned()),
            email_verified: true,
            name: Some("Nick".to_owned()),
            nonce: None,
            // The kit's clock sits at 1_788_775_200.
            issued_at: 1_788_775_100,
            expires_at: 1_788_778_800,
            key_id: KEY_ID.to_owned(),
            email_verified_as_string: false,
        }
    }
}

#[derive(Default)]
struct Inner {
    calls: RwLock<Vec<(String, String, String)>>,
    claims: RwLock<Option<TokenClaims>>,
    /// The nonce the flow asked for, captured from the authorization URL.
    nonce: RwLock<Option<String>>,
    /// Serve this key id in the JWKS, which is how a rotation is staged.
    published_key_id: RwLock<Option<String>>,
    token_error: RwLock<Option<(u16, Value)>>,
    discovery_error: RwLock<Option<u16>>,
}

#[derive(Clone, Default)]
pub struct FakeProvider {
    inner: Arc<Inner>,
}

impl FakeProvider {
    pub fn new() -> Self {
        Self::default()
    }

    /// What the next ID token will say.
    pub fn set_claims(&self, claims: TokenClaims) {
        *self.inner.claims.write().expect("lock") = Some(claims);
    }

    /// The nonce the module put in the authorization URL. A real provider
    /// echoes it into the ID token, and so does this one unless a test says
    /// otherwise.
    pub fn set_nonce(&self, nonce: &str) {
        *self.inner.nonce.write().expect("lock") = Some(nonce.to_owned());
    }

    /// Publish a different key id in the JWKS than the one that signs, which
    /// is what a key rotation looks like from the relying party's side.
    pub fn publish_key_id(&self, key_id: &str) {
        *self.inner.published_key_id.write().expect("lock") = Some(key_id.to_owned());
    }

    pub fn fail_token(&self, status: u16, body: Value) {
        *self.inner.token_error.write().expect("lock") = Some((status, body));
    }

    pub fn fail_discovery(&self, status: u16) {
        *self.inner.discovery_error.write().expect("lock") = Some(status);
    }

    pub fn calls(&self) -> Vec<(String, String, String)> {
        self.inner.calls.read().expect("lock").clone()
    }

    pub fn calls_to(&self, url_contains: &str) -> usize {
        self.calls()
            .iter()
            .filter(|(_, url, _)| url.contains(url_contains))
            .count()
    }

    fn claims(&self) -> TokenClaims {
        self.inner
            .claims
            .read()
            .expect("lock")
            .clone()
            .unwrap_or_default()
    }

    fn id_token(&self) -> String {
        let mut claims = self.claims();
        if claims.nonce.is_none() {
            claims
                .nonce
                .clone_from(&self.inner.nonce.read().expect("lock"));
        }
        mint(&claims)
    }

    fn jwks(&self) -> Value {
        use rsa::traits::PublicKeyParts as _;
        let public = rsa::RsaPublicKey::from(key().clone());
        let key_id = self
            .inner
            .published_key_id
            .read()
            .expect("lock")
            .clone()
            .unwrap_or_else(|| KEY_ID.to_owned());
        json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": key_id,
                "n": Base64UrlUnpadded::encode_string(&public.n().to_bytes_be()),
                "e": Base64UrlUnpadded::encode_string(&public.e().to_bytes_be()),
            }]
        })
    }
}

impl TokenClaims {
    /// The shape Apple sends: its issuer, the Services ID as the audience,
    /// a `pairwise` subject, and no `name` claim, because Apple never puts
    /// the name in the ID token. That is the whole reason the name has to
    /// come out of the form body instead.
    pub fn apple() -> Self {
        Self {
            issuer: APPLE_ISSUER.to_owned(),
            audience: APPLE_CLIENT_ID.to_owned(),
            subject: "apple-subject-1".to_owned(),
            email: Some("nick@example.com".to_owned()),
            email_verified: true,
            name: None,
            // What Apple actually sends.
            email_verified_as_string: true,
            ..Self::default()
        }
    }
}

/// A Google-shaped ID token, signed for real with the test key.
fn mint(claims: &TokenClaims) -> String {
    let header = json!({ "alg": "RS256", "typ": "JWT", "kid": claims.key_id });
    let mut body = json!({
        "iss": claims.issuer,
        "aud": claims.audience,
        "sub": claims.subject,
        "iat": claims.issued_at,
        "exp": claims.expires_at,
    });
    if let Some(nonce) = &claims.nonce {
        body["nonce"] = json!(nonce);
    }
    if let Some(email) = &claims.email {
        body["email"] = json!(email);
        body["email_verified"] = if claims.email_verified_as_string {
            json!(claims.email_verified.to_string())
        } else {
            json!(claims.email_verified)
        };
    }
    if let Some(name) = &claims.name {
        body["name"] = json!(name);
    }

    let signing_input = format!(
        "{}.{}",
        Base64UrlUnpadded::encode_string(&serde_json::to_vec(&header).expect("header")),
        Base64UrlUnpadded::encode_string(&serde_json::to_vec(&body).expect("body")),
    );
    let signer = rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(key().clone());
    let signature = signer.sign(signing_input.as_bytes()).to_vec();
    format!(
        "{signing_input}.{}",
        Base64UrlUnpadded::encode_string(&signature)
    )
}

fn json_response(status: u16, body: &Value) -> Response<Bytes> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Bytes::from(serde_json::to_vec(body).expect("json")))
        .expect("response")
}

#[async_trait]
impl HttpClient for FakeProvider {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let url = request.uri().to_string();
        let method = request.method().to_string();
        let body = String::from_utf8_lossy(request.body()).to_string();
        self.inner
            .calls
            .write()
            .expect("lock")
            .push((method.clone(), url.clone(), body));

        let apple = url.contains("appleid.apple.com");

        if url.contains("/.well-known/openid-configuration") {
            if let Some(status) = *self.inner.discovery_error.read().expect("lock") {
                return Ok(json_response(status, &json!({ "error": "unavailable" })));
            }
            if apple {
                return Ok(json_response(
                    200,
                    &json!({
                        "issuer": APPLE_ISSUER,
                        "authorization_endpoint": APPLE_AUTHORIZATION_ENDPOINT,
                        "token_endpoint": APPLE_TOKEN_ENDPOINT,
                        "jwks_uri": APPLE_JWKS_URI,
                        "response_types_supported": ["code"],
                        "subject_types_supported": ["pairwise"],
                        "id_token_signing_alg_values_supported": ["RS256"],
                        // Apple's own document lists exactly these, and
                        // `form_post` is why the callback is a POST.
                        "response_modes_supported": ["query", "fragment", "form_post"],
                        "token_endpoint_auth_methods_supported": ["client_secret_post"],
                        "scopes_supported": ["openid", "email", "name"],
                        "claims_supported": ["sub", "email", "email_verified"],
                    }),
                ));
            }
            return Ok(json_response(
                200,
                &json!({
                    "issuer": ISSUER,
                    "authorization_endpoint": AUTHORIZATION_ENDPOINT,
                    "token_endpoint": TOKEN_ENDPOINT,
                    "jwks_uri": JWKS_URI,
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                    "scopes_supported": ["openid", "email", "profile"],
                    "claims_supported": ["sub", "email", "email_verified", "name"],
                }),
            ));
        }

        if url.starts_with(JWKS_URI) || url.starts_with(APPLE_JWKS_URI) {
            return Ok(json_response(200, &self.jwks()));
        }

        if url.starts_with(TOKEN_ENDPOINT) || url.starts_with(APPLE_TOKEN_ENDPOINT) {
            if let Some((status, body)) = self.inner.token_error.read().expect("lock").clone() {
                return Ok(json_response(status, &body));
            }
            return Ok(json_response(
                200,
                &json!({
                    "access_token": "test-access-token",
                    "token_type": "Bearer",
                    "expires_in": 3599,
                    "id_token": self.id_token(),
                }),
            ));
        }

        Ok(json_response(
            404,
            &json!({ "error": format!("the fake provider has no route for {url}") }),
        ))
    }
}
