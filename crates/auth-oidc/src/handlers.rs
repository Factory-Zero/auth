//! The routes (issues #15, #16): `/{provider}/start`, and
//! `/{provider}/callback` on the one method that provider uses.
//!
//! All are public. `/start` is guarded by the rate limiter and by nothing
//! else, because there is nothing yet to guard; a callback is guarded by
//! the signed flow cookie, which is the only thing that makes a callback
//! ours rather than anybody's.
//!
//! The callback exists twice because Apple posts where everyone else
//! redirects (ADR 0102). Both methods share one body; each refuses the
//! providers that do not use it, so an authorization response can only be
//! delivered the way its own provider delivers it.

use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use factory0_auth_core::cookie_value as session_cookie_value;
use factory0_core::{Clock, Problem, Scope};
use http::{HeaderMap, StatusCode, header};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope as OidcScope,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::apple;
use crate::discovery::{PortHttpClient, key_id_of};
use crate::flow::{self, Flow};
use crate::provider::{self, Provider};
use crate::session::{self, Completed, Identity};
use crate::{CALLBACK_REFUSED, ModuleState, PROVIDER_UNAVAILABLE};

/// 32 bytes each for the state, the nonce and the PKCE verifier. Generated
/// here rather than through `openidconnect`'s helpers so every random value
/// in this service comes from the same place.
const RANDOM_BYTES: usize = 32;

/// A `return_to` longer than this is not a path anyone meant.
const MAX_RETURN_TO: usize = 512;

pub(crate) fn router() -> axum::Router<Arc<ModuleState>> {
    axum::Router::new()
        .route("/{provider}/start", get(start))
        // Two methods, one path. A provider uses exactly one of them and
        // the other answers 404 for it, so a `form_post` provider cannot
        // be completed through the query-string route and vice versa.
        .route("/{provider}/callback", get(callback).post(callback_form))
}

#[derive(Debug, Deserialize)]
pub(crate) struct StartQuery {
    return_to: Option<String>,
}

/// The authorization response, however it arrived.
///
/// Apple's `form_post` carries the same three fields as a redirect plus
/// `user`, which no other provider sends and which arrives only on the
/// very first authorization.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    /// Apple only: JSON with the person's name, once and never again.
    user: Option<String>,
}

/// Where the browser may be sent after signing in.
///
/// Only a path on this service. An absolute URL, a protocol-relative `//`,
/// or a backslash the browser may normalise to one, would each turn this
/// endpoint into an open redirect — the classic way a login flow is used to
/// launder a phishing link.
pub(crate) fn safe_return_to(candidate: Option<&str>) -> Option<String> {
    let value = candidate?.trim();
    if value.len() > MAX_RETURN_TO || !value.starts_with('/') {
        return None;
    }
    if value.starts_with("//") || value.starts_with("/\\") {
        return None;
    }
    if value.chars().any(char::is_control) {
        return None;
    }
    Some(value.to_owned())
}

fn random_token() -> Option<String> {
    let mut bytes = [0u8; RANDOM_BYTES];
    getrandom::fill(&mut bytes).ok()?;
    Some(Base64UrlUnpadded::encode_string(&bytes))
}

fn refused(scope: &Scope) -> Problem {
    Problem::new(&CALLBACK_REFUSED).instance(&scope.request_id)
}

fn unavailable(scope: &Scope) -> Problem {
    Problem::new(&PROVIDER_UNAVAILABLE).instance(&scope.request_id)
}

/// A fixed page for the person at the end of a redirect. Nothing from the
/// request reaches it: a provider can put anything in `error_description`,
/// and reflecting it would be a cross-site scripting hole on our own origin.
fn page(status: StatusCode, message: &str) -> Response {
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>Sign in</title></head>\
<body style=\"font:16px/1.5 system-ui,sans-serif;margin:3rem auto;max-width:32rem;padding:0 1rem\">\
<p>{message}</p></body></html>"
    );
    (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(body),
    )
        .into_response()
}

async fn limit(state: &ModuleState, headers: &HeaderMap) -> Option<Response> {
    let limiter = state.ctx.ports.rate_limiter.as_deref()?;
    let ip = factory0_core::client_ip(headers);
    for key in factory0_core::rate_limit_keys(ip.as_deref(), None) {
        match limiter.limit(&format!("auth-oidc:{key}")).await {
            Ok(decision) if !decision.ok => {
                return Some(factory0_core::rate_limited(decision.retry_after).into_response());
            }
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(error = %err, "the auth-oidc rate limiter is unavailable");
                return None;
            }
        }
    }
    None
}

fn provider_of(slug: &str) -> Result<&'static Provider, Problem> {
    provider::by_slug(slug).ok_or_else(Problem::not_found)
}

/// Builds the provider client. The concrete type is not nameable without
/// spelling out openidconnect's type-state, so it is built where it is used.
macro_rules! oidc_client {
    ($metadata:expr, $config:expr, $provider:expr) => {
        RedirectUrl::new($config.redirect_uri.clone()).map(|redirect| {
            CoreClient::from_provider_metadata(
                $metadata,
                ClientId::new($config.client_id.clone()),
                Some(ClientSecret::new($config.client_secret.clone())),
            )
            .set_redirect_uri(redirect)
            // Pinned by the descriptor rather than read from the document.
            .set_auth_type($provider.auth_type.as_oauth())
        })
    };
}

async fn start(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Query(query): Query<StartQuery>,
) -> Result<Response, Problem> {
    if let Some(limited) = limit(&state, &headers).await {
        return Ok(limited);
    }
    let provider = provider_of(&slug)?;
    let settings = state.settings()?;
    let ctx = state.ctx.as_ref();
    let (Some(http), Some(clock), Some(signer)) = (
        ctx.ports.http.clone(),
        ctx.ports.clock.as_deref(),
        ctx.ports.signer.as_deref(),
    ) else {
        return Err(Problem::not_ready("auth-oidc needs http, clock and signer"));
    };
    let config = state.provider_config(provider, clock)?;

    let metadata = state
        .discovery
        .metadata(provider, http, clock, false)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "provider discovery failed");
            unavailable(&scope)
        })?;

    let (Some(state_token), Some(nonce), Some(verifier)) =
        (random_token(), random_token(), random_token())
    else {
        tracing::error!("entropy source failed");
        return Err(Problem::internal().instance(&scope.request_id));
    };

    let client = oidc_client!(metadata, config, provider).map_err(|err| {
        tracing::error!(error = %err, "the configured redirect uri is not a url");
        unavailable(&scope)
    })?;
    let challenge =
        PkceCodeChallenge::from_code_verifier_sha256(&PkceCodeVerifier::new(verifier.clone()));
    // `authorize_url` wants `'static` factories, so the closures own their
    // copies rather than borrowing the locals we are about to seal.
    let state_for_url = state_token.clone();
    let nonce_for_url = nonce.clone();
    let mut request = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            move || CsrfToken::new(state_for_url.clone()),
            move || Nonce::new(nonce_for_url.clone()),
        )
        .set_pkce_challenge(challenge);
    for scope in provider.scopes {
        request = request.add_scope(OidcScope::new((*scope).to_owned()));
    }
    if provider.is_form_post() {
        // Apple returns the response as a cross-site POST. It does this
        // anyway once `name` or `email` is requested, but saying so makes
        // the descriptor and the callback route agree out loud rather than
        // by coincidence.
        request = request.add_extra_param("response_mode", "form_post");
    }
    let (url, csrf, _nonce) = request.url();
    let csrf = csrf.secret().clone();

    let sealed = Flow {
        provider: provider.slug.to_owned(),
        state: csrf,
        nonce,
        verifier,
        return_to: safe_return_to(query.return_to.as_deref())
            .unwrap_or_else(|| settings.default_return_to.clone()),
        expires_at: clock.now().unix_timestamp() + flow::TTL_SECS,
    }
    .seal(signer);

    Ok((
        StatusCode::FOUND,
        [
            (
                header::SET_COOKIE,
                flow::set_cookie(&sealed, flow::SameSite::for_provider(provider)),
            ),
            (header::LOCATION, url.to_string()),
        ],
    )
        .into_response())
}

/// The redirect callback: every provider but Apple.
async fn callback(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Query(query): Query<CallbackParams>,
) -> Result<Response, Problem> {
    let provider = provider_of(&slug)?;
    if provider.is_form_post() {
        // Apple posts. A GET here is somebody poking at the route, and
        // answering it would mean accepting an authorization response
        // through a path this provider never uses.
        return Err(Problem::not_found());
    }
    complete_callback(state, scope, headers, provider, query).await
}

/// The `form_post` callback: Apple only (#3, #16).
///
/// The body is `application/x-www-form-urlencoded`, which needs the
/// harness's `form` feature (Cratefield/harness#46). The request is
/// cross-site, so the flow cookie only arrives because `/start` set it
/// with `SameSite=None` for this provider.
async fn callback_form(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    Path(slug): Path<String>,
    body: String,
) -> Result<Response, Problem> {
    let provider = provider_of(&slug)?;
    if !provider.is_form_post() {
        return Err(Problem::not_found());
    }
    // Parsed here rather than through the `Form` extractor so a malformed
    // body gets this module's page instead of axum's rejection text, and
    // so the answer is identical to a missing `state`: a body that will
    // not parse is either a spoofed post or a provider change, and neither
    // is worth telling the sender apart.
    let Ok(params) = serde_urlencoded::from_str::<CallbackParams>(&body) else {
        return Ok(clear_flow(expired_page(), provider));
    };
    complete_callback(state, scope, headers, provider, params).await
}

#[allow(clippy::too_many_lines)]
async fn complete_callback(
    state: Arc<ModuleState>,
    scope: Scope,
    headers: HeaderMap,
    provider: &'static Provider,
    query: CallbackParams,
) -> Result<Response, Problem> {
    if let Some(limited) = limit(&state, &headers).await {
        return Ok(limited);
    }
    let ctx = state.ctx.as_ref();
    let (Some(db), Some(http), Some(clock), Some(signer), Some(id_gen)) = (
        ctx.ports.db.as_deref(),
        ctx.ports.http.clone(),
        ctx.ports.clock.as_deref(),
        ctx.ports.signer.as_deref(),
        ctx.ports.id_gen.as_deref(),
    ) else {
        return Err(Problem::not_ready("auth-oidc needs its ports"));
    };
    let config = state.provider_config(provider, clock)?;

    // The flow cookie is what makes this callback ours. Without it, or with
    // one that does not verify, there is nothing here worth reading.
    let Some(cookie) = flow::cookie_value(&headers) else {
        return Ok(expired_page());
    };
    let Some(flow) = Flow::open(signer, clock, provider.slug, &cookie) else {
        return Ok(expired_page());
    };

    // The state is compared first, on the error path too. The provider
    // returns it with an error response, so checking it first means a
    // stranger cannot abort somebody's login in progress by sending their
    // browser to `/callback?error=...`.
    let Some(returned_state) = query.state.as_deref() else {
        return Ok(clear_flow(expired_page(), provider));
    };
    if returned_state != flow.state {
        tracing::warn!("the state in a callback did not match the flow cookie");
        return Ok(refused(&scope).into_response());
    }

    // The provider refused, or the person cancelled. Logged, never rendered.
    if let Some(error) = query.error.as_deref() {
        tracing::info!(provider = provider.slug, provider_error = %error, "sign-in was not granted");
        return Ok(clear_flow(
            page(
                StatusCode::OK,
                "Sign-in was not completed. You can close this tab and try again.",
            ),
            provider,
        ));
    }

    let Some(code) = query.code.as_deref() else {
        return Ok(clear_flow(expired_page(), provider));
    };

    let mut identity = match exchange(&state, provider, &config, clock, &http, &flow, code).await {
        Ok(identity) => identity,
        Err(problem) => return Ok(clear_flow(problem.into_response(), provider)),
    };

    // Apple's first-authorization name (#3). It is in the form body, not
    // the ID token, and it arrives exactly once: on every later sign-in
    // this field is absent, so if it is not taken here it is gone. It only
    // fills a gap, never overwrites what the ID token said.
    if identity.name.is_none()
        && let Some(name) = query.user.as_deref().and_then(apple::name_from_user_field)
    {
        identity.name = Some(name);
    }

    // A callback that arrives with a session cookie is a signed-in person
    // adding a provider; the linking rules need to know that.
    let presented = session_cookie_value(&headers);
    let current_user = match presented.as_deref() {
        Some(value) => factory0_auth_core::validate(db, clock, value)
            .await
            .ok()
            .flatten()
            .map(|session| session.user_id),
        None => None,
    };

    let ip = factory0_core::client_ip(&headers);
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok());
    let completed = session::complete(
        ctx,
        &scope,
        &session::Ports { db, clock, id_gen },
        provider,
        &identity,
        &session::Caller {
            current_user: current_user.as_deref(),
            presented_cookie: presented.as_deref(),
            ip: ip.as_deref(),
            user_agent,
        },
    )
    .await?;

    Ok(match completed {
        Completed::SignedIn { session } => {
            // Two `Set-Cookie` headers, appended one at a time. An array of
            // header pairs *inserts*, so the second would replace the first
            // and the session cookie would never reach the browser.
            let mut response =
                (StatusCode::FOUND, [(header::LOCATION, flow.return_to)]).into_response();
            for cookie in [
                session::session_cookie(&session),
                flow::clear_cookie(flow::SameSite::for_provider(provider)),
            ] {
                if let Ok(value) = header::HeaderValue::from_str(&cookie) {
                    response.headers_mut().append(header::SET_COOKIE, value);
                }
            }
            response
        }
        Completed::NeedsPerson { message } => clear_flow(page(StatusCode::OK, message), provider),
    })
}

/// Exchanges the code and verifies the ID token, refreshing discovery once
/// if the token names a signing key the cached JWKS has never seen — which
/// is what a key rotation looks like from here.
async fn exchange(
    state: &ModuleState,
    provider: &Provider,
    config: &crate::ProviderConfig,
    clock: &dyn Clock,
    http: &Arc<dyn factory0_core::HttpClient>,
    flow: &Flow,
    code: &str,
) -> Result<Identity, Problem> {
    let metadata = state
        .discovery
        .metadata(provider, Arc::clone(http), clock, false)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "provider discovery failed");
            Problem::new(&PROVIDER_UNAVAILABLE)
        })?;

    let oidc_http = PortHttpClient::new(Arc::clone(http));
    let token = {
        let client = oidc_client!(metadata.clone(), config, provider).map_err(|err| {
            tracing::error!(error = %err, "the configured redirect uri is not a url");
            Problem::new(&PROVIDER_UNAVAILABLE)
        })?;
        client
            .exchange_code(AuthorizationCode::new(code.to_owned()))
            .map_err(|err| {
                tracing::error!(error = %err, "the provider metadata has no token endpoint");
                Problem::new(&PROVIDER_UNAVAILABLE)
            })?
            .set_pkce_verifier(PkceCodeVerifier::new(flow.verifier.clone()))
            .request_async(&oidc_http)
            .await
            .map_err(|err| {
                tracing::warn!(error = %err, "the token exchange failed");
                Problem::new(&PROVIDER_UNAVAILABLE)
            })?
    };

    let id_token = token
        .extra_fields()
        .id_token()
        .ok_or_else(|| {
            tracing::warn!("the token response carried no id token");
            Problem::new(&PROVIDER_UNAVAILABLE)
        })?
        .clone();

    // A key we have never heard of is the one failure worth a second
    // attempt: providers rotate, and a cached JWKS should not lock everyone
    // out until the isolate recycles.
    let unknown_key = key_id_of(&id_token.to_string())
        .is_some_and(|kid| !state.discovery.knows_key(provider.slug, &kid));
    let metadata = if unknown_key {
        state
            .discovery
            .metadata(provider, Arc::clone(http), clock, true)
            .await
            .unwrap_or(metadata)
    } else {
        metadata
    };

    let claims = {
        let client = oidc_client!(metadata, config, provider).map_err(|err| {
            tracing::error!(error = %err, "the configured redirect uri is not a url");
            Problem::new(&PROVIDER_UNAVAILABLE)
        })?;
        // The clock comes from the port, never from `chrono::Utc::now`,
        // which panics on wasm32 (ADR 0100).
        let now = || {
            chrono::DateTime::from_timestamp(clock.now().unix_timestamp(), 0).unwrap_or_default()
        };
        let verifier = client
            .id_token_verifier()
            // Pinned here rather than taken from the discovery document.
            // The client holds a secret, and openidconnect verifies an
            // HS256 token with it, so a provider document that listed HS256
            // would quietly turn our own client secret into the signing
            // key. Google lists only RS256; this makes that a rule rather
            // than a coincidence.
            .set_allowed_algs(provider.signing_algorithms.iter().cloned())
            .set_time_fn(now);
        id_token
            .claims(&verifier, &Nonce::new(flow.nonce.clone()))
            .map_err(|err| {
                // Signature, issuer, audience, expiry and nonce all land
                // here, and the caller answers the same way for each.
                tracing::warn!(error = %err, "id token verification failed");
                Problem::new(&CALLBACK_REFUSED)
            })?
            .clone()
    };

    Ok(Identity {
        subject: claims.subject().to_string(),
        email: claims
            .email()
            .map(|email| factory0_core::normalize_email(email.as_str())),
        email_verified: claims.email_verified().unwrap_or(false),
        name: claims
            .name()
            .and_then(|name| name.get(None))
            .map(|name| name.as_str().to_owned()),
    })
}

fn expired_page() -> Response {
    page(
        StatusCode::BAD_REQUEST,
        "That sign-in link has expired or was already used. Start again.",
    )
}

/// Adds the header that clears the flow cookie, so a spent or abandoned
/// flow does not linger in the browser.
///
/// The provider decides the `SameSite` on the clear, for the same reason it
/// decided it on the cookie.
fn clear_flow(response: Response, provider: &Provider) -> Response {
    let mut response = response;
    let cookie = flow::clear_cookie(flow::SameSite::for_provider(provider));
    if let Ok(value) = header::HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_return_to_may_only_be_a_path_on_this_service() {
        assert_eq!(
            safe_return_to(Some("/account")).as_deref(),
            Some("/account")
        );
        assert_eq!(
            safe_return_to(Some("/v1/auth-core/authorize?client_id=x")).as_deref(),
            Some("/v1/auth-core/authorize?client_id=x")
        );
        // Every one of these is an open redirect if it gets through.
        for bad in [
            "https://evil.example",
            "//evil.example",
            "/\\evil.example",
            "http://evil.example",
            "javascript:alert(1)",
            "evil.example",
            "",
        ] {
            assert_eq!(safe_return_to(Some(bad)), None, "{bad} was accepted");
        }
        assert_eq!(safe_return_to(None), None);
        assert_eq!(safe_return_to(Some(&format!("/{}", "a".repeat(600)))), None);
        assert_eq!(safe_return_to(Some("/ok\nSet-Cookie: x")), None);
    }

    #[test]
    fn random_tokens_are_url_safe_and_distinct() {
        let first = random_token().expect("entropy");
        let second = random_token().expect("entropy");
        assert_ne!(first, second);
        assert!(
            first
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }
}
