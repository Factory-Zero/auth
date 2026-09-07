//! The two routes (issue #17): `GET /start` and `GET /callback`.
//!
//! Both are public. `/start` is guarded by the rate limiter and by nothing
//! else, because there is nothing yet to guard; `/callback` is guarded by
//! the signed flow cookie, which is the only thing that makes a callback
//! ours rather than anybody's.
//!
//! Meta redirects rather than posting, so unlike Apple this is one method
//! and an ordinary `SameSite=Lax` cookie.

use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use factory0_auth_core::cookie_value as session_cookie_value;
use factory0_auth_core::federated::{Caller, Ports};
use factory0_core::{Problem, Scope};
use http::{HeaderMap, StatusCode, header};
use oauth2::{
    AuthUrl, AuthorizationCode, Client, ClientId, ClientSecret, CsrfToken, EndpointNotSet,
    EndpointSet, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope as OauthScope,
    StandardRevocableToken, TokenResponse, TokenUrl,
    basic::{BasicClient, BasicErrorResponseType, BasicTokenType},
};
use serde::Deserialize;
use std::sync::Arc;

use crate::flow::{self, Flow};
use crate::graph::{self, PortHttpClient};
use crate::session::{self, Completed};
use crate::{CALLBACK_REFUSED, META_UNAVAILABLE, ModuleState, SCOPES, Settings};

/// 32 bytes each for the state and the PKCE verifier.
const RANDOM_BYTES: usize = 32;

/// A `return_to` longer than this is not a path anyone meant.
const MAX_RETURN_TO: usize = 512;

pub(crate) fn router() -> axum::Router<Arc<ModuleState>> {
    axum::Router::new()
        .route("/start", get(start))
        .route("/callback", get(callback))
}

#[derive(Debug, Deserialize)]
pub(crate) struct StartQuery {
    return_to: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    /// Meta's own refusal, e.g. when a person cancels.
    error: Option<String>,
}

/// Where the browser may be sent after signing in.
///
/// Only a path on this service. An absolute URL, a protocol-relative `//`,
/// or a backslash the browser may normalise to one, would each turn this
/// endpoint into an open redirect.
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

/// A fixed page for the person at the end of a redirect. Nothing from the
/// request reaches it: Meta can put anything in `error_description`, and
/// reflecting it would be a cross-site scripting hole on our own origin.
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

fn expired_page() -> Response {
    page(
        StatusCode::BAD_REQUEST,
        "That sign-in link has expired or was already used. Start again.",
    )
}

/// Adds the header that clears the flow cookie, so a spent or abandoned
/// flow does not linger in the browser.
fn clear_flow(response: Response) -> Response {
    let mut response = response;
    if let Ok(value) = header::HeaderValue::from_str(&flow::clear_cookie()) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

async fn limit(state: &ModuleState, headers: &HeaderMap) -> Option<Response> {
    let limiter = state.ctx.ports.rate_limiter.as_deref()?;
    let ip = factory0_core::client_ip(headers);
    for key in factory0_core::rate_limit_keys(ip.as_deref(), None) {
        match limiter.limit(&format!("auth-meta:{key}")).await {
            Ok(decision) if !decision.ok => {
                return Some(factory0_core::rate_limited(decision.retry_after).into_response());
            }
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(error = %err, "the auth-meta rate limiter is unavailable");
                return None;
            }
        }
    }
    None
}

/// The oauth2 client, with both endpoints set.
///
/// Spelled out rather than inferred because `oauth2`'s type-state carries
/// which endpoints are configured, and the concrete type is not nameable
/// without saying so.
type MetaClient = Client<
    oauth2::StandardErrorResponse<BasicErrorResponseType>,
    oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, BasicTokenType>,
    oauth2::StandardTokenIntrospectionResponse<oauth2::EmptyExtraTokenFields, BasicTokenType>,
    StandardRevocableToken,
    oauth2::StandardErrorResponse<oauth2::RevocationErrorResponseType>,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
>;

fn client(settings: &Settings) -> Option<MetaClient> {
    Some(
        BasicClient::new(ClientId::new(settings.client_id.clone()))
            .set_client_secret(ClientSecret::new(settings.client_secret.clone()))
            .set_auth_uri(
                AuthUrl::new(graph::authorization_endpoint(&settings.graph_version)).ok()?,
            )
            .set_token_uri(TokenUrl::new(graph::token_endpoint(&settings.graph_version)).ok()?)
            .set_redirect_uri(RedirectUrl::new(settings.redirect_uri()).ok()?)
            // Meta expects the app secret in the request body, not HTTP
            // Basic. Pinned here rather than left to a default, the same
            // way the other providers' auth method is.
            .set_auth_type(oauth2::AuthType::RequestBody),
    )
}

async fn start(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    Query(query): Query<StartQuery>,
) -> Result<Response, Problem> {
    if let Some(limited) = limit(&state, &headers).await {
        return Ok(limited);
    }
    let settings = state.settings()?;
    let ctx = state.ctx.as_ref();
    let (Some(clock), Some(signer)) = (ctx.ports.clock.as_deref(), ctx.ports.signer.as_deref())
    else {
        return Err(Problem::not_ready("auth-meta needs clock and signer"));
    };
    let Some(client) = client(settings) else {
        tracing::error!("the configured Meta endpoints are not urls");
        return Err(Problem::new(&META_UNAVAILABLE).instance(&scope.request_id));
    };

    let (Some(state_token), Some(verifier)) = (random_token(), random_token()) else {
        tracing::error!("entropy source failed");
        return Err(Problem::internal().instance(&scope.request_id));
    };

    // Who is signed in now, read here because `/start` is same-site.
    let signed_in_user = match (ctx.ports.db.as_deref(), session_cookie_value(&headers)) {
        (Some(db), Some(value)) => factory0_auth_core::validate(db, clock, &value)
            .await
            .ok()
            .flatten()
            .map(|session| session.user_id),
        _ => None,
    };

    let challenge =
        PkceCodeChallenge::from_code_verifier_sha256(&PkceCodeVerifier::new(verifier.clone()));
    let state_for_url = state_token.clone();
    let mut request = client
        .authorize_url(move || CsrfToken::new(state_for_url.clone()))
        .set_pkce_challenge(challenge);
    for scope in SCOPES {
        request = request.add_scope(OauthScope::new((*scope).to_owned()));
    }
    let (url, csrf) = request.url();

    let sealed = Flow {
        state: csrf.secret().clone(),
        verifier,
        return_to: safe_return_to(query.return_to.as_deref())
            .unwrap_or_else(|| settings.default_return_to.clone()),
        expires_at: clock.now().unix_timestamp() + flow::TTL_SECS,
        signed_in_user,
    }
    .seal(signer);

    Ok((
        StatusCode::FOUND,
        [
            (header::SET_COOKIE, flow::set_cookie(&sealed)),
            (header::LOCATION, url.to_string()),
        ],
    )
        .into_response())
}

#[allow(clippy::too_many_lines)]
async fn callback(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, Problem> {
    if let Some(limited) = limit(&state, &headers).await {
        return Ok(limited);
    }
    let settings = state.settings()?;
    let ctx = state.ctx.as_ref();
    let (Some(db), Some(http), Some(clock), Some(signer), Some(id_gen)) = (
        ctx.ports.db.as_deref(),
        ctx.ports.http.clone(),
        ctx.ports.clock.as_deref(),
        ctx.ports.signer.as_deref(),
        ctx.ports.id_gen.as_deref(),
    ) else {
        return Err(Problem::not_ready("auth-meta needs its ports"));
    };

    // The flow cookie is what makes this callback ours. Without it, or with
    // one that does not verify, there is nothing here worth reading.
    let Some(cookie) = flow::cookie_value(&headers) else {
        return Ok(expired_page());
    };
    let Some(flow) = Flow::open(signer, clock, &cookie) else {
        return Ok(expired_page());
    };

    // The state is compared first, on the error path too. Meta returns it
    // with an error response, so checking it first means a stranger cannot
    // abort somebody's login in progress by sending their browser to
    // `/callback?error=...`. Nothing is cleared until it matches, for the
    // same reason.
    let Some(returned_state) = query.state.as_deref() else {
        return Ok(expired_page());
    };
    if returned_state != flow.state {
        tracing::warn!("the state in a callback did not match the flow cookie");
        return Ok(Problem::new(&CALLBACK_REFUSED)
            .instance(&scope.request_id)
            .into_response());
    }

    if let Some(error) = query.error.as_deref() {
        tracing::info!(provider_error = %error, "a Meta sign-in was not granted");
        return Ok(clear_flow(page(
            StatusCode::OK,
            "Sign-in was not completed. You can close this tab and try again.",
        )));
    }

    let Some(code) = query.code.as_deref() else {
        return Ok(clear_flow(expired_page()));
    };

    let Some(client) = client(settings) else {
        tracing::error!("the configured Meta endpoints are not urls");
        return Ok(clear_flow(
            Problem::new(&META_UNAVAILABLE)
                .instance(&scope.request_id)
                .into_response(),
        ));
    };

    let oauth_http = PortHttpClient::new(Arc::clone(&http));
    let token = match client
        .exchange_code(AuthorizationCode::new(code.to_owned()))
        .set_pkce_verifier(PkceCodeVerifier::new(flow.verifier.clone()))
        .request_async(&oauth_http)
        .await
    {
        Ok(token) => token,
        Err(err) => {
            tracing::warn!(error = %err, "the Meta token exchange failed");
            return Ok(clear_flow(
                Problem::new(&META_UNAVAILABLE)
                    .instance(&scope.request_id)
                    .into_response(),
            ));
        }
    };

    // No `debug_token` call. The token arrived on a back-channel response
    // to a request this service made, to Meta's own token endpoint,
    // authenticated with the app secret — so it is by construction a token
    // issued to this app. `debug_token` would re-ask a question the
    // exchange already answered, at the cost of a second round trip on
    // every sign-in (ADR 0104).
    let profile = match graph::profile(
        &http,
        &settings.graph_version,
        token.access_token().secret(),
    )
    .await
    {
        Ok(profile) => profile,
        Err(err) => {
            tracing::warn!(error = %err, "the Meta profile call failed");
            return Ok(clear_flow(
                Problem::new(&META_UNAVAILABLE)
                    .instance(&scope.request_id)
                    .into_response(),
            ));
        }
    };

    let presented = session_cookie_value(&headers);
    let current_user = match presented.as_deref() {
        Some(value) => factory0_auth_core::validate(db, clock, value)
            .await
            .ok()
            .flatten()
            .map(|session| session.user_id),
        // Meta redirects, so the session cookie normally arrives. The
        // sealed answer is the fallback, re-checked because the account
        // may have been disabled in the ten minutes since `/start`.
        None => match flow.signed_in_user.as_deref() {
            Some(user_id) => factory0_auth_core::user_by_id(db, user_id)
                .await
                .ok()
                .flatten()
                .filter(|user| user.status == factory0_auth_core::STATUS_ACTIVE)
                .map(|user| user.id),
            None => None,
        },
    };

    let ip = factory0_core::client_ip(&headers);
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok());
    let completed = session::complete(
        ctx,
        &scope,
        &Ports { db, clock, id_gen },
        &profile,
        &Caller {
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
            for cookie in [session::session_cookie(&session), flow::clear_cookie()] {
                if let Ok(value) = header::HeaderValue::from_str(&cookie) {
                    response.headers_mut().append(header::SET_COOKIE, value);
                }
            }
            response
        }
        Completed::NeedsPerson { message } => clear_flow(page(StatusCode::OK, message)),
    })
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
