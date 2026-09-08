//! Request plumbing the two ceremonies share.

use axum::response::{IntoResponse, Response};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use cratefield_core::{Clock, Database, IdGen, Json, Problem, Scope};
use factory0_auth_core::{SESSION_INVALID, ValidSession, cookie_value, validate};
use http::HeaderMap;
use http::StatusCode;

use crate::ModuleState;

/// The ports the module declared. `Harness::build` refuses a runtime that is
/// missing one, so reaching a `None` arm means the harness was bypassed;
/// answer 503 rather than panicking inside a Worker.
pub(crate) fn ports(
    state: &ModuleState,
) -> Result<(&dyn Database, &dyn Clock, &dyn IdGen), Problem> {
    let (Some(db), Some(clock), Some(id_gen)) = (
        state.ctx.ports.db.as_deref(),
        state.ctx.ports.clock.as_deref(),
        state.ctx.ports.id_gen.as_deref(),
    ) else {
        return Err(Problem::not_ready(
            "the passkeys module needs db, clock and idgen",
        ));
    };
    Ok((db, clock, id_gen))
}

/// The signed-in user, or the one 401 every signed-out caller sees.
/// auth-core's own `Session` extractor is bound to its private state, so the
/// same two steps are done here rather than reaching into it.
pub(crate) async fn require_session(
    state: &ModuleState,
    headers: &HeaderMap,
    scope: &Scope,
) -> Result<ValidSession, Problem> {
    let (db, clock, _) = ports(state)?;
    let denied = || Problem::new(&SESSION_INVALID).instance(&scope.request_id);
    let Some(value) = cookie_value(headers) else {
        return Err(denied());
    };
    match validate(db, clock, &value).await {
        Ok(Some(session)) => Ok(session),
        Ok(None) => Err(denied()),
        Err(err) => {
            tracing::error!(error = %err, "session validation failed");
            Err(Problem::internal().instance(&scope.request_id))
        }
    }
}

/// The signed-in user, for an endpoint that **changes how they sign in**.
///
/// A live session is not enough here (issue #31). Adding a passkey to a
/// hijacked session is the classic persistence step: the passkey outlives
/// the password change and the session revocation that follow, and nothing
/// about it looks unusual on an account page. So the login behind the
/// session has to be recent, not merely valid.
///
/// The refusal is `403 auth/reauthentication-required`, distinct from the
/// `401` a signed-out caller gets, so a client re-authenticates and retries
/// instead of dropping the person into a full login.
pub(crate) async fn require_recent_session(
    state: &ModuleState,
    headers: &HeaderMap,
    scope: &Scope,
) -> Result<ValidSession, Problem> {
    let session = require_session(state, headers, scope).await?;
    let (_, clock, _) = ports(state)?;
    factory0_auth_core::require_recent_authentication(
        &session,
        clock.now(),
        state.step_up_window_secs,
    )
    .map_err(|problem| problem.instance(&scope.request_id))?;
    Ok(session)
}

/// The rate limit on the two endpoints anyone can call. Keyed on the client
/// address **only**: keying on the email as well would let anyone lock a
/// named account out of its own logins, which trades one denial of service
/// for a worse one.
///
/// Fails open with a warning when the limiter itself is unreachable. An edge
/// binding outage must not take logins down, and the ceremony still has to
/// pass a single-use challenge and a signature.
pub(crate) async fn limit_login(state: &ModuleState, headers: &HeaderMap) -> Option<Response> {
    let limiter = state.ctx.ports.rate_limiter.as_deref()?;
    let ip = cratefield_core::client_ip(headers);
    for key in cratefield_core::rate_limit_keys(ip.as_deref(), None) {
        match limiter.limit(&format!("auth-passkeys:{key}")).await {
            Ok(decision) if !decision.ok => {
                return Some(cratefield_core::rate_limited(decision.retry_after).into_response());
            }
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(error = %err, "the passkey rate limiter is unavailable");
                return None;
            }
        }
    }
    None
}

/// The single answer every failed ceremony gets, whatever went wrong.
pub(crate) fn ceremony_failed(scope: &Scope) -> Problem {
    Problem::new(&crate::CEREMONY_FAILED).instance(&scope.request_id)
}

pub(crate) fn internal(scope: &Scope) -> Problem {
    Problem::internal().instance(&scope.request_id)
}

pub(crate) fn b64u(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const HEX: [u8; 16] = *b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

pub(crate) fn ok(body: serde_json::Value) -> Response {
    (StatusCode::OK, Json(body)).into_response()
}

/// The client address and user agent a session records, as far as the edge
/// tells us.
pub(crate) fn client_hints(headers: &HeaderMap) -> (Option<String>, Option<String>) {
    let ip = cratefield_core::client_ip(headers);
    let user_agent = headers
        .get(http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    (ip, user_agent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_lowercase_and_padded() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(hex(&[]), "");
    }

    #[test]
    fn base64url_is_unpadded() {
        assert_eq!(b64u(b"any carnal pleas"), "YW55IGNhcm5hbCBwbGVhcw");
    }
}
