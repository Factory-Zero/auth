//! The three routes (issues #19, #20): register, login and change.
//!
//! Everything unusual here is about not answering a question nobody asked:
//! whether an address has an account. Registration answers identically
//! whether it created one; login answers identically for a wrong password,
//! an unknown address, a disabled account and a locked one; and an unknown
//! address is still verified against a fixed dummy hash so the *timing*
//! does not answer either.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use factory0_auth_core::{
    CREDENTIAL_PASSWORD, CredentialRow, IssuedSession, Login, PROVIDER_PASSWORD, STATUS_ACTIVE,
    SessionError, cookie_value as session_cookie_value, hash_password, insert_credential,
    insert_identity, issue as issue_session, password_credential, set_cookie, set_password_hash,
    set_password_lockout, user_by_id, user_by_primary_email, verify_password,
};
use factory0_core::{Json, Problem, Scope};
use http::{HeaderMap, StatusCode, header};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

use crate::breach;
use crate::lockout::{self, State as LockState};
use crate::{LOGIN_REFUSED, ModuleState, NOT_READY, PASSWORD_UNSUITABLE, password_length_ok};

pub(crate) const EVENT_REGISTERED: &str = "auth-password.registered";
pub(crate) const EVENT_LOGGED_IN: &str = "auth-password.logged_in";
pub(crate) const EVENT_LOCKED: &str = "auth-password.locked";
pub(crate) const EVENT_CHANGED: &str = "auth-password.changed";
/// Somebody tried to register an address that already has an account. The
/// caller of this event sends "someone tried to register" to the existing
/// address; the person at the keyboard is told nothing.
pub(crate) const EVENT_DUPLICATE_REGISTRATION: &str = "auth-password.duplicate_registration";

/// RFC 8176: a password is knowledge, and that is all it is.
const AMR: [&str; 1] = ["pwd"];

/// A hash of a value nobody knows, verified against when the address is
/// unknown so an attacker cannot tell "no such account" from "wrong
/// password" by how long the answer took.
///
/// A constant rather than a hash computed at startup: it must cost the
/// same as a real verify, and it must not depend on anything that could
/// make it cheaper on some deployments than others. Parameters match the
/// ones `hash_password` writes (ADR 0100).
const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$\
Kr9MypcBcrKQhCA8Kk+auQ$zjwKC0g9HxLO1hfYduVa2r+tjokQEWUTbRcg/Ml2S64";

pub(crate) fn router() -> axum::Router<Arc<ModuleState>> {
    axum::Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/change", post(change))
}

#[derive(Debug, Default, Deserialize)]
struct Credentials {
    #[serde(default)]
    email: String,
    #[serde(default)]
    password: String,
}

#[derive(Debug, Default, Deserialize)]
struct ChangeBody {
    #[serde(default)]
    current_password: String,
    #[serde(default)]
    new_password: String,
}

fn refused(scope: &Scope) -> Problem {
    Problem::new(&LOGIN_REFUSED).instance(&scope.request_id)
}

/// The one answer registration gives, whether or not it created anything.
fn accepted() -> Response {
    (
        StatusCode::ACCEPTED,
        Json(json!({
            "status": "accepted",
            "message": "If that address can be registered, check your email to finish.",
        })),
    )
        .into_response()
}

async fn limit(state: &ModuleState, headers: &HeaderMap, email: Option<&str>) -> Option<Response> {
    let limiter = state.ctx.ports.rate_limiter.as_deref()?;
    let ip = factory0_core::client_ip(headers);
    // Keyed on the address as well as the caller: an attacker with a
    // botnet defeats an IP limit, and a person's account is worth
    // protecting from a distributed guess even before the lockout bites.
    for key in factory0_core::rate_limit_keys(ip.as_deref(), email) {
        match limiter.limit(&format!("auth-password:{key}")).await {
            Ok(decision) if !decision.ok => {
                return Some(factory0_core::rate_limited(decision.retry_after).into_response());
            }
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(error = %err, "the auth-password rate limiter is unavailable");
                return None;
            }
        }
    }
    None
}

/// Verifies the captcha when a deployment provides one.
///
/// Absent, this is a no-op: `fz doctor` is what refuses a production
/// venture with public writes and no captcha, and a module that refused to
/// start without one would take the service down instead.
async fn captcha_ok(state: &ModuleState, token: Option<&str>, headers: &HeaderMap) -> bool {
    let Some(captcha) = state.ctx.ports.captcha.as_deref() else {
        return true;
    };
    let ip = factory0_core::client_ip(headers);
    match captcha
        .verify(token.unwrap_or_default(), ip.as_deref())
        .await
    {
        Ok(verdict) => verdict.ok,
        Err(err) => {
            // Fail closed: a captcha that cannot be checked is a captcha
            // that has not been passed. The opposite would make an outage
            // at the captcha provider into an open door here.
            tracing::warn!(error = %err, "the captcha could not be verified");
            false
        }
    }
}

/// The shallowest possible address check: something, an `@`, something
/// with a dot in it.
///
/// Deliberately not a validator. Anything stricter rejects addresses that
/// work, and the real check is that a magic link to it arrives (#21).
/// This exists only so a bare `@` does not become an account.
fn looks_like_an_address(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}

fn body_of(raw: &[u8]) -> Value {
    serde_json::from_slice(raw).unwrap_or(Value::Null)
}

/// `POST /register`.
///
/// Answers `202` and the same body whether it created an account, found
/// the address already registered, or was handed something it will not
/// store. The person who owns an already-registered address is told by
/// mail; the person at the keyboard learns nothing.
async fn register(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    raw: bytes::Bytes,
) -> Result<Response, Problem> {
    if let Some(limited) = limit(&state, &headers, None).await {
        return Ok(limited);
    }
    let body = body_of(&raw);
    let credentials: Credentials = serde_json::from_value(body.clone()).unwrap_or_default();
    let captcha_token = body
        .get("captchaToken")
        .and_then(Value::as_str)
        .or_else(|| body.get("captcha_token").and_then(Value::as_str));
    if !captcha_ok(&state, captcha_token, &headers).await {
        return Err(refused(&scope));
    }

    let ctx = state.ctx.as_ref();
    let (Some(db), Some(clock), Some(id_gen)) = (
        ctx.ports.db.as_deref(),
        ctx.ports.clock.as_deref(),
        ctx.ports.id_gen.as_deref(),
    ) else {
        return Err(Problem::new(&NOT_READY));
    };

    // Length and the breach corpus are the person's own business: telling
    // them their password is too short reveals nothing about anybody else,
    // and refusing silently would leave them unable to sign in later.
    if !password_length_ok(&credentials.password) {
        return Err(Problem::new(&PASSWORD_UNSUITABLE).instance(&scope.request_id));
    }
    if state.settings.breach_check
        && let Some(http) = ctx.ports.http.as_ref()
        && breach::is_breached(http, &credentials.password).await
    {
        return Err(Problem::new(&PASSWORD_UNSUITABLE).instance(&scope.request_id));
    }

    let email = factory0_core::normalize_email(&credentials.email);
    if !looks_like_an_address(&email) {
        // Not an address. Answered like everything else here, because
        // "that is not an email" and "that email is taken" must not be
        // distinguishable.
        return Ok(accepted());
    }

    // The password is hashed **before** the existence check, so the two
    // paths cost the same. Hashing only when the address is new would make
    // registration a timing oracle for who already has an account.
    let Ok(password_hash) = hash_password(&credentials.password) else {
        tracing::error!("could not hash a password");
        return Err(Problem::internal().instance(&scope.request_id));
    };

    match user_by_primary_email(db, &email).await {
        Ok(Some(existing)) => {
            // Somebody has this address. Tell *them*, by mail, and tell
            // the caller exactly what a new registration is told.
            ctx.events.emit_in(
                &scope,
                EVENT_DUPLICATE_REGISTRATION,
                json!({ "user_id": existing.id, "email": email }),
            );
            return Ok(accepted());
        }
        Ok(None) => {}
        Err(err) => {
            tracing::error!(error = %err, "could not look up an address");
            return Err(Problem::internal().instance(&scope.request_id));
        }
    }

    match create_account(db, clock, id_gen, &email, &password_hash).await {
        Ok(user_id) => {
            ctx.events.emit_in(
                &scope,
                EVENT_REGISTERED,
                json!({ "user_id": user_id, "email": email }),
            );
            Ok(accepted())
        }
        Err(err) => {
            tracing::error!(error = %err, "could not register an account");
            Err(Problem::internal().instance(&scope.request_id))
        }
    }
}

/// Creates the user, the `password` identity and the credential.
///
/// Not atomic: the `Database` port has no transaction spanning statements.
/// A failure part-way leaves a user with no way in, which the address's
/// owner can recover from by registering again — the duplicate path finds
/// the row and mails them.
async fn create_account(
    db: &dyn factory0_core::Database,
    clock: &dyn factory0_core::Clock,
    id_gen: &dyn factory0_core::IdGen,
    email: &str,
    password_hash: &str,
) -> Result<String, factory0_core::DbError> {
    let now = lockout::iso(clock.now());
    let user_id = id_gen.ulid();
    let user = factory0_auth_core::UserRow {
        id: user_id.clone(),
        display_name: None,
        primary_email: Some(email.to_owned()),
        // Unverified until a magic link says otherwise (#21). The linking
        // rules only ever auto-link a verified address, so registering
        // must not be a way to claim one.
        primary_email_verified: false,
        status: STATUS_ACTIVE.to_owned(),
        created_at: now.clone(),
        updated_at: now.clone(),
    };
    factory0_auth_core::insert_user(db, &user).await?;

    let identity = factory0_auth_core::IdentityRow {
        id: id_gen.ulid(),
        user_id: user_id.clone(),
        provider: PROVIDER_PASSWORD.to_owned(),
        // The normalised address is the subject for this provider, the
        // same way a `sub` is for Google.
        provider_subject: email.to_owned(),
        email: Some(email.to_owned()),
        email_verified: false,
        name_at_link: None,
        created_at: now.clone(),
        last_login_at: None,
    };
    insert_identity(db, &identity).await?;

    let credential = CredentialRow {
        id: id_gen.ulid(),
        user_id: user_id.clone(),
        kind: CREDENTIAL_PASSWORD.to_owned(),
        passkey_credential_id: None,
        passkey_public_key_cose: None,
        passkey_sign_count: None,
        passkey_aaguid: None,
        passkey_transports: None,
        password_hash: Some(factory0_auth_core::Redacted(password_hash.to_owned())),
        label: None,
        created_at: now,
        last_used_at: None,
        passkey_suspect_at: None,
        failed_attempts: 0,
        failed_window_started_at: None,
        locked_until: None,
    };
    insert_credential(db, &credential).await?;
    Ok(user_id)
}

/// `POST /login`.
async fn login(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    raw: bytes::Bytes,
) -> Result<Response, Problem> {
    let body = body_of(&raw);
    let credentials: Credentials = serde_json::from_value(body.clone()).unwrap_or_default();
    let email = factory0_core::normalize_email(&credentials.email);

    if let Some(limited) = limit(&state, &headers, Some(&email)).await {
        return Ok(limited);
    }
    let captcha_token = body
        .get("captchaToken")
        .and_then(Value::as_str)
        .or_else(|| body.get("captcha_token").and_then(Value::as_str));
    if !captcha_ok(&state, captcha_token, &headers).await {
        return Err(refused(&scope));
    }

    let ctx = state.ctx.as_ref();
    let (Some(db), Some(clock), Some(id_gen)) = (
        ctx.ports.db.as_deref(),
        ctx.ports.clock.as_deref(),
        ctx.ports.id_gen.as_deref(),
    ) else {
        return Err(Problem::new(&NOT_READY));
    };
    let now = clock.now();

    let attempt = attempt(db, &email, &credentials.password, now, &scope).await?;
    let Attempt {
        user,
        credential,
        locked,
        stored,
        presented_ok,
        active,
    } = attempt;

    if !presented_ok || locked || !active || credential.is_none() {
        // A failure against a real credential counts towards the lockout.
        // An unknown address does not: there is nothing to lock, and
        // counting would need a row to count in.
        if let Some(credential) = &credential
            && !locked
            && !presented_ok
        {
            record_failure(db, ctx, &scope, credential, &state.settings, now).await;
        }
        return Err(refused(&scope));
    }

    // Past here the password is right and the account can sign in.
    let Some(user) = user else {
        return Err(refused(&scope));
    };
    let credential = credential.expect("checked above");

    // Rehash when the stored parameters are not the ones we write now.
    // Doing it on login is the only moment the plaintext is available.
    if let Some(stored) = stored.as_deref()
        && factory0_auth_core::password_needs_rehash(stored)
        && let Ok(fresh) = hash_password(&credentials.password)
        && let Err(err) = set_password_hash(db, &credential.id, &fresh).await
    {
        tracing::warn!(error = %err, "could not rehash a password");
    } else if credential.failed_attempts > 0 || credential.locked_until.is_some() {
        // A successful login clears the counter, so a person who mistypes
        // twice and then succeeds does not carry those failures for an
        // hour.
        if let Err(err) = set_password_lockout(db, &credential.id, 0, None, None).await {
            tracing::warn!(error = %err, "could not clear a lockout");
        }
    }

    let presented = session_cookie_value(&headers);
    let ip = factory0_core::client_ip(&headers);
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok());
    let session = issue_session(
        db,
        clock,
        id_gen,
        Login {
            user_id: &user.id,
            ip: ip.as_deref(),
            user_agent,
            presented_cookie: presented.as_deref(),
            amr: &AMR,
        },
    )
    .await
    .map_err(|err| match err {
        SessionError::NotActive => refused(&scope),
        err => {
            tracing::error!(error = %err, "could not issue a session");
            Problem::internal().instance(&scope.request_id)
        }
    })?;

    ctx.events.emit_in(
        &scope,
        EVENT_LOGGED_IN,
        json!({ "user_id": user.id, "session_id": session.session_id }),
    );
    Ok(signed_in(&session))
}

/// Records a failed attempt, and announces a lock when this one caused it.
async fn record_failure(
    db: &dyn factory0_core::Database,
    ctx: &factory0_core::ModuleContext,
    scope: &Scope,
    credential: &CredentialRow,
    settings: &crate::Settings,
    now: time::OffsetDateTime,
) {
    let (count, window, locked_until) = lockout::after_failure(credential, settings, now);
    if let Err(err) = set_password_lockout(
        db,
        &credential.id,
        count,
        Some(&window),
        locked_until.as_deref(),
    )
    .await
    {
        tracing::warn!(error = %err, "could not record a failed attempt");
    }
    if locked_until.is_some() {
        ctx.events.emit_in(
            scope,
            EVENT_LOCKED,
            json!({ "user_id": credential.user_id, "until": locked_until }),
        );
    }
}

/// What one login attempt found, after paying the same cost whatever the
/// answer turns out to be.
struct Attempt {
    user: Option<factory0_auth_core::UserRow>,
    credential: Option<CredentialRow>,
    locked: bool,
    stored: Option<String>,
    presented_ok: bool,
    active: bool,
}

/// Looks the account up and verifies the password.
///
/// Split out so `login` stays readable, and kept as one function because
/// every step here has to happen for every attempt: returning early on a
/// missing account would make the answer's *timing* say so.
async fn attempt(
    db: &dyn factory0_core::Database,
    email: &str,
    password: &str,
    now: time::OffsetDateTime,
    scope: &Scope,
) -> Result<Attempt, Problem> {
    // Find the account, the credential, and whether either is usable.
    // Nothing below returns early on a *different* answer: every failure
    // ends at the same `refused`, after the same work.
    let user = match user_by_primary_email(db, email).await {
        Ok(user) => user,
        Err(err) => {
            tracing::error!(error = %err, "could not look up an address");
            return Err(Problem::internal().instance(&scope.request_id));
        }
    };
    let credential = match &user {
        Some(user) => match password_credential(db, &user.id).await {
            Ok(credential) => credential,
            Err(err) => {
                tracing::error!(error = %err, "could not read a password credential");
                return Err(Problem::internal().instance(&scope.request_id));
            }
        },
        None => None,
    };

    let locked = credential
        .as_ref()
        .is_some_and(|credential| lockout::state(credential, now) == LockState::Locked);

    let stored = credential
        .as_ref()
        .and_then(|credential| credential.password_hash.as_ref())
        .map(|hash| hash.0.clone());

    // The dummy verify. An unknown address, an account with no password,
    // and a locked one all still pay for one Argon2id verify, because the
    // *time* the answer takes must not tell an attacker which it was.
    let presented_ok = verify_password(password, stored.as_deref().unwrap_or(DUMMY_HASH));

    let active = user
        .as_ref()
        .is_some_and(|user| user.status == STATUS_ACTIVE);

    Ok(Attempt {
        user,
        credential,
        locked,
        stored,
        presented_ok,
        active,
    })
}

/// `POST /change`, for somebody already signed in.
///
/// Requires the current password, and revokes every other session: a
/// password change is what a person does when they think somebody else
/// has it, and leaving those sessions alive would make it useless.
async fn change(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    raw: bytes::Bytes,
) -> Result<Response, Problem> {
    if let Some(limited) = limit(&state, &headers, None).await {
        return Ok(limited);
    }
    let ctx = state.ctx.as_ref();
    let (Some(db), Some(clock), Some(id_gen)) = (
        ctx.ports.db.as_deref(),
        ctx.ports.clock.as_deref(),
        ctx.ports.id_gen.as_deref(),
    ) else {
        return Err(Problem::new(&NOT_READY));
    };

    let Some(cookie) = session_cookie_value(&headers) else {
        return Err(refused(&scope));
    };
    let Ok(Some(session)) = factory0_auth_core::validate(db, clock, &cookie).await else {
        return Err(refused(&scope));
    };
    let Ok(Some(user)) = user_by_id(db, &session.user_id).await else {
        return Err(refused(&scope));
    };
    if user.status != STATUS_ACTIVE {
        return Err(refused(&scope));
    }

    let body: ChangeBody = serde_json::from_slice(&raw).unwrap_or_default();
    if !password_length_ok(&body.new_password) {
        return Err(Problem::new(&PASSWORD_UNSUITABLE).instance(&scope.request_id));
    }
    if state.settings.breach_check
        && let Some(http) = ctx.ports.http.as_ref()
        && breach::is_breached(http, &body.new_password).await
    {
        return Err(Problem::new(&PASSWORD_UNSUITABLE).instance(&scope.request_id));
    }

    let Ok(Some(credential)) = password_credential(db, &user.id).await else {
        return Err(refused(&scope));
    };
    let stored = credential
        .password_hash
        .as_ref()
        .map(|hash| hash.0.clone())
        .unwrap_or_default();
    if !verify_password(&body.current_password, &stored) {
        return Err(refused(&scope));
    }

    let Ok(fresh) = hash_password(&body.new_password) else {
        return Err(Problem::internal().instance(&scope.request_id));
    };
    if let Err(err) = set_password_hash(db, &credential.id, &fresh).await {
        tracing::error!(error = %err, "could not store a changed password");
        return Err(Problem::internal().instance(&scope.request_id));
    }

    // Every other session goes. Then a fresh one, so the person changing
    // their password is not signed out by their own action.
    if let Err(err) =
        factory0_auth_core::revoke_all_sessions(db, &user.id, &lockout::iso(clock.now())).await
    {
        tracing::error!(error = %err, "could not revoke sessions after a password change");
        return Err(Problem::internal().instance(&scope.request_id));
    }
    let session = issue_session(
        db,
        clock,
        id_gen,
        Login {
            user_id: &user.id,
            ip: factory0_core::client_ip(&headers).as_deref(),
            user_agent: headers
                .get(header::USER_AGENT)
                .and_then(|value| value.to_str().ok()),
            // Already revoked above.
            presented_cookie: None,
            amr: &AMR,
        },
    )
    .await
    .map_err(|_| Problem::internal().instance(&scope.request_id))?;

    ctx.events
        .emit_in(&scope, EVENT_CHANGED, json!({ "user_id": user.id }));
    Ok(signed_in(&session))
}

fn signed_in(session: &IssuedSession) -> Response {
    (
        StatusCode::OK,
        [(header::SET_COOKIE, set_cookie(&session.value))],
        Json(json!({ "user_id": session.session_id })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dummy_hash_actually_costs_what_a_real_verify_costs() {
        // The point of the dummy is the *work*: an unknown address must
        // pay for one Argon2id verify so the timing does not say it is
        // unknown. A malformed string would fail to parse and return
        // early, doing no work at all, and the defence would be silently
        // gone — which is why this asserts the hash is usable rather than
        // that it merely looks right.
        assert!(DUMMY_HASH.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(
            !factory0_auth_core::password_needs_rehash(DUMMY_HASH),
            "the dummy's parameters must match the ones we write"
        );

        // A real hash at the same parameters verifies against its own
        // password, which proves the parser accepts this shape. The dummy
        // then has to be indistinguishable from it except in its digest.
        let real = factory0_auth_core::hash_password("a known password").expect("hash");
        assert!(verify_password("a known password", &real));
        let params = |phc: &str| phc.rsplitn(3, '$').last().map(str::to_owned);
        assert_eq!(
            params(DUMMY_HASH),
            params(&real),
            "the dummy must carry the same algorithm and parameters"
        );

        // And it must not verify against anything.
        assert!(!verify_password("anything at all", DUMMY_HASH));
        assert!(!verify_password("", DUMMY_HASH));
    }

    #[test]
    fn a_bare_at_sign_is_not_an_address() {
        assert!(looks_like_an_address("ada@example.com"));
        assert!(looks_like_an_address("a+b@sub.example.co.uk"));
        for bad in [
            "",
            "@",
            "ada",
            "ada@",
            "@example.com",
            "ada@example",
            "ada@.com",
            "ada@com.",
        ] {
            assert!(!looks_like_an_address(bad), "{bad:?} was accepted");
        }
    }

    #[test]
    fn a_password_login_claims_only_knowledge() {
        assert_eq!(AMR, ["pwd"]);
    }
}
