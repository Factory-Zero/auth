//! Issue #8 acceptance: issuing (cookie shape, `__Host-` rules, only
//! the SHA-256 stored), validation with the five-minute `last_seen`
//! throttle, the 30-day slide under the 90-day absolute cap,
//! revocation single and all, logout, the fixation rule, the `Session`
//! extractor's one 401 for unknown/revoked/expired, and the listing
//! with `ip_hash` and `ua_family` — against the sqlite adapter through
//! the `Clock` port, never a wall clock.

use axum::http::{Method, StatusCode, header};
use axum::response::Response;
use cratefield_testing::{FixedClock, TestHarness};
use factory0_auth_core::{AuthCore, Login, UserRow, issue, sessions_by_user, validate};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;

const EPOCH: i64 = 1_800_000_000;
const DAY: i64 = 86_400;

fn at(secs: i64) -> FixedClock {
    FixedClock(OffsetDateTime::from_unix_timestamp(secs).expect("epoch in range"))
}

fn iso(secs: i64) -> String {
    OffsetDateTime::from_unix_timestamp(secs)
        .expect("epoch in range")
        .replace_nanosecond(0)
        .expect("in range")
        .format(&Rfc3339)
        .expect("rfc3339")
}

fn kit() -> TestHarness {
    TestHarness::new(vec![Box::new(AuthCore::new())])
}

async fn user(kit: &TestHarness, id: &str) {
    factory0_auth_core::insert_user(
        &*kit.db,
        &UserRow {
            id: id.to_owned(),
            display_name: None,
            primary_email: Some(format!("{id}@example.com")),
            primary_email_verified: true,
            status: "active".to_owned(),
            created_at: iso(EPOCH),
            updated_at: iso(EPOCH),
        },
    )
    .await
    .expect("user");
}

/// A disabled account, or one that does not exist at all, gets no session
/// from any login method: the check lives in `issue`, which is the one
/// funnel every method goes through.
#[test]
fn a_session_is_never_issued_to_an_account_that_is_not_active() {
    pollster::block_on(async {
        let kit = TestHarness::new(vec![Box::new(AuthCore::new())]);
        user(&kit, "u1").await;
        cratefield_core::Database::execute(
            &*kit.db,
            &cratefield_core::Statement::new(
                "UPDATE users SET status = 'disabled' WHERE id = 'u1'",
            ),
        )
        .await
        .expect("status updates");

        let refused = issue(
            &*kit.db,
            &at(EPOCH),
            &cratefield_core::UlidIdGen,
            Login {
                user_id: "u1",
                ip: None,
                user_agent: None,
                presented_cookie: None,
                presented_session_id: None,
                amr: &["passkey"],
            },
        )
        .await;
        assert!(
            matches!(refused, Err(factory0_auth_core::SessionError::NotActive)),
            "a disabled account was issued a session"
        );

        // An account that was never there is refused the same way, so the
        // answer says nothing about whether it exists.
        let missing = issue(
            &*kit.db,
            &at(EPOCH),
            &cratefield_core::UlidIdGen,
            Login {
                user_id: "nobody",
                ip: None,
                user_agent: None,
                presented_cookie: None,
                presented_session_id: None,
                amr: &["passkey"],
            },
        )
        .await;
        assert!(matches!(
            missing,
            Err(factory0_auth_core::SessionError::NotActive)
        ));
        assert_eq!(
            sessions_by_user(&*kit.db, "u1").await.expect("query").len(),
            0
        );
    });
}

async fn login(
    kit: &TestHarness,
    user_id: &str,
    presented: Option<&str>,
) -> factory0_auth_core::IssuedSession {
    issue(
        &*kit.db,
        &at(EPOCH),
        &cratefield_core::UlidIdGen,
        Login {
            user_id,
            ip: Some("203.0.113.7"),
            user_agent: Some("Mozilla/5.0 Macintosh Safari/605.1.15"),
            presented_cookie: presented,
            presented_session_id: None,
            amr: &["passkey"],
        },
    )
    .await
    .expect("issue")
}

async fn route(
    kit: &TestHarness,
    method: Method,
    path: &str,
    cookie: Option<&str>,
) -> (StatusCode, Value, Option<String>) {
    let mut builder = axum::http::Request::builder().method(method).uri(path);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, format!("__Host-fz_session={cookie}"));
    }
    let request = builder.body(axum::body::Body::empty()).expect("builds");
    let response: Response = kit.router.clone().oneshot(request).await.expect("answers");
    let status = response.status();
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json, set_cookie)
}

#[pollster::test]
async fn issue_stores_only_the_hash_and_builds_the_host_cookie() {
    let kit = kit();
    user(&kit, "u1").await;
    let issued = login(&kit, "u1", None).await;

    assert_eq!(issued.value.len(), 43);
    assert!(
        issued
            .cookie
            .starts_with(&format!("__Host-fz_session={}", issued.value))
    );
    for attribute in ["Path=/", "Secure", "HttpOnly", "SameSite=Lax"] {
        assert!(issued.cookie.contains(attribute), "{attribute}");
    }
    assert!(!issued.cookie.to_lowercase().contains("domain"));

    let rows = sessions_by_user(&*kit.db, "u1").await.unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    let expected = {
        use sha2::Digest;
        sha2::Sha256::digest(issued.value.as_bytes()).to_vec()
    };
    assert_eq!(
        row.token_hash.0, expected,
        "the value itself is never stored"
    );
    assert_eq!(row.expires_at, iso(EPOCH + 30 * DAY));
    assert_eq!(row.last_seen_at, iso(EPOCH));
    assert!(row.ip_hash.is_some());
    assert_eq!(row.ua_family.as_deref(), Some("safari"));

    let ok = validate(&*kit.db, &at(EPOCH + 60), &issued.value)
        .await
        .expect("validate");
    let ok = ok.expect("the session validates");
    assert_eq!(ok.id, issued.session_id);
    assert_eq!(ok.user_id, "u1");
    // The login behind the session, not the moment it was last used: this
    // is what the step-up rule reads, and sliding must never move it.
    assert_eq!(
        ok.authenticated_at.unix_timestamp(),
        EPOCH,
        "authenticated_at is not the login time"
    );
    assert_eq!(
        ok.amr,
        vec!["passkey".to_owned()],
        "the amr recorded at login was lost"
    );
    assert!(
        validate(
            &*kit.db,
            &at(EPOCH + 60),
            "not-the-value-at-all-just-43-chars-xxxxxxxxx"
        )
        .await
        .unwrap()
        .is_none()
    );
}

#[pollster::test]
async fn last_seen_refreshes_at_most_once_per_five_minutes() {
    let kit = kit();
    user(&kit, "u1").await;
    let issued = login(&kit, "u1", None).await;

    // 100 seconds in: validated, no write.
    validate(&*kit.db, &at(EPOCH + 100), &issued.value)
        .await
        .unwrap()
        .expect("valid");
    let row = &sessions_by_user(&*kit.db, "u1").await.unwrap()[0];
    assert_eq!(row.last_seen_at, iso(EPOCH), "under the throttle: no write");
    assert_eq!(row.expires_at, iso(EPOCH + 30 * DAY));

    // 301 seconds in: the slide lands.
    validate(&*kit.db, &at(EPOCH + 301), &issued.value)
        .await
        .unwrap()
        .expect("valid");
    let row = &sessions_by_user(&*kit.db, "u1").await.unwrap()[0];
    assert_eq!(row.last_seen_at, iso(EPOCH + 301));
    assert_eq!(
        row.expires_at,
        iso(EPOCH + 301 + 30 * DAY),
        "slides to last_seen + 30 d"
    );
}

#[pollster::test]
async fn the_slide_never_passes_ninety_days_from_creation() {
    let kit = kit();
    user(&kit, "u1").await;
    let issued = login(&kit, "u1", None).await;

    assert!(
        validate(&*kit.db, &at(EPOCH + 30 * DAY), &issued.value)
            .await
            .unwrap()
            .is_none(),
        "30 days untouched: expired at the window"
    );

    // Keep one alive with hops and watch the expiry slide, then cap.
    let live = login(&kit, "u1", None).await;
    for (days, expected_expiry) in [(20, 50), (40, 70), (60, 90), (80, 90)] {
        validate(&*kit.db, &at(EPOCH + days * DAY), &live.value)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("still valid at day {days}"));
        let row = sessions_by_user(&*kit.db, "u1")
            .await
            .unwrap()
            .into_iter()
            .find(|row| row.id == live.session_id)
            .expect("the live session row");
        assert_eq!(
            row.expires_at,
            iso(EPOCH + expected_expiry * DAY),
            "day {days}: expiry is min(last_seen + 30 d, created + 90 d)"
        );
    }

    assert!(
        validate(&*kit.db, &at(EPOCH + 90 * DAY), &live.value)
            .await
            .unwrap()
            .is_none(),
        "at the cap the session is expired"
    );
}

#[pollster::test]
async fn revoked_expired_and_unknown_are_indistinguishable() {
    let kit = kit();
    user(&kit, "u1").await;

    let revoked = login(&kit, "u1", None).await;
    factory0_auth_core::revoke_session(&*kit.db, &revoked.session_id, &iso(EPOCH + 10))
        .await
        .unwrap();

    let expired = login(&kit, "u1", None).await;
    // expires_at is EPOCH + 30 d by construction; far past it.
    let far = EPOCH + 400 * DAY;
    assert!(
        validate(&*kit.db, &at(far), &expired.value)
            .await
            .unwrap()
            .is_none(),
        "expired"
    );

    let unknown = validate(&*kit.db, &at(EPOCH + 10), &revoked.value)
        .await
        .unwrap()
        .is_none();
    assert!(unknown, "revoked");

    // All three are Ok(None) — same type, same shape, no detail.
    let results = [
        validate(&*kit.db, &at(EPOCH + 10), &revoked.value).await,
        validate(&*kit.db, &at(far), &expired.value).await,
        validate(&*kit.db, &at(EPOCH + 10), "x".repeat(43).as_str()).await,
    ];
    for result in &results {
        assert!(matches!(result, Ok(None)), "{result:?}");
    }
}

#[pollster::test]
async fn revoke_all_kills_every_session_of_the_user_only() {
    let kit = kit();
    user(&kit, "u1").await;
    user(&kit, "u2").await;
    let s1 = login(&kit, "u1", None).await;
    let s2 = login(&kit, "u1", None).await;
    let other = login(&kit, "u2", None).await;

    let revoked = factory0_auth_core::revoke_all_sessions(&*kit.db, "u1", &iso(EPOCH + 5))
        .await
        .unwrap();
    assert_eq!(revoked, 2);

    assert!(
        validate(&*kit.db, &at(EPOCH + 6), &s1.value)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        validate(&*kit.db, &at(EPOCH + 6), &s2.value)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        validate(&*kit.db, &at(EPOCH + 6), &other.value)
            .await
            .unwrap()
            .is_some(),
        "another user's session is untouched"
    );
}

#[pollster::test]
async fn login_revokes_the_presented_session_and_mints_a_fresh_value() {
    let kit = kit();
    user(&kit, "u1").await;
    let first = login(&kit, "u1", None).await;

    let second = login(&kit, "u1", Some(&first.value)).await;
    assert_ne!(first.value, second.value, "a new session is always issued");
    assert_ne!(first.session_id, second.session_id);

    assert!(
        validate(&*kit.db, &at(EPOCH + 10), &first.value)
            .await
            .unwrap()
            .is_none(),
        "the pre-login session is revoked (fixation)"
    );
    assert!(
        validate(&*kit.db, &at(EPOCH + 10), &second.value)
            .await
            .unwrap()
            .is_some()
    );
}

#[pollster::test]
async fn the_extractor_answers_one_401_for_every_signed_out_shape() {
    let kit = kit();
    user(&kit, "u1").await;
    let signed_out = route(&kit, Method::GET, "/v1/auth-core/sessions", None).await;
    assert_eq!(signed_out.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        signed_out.1["type"],
        "https://factory0.ventures/problems/auth/session-invalid"
    );

    let unknown = route(
        &kit,
        Method::GET,
        "/v1/auth-core/sessions",
        Some(&"a".repeat(43)),
    )
    .await;
    assert_eq!(unknown.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        unknown.1["type"], "https://factory0.ventures/problems/auth/session-invalid",
        "unknown cookie: same problem as no cookie"
    );

    let revoked = login(&kit, "u1", None).await;
    factory0_auth_core::revoke_session(&*kit.db, &revoked.session_id, &iso(EPOCH + 1))
        .await
        .unwrap();
    let revoked = route(
        &kit,
        Method::GET,
        "/v1/auth-core/sessions",
        Some(&revoked.value),
    )
    .await;
    assert_eq!(revoked.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        revoked.1["type"],
        "https://factory0.ventures/problems/auth/session-invalid"
    );
}

#[pollster::test]
async fn the_expired_shape_through_the_router_is_the_same_401() {
    let kit = kit();
    user(&kit, "u1").await;
    let stale = issue(
        &*kit.db,
        &at(EPOCH - 40 * DAY),
        &cratefield_core::UlidIdGen,
        Login {
            user_id: "u1",
            ip: None,
            user_agent: None,
            presented_cookie: None,
            presented_session_id: None,
            amr: &[],
        },
    )
    .await
    .expect("issue in the past");

    let (status, json, _) = route(
        &kit,
        Method::GET,
        "/v1/auth-core/sessions",
        Some(&stale.value),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        json["type"],
        "https://factory0.ventures/problems/auth/session-invalid"
    );
}

#[pollster::test]
async fn listing_shows_ip_hash_ua_family_and_the_current_flag() {
    let kit = kit();
    user(&kit, "u1").await;
    let chrome = issue(
        &*kit.db,
        &at(EPOCH),
        &cratefield_core::UlidIdGen,
        Login {
            user_id: "u1",
            ip: Some("198.51.100.9"),
            user_agent: Some("Mozilla/5.0 Windows Chrome/120.0 Safari/537.36"),
            presented_cookie: None,
            presented_session_id: None,
            amr: &[],
        },
    )
    .await
    .unwrap();
    let safari = login(&kit, "u1", None).await;

    let (status, body, _) = route(
        &kit,
        Method::GET,
        "/v1/auth-core/sessions",
        Some(&safari.value),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let sessions = body["sessions"].as_array().cloned().unwrap_or_default();
    assert_eq!(sessions.len(), 2, "both live sessions");

    let current = sessions
        .iter()
        .find(|s| s["current"] == Value::Bool(true))
        .expect("exactly the presented session is current");
    assert_eq!(current["ua_family"], "safari");
    assert!(current["ip_hash"].as_str().is_some_and(|h| h.len() == 64));

    let other = sessions
        .iter()
        .find(|s| s["id"] == chrome.session_id.as_str())
        .expect("the chrome session is listed");
    assert_eq!(other["ua_family"], "chrome");
    assert_eq!(other["current"], Value::Bool(false));
}

#[pollster::test]
async fn logout_revokes_and_clears_the_cookie() {
    let kit = kit();
    user(&kit, "u1").await;
    let issued = login(&kit, "u1", None).await;

    let (status, body, set_cookie) = route(
        &kit,
        Method::POST,
        "/v1/auth-core/logout",
        Some(&issued.value),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);
    let clear = set_cookie.expect("Set-Cookie present");
    assert!(clear.starts_with("__Host-fz_session=;"));
    assert!(clear.contains("Max-Age=0"));

    let (status, _, _) = route(
        &kit,
        Method::GET,
        "/v1/auth-core/sessions",
        Some(&issued.value),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the session died with logout"
    );

    let again = route(
        &kit,
        Method::POST,
        "/v1/auth-core/logout",
        Some(&issued.value),
    )
    .await;
    assert_eq!(
        again.0,
        StatusCode::UNAUTHORIZED,
        "logout without a live session is 401"
    );
}

#[pollster::test]
async fn logout_all_kills_every_session_and_clears_the_cookie() {
    let kit = kit();
    user(&kit, "u1").await;
    user(&kit, "u2").await;
    let first = login(&kit, "u1", None).await;
    let second = login(&kit, "u1", None).await;
    let stranger = login(&kit, "u2", None).await;

    let (status, body, set_cookie) = route(
        &kit,
        Method::POST,
        "/v1/auth-core/logout-all",
        Some(&second.value),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked"], 2);
    assert!(set_cookie.expect("clears").contains("Max-Age=0"));

    for value in [&first.value, &second.value] {
        assert!(
            validate(&*kit.db, &at(EPOCH + 60), value)
                .await
                .unwrap()
                .is_none(),
            "both of u1's sessions are dead"
        );
    }
    assert!(
        validate(&*kit.db, &at(EPOCH + 60), &stranger.value)
            .await
            .unwrap()
            .is_some(),
        "u2 keeps their session"
    );
}

#[pollster::test]
async fn deleting_a_session_is_scoped_to_its_owner() {
    let kit = kit();
    user(&kit, "u1").await;
    user(&kit, "u2").await;
    let mine = login(&kit, "u1", None).await;
    let theirs = login(&kit, "u2", None).await;

    let (status, _, _) = route(
        &kit,
        Method::DELETE,
        &format!("/v1/auth-core/sessions/{}", theirs.session_id),
        Some(&mine.value),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "another user's session id is a 404"
    );

    let (status, body, _) = route(
        &kit,
        Method::DELETE,
        &format!("/v1/auth-core/sessions/{}", mine.session_id),
        Some(&mine.value),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked"], 1);
    assert!(
        validate(&*kit.db, &at(EPOCH + 60), &mine.value)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        validate(&*kit.db, &at(EPOCH + 60), &theirs.value)
            .await
            .unwrap()
            .is_some()
    );

    let (status, _, _) = route(
        &kit,
        Method::DELETE,
        &format!("/v1/auth-core/sessions/{}", mine.session_id),
        Some(&"a".repeat(43)),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[pollster::test]
async fn admin_routes_still_sit_behind_the_admin_layer() {
    let kit = kit();
    let (status, _, _) = route(&kit, Method::GET, "/v1/auth-core/admin/clients", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
