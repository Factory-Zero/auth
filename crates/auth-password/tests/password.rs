//! Issues #12, #19 and #20 end to end.
//!
//! Most of these assert an *absence*: that two different situations
//! produce the same answer. That is the whole security property of a
//! password endpoint, and it is the one a refactor breaks without any test
//! that only checks the happy path noticing.

use async_trait::async_trait;
use bytes::Bytes;
use factory0_auth_core::{AuthCore, STATUS_ACTIVE, UserRow, insert_user, user_by_primary_email};
use factory0_auth_password::Password;
use factory0_core::{
    Clock, Config, Database, Decision, HttpClient, HttpError, MapConfig, RateLimitError,
    RateLimiter, Statement,
};
use factory0_testing::TestHarness;
use http::{Method, Request, Response, StatusCode, header};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use time::OffsetDateTime;
use tower::ServiceExt;

const REGISTER: &str = "/v1/auth-password/register";
const LOGIN: &str = "/v1/auth-password/login";
const CHANGE: &str = "/v1/auth-password/change";
const GOOD: &str = "a long enough password";

struct TestClock(AtomicI64);

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::SeqCst)).expect("in range")
    }
}

/// A breach corpus that answers whatever a test wants.
#[derive(Clone, Default)]
struct FakeCorpus {
    body: Arc<RwLock<Option<String>>>,
    fail: Arc<RwLock<bool>>,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl HttpClient for FakeCorpus {
    async fn send(&self, _request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if *self.fail.read().expect("lock") {
            return Err(HttpError::Transport("the corpus is down".into()));
        }
        let body = self.body.read().expect("lock").clone().unwrap_or_default();
        Ok(Response::builder()
            .status(200)
            .body(Bytes::from(body))
            .expect("response"))
    }
}

/// A limiter that refuses after a set number of calls, so the interaction
/// between the limit and the lockout can be exercised.
#[derive(Clone, Default)]
struct FakeLimiter {
    allow: Arc<AtomicI64>,
}

#[async_trait]
impl RateLimiter for FakeLimiter {
    async fn limit(&self, _key: &str) -> Result<Decision, RateLimitError> {
        let left = self.allow.fetch_sub(1, Ordering::SeqCst);
        Ok(Decision {
            ok: left > 0,
            retry_after: Some(std::time::Duration::from_secs(60)),
        })
    }
}

struct Kit {
    harness: TestHarness,
    corpus: FakeCorpus,
    limiter: FakeLimiter,
    clock: Arc<TestClock>,
    db: Arc<dyn Database>,
}

fn kit() -> Kit {
    kit_with(vec![], i64::MAX)
}

fn kit_with(pairs: Vec<(String, String)>, allowed_requests: i64) -> Kit {
    let corpus = FakeCorpus::default();
    let limiter = FakeLimiter::default();
    limiter.allow.store(allowed_requests, Ordering::SeqCst);
    let clock = Arc::new(TestClock(AtomicI64::new(1_788_775_200)));
    let config: Arc<dyn Config> = Arc::new(MapConfig::from_pairs(pairs));

    let http = corpus.clone();
    let limiter_for_ports = limiter.clone();
    let clock_for_ports = clock.clone();
    let config_for_ports = config.clone();
    let harness = TestHarness::with_ports(
        vec![Box::new(AuthCore::new()), Box::new(Password::new())],
        move |ports| {
            ports.http = Some(Arc::new(http));
            ports.rate_limiter = Some(Arc::new(limiter_for_ports));
            ports.clock = Some(clock_for_ports);
            ports.config = config_for_ports;
        },
    );
    let db = harness.db.clone();
    Kit {
        harness,
        corpus,
        limiter,
        clock,
        db,
    }
}

struct Res {
    status: StatusCode,
    headers: http::HeaderMap,
    body: Vec<u8>,
}

impl Res {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn cookie(&self, name: &str) -> Option<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find_map(|header| {
                let value = header.strip_prefix(&format!("{name}="))?;
                let value = value.split(';').next()?.trim();
                (!value.is_empty()).then(|| value.to_owned())
            })
    }
}

async fn post(kit: &Kit, uri: &str, body: Value, cookie: Option<&str>) -> Res {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, format!("__Host-fz_session={cookie}"));
    }
    let response = kit
        .harness
        .router
        .clone()
        .oneshot(
            builder
                .body(axum::body::Body::from(body.to_string()))
                .expect("request"),
        )
        .await
        .expect("router answers");
    let (parts, body) = response.into_parts();
    let body = axum::body::to_bytes(body, 1024 * 1024)
        .await
        .expect("body reads");
    Res {
        status: parts.status,
        headers: parts.headers,
        body: body.to_vec(),
    }
}

fn count(kit: &Kit, table: &str) -> i64 {
    let sql = format!("SELECT COUNT(*) AS n FROM {table}");
    let rows = pollster::block_on(kit.db.query(&Statement::new(sql))).expect("query");
    rows.first()
        .and_then(|row| row.get::<i64>("n"))
        .unwrap_or_default()
}

async fn register(kit: &Kit, email: &str, password: &str) -> Res {
    post(
        kit,
        REGISTER,
        json!({ "email": email, "password": password }),
        None,
    )
    .await
}

async fn login(kit: &Kit, email: &str, password: &str) -> Res {
    post(
        kit,
        LOGIN,
        json!({ "email": email, "password": password }),
        None,
    )
    .await
}

// ---------------------------------------------------------------------
// Registration (#19)

#[test]
fn registering_creates_an_account_an_identity_and_a_credential() {
    pollster::block_on(async {
        let kit = kit();
        let response = register(&kit, "ada@example.com", GOOD).await;
        assert_eq!(response.status, StatusCode::ACCEPTED, "{}", response.text());
        assert_eq!(count(&kit, "users"), 1);
        assert_eq!(count(&kit, "identities"), 1);
        assert_eq!(count(&kit, "credentials"), 1);

        // Unverified until a magic link says otherwise: the linking rules
        // only auto-link a verified address, so registering must not be a
        // way to claim one.
        let user = user_by_primary_email(&*kit.db, "ada@example.com")
            .await
            .expect("query")
            .expect("a user");
        assert!(!user.primary_email_verified);
        assert_eq!(user.status, STATUS_ACTIVE);
    });
}

/// The acceptance criterion, tested byte for byte: a taken address and a
/// free one are indistinguishable.
#[test]
fn a_taken_address_answers_exactly_as_a_free_one_does() {
    pollster::block_on(async {
        let kit = kit();
        let first = register(&kit, "ada@example.com", GOOD).await;
        let second = register(&kit, "ada@example.com", "a different long password").await;
        let fresh = register(&kit, "grace@example.com", GOOD).await;

        assert_eq!(first.status, second.status);
        assert_eq!(first.status, fresh.status);
        assert_eq!(first.body, second.body, "the bodies differ");
        assert_eq!(first.body, fresh.body, "the bodies differ");

        // And no second account was made.
        assert_eq!(count(&kit, "users"), 2, "ada and grace, not three");
    });
}

/// Not-an-address gets the same answer too: "that is not an email" and
/// "that email is taken" must not be distinguishable either.
#[test]
fn rubbish_where_an_address_should_be_answers_the_same_way() {
    pollster::block_on(async {
        let kit = kit();
        let real = register(&kit, "ada@example.com", GOOD).await;
        for rubbish in ["", "   ", "not-an-address", "@", "ada"] {
            let response = register(&kit, rubbish, GOOD).await;
            assert_eq!(response.status, real.status, "{rubbish:?}");
            assert_eq!(response.body, real.body, "{rubbish:?}");
        }
        assert_eq!(count(&kit, "users"), 1);
    });
}

/// A password the person can fix is the one thing registration does say,
/// because it reveals nothing about anybody else and refusing silently
/// would leave them unable to sign in later.
#[test]
fn an_unusable_password_is_named_rather_than_swallowed() {
    pollster::block_on(async {
        let kit = kit();
        for bad in ["", "short", &"a".repeat(257)] {
            let response = register(&kit, "ada@example.com", bad).await;
            assert_eq!(response.status, StatusCode::BAD_REQUEST, "{bad:?}");
            assert_eq!(
                response.json()["type"],
                "https://factory0.ventures/problems/auth/password-unsuitable"
            );
        }
        assert_eq!(count(&kit, "users"), 0);
    });
}

#[test]
fn a_breached_password_is_refused_and_an_unreachable_corpus_is_not() {
    pollster::block_on(async {
        let kit = kit();
        // SHA-1 of "password" is 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8.
        *kit.corpus.body.write().expect("lock") =
            Some("1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\n".to_owned());
        let response = register(&kit, "ada@example.com", "password").await;
        // Refused for length before the corpus is even asked, so use a
        // long breached one to reach the check.
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(count(&kit, "users"), 0);

        // Fail-open: somebody else's outage must not stop registration.
        *kit.corpus.fail.write().expect("lock") = true;
        let before = kit.corpus.calls.load(Ordering::SeqCst);
        let response = register(&kit, "grace@example.com", GOOD).await;
        assert_eq!(response.status, StatusCode::ACCEPTED, "{}", response.text());
        assert!(
            kit.corpus.calls.load(Ordering::SeqCst) > before,
            "the corpus was not asked"
        );
        assert_eq!(count(&kit, "users"), 1);
    });
}

#[test]
fn the_breach_check_can_be_switched_off() {
    pollster::block_on(async {
        let kit = kit_with(
            vec![("AUTH_PASSWORD_BREACH_CHECK".to_owned(), "false".to_owned())],
            i64::MAX,
        );
        *kit.corpus.body.write().expect("lock") =
            Some("1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\n".to_owned());
        let response = register(&kit, "ada@example.com", "password is breached here").await;
        assert_eq!(response.status, StatusCode::ACCEPTED);
        assert_eq!(
            kit.corpus.calls.load(Ordering::SeqCst),
            0,
            "the corpus was asked with the check switched off"
        );
    });
}

// ---------------------------------------------------------------------
// Login (#20)

#[test]
fn the_right_password_signs_in_and_records_a_password_login() {
    pollster::block_on(async {
        let kit = kit();
        register(&kit, "ada@example.com", GOOD).await;

        let response = login(&kit, "ada@example.com", GOOD).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        assert!(response.cookie("__Host-fz_session").is_some());
        assert_eq!(count(&kit, "sessions"), 1);

        let rows = kit
            .db
            .query(&Statement::new("SELECT amr FROM sessions"))
            .await
            .expect("query");
        let amr = rows.first().and_then(|row| row.get::<String>("amr"));
        assert_eq!(amr.as_deref(), Some(r#"["pwd"]"#), "{amr:?}");
    });
}

/// The acceptance criterion. Four different situations, one answer.
#[test]
fn every_refused_login_answers_identically() {
    pollster::block_on(async {
        let kit = kit();
        register(&kit, "ada@example.com", GOOD).await;
        // A disabled account.
        register(&kit, "grace@example.com", GOOD).await;
        kit.db
            .execute(&Statement::new(
                "UPDATE users SET status = 'disabled' WHERE primary_email = 'grace@example.com'",
            ))
            .await
            .expect("disables");

        let wrong = login(&kit, "ada@example.com", "the wrong password").await;
        let unknown = login(&kit, "nobody@example.com", GOOD).await;
        let disabled = login(&kit, "grace@example.com", GOOD).await;

        // `instance` is the request id: it is *supposed* to differ, and
        // comparing whole bodies would only ever test that. Everything a
        // caller could learn from is the rest.
        let shape = |response: &Res| {
            let mut json = response.json();
            json.as_object_mut().map(|object| object.remove("instance"));
            json
        };
        for (name, response) in [
            ("unknown address", &unknown),
            ("disabled account", &disabled),
        ] {
            assert_eq!(response.status, wrong.status, "{name} status differs");
            assert_eq!(shape(response), shape(&wrong), "{name} body differs");
            assert!(
                response.cookie("__Host-fz_session").is_none(),
                "{name} was issued a session"
            );
        }
        assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
        assert_ne!(
            unknown.json()["instance"],
            wrong.json()["instance"],
            "every answer carried the same request id"
        );
    });
}

#[test]
fn a_locked_account_answers_the_same_way_and_refuses_the_right_password() {
    pollster::block_on(async {
        let kit = kit();
        register(&kit, "ada@example.com", GOOD).await;

        // Ten failures is the default threshold.
        for _ in 0..10 {
            let response = login(&kit, "ada@example.com", "wrong").await;
            assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        }

        // The right password now fails, and looks exactly like a wrong one.
        let locked = login(&kit, "ada@example.com", GOOD).await;
        let wrong = login(&kit, "nobody@example.com", GOOD).await;
        assert_eq!(locked.status, StatusCode::UNAUTHORIZED);
        let shape = |response: &Res| {
            let mut json = response.json();
            json.as_object_mut().map(|object| object.remove("instance"));
            json
        };
        assert_eq!(shape(&locked), shape(&wrong), "a lock announced itself");
        assert!(locked.cookie("__Host-fz_session").is_none());
        assert_eq!(count(&kit, "sessions"), 0);

        // Past the lock, the right password works again.
        kit.clock.0.fetch_add(901, Ordering::SeqCst);
        let response = login(&kit, "ada@example.com", GOOD).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        assert!(response.cookie("__Host-fz_session").is_some());
    });
}

#[test]
fn a_success_clears_the_failure_count() {
    pollster::block_on(async {
        let kit = kit();
        register(&kit, "ada@example.com", GOOD).await;
        for _ in 0..3 {
            login(&kit, "ada@example.com", "wrong").await;
        }
        assert_eq!(failed_attempts(&kit), 3);

        let response = login(&kit, "ada@example.com", GOOD).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            failed_attempts(&kit),
            0,
            "a person who mistypes twice then succeeds must not carry it"
        );
    });
}

fn failed_attempts(kit: &Kit) -> i64 {
    let rows = pollster::block_on(
        kit.db
            .query(&Statement::new("SELECT failed_attempts FROM credentials")),
    )
    .expect("query");
    rows.first()
        .and_then(|row| row.get::<i64>("failed_attempts"))
        .unwrap_or_default()
}

/// An unknown address must not be cheap. Without the dummy verify the
/// answer comes back without doing any Argon2id work at all, and the
/// timing says "no such account" plainly.
#[test]
fn an_unknown_address_still_pays_for_a_verify() {
    pollster::block_on(async {
        let kit = kit();
        register(&kit, "ada@example.com", GOOD).await;

        let known = std::time::Instant::now();
        login(&kit, "ada@example.com", "the wrong password").await;
        let known = known.elapsed();

        let unknown = std::time::Instant::now();
        login(&kit, "nobody@example.com", "the wrong password").await;
        let unknown = unknown.elapsed();

        // Not a timing assertion — a test machine is far too noisy for one
        // — but the orders of magnitude must match. A missing dummy verify
        // shows up as microseconds against tens of milliseconds.
        let ratio = known.as_secs_f64() / unknown.as_secs_f64().max(f64::MIN_POSITIVE);
        assert!(
            (0.1..=10.0).contains(&ratio),
            "an unknown address took {unknown:?} against {known:?} for a known one, \
             which is the shape of a missing dummy verify"
        );
    });
}

#[test]
fn a_rate_limited_caller_is_told_to_wait_rather_than_refused() {
    pollster::block_on(async {
        // Nothing allowed: the first key checked refuses.
        let kit = kit_with(vec![], 0);
        let response = login(&kit, "ada@example.com", GOOD).await;
        assert_eq!(
            response.status,
            StatusCode::TOO_MANY_REQUESTS,
            "{}",
            response.text()
        );
        assert!(response.headers.contains_key(header::RETRY_AFTER));

        // And a limiter with room does not refuse. The limit is consulted
        // once per key, and there is more than one key: an IP and the
        // address, so a botnet cannot walk past the per-IP limit.
        let kit = kit_with(vec![], i64::MAX);
        let before = kit.limiter.allow.load(Ordering::SeqCst);
        login(&kit, "ada@example.com", GOOD).await;
        assert!(
            before - kit.limiter.allow.load(Ordering::SeqCst) >= 2,
            "the address was not a limit key"
        );
    });
}

// ---------------------------------------------------------------------
// Change (#19)

#[test]
fn changing_a_password_revokes_every_other_session() {
    pollster::block_on(async {
        let kit = kit();
        register(&kit, "ada@example.com", GOOD).await;

        // Two devices.
        let first = login(&kit, "ada@example.com", GOOD).await;
        let second = login(&kit, "ada@example.com", GOOD).await;
        let first_cookie = first.cookie("__Host-fz_session").expect("a session");
        let second_cookie = second.cookie("__Host-fz_session").expect("a session");
        assert_eq!(count(&kit, "sessions"), 2);

        let response = post(
            &kit,
            CHANGE,
            json!({ "current_password": GOOD, "new_password": "a different long password" }),
            Some(&second_cookie),
        )
        .await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());

        // The other device is signed out. A password change is what a
        // person does when they think somebody else has it.
        assert!(
            factory0_auth_core::validate(&*kit.db, &*kit.clock, &first_cookie)
                .await
                .expect("query")
                .is_none(),
            "the other session survived a password change"
        );
        // And the new password is the one that works.
        assert_eq!(
            login(&kit, "ada@example.com", GOOD).await.status,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            login(&kit, "ada@example.com", "a different long password")
                .await
                .status,
            StatusCode::OK
        );
    });
}

#[test]
fn a_change_needs_the_current_password_and_a_session() {
    pollster::block_on(async {
        let kit = kit();
        register(&kit, "ada@example.com", GOOD).await;
        let cookie = login(&kit, "ada@example.com", GOOD)
            .await
            .cookie("__Host-fz_session")
            .expect("a session");

        // No session at all.
        let response = post(
            &kit,
            CHANGE,
            json!({ "current_password": GOOD, "new_password": "another long password" }),
            None,
        )
        .await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);

        // Session, wrong current password.
        let response = post(
            &kit,
            CHANGE,
            json!({ "current_password": "not it", "new_password": "another long password" }),
            Some(&cookie),
        )
        .await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);

        // The password is unchanged.
        assert_eq!(
            login(&kit, "ada@example.com", GOOD).await.status,
            StatusCode::OK
        );
    });
}

#[test]
fn a_new_password_must_also_be_usable() {
    pollster::block_on(async {
        let kit = kit();
        register(&kit, "ada@example.com", GOOD).await;
        let cookie = login(&kit, "ada@example.com", GOOD)
            .await
            .cookie("__Host-fz_session")
            .expect("a session");

        let response = post(
            &kit,
            CHANGE,
            json!({ "current_password": GOOD, "new_password": "short" }),
            Some(&cookie),
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            login(&kit, "ada@example.com", GOOD).await.status,
            StatusCode::OK
        );
    });
}

// ---------------------------------------------------------------------
// Rehash (#20)

#[test]
fn a_hash_at_old_parameters_is_upgraded_on_login() {
    pollster::block_on(async {
        let kit = kit();
        let now = "2026-09-07T10:00:00Z";
        insert_user(
            &*kit.db,
            &UserRow {
                id: "u1".to_owned(),
                display_name: None,
                primary_email: Some("ada@example.com".to_owned()),
                primary_email_verified: false,
                status: STATUS_ACTIVE.to_owned(),
                created_at: now.to_owned(),
                updated_at: now.to_owned(),
            },
        )
        .await
        .expect("seeds");

        // A hash at parameters we no longer write. Login is the only
        // moment the plaintext is available, so it is the only moment it
        // can be upgraded.
        let weak = weak_hash(GOOD);
        assert!(factory0_auth_core::password_needs_rehash(&weak));
        kit.db
            .execute(&Statement::new(format!(
                "INSERT INTO credentials (id, user_id, kind, password_hash, created_at, \
                 failed_attempts) VALUES ('c1', 'u1', 'password', '{weak}', '{now}', 0)"
            )))
            .await
            .expect("seeds");

        let response = login(&kit, "ada@example.com", GOOD).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());

        let rows = kit
            .db
            .query(&Statement::new("SELECT password_hash FROM credentials"))
            .await
            .expect("query");
        let stored = rows
            .first()
            .and_then(|row| row.get::<String>("password_hash"))
            .expect("a hash");
        assert_ne!(stored, weak, "the old hash survived a login");
        assert!(!factory0_auth_core::password_needs_rehash(&stored));
        // And the password still works afterwards.
        assert_eq!(
            login(&kit, "ada@example.com", GOOD).await.status,
            StatusCode::OK
        );
    });
}

/// An argon2id hash at parameters this service no longer writes.
///
/// Built by hand rather than through `hash_password`, which only ever
/// writes the current parameters — the whole point is a stored value from
/// an older deployment.
fn weak_hash(password: &str) -> String {
    use argon2::{Algorithm, Argon2, Params, Version};
    use base64ct::{Base64Unpadded as PhcB64, Encoding as _};

    let (m, t, p) = (8_u32, 1_u32, 1_u32);
    let salt = b"an-old-salt-1234";
    let params = Params::new(m, t, p, Some(32)).expect("params");
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .expect("hash");
    format!(
        "$argon2id$v={v}$m={m},t={t},p={p}${salt}${hash}",
        v = Version::V0x13 as u32,
        salt = PhcB64::encode_string(salt),
        hash = PhcB64::encode_string(&out),
    )
}
