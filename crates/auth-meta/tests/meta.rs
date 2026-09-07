//! Issue #17 acceptance: start and callback against a fake Meta serving the
//! token endpoint and the Graph profile call, with and without an email;
//! state mismatch and a token-exchange error both failing cleanly.
//!
//! There is no ID token to forge here and no JWKS to serve, which is the
//! whole difference from the OIDC providers: what makes an identity is a
//! Graph answer to a call carrying a token our own back channel obtained.

use async_trait::async_trait;
use bytes::Bytes;
use factory0_auth_core::{AuthCore, UserRow, identity_by_provider_subject, insert_user};
use factory0_auth_meta::Meta;
use factory0_core::{Clock, Config, Database, HttpClient, HttpError, IdGen, MapConfig, UlidIdGen};
use factory0_testing::TestHarness;
use http::{Method, Request, Response, StatusCode, header};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, RwLock};
use time::OffsetDateTime;
use tower::ServiceExt;

const CLIENT_ID: &str = "1234567890";
const REDIRECT_BASE: &str = "https://auth.factory0.ventures";
const START: &str = "/v1/auth-meta/start";
const CALLBACK: &str = "/v1/auth-meta/callback";

struct TestClock(AtomicI64);

impl Clock for TestClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::SeqCst)).expect("in range")
    }
}

/// A fake Meta: the token endpoint and the Graph profile call, with every
/// answer a test needs to change.
#[derive(Default)]
struct Inner {
    calls: RwLock<Vec<(String, String, String)>>,
    profile: RwLock<Option<Value>>,
    token_error: RwLock<Option<(u16, Value)>>,
    profile_status: RwLock<Option<u16>>,
}

#[derive(Clone, Default)]
struct FakeMeta {
    inner: Arc<Inner>,
}

impl FakeMeta {
    fn set_profile(&self, profile: Value) {
        *self.inner.profile.write().expect("lock") = Some(profile);
    }

    fn fail_token(&self, status: u16, body: Value) {
        *self.inner.token_error.write().expect("lock") = Some((status, body));
    }

    fn fail_profile(&self, status: u16) {
        *self.inner.profile_status.write().expect("lock") = Some(status);
    }

    fn calls(&self) -> Vec<(String, String, String)> {
        self.inner.calls.read().expect("lock").clone()
    }

    fn calls_to(&self, fragment: &str) -> usize {
        self.calls()
            .iter()
            .filter(|(_, url, _)| url.contains(fragment))
            .count()
    }

    /// The `Authorization` header the profile call carried, if any.
    fn profile_auth(&self) -> Option<String> {
        self.calls()
            .into_iter()
            .find(|(_, url, _)| url.contains("/me"))
            .map(|(_, _, auth)| auth)
    }
}

fn json_response(status: u16, body: &Value) -> Response<Bytes> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Bytes::from(serde_json::to_vec(body).expect("json")))
        .expect("response")
}

#[async_trait]
impl HttpClient for FakeMeta {
    async fn send(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let url = request.uri().to_string();
        let method = request.method().to_string();
        // For the profile call the interesting part is the header; for the
        // token call it is the body.
        let detail = if url.contains("/me") {
            request
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned()
        } else {
            String::from_utf8_lossy(request.body()).to_string()
        };
        self.inner
            .calls
            .write()
            .expect("lock")
            .push((method, url.clone(), detail));

        if url.contains("/oauth/access_token") {
            if let Some((status, body)) = self.inner.token_error.read().expect("lock").clone() {
                return Ok(json_response(status, &body));
            }
            return Ok(json_response(
                200,
                &json!({
                    "access_token": "a-meta-access-token",
                    "token_type": "bearer",
                    "expires_in": 5_184_000,
                }),
            ));
        }

        if url.contains("/me") {
            if let Some(status) = *self.inner.profile_status.read().expect("lock") {
                return Ok(json_response(status, &json!({ "error": { "code": 190 } })));
            }
            let profile = self
                .inner
                .profile
                .read()
                .expect("lock")
                .clone()
                .unwrap_or_else(|| json!({ "id": "meta-subject-1", "name": "Ada" }));
            return Ok(json_response(200, &profile));
        }

        Ok(json_response(
            404,
            &json!({ "error": format!("the fake Meta has no route for {url}") }),
        ))
    }
}

struct Kit {
    harness: TestHarness,
    meta: FakeMeta,
    clock: Arc<TestClock>,
    db: Arc<dyn Database>,
    id_gen: Arc<dyn IdGen>,
}

fn kit() -> Kit {
    kit_with(vec![
        ("AUTH_META_CLIENT_ID".to_owned(), CLIENT_ID.to_owned()),
        (
            "AUTH_META_CLIENT_SECRET".to_owned(),
            "the-app-secret".to_owned(),
        ),
        (
            "AUTH_META_REDIRECT_BASE".to_owned(),
            REDIRECT_BASE.to_owned(),
        ),
    ])
}

fn kit_with(pairs: Vec<(String, String)>) -> Kit {
    let meta = FakeMeta::default();
    let clock = Arc::new(TestClock(AtomicI64::new(1_788_775_200)));
    let config: Arc<dyn Config> = Arc::new(MapConfig::from_pairs(pairs));

    let http = meta.clone();
    let clock_for_ports = clock.clone();
    let config_for_ports = config.clone();
    let harness = TestHarness::with_ports(
        vec![Box::new(AuthCore::new()), Box::new(Meta::new())],
        move |ports| {
            ports.http = Some(Arc::new(http));
            ports.clock = Some(clock_for_ports);
            ports.config = config_for_ports;
        },
    );
    let db = harness.db.clone();
    Kit {
        harness,
        meta,
        clock,
        db,
        id_gen: Arc::new(UlidIdGen),
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

    fn location(&self) -> Option<String> {
        self.headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
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

    fn cleared(&self, name: &str) -> bool {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .any(|header| header.starts_with(&format!("{name}=")) && header.contains("Max-Age=0"))
    }
}

async fn get(kit: &Kit, uri: &str, cookies: &[(&str, &str)]) -> Res {
    let mut builder = Request::builder().method(Method::GET).uri(uri);
    if !cookies.is_empty() {
        let joined = cookies
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        builder = builder.header(header::COOKIE, joined);
    }
    let response = kit
        .harness
        .router
        .clone()
        .oneshot(builder.body(axum::body::Body::empty()).expect("request"))
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

struct Started {
    flow_cookie: String,
    state: String,
}

async fn start(kit: &Kit, cookies: &[(&str, &str)]) -> Started {
    let response = get(kit, START, cookies).await;
    assert_eq!(
        response.status,
        StatusCode::FOUND,
        "start did not redirect: {}",
        response.text()
    );
    let url = response.location().expect("a Location header");
    let parsed = url::Url::parse(&url).expect("an absolute authorization url");
    let state = parsed
        .query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.to_string())
        .expect("a state");
    Started {
        flow_cookie: response.cookie("__Host-fz_meta").expect("a flow cookie"),
        state,
    }
}

fn count(kit: &Kit, table: &str) -> i64 {
    let sql = format!("SELECT COUNT(*) AS n FROM {table}");
    let rows =
        pollster::block_on(kit.db.query(&factory0_core::Statement::new(sql))).expect("query");
    rows.first()
        .and_then(|row| row.get::<i64>("n"))
        .unwrap_or_default()
}

// ---------------------------------------------------------------------

#[test]
fn start_redirects_to_meta_with_pkce_and_a_flow_cookie() {
    pollster::block_on(async {
        let kit = kit();
        let response = get(&kit, START, &[]).await;
        assert_eq!(response.status, StatusCode::FOUND);

        let url = response.location().expect("Location");
        let parsed = url::Url::parse(&url).expect("url");
        assert_eq!(parsed.host_str(), Some("www.facebook.com"));
        let param = |name: &str| {
            parsed
                .query_pairs()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.to_string())
        };
        assert_eq!(param("client_id").as_deref(), Some(CLIENT_ID));
        assert_eq!(param("response_type").as_deref(), Some("code"));
        assert_eq!(
            param("redirect_uri").as_deref(),
            Some("https://auth.factory0.ventures/v1/auth-meta/callback")
        );
        // PKCE is not optional: a code that leaks is useless without the
        // verifier, which never leaves the cookie.
        assert_eq!(param("code_challenge_method").as_deref(), Some("S256"));
        assert!(param("code_challenge").is_some());
        let scope = param("scope").expect("scopes");
        assert!(scope.contains("email"), "{scope}");
        assert!(scope.contains("public_profile"), "{scope}");

        let cookie = response
            .headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|header| header.starts_with("__Host-fz_meta="))
            .expect("a flow cookie");
        assert!(cookie.contains("SameSite=Lax"), "{cookie}");
        assert!(cookie.contains("HttpOnly"), "{cookie}");
        assert!(cookie.contains("Secure"), "{cookie}");
    });
}

#[test]
fn a_first_login_creates_the_account_and_a_second_finds_it() {
    pollster::block_on(async {
        let kit = kit();
        kit.meta.set_profile(json!({
            "id": "meta-subject-1",
            "name": "Ada Lovelace",
            "email": "ada@example.com",
        }));

        let started = start(&kit, &[]).await;
        let response = get(
            &kit,
            &format!("{CALLBACK}?code=meta-code&state={}", started.state),
            &[("__Host-fz_meta", &started.flow_cookie)],
        )
        .await;
        assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
        assert!(response.cookie("__Host-fz_session").is_some());
        assert_eq!(response.location().as_deref(), Some("/"));
        assert_eq!(count(&kit, "users"), 1);
        assert_eq!(count(&kit, "identities"), 1);

        // The same Facebook account again: the identity matches, so no
        // second user appears.
        let started = start(&kit, &[]).await;
        let response = get(
            &kit,
            &format!("{CALLBACK}?code=meta-code-2&state={}", started.state),
            &[("__Host-fz_meta", &started.flow_cookie)],
        )
        .await;
        assert_eq!(response.status, StatusCode::FOUND);
        assert_eq!(count(&kit, "users"), 1, "a second login made an account");
        assert_eq!(count(&kit, "identities"), 1);

        let identity = identity_by_provider_subject(&*kit.db, "meta", "meta-subject-1")
            .await
            .expect("query")
            .expect("an identity");
        assert_eq!(identity.name_at_link.as_deref(), Some("Ada Lovelace"));
    });
}

/// The decision this module turns on: Meta's address is never stored as
/// verified, so it can never auto-link to somebody else's account.
#[test]
fn the_address_meta_reports_is_never_stored_as_verified() {
    pollster::block_on(async {
        let kit = kit();
        kit.meta.set_profile(json!({
            "id": "meta-subject-1",
            "email": "ada@example.com",
        }));

        let started = start(&kit, &[]).await;
        let response = get(
            &kit,
            &format!("{CALLBACK}?code=meta-code&state={}", started.state),
            &[("__Host-fz_meta", &started.flow_cookie)],
        )
        .await;
        assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());

        let identity = identity_by_provider_subject(&*kit.db, "meta", "meta-subject-1")
            .await
            .expect("query")
            .expect("an identity");
        assert!(
            !identity.email_verified,
            "storing Meta's address as verified would let it auto-link"
        );
    });
}

/// And the consequence: an existing account on the same address is not
/// walked into. The person is told to sign in the way they already can.
#[test]
fn an_existing_account_on_the_same_address_is_not_taken_over() {
    pollster::block_on(async {
        let kit = kit();
        let existing = kit.id_gen.ulid();
        insert_user(
            &*kit.db,
            &UserRow {
                id: existing.clone(),
                display_name: None,
                primary_email: Some("ada@example.com".to_owned()),
                // Verified on our side. Meta's is not, so no auto-link.
                primary_email_verified: true,
                status: "active".to_owned(),
                created_at: "2026-09-07T10:00:00Z".to_owned(),
                updated_at: "2026-09-07T10:00:00Z".to_owned(),
            },
        )
        .await
        .expect("seeds");

        kit.meta.set_profile(json!({
            "id": "meta-subject-1",
            "email": "ada@example.com",
        }));

        let started = start(&kit, &[]).await;
        let response = get(
            &kit,
            &format!("{CALLBACK}?code=meta-code&state={}", started.state),
            &[("__Host-fz_meta", &started.flow_cookie)],
        )
        .await;

        // A page, not a session: the rules will not guess.
        assert_eq!(response.status, StatusCode::OK);
        assert!(
            response.cookie("__Host-fz_session").is_none(),
            "a Meta sign-in walked into an existing account"
        );
        assert_eq!(count(&kit, "identities"), 0);
        assert_eq!(count(&kit, "users"), 1);
    });
}

/// An email is a permission a person can decline, and declining it must
/// still sign them in.
#[test]
fn a_profile_without_an_email_still_signs_in() {
    pollster::block_on(async {
        let kit = kit();
        kit.meta
            .set_profile(json!({ "id": "meta-subject-2", "name": "Ada" }));

        let started = start(&kit, &[]).await;
        let response = get(
            &kit,
            &format!("{CALLBACK}?code=meta-code&state={}", started.state),
            &[("__Host-fz_meta", &started.flow_cookie)],
        )
        .await;
        assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
        assert!(response.cookie("__Host-fz_session").is_some());
        assert_eq!(count(&kit, "users"), 1);
    });
}

#[test]
fn the_profile_call_carries_the_token_in_a_header_not_the_url() {
    pollster::block_on(async {
        let kit = kit();
        let started = start(&kit, &[]).await;
        let response = get(
            &kit,
            &format!("{CALLBACK}?code=meta-code&state={}", started.state),
            &[("__Host-fz_meta", &started.flow_cookie)],
        )
        .await;
        assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());

        assert_eq!(
            kit.meta.profile_auth().as_deref(),
            Some("Bearer a-meta-access-token")
        );
        // A token in a URL reaches proxy logs and referrers.
        for (_, url, _) in kit.meta.calls() {
            assert!(!url.contains("access_token="), "token in a url: {url}");
        }
    });
}

/// The token exchange puts the app secret in the body, because Meta does
/// not accept HTTP Basic.
#[test]
fn the_token_exchange_sends_the_secret_in_the_body() {
    pollster::block_on(async {
        let kit = kit();
        let started = start(&kit, &[]).await;
        let _ = get(
            &kit,
            &format!("{CALLBACK}?code=meta-code&state={}", started.state),
            &[("__Host-fz_meta", &started.flow_cookie)],
        )
        .await;

        let (_, _, body) = kit
            .meta
            .calls()
            .into_iter()
            .find(|(_, url, _)| url.contains("/oauth/access_token"))
            .expect("a token request");
        assert!(body.contains("client_secret=the-app-secret"), "{body}");
        assert!(body.contains("code_verifier="), "PKCE is missing: {body}");
        assert!(body.contains("grant_type=authorization_code"), "{body}");
    });
}

#[test]
fn a_state_that_does_not_match_the_cookie_is_refused_before_the_exchange() {
    pollster::block_on(async {
        let kit = kit();
        let started = start(&kit, &[]).await;
        let response = get(
            &kit,
            &format!("{CALLBACK}?code=meta-code&state=not-the-state"),
            &[("__Host-fz_meta", &started.flow_cookie)],
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(count(&kit, "users"), 0);
        assert_eq!(
            kit.meta.calls_to("/oauth/access_token"),
            0,
            "a mismatched state still spent the code"
        );
        assert!(
            !response.cleared("__Host-fz_meta"),
            "an unmatched state must not clear a flow it did not prove it owned"
        );
    });
}

#[test]
fn a_callback_without_the_flow_cookie_is_refused() {
    pollster::block_on(async {
        let kit = kit();
        let started = start(&kit, &[]).await;
        let response = get(
            &kit,
            &format!("{CALLBACK}?code=meta-code&state={}", started.state),
            &[],
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(count(&kit, "users"), 0);
        assert_eq!(kit.meta.calls_to("/oauth/access_token"), 0);
    });
}

#[test]
fn an_expired_flow_is_refused() {
    pollster::block_on(async {
        let kit = kit();
        let started = start(&kit, &[]).await;
        // Ten minutes is the window; a second past it is dead.
        kit.clock.0.fetch_add(601, Ordering::SeqCst);
        let response = get(
            &kit,
            &format!("{CALLBACK}?code=meta-code&state={}", started.state),
            &[("__Host-fz_meta", &started.flow_cookie)],
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(count(&kit, "users"), 0);
    });
}

#[test]
fn a_token_exchange_error_fails_cleanly() {
    pollster::block_on(async {
        let kit = kit();
        kit.meta.fail_token(
            400,
            json!({ "error": { "message": "This authorization code has been used." } }),
        );
        let started = start(&kit, &[]).await;
        let response = get(
            &kit,
            &format!("{CALLBACK}?code=meta-code&state={}", started.state),
            &[("__Host-fz_meta", &started.flow_cookie)],
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_GATEWAY);
        assert_eq!(count(&kit, "users"), 0);
        // Nothing Meta said reaches the person.
        assert!(
            !response.text().contains("authorization code has been used"),
            "a provider message was reflected: {}",
            response.text()
        );
        assert_eq!(kit.meta.calls_to("/me"), 0, "the profile was still fetched");
    });
}

#[test]
fn a_profile_call_failure_fails_cleanly() {
    pollster::block_on(async {
        let kit = kit();
        kit.meta.fail_profile(401);
        let started = start(&kit, &[]).await;
        let response = get(
            &kit,
            &format!("{CALLBACK}?code=meta-code&state={}", started.state),
            &[("__Host-fz_meta", &started.flow_cookie)],
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_GATEWAY);
        assert_eq!(count(&kit, "users"), 0);
    });
}

#[test]
fn meta_refusing_the_person_is_not_an_error_page() {
    pollster::block_on(async {
        let kit = kit();
        let started = start(&kit, &[]).await;
        let response = get(
            &kit,
            &format!(
                "{CALLBACK}?error=access_denied&error_description=%3Cscript%3E&state={}",
                started.state
            ),
            &[("__Host-fz_meta", &started.flow_cookie)],
        )
        .await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(count(&kit, "users"), 0);
        // Meta can put anything in `error_description`; none of it is ours
        // to render.
        assert!(!response.text().contains("<script>"), "{}", response.text());
        assert!(response.cleared("__Host-fz_meta"));
    });
}

#[test]
fn an_unconfigured_deployment_says_so() {
    pollster::block_on(async {
        let kit = kit_with(vec![]);
        let response = get(&kit, START, &[]).await;
        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
        let body: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
        assert_eq!(
            body["type"],
            "https://factory0.ventures/problems/auth/meta-not-configured"
        );
    });
}

#[test]
fn a_disabled_account_gets_no_session() {
    pollster::block_on(async {
        let kit = kit();
        kit.meta
            .set_profile(json!({ "id": "meta-subject-1", "name": "Ada" }));

        let started = start(&kit, &[]).await;
        let response = get(
            &kit,
            &format!("{CALLBACK}?code=meta-code&state={}", started.state),
            &[("__Host-fz_meta", &started.flow_cookie)],
        )
        .await;
        assert_eq!(response.status, StatusCode::FOUND);

        // An administrator switches it off. `users.status` is the service's
        // one kill switch, and a login method that ignored it would make
        // the switch useless.
        kit.db
            .execute(&factory0_core::Statement::new(
                "UPDATE users SET status = 'disabled'",
            ))
            .await
            .expect("status updates");

        let started = start(&kit, &[]).await;
        let response = get(
            &kit,
            &format!("{CALLBACK}?code=meta-code&state={}", started.state),
            &[("__Host-fz_meta", &started.flow_cookie)],
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(
            response.cookie("__Host-fz_session").is_none(),
            "a disabled account was issued a session"
        );
    });
}
