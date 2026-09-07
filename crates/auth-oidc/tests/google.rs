//! Issue #15 acceptance: start and callback against a fake provider serving
//! discovery, JWKS and token responses; nonce, state, expiry and audience
//! failures; and a first login that creates a user with a second that finds
//! the same one.

mod support;

use http::StatusCode;
use support::provider::{CLIENT_ID, ISSUER, TokenClaims};
use support::{CALLBACK, START, callback, count, get, kit, start};

#[test]
fn start_redirects_to_the_provider_with_pkce_and_a_flow_cookie() {
    pollster::block_on(async {
        let kit = kit();
        let started = start(&kit, "").await;

        let url = url::Url::parse(&started.authorization_url).expect("url");
        assert_eq!(url.host_str(), Some("accounts.google.com"));
        let param = |name: &str| {
            url.query_pairs()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.to_string())
        };
        assert_eq!(param("client_id").as_deref(), Some(CLIENT_ID));
        assert_eq!(param("response_type").as_deref(), Some("code"));
        assert_eq!(
            param("redirect_uri").as_deref(),
            Some("https://auth.factory0.ventures/v1/auth-oidc/google/callback")
        );
        // PKCE is not optional here: an authorization code that leaks is
        // useless without the verifier, which never leaves the cookie.
        assert_eq!(param("code_challenge_method").as_deref(), Some("S256"));
        assert!(param("code_challenge").is_some());
        let scope = param("scope").expect("scopes");
        for wanted in ["openid", "email", "profile"] {
            assert!(scope.contains(wanted), "{wanted} missing from {scope}");
        }
        assert!(!started.state.is_empty());
        assert!(!started.nonce.is_empty());
    });
}

#[test]
fn a_first_login_creates_the_account_and_a_second_finds_it() {
    pollster::block_on(async {
        let kit = kit();

        let started = start(&kit, "").await;
        let first = callback(&kit, &started, "auth-code", &started.state).await;
        assert_eq!(first.status, StatusCode::FOUND, "{}", first.text());
        assert!(
            first.cookie("__Host-fz_session").is_some(),
            "no session cookie"
        );
        assert_eq!(first.location().as_deref(), Some("/"));
        assert_eq!(count(&kit, "users"), 1);
        assert_eq!(count(&kit, "identities"), 1);
        assert_eq!(count(&kit, "sessions"), 1);

        // The same Google account again: the identity matches, so no second
        // user appears.
        let started = start(&kit, "").await;
        let second = callback(&kit, &started, "auth-code", &started.state).await;
        assert_eq!(second.status, StatusCode::FOUND, "{}", second.text());
        assert_eq!(
            count(&kit, "users"),
            1,
            "a second login made a second account"
        );
        assert_eq!(count(&kit, "identities"), 1);
        assert_eq!(count(&kit, "sessions"), 2);

        // The account carries what Google said about it.
        assert_eq!(
            support::column(&kit, "SELECT primary_email FROM users", "primary_email").as_deref(),
            Some("nick@example.com")
        );
        assert_eq!(
            support::column(&kit, "SELECT provider FROM identities", "provider").as_deref(),
            Some("google")
        );
    });
}

#[test]
fn the_flow_cookie_is_spent_and_cleared() {
    pollster::block_on(async {
        let kit = kit();
        let started = start(&kit, "").await;
        let response = callback(&kit, &started, "auth-code", &started.state).await;

        // The flow is over: the cookie is cleared on the way out so it
        // cannot be presented again.
        let cleared = response
            .cookies()
            .into_iter()
            .find(|header| header.starts_with("__Host-fz_oidc="))
            .expect("the flow cookie is cleared");
        assert!(cleared.contains("Max-Age=0"), "{cleared}");
    });
}

#[test]
fn a_state_that_does_not_match_the_cookie_is_refused() {
    pollster::block_on(async {
        let kit = kit();
        let started = start(&kit, "").await;
        // The classic cross-site request forgery on an OAuth callback: a
        // code from the attacker's session, delivered to the victim's
        // browser.
        let response = callback(&kit, &started, "auth-code", "not-the-state").await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(count(&kit, "users"), 0);
        assert_eq!(
            kit.provider.calls_to("oauth2.googleapis.com/token"),
            0,
            "a mismatched state still spent the code"
        );
    });
}

#[test]
fn a_callback_without_the_flow_cookie_is_refused() {
    pollster::block_on(async {
        let kit = kit();
        let started = start(&kit, "").await;
        let response = get(
            &kit,
            &format!("{CALLBACK}?code=auth-code&state={}", started.state),
            &[],
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(count(&kit, "users"), 0);
    });
}

#[test]
fn a_flow_cookie_expires() {
    pollster::block_on(async {
        let kit = kit();
        let started = start(&kit, "").await;
        // Ten minutes is the window; a minute past it is dead.
        kit.clock.advance_secs(601);
        let response = callback(&kit, &started, "auth-code", &started.state).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(count(&kit, "users"), 0);
    });
}

#[test]
fn an_id_token_with_the_wrong_nonce_is_refused() {
    pollster::block_on(async {
        let kit = kit();
        let started = start(&kit, "").await;
        // A token minted for a different flow. Without the nonce check this
        // is a replay of somebody else's sign-in.
        kit.provider.set_claims(TokenClaims {
            nonce: Some("a-different-nonce".to_owned()),
            ..TokenClaims::default()
        });
        let response = callback(&kit, &started, "auth-code", &started.state).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(count(&kit, "users"), 0);
    });
}

#[test]
fn an_id_token_for_another_audience_is_refused() {
    pollster::block_on(async {
        let kit = kit();
        let started = start(&kit, "").await;
        // A perfectly valid Google token, issued to somebody else's client.
        kit.provider.set_claims(TokenClaims {
            audience: "another-app.apps.googleusercontent.com".to_owned(),
            ..TokenClaims::default()
        });
        let response = callback(&kit, &started, "auth-code", &started.state).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(count(&kit, "users"), 0);
    });
}

#[test]
fn an_expired_id_token_is_refused() {
    pollster::block_on(async {
        let kit = kit();
        let started = start(&kit, "").await;
        kit.provider.set_claims(TokenClaims {
            issued_at: 1_788_700_000,
            expires_at: 1_788_770_000,
            ..TokenClaims::default()
        });
        let response = callback(&kit, &started, "auth-code", &started.state).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(count(&kit, "users"), 0);
    });
}

#[test]
fn an_id_token_from_another_issuer_is_refused() {
    pollster::block_on(async {
        let kit = kit();
        let started = start(&kit, "").await;
        kit.provider.set_claims(TokenClaims {
            issuer: "https://accounts.evil.example".to_owned(),
            ..TokenClaims::default()
        });
        let response = callback(&kit, &started, "auth-code", &started.state).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(count(&kit, "users"), 0);
    });
}

#[test]
fn a_provider_that_refuses_is_reported_without_reflecting_anything() {
    pollster::block_on(async {
        let kit = kit();
        let started = start(&kit, "").await;
        let payload = "%3Cscript%3Ealert(1)%3C%2Fscript%3E";
        // A real provider returns the state with an error response too.
        let response = get(
            &kit,
            &format!(
                "{CALLBACK}?error=access_denied&error_description={payload}&state={}",
                started.state
            ),
            &[("__Host-fz_oidc", &started.flow_cookie)],
        )
        .await;

        assert_eq!(response.status, StatusCode::OK);
        let body = response.text();
        assert!(!body.contains("<script>"), "reflected a script tag: {body}");
        assert!(!body.contains("alert(1)"), "reflected the payload: {body}");
        assert!(
            !body.contains("access_denied"),
            "reflected the error: {body}"
        );
        assert_eq!(count(&kit, "users"), 0);
    });
}

#[test]
fn a_stranger_cannot_abort_a_login_in_progress() {
    pollster::block_on(async {
        let kit = kit();
        let started = start(&kit, "").await;

        // A cross-site top-level navigation to the callback with an error
        // and no valid state. If the error were acted on first, this would
        // clear the flow cookie and the real callback would then fail as
        // "expired" — a login anyone could break from anywhere.
        let interference = get(
            &kit,
            &format!("{CALLBACK}?error=access_denied&state=not-the-state"),
            &[("__Host-fz_oidc", &started.flow_cookie)],
        )
        .await;
        assert_eq!(interference.status, StatusCode::BAD_REQUEST);
        assert!(
            interference
                .cookies()
                .iter()
                .all(|header| !header.contains("Max-Age=0")),
            "the flow cookie was cleared by a stranger"
        );

        // The real callback still completes.
        let response = callback(&kit, &started, "auth-code", &started.state).await;
        assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
    });
}

#[test]
fn a_key_rotation_is_survived_with_one_extra_discovery() {
    pollster::block_on(async {
        let kit = kit();
        // Warm the cache with the current key.
        let started = start(&kit, "").await;
        let first = callback(&kit, &started, "auth-code", &started.state).await;
        assert_eq!(first.status, StatusCode::FOUND);
        let discoveries = kit.provider.calls_to("openid-configuration");

        // The provider rotates: it signs with a key id the cached JWKS has
        // never seen, and publishes it.
        kit.provider.publish_key_id("test-key-2");
        kit.provider.set_claims(TokenClaims {
            key_id: "test-key-2".to_owned(),
            ..TokenClaims::default()
        });

        let started = start(&kit, "").await;
        let response = callback(&kit, &started, "auth-code", &started.state).await;
        assert_eq!(
            response.status,
            StatusCode::FOUND,
            "a key rotation locked everyone out: {}",
            response.text()
        );
        assert!(
            kit.provider.calls_to("openid-configuration") > discoveries,
            "the cache was not refreshed for the unknown key"
        );
    });
}

#[test]
fn discovery_is_cached_between_logins() {
    pollster::block_on(async {
        let kit = kit();
        for _ in 0..3 {
            let started = start(&kit, "").await;
            let response = callback(&kit, &started, "auth-code", &started.state).await;
            assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
        }
        // Three logins, six calls that could each have refetched discovery.
        assert_eq!(
            kit.provider.calls_to("openid-configuration"),
            1,
            "discovery was not cached"
        );
    });
}

#[test]
fn a_return_to_is_honoured_only_when_it_stays_on_this_service() {
    pollster::block_on(async {
        let kit = kit();
        let started = start(&kit, "?return_to=/v1/auth-core/authorize%3Fclient_id%3Dx").await;
        let response = callback(&kit, &started, "auth-code", &started.state).await;
        assert_eq!(
            response.location().as_deref(),
            Some("/v1/auth-core/authorize?client_id=x")
        );
    });

    // An absolute URL is ignored rather than obeyed: a login flow that
    // redirects anywhere is a phishing laundry.
    pollster::block_on(async {
        let kit = kit();
        let started = start(&kit, "?return_to=https://evil.example/steal").await;
        let response = callback(&kit, &started, "auth-code", &started.state).await;
        assert_eq!(response.location().as_deref(), Some("/"));
    });
}

#[test]
fn an_unknown_provider_is_not_found() {
    pollster::block_on(async {
        let kit = kit();
        for path in [
            "/v1/auth-oidc/nonsense/start",
            "/v1/auth-oidc/nonsense/callback?code=x&state=y",
        ] {
            let response = get(&kit, path, &[]).await;
            assert_eq!(response.status, StatusCode::NOT_FOUND, "{path}");
        }

        // Apple is a provider this module serves (#16); on a kit that
        // configures only Google it is unconfigured, which is a different
        // answer from unknown and a much more useful one.
        let response = get(&kit, "/v1/auth-oidc/apple/start", &[]).await;
        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
    });
}

#[test]
fn each_provider_answers_only_on_the_callback_method_it_uses() {
    // Apple posts and Google redirects. Serving both methods for both
    // would mean an authorization response could be delivered through a
    // path the provider never uses.
    pollster::block_on(async {
        let kit = kit();
        // Google has no form_post callback.
        let response =
            support::post_form(&kit, "/v1/auth-oidc/google/callback", "code=x&state=y").await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);

        // Apple has no redirect callback.
        let response = get(&kit, "/v1/auth-oidc/apple/callback?code=x&state=y", &[]).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);
    });
}

#[test]
fn an_unconfigured_provider_says_so() {
    pollster::block_on(async {
        let kit = support::kit_with(vec![(
            "AUTH_OIDC_REDIRECT_BASE".to_owned(),
            support::REDIRECT_BASE.to_owned(),
        )]);
        let response = get(&kit, START, &[]).await;
        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.json()["type"],
            "https://factory0.ventures/problems/auth/oidc-provider-unconfigured"
        );
        let _ = ISSUER;
    });
}
