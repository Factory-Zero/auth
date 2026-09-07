//! Sign in with Apple, end to end (issues #3, #16).
//!
//! The Google suite already covers everything the two providers share.
//! What is here is only the three things Apple does differently, and the
//! ways each of them fails when it is got wrong:
//!
//! 1. a client secret minted per exchange rather than configured,
//! 2. a cross-site `form_post` callback, with the cookie that survives one,
//! 3. a name that arrives once, in the form body, and never again.

mod support;

use base64ct::{Base64UrlUnpadded, Encoding as _};
use factory0_auth_core::{UserRow, identity_by_provider_subject, insert_user};
use http::StatusCode;
use serde_json::Value;
use support::provider::{APPLE_CLIENT_ID, TokenClaims};
use support::{
    APPLE_CALLBACK, APPLE_START, Kit, REDIRECT_BASE, Res, apple_kit, count, get, kit, kit_with,
    post_form_with, start_at,
};

/// The form body Apple posts back, without the one-time `user` field.
fn body(code: &str, state: &str) -> String {
    format!("code={code}&state={state}")
}

/// Percent-encodes the way a browser posting a form does.
fn form_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char);
            }
            b' ' => out.push('+'),
            other => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                out.push('%');
                out.push(HEX[(other >> 4) as usize] as char);
                out.push(HEX[(other & 0x0f) as usize] as char);
            }
        }
    }
    out
}

fn session_cookie(response: &Res) -> Option<String> {
    response.cookie("__Host-fz_session")
}

#[test]
fn a_first_authorization_signs_in_and_keeps_the_name_from_the_form_body() {
    pollster::block_on(async {
        let kit = apple_kit();
        kit.provider.set_claims(TokenClaims::apple());
        let started = start_at(&kit, APPLE_START, "").await;

        // Apple's first authorization carries `user`, and it is the only
        // place the name ever appears: the ID token has no `name` claim.
        let user =
            r#"{"name":{"firstName":"Ada","lastName":"Lovelace"},"email":"nick@example.com"}"#;
        let response = post_form_with(
            &kit,
            APPLE_CALLBACK,
            &format!(
                "{}&user={}",
                body("apple-code", &started.state),
                form_encode(user)
            ),
            &[("__Host-fz_oidc", &started.flow_cookie)],
        )
        .await;

        assert_eq!(
            response.status,
            StatusCode::FOUND,
            "the cross-site POST callback did not sign in: {}",
            response.text()
        );
        assert!(session_cookie(&response).is_some(), "no session cookie");

        let identity = identity_by_provider_subject(&*kit.db, "apple", "apple-subject-1")
            .await
            .expect("query")
            .expect("an identity row");
        assert_eq!(
            identity.name_at_link.as_deref(),
            Some("Ada Lovelace"),
            "the one-time name was not kept"
        );
    });
}

#[test]
fn a_later_sign_in_arrives_without_a_name_and_still_works() {
    // This is the half of the quirk that bites: everything is fine on the
    // first authorization and every later one has no `user` field at all.
    pollster::block_on(async {
        let kit = apple_kit();
        kit.provider.set_claims(TokenClaims::apple());

        let first = start_at(&kit, APPLE_START, "").await;
        let user = r#"{"name":{"firstName":"Ada","lastName":"Lovelace"}}"#;
        let response = post_form_with(
            &kit,
            APPLE_CALLBACK,
            &format!(
                "{}&user={}",
                body("code-1", &first.state),
                form_encode(user)
            ),
            &[("__Host-fz_oidc", &first.flow_cookie)],
        )
        .await;
        assert_eq!(response.status, StatusCode::FOUND);

        // Second sign-in: same subject, no `user` field.
        kit.provider.set_claims(TokenClaims::apple());
        let second = start_at(&kit, APPLE_START, "").await;
        let response = post_form_with(
            &kit,
            APPLE_CALLBACK,
            &body("code-2", &second.state),
            &[("__Host-fz_oidc", &second.flow_cookie)],
        )
        .await;
        assert_eq!(
            response.status,
            StatusCode::FOUND,
            "a second Apple sign-in must not need the name: {}",
            response.text()
        );
        assert!(session_cookie(&response).is_some());

        // One account, one identity, and the name from the first time.
        assert_eq!(
            count(&kit, "users"),
            1,
            "the second sign-in made an account"
        );
        assert_eq!(count(&kit, "identities"), 1);
        let identity = identity_by_provider_subject(&*kit.db, "apple", "apple-subject-1")
            .await
            .expect("query")
            .expect("an identity row");
        assert_eq!(
            identity.name_at_link.as_deref(),
            Some("Ada Lovelace"),
            "the name learned on the first authorization was lost"
        );
    });
}

async fn seed_user(kit: &Kit, email: &str) -> String {
    let id = kit.id_gen.ulid();
    insert_user(
        &*kit.db,
        &UserRow {
            id: id.clone(),
            display_name: None,
            primary_email: Some(email.to_owned()),
            primary_email_verified: true,
            status: "active".to_owned(),
            created_at: "2026-09-07T10:00:00Z".to_owned(),
            updated_at: "2026-09-07T10:00:00Z".to_owned(),
        },
    )
    .await
    .expect("user inserts");
    id
}

#[test]
fn the_flow_cookie_is_the_one_a_cross_site_post_can_carry() {
    // With `SameSite=Lax` the browser sends no cookie on Apple's POST, the
    // callback reads as expired, and every Apple sign-in fails with nothing
    // in the logs to say why. This is that bug's regression test.
    pollster::block_on(async {
        let kit = apple_kit();
        let response = get(&kit, APPLE_START, &[]).await;
        assert_eq!(response.status, StatusCode::FOUND);
        let cookie = response
            .cookies()
            .into_iter()
            .find(|header| header.starts_with("__Host-fz_oidc="))
            .expect("a flow cookie");
        assert!(cookie.contains("SameSite=None"), "{cookie}");
        assert!(cookie.contains("Secure"), "{cookie}");
        assert!(cookie.contains("HttpOnly"), "{cookie}");

        // Google's is unchanged: only the provider that needs it is widened.
        let response = get(&kit, "/v1/auth-oidc/google/start", &[]).await;
        let cookie = response
            .cookies()
            .into_iter()
            .find(|header| header.starts_with("__Host-fz_oidc="))
            .expect("a flow cookie");
        assert!(cookie.contains("SameSite=Lax"), "{cookie}");
    });
}

#[test]
fn the_authorization_url_asks_for_form_post_and_the_name_scope() {
    pollster::block_on(async {
        let kit = apple_kit();
        let started = start_at(&kit, APPLE_START, "").await;
        let url = url::Url::parse(&started.authorization_url).expect("a url");
        let param = |name: &str| {
            url.query_pairs()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.to_string())
        };
        assert_eq!(param("response_mode").as_deref(), Some("form_post"));
        assert_eq!(param("client_id").as_deref(), Some(APPLE_CLIENT_ID));
        let scope = param("scope").unwrap_or_default();
        assert!(scope.contains("name"), "{scope}");
        assert!(scope.contains("email"), "{scope}");
        assert!(
            url.as_str().starts_with("https://appleid.apple.com/"),
            "the URL must come from Apple's own discovery: {url}"
        );
    });
}

#[test]
fn the_token_request_carries_a_minted_client_secret() {
    pollster::block_on(async {
        let kit = apple_kit();
        kit.provider.set_claims(TokenClaims::apple());
        let started = start_at(&kit, APPLE_START, "").await;
        let response = post_form_with(
            &kit,
            APPLE_CALLBACK,
            &body("apple-code", &started.state),
            &[("__Host-fz_oidc", &started.flow_cookie)],
        )
        .await;
        assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());

        let token_call = kit
            .provider
            .calls()
            .into_iter()
            .find(|(_, url, _)| url.contains("appleid.apple.com/auth/token"))
            .expect("a token request to Apple");
        let secret = form_field(&token_call.2, "client_secret")
            .expect("the token request carried a client_secret");

        // Not a configured string: a signed ES256 JWT with Apple's claims.
        let parts: Vec<&str> = secret.split('.').collect();
        assert_eq!(parts.len(), 3, "the client secret is not a JWT: {secret}");
        let header = decode(parts[0]);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "KEY7890123");
        let claims = decode(parts[1]);
        assert_eq!(claims["iss"], "TEAM123456");
        assert_eq!(claims["sub"], APPLE_CLIENT_ID, "sub is the Services ID");
        assert_eq!(claims["aud"], "https://appleid.apple.com");
        let issued = claims["iat"].as_i64().expect("iat");
        let expires = claims["exp"].as_i64().expect("exp");
        assert!(expires > issued);
        // Six months is Apple's ceiling and a secret past it is refused.
        assert!(expires - issued < 15_777_000, "the lifetime is too long");
    });
}

fn decode(part: &str) -> Value {
    let bytes = Base64UrlUnpadded::decode_vec(part).expect("base64url");
    serde_json::from_slice(&bytes).expect("json")
}

/// One field out of a form-encoded body.
fn form_field(body: &str, name: &str) -> Option<String> {
    url::form_urlencoded::parse(body.as_bytes())
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.to_string())
}

#[test]
fn a_post_without_the_flow_cookie_is_refused() {
    // The cross-site POST is the one route a stranger can aim at us with a
    // body of their choosing. Without the signed cookie there is nothing
    // here worth reading, whatever the body says.
    pollster::block_on(async {
        let kit = apple_kit();
        kit.provider.set_claims(TokenClaims::apple());
        let started = start_at(&kit, APPLE_START, "").await;

        let response = post_form_with(
            &kit,
            APPLE_CALLBACK,
            &body("apple-code", &started.state),
            &[],
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(session_cookie(&response).is_none(), "a session was issued");
    });
}

#[test]
fn a_post_whose_state_does_not_match_the_cookie_is_refused() {
    pollster::block_on(async {
        let kit = apple_kit();
        kit.provider.set_claims(TokenClaims::apple());
        let started = start_at(&kit, APPLE_START, "").await;

        let response = post_form_with(
            &kit,
            APPLE_CALLBACK,
            &body("apple-code", "not-the-state"),
            &[("__Host-fz_oidc", &started.flow_cookie)],
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(session_cookie(&response).is_none());
        assert_eq!(
            kit.provider
                .calls()
                .iter()
                .filter(|(_, url, _)| url.contains("/auth/token"))
                .count(),
            0,
            "a mismatched state must be refused before the token exchange"
        );
    });
}

#[test]
fn a_body_that_will_not_parse_answers_like_an_expired_flow() {
    pollster::block_on(async {
        let kit = apple_kit();
        let started = start_at(&kit, APPLE_START, "").await;
        for bad in ["", "%%%", "code", "state=&code="] {
            let response = post_form_with(
                &kit,
                APPLE_CALLBACK,
                bad,
                &[("__Host-fz_oidc", &started.flow_cookie)],
            )
            .await;
            assert_eq!(response.status, StatusCode::BAD_REQUEST, "{bad:?}");
            assert!(session_cookie(&response).is_none(), "{bad:?}");
        }
    });
}

#[test]
fn a_relay_address_never_links_to_an_existing_account() {
    // Apple hands out a per-app alias. Two people can hold relay addresses
    // that look equally plausible, so one can never be evidence that this
    // is the same person as an existing account.
    pollster::block_on(async {
        let kit = apple_kit();
        let relay = "xyz@privaterelay.appleid.com";

        // An existing, verified account on the very same relay address.
        let existing = seed_user(&kit, relay).await;

        let mut claims = TokenClaims::apple();
        claims.email = Some(relay.to_owned());
        claims.email_verified = true;
        kit.provider.set_claims(claims);

        let started = start_at(&kit, APPLE_START, "").await;
        let response = post_form_with(
            &kit,
            APPLE_CALLBACK,
            &body("apple-code", &started.state),
            &[("__Host-fz_oidc", &started.flow_cookie)],
        )
        .await;
        assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());

        // A second account, not a link onto the first.
        assert_eq!(
            count(&kit, "users"),
            2,
            "a relay address linked to a stranger's account"
        );
        let identity = identity_by_provider_subject(&*kit.db, "apple", "apple-subject-1")
            .await
            .expect("query")
            .expect("an identity row");
        assert_ne!(
            identity.user_id, existing,
            "the existing account gained a way in"
        );
    });
}

#[test]
fn a_half_configured_apple_refuses_to_start_at_all() {
    // A Services ID with no signing settings cannot mint, so the module
    // refuses its whole configuration rather than answering requests it
    // will fail later at Apple with an error that names nothing.
    // `validate_config` says which keys are missing; `fz doctor` prints it.
    pollster::block_on(async {
        let kit = kit_with(vec![
            (
                "AUTH_OIDC_REDIRECT_BASE".to_owned(),
                REDIRECT_BASE.to_owned(),
            ),
            (
                "AUTH_OIDC_APPLE_CLIENT_ID".to_owned(),
                APPLE_CLIENT_ID.to_owned(),
            ),
        ]);
        let response = get(&kit, APPLE_START, &[]).await;
        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
    });
}

#[test]
fn a_deployment_with_no_apple_settings_says_the_provider_is_unconfigured() {
    // Google-only is a valid deployment. Pressing an Apple button there is
    // a named 503, not a crash and not a 404.
    pollster::block_on(async {
        let kit = kit();
        let response = get(&kit, APPLE_START, &[]).await;
        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.json()["type"],
            "https://factory0.ventures/problems/auth/oidc-provider-unconfigured"
        );
    });
}
