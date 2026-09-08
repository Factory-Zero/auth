//! Issue #13 acceptance: options and verify against real ceremonies, and a
//! wrong origin, wrong RP id, reused challenge and expired challenge all
//! failing.

mod support;

use http::{Method, StatusCode};
use support::{
    Algorithm, ORIGIN, OTHER_ORIGIN, RP_ID, SoftAuthenticator, challenge_of, post, send,
};

const OPTIONS: &str = "/v1/auth-passkeys/register/options";
const VERIFY: &str = "/v1/auth-passkeys/register/verify";
const CREDENTIALS: &str = "/v1/auth-passkeys/credentials";

fn verify_body(credential: &webauthn_rs_proto::RegisterPublicKeyCredential, label: &str) -> String {
    serde_json::json!({ "credential": credential, "label": label }).to_string()
}

#[test]
fn registration_needs_a_session() {
    pollster::block_on(async {
        let kit = support::kit();
        let response = post(&kit, OPTIONS, "{}", None).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.json()["type"],
            "https://factory0.ventures/problems/auth/session-invalid"
        );
    });
}

#[test]
fn options_describe_the_relying_party_and_the_algorithms_we_accept() {
    pollster::block_on(async {
        let kit = support::kit();
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in(&user).await;

        let response = post(&kit, OPTIONS, "{}", Some(&cookie)).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
        let body = response.json();
        let public_key = &body["publicKey"];

        assert_eq!(public_key["rp"]["id"], RP_ID);
        assert_eq!(public_key["rp"]["name"], "Factory Zero");
        assert_eq!(public_key["user"]["name"], "nick@example.com");
        // ES256 first, then RS256 (Windows Hello) and EdDSA.
        let algorithms: Vec<i64> = public_key["pubKeyCredParams"]
            .as_array()
            .expect("algorithms")
            .iter()
            .map(|param| param["alg"].as_i64().expect("alg"))
            .collect();
        assert_eq!(algorithms, [-7, -257, -8]);
        assert_eq!(
            public_key["authenticatorSelection"]["userVerification"],
            "preferred"
        );
        assert_eq!(public_key["attestation"], "none");
        assert!(!challenge_of(&body).is_empty());
    });
}

#[test]
fn a_registered_passkey_is_stored_and_listed() {
    pollster::block_on(async {
        let kit = support::kit();
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in(&user).await;
        let authenticator = SoftAuthenticator::new(Algorithm::Es256);

        let options = post(&kit, OPTIONS, "{}", Some(&cookie)).await.json();
        let challenge = challenge_of(&options);
        let credential = authenticator.register(RP_ID, ORIGIN, &challenge);

        let stored = post(
            &kit,
            VERIFY,
            &verify_body(&credential, "  My laptop  "),
            Some(&cookie),
        )
        .await;
        assert_eq!(stored.status, StatusCode::OK, "{}", stored.text());
        // The label is trimmed, and the AAGUID is kept so the account page
        // can say which authenticator this is.
        assert_eq!(stored.json()["label"], "My laptop");
        assert_eq!(stored.json()["aaguid"], "abababababababababababababababab");

        let listed = send(&kit, Method::GET, CREDENTIALS, None, Some(&cookie))
            .await
            .json();
        let passkeys = listed["passkeys"].as_array().expect("passkeys");
        assert_eq!(passkeys.len(), 1);
        assert_eq!(passkeys[0]["label"], "My laptop");
        assert!(passkeys[0]["suspect_at"].is_null());
    });
}

#[test]
fn the_same_authenticator_cannot_be_registered_twice() {
    pollster::block_on(async {
        let kit = support::kit();
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in(&user).await;
        let authenticator = SoftAuthenticator::new(Algorithm::Es256);

        for expected in [StatusCode::OK, StatusCode::CONFLICT] {
            let options = post(&kit, OPTIONS, "{}", Some(&cookie)).await.json();
            let challenge = challenge_of(&options);
            let credential = authenticator.register(RP_ID, ORIGIN, &challenge);
            let response = post(
                &kit,
                VERIFY,
                &verify_body(&credential, "one"),
                Some(&cookie),
            )
            .await;
            assert_eq!(response.status, expected, "{}", response.text());
        }

        // `excludeCredentials` is advice to the browser; the second attempt
        // proves the server enforces it too.
        let options = post(&kit, OPTIONS, "{}", Some(&cookie)).await.json();
        let excluded = options["publicKey"]["excludeCredentials"]
            .as_array()
            .expect("exclude list");
        assert_eq!(excluded.len(), 1);
    });
}

#[test]
fn a_ceremony_from_another_origin_is_refused() {
    pollster::block_on(async {
        let kit = support::kit();
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in(&user).await;
        let authenticator = SoftAuthenticator::new(Algorithm::Es256);

        let options = post(&kit, OPTIONS, "{}", Some(&cookie)).await.json();
        let challenge = challenge_of(&options);
        let credential = authenticator.register(RP_ID, OTHER_ORIGIN, &challenge);

        let response = post(&kit, VERIFY, &verify_body(&credential, "x"), Some(&cookie)).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.json()["type"],
            "https://factory0.ventures/problems/auth/passkey-ceremony-failed"
        );
    });
}

#[test]
fn a_ceremony_for_another_relying_party_is_refused() {
    pollster::block_on(async {
        let kit = support::kit();
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in(&user).await;
        let authenticator = SoftAuthenticator::new(Algorithm::Es256);

        let options = post(&kit, OPTIONS, "{}", Some(&cookie)).await.json();
        let challenge = challenge_of(&options);
        // The rpIdHash inside the authenticator data is for somebody else.
        let credential = authenticator.register("other.example", ORIGIN, &challenge);

        let response = post(&kit, VERIFY, &verify_body(&credential, "x"), Some(&cookie)).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    });
}

#[test]
fn a_challenge_can_be_spent_once() {
    pollster::block_on(async {
        let kit = support::kit();
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in(&user).await;
        let first = SoftAuthenticator::new(Algorithm::Es256);
        let second = SoftAuthenticator::new(Algorithm::Es256).with_credential_id(b"second-id");

        let options = post(&kit, OPTIONS, "{}", Some(&cookie)).await.json();
        let challenge = challenge_of(&options);

        let accepted = post(
            &kit,
            VERIFY,
            &verify_body(&first.register(RP_ID, ORIGIN, &challenge), "first"),
            Some(&cookie),
        )
        .await;
        assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.text());

        // Same challenge, different authenticator: the row is gone.
        let replayed = post(
            &kit,
            VERIFY,
            &verify_body(&second.register(RP_ID, ORIGIN, &challenge), "second"),
            Some(&cookie),
        )
        .await;
        assert_eq!(replayed.status, StatusCode::UNAUTHORIZED);
    });
}

#[test]
fn a_challenge_expires() {
    pollster::block_on(async {
        let kit = support::kit();
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in(&user).await;
        let authenticator = SoftAuthenticator::new(Algorithm::Es256);

        let options = post(&kit, OPTIONS, "{}", Some(&cookie)).await.json();
        let challenge = challenge_of(&options);

        // Five minutes is the issue's number; a minute past it is dead.
        kit.clock.advance_secs(361);

        let response = post(
            &kit,
            VERIFY,
            &verify_body(&authenticator.register(RP_ID, ORIGIN, &challenge), "late"),
            Some(&cookie),
        )
        .await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    });
}

#[test]
fn a_challenge_issued_to_one_account_cannot_register_a_passkey_on_another() {
    pollster::block_on(async {
        let kit = support::kit();
        let mallory = kit.user("mallory@example.com").await;
        let victim = kit.user("victim@example.com").await;
        let mallory_cookie = kit.sign_in(&mallory).await;
        let victim_cookie = kit.sign_in(&victim).await;
        let authenticator = SoftAuthenticator::new(Algorithm::Es256);

        // Mallory's challenge, presented by the victim's session.
        let options = post(&kit, OPTIONS, "{}", Some(&mallory_cookie))
            .await
            .json();
        let challenge = challenge_of(&options);
        let response = post(
            &kit,
            VERIFY,
            &verify_body(&authenticator.register(RP_ID, ORIGIN, &challenge), "x"),
            Some(&victim_cookie),
        )
        .await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    });
}

#[test]
fn a_login_response_cannot_be_replayed_into_registration() {
    pollster::block_on(async {
        let kit = support::kit();
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in(&user).await;
        let authenticator = SoftAuthenticator::new(Algorithm::Es256);

        let options = post(&kit, OPTIONS, "{}", Some(&cookie)).await.json();
        let challenge = challenge_of(&options);
        // Same challenge, but the client data says this was a login.
        let credential = authenticator.register_with(RP_ID, ORIGIN, &challenge, "webauthn.get");

        let response = post(&kit, VERIFY, &verify_body(&credential, "x"), Some(&cookie)).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    });
}

#[test]
fn an_authenticator_that_returns_extension_outputs_registers() {
    pollster::block_on(async {
        let kit = support::kit();
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in(&user).await;
        // Chrome asks a security key for `credProtect` whenever a
        // discoverable credential is created without `userVerification:
        // required`, which is exactly what this module requests. The key
        // echoes it in the authenticator data with the ED flag set, and
        // treating those bytes as corruption would refuse every such
        // registration on real hardware.
        let authenticator = SoftAuthenticator::new(Algorithm::Es256).with_extension_output();

        let options = post(&kit, OPTIONS, "{}", Some(&cookie)).await.json();
        let challenge = challenge_of(&options);
        let response = post(
            &kit,
            VERIFY,
            &verify_body(&authenticator.register(RP_ID, ORIGIN, &challenge), "key"),
            Some(&cookie),
        )
        .await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    });
}

#[test]
fn a_label_longer_than_the_limit_is_a_validation_error() {
    pollster::block_on(async {
        let kit = support::kit();
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in(&user).await;
        let authenticator = SoftAuthenticator::new(Algorithm::Es256);

        let options = post(&kit, OPTIONS, "{}", Some(&cookie)).await.json();
        let challenge = challenge_of(&options);
        let credential = authenticator.register(RP_ID, ORIGIN, &challenge);
        let long = "a".repeat(65);

        let response = post(
            &kit,
            VERIFY,
            &verify_body(&credential, &long),
            Some(&cookie),
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
    });
}

#[test]
fn the_last_login_method_cannot_be_deleted() {
    pollster::block_on(async {
        let kit = support::kit();
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in(&user).await;

        let mut ids = Vec::new();
        for (index, credential_id) in [b"first-id".as_slice(), b"second-id".as_slice()]
            .into_iter()
            .enumerate()
        {
            let authenticator =
                SoftAuthenticator::new(Algorithm::Es256).with_credential_id(credential_id);
            let options = post(&kit, OPTIONS, "{}", Some(&cookie)).await.json();
            let challenge = challenge_of(&options);
            let stored = post(
                &kit,
                VERIFY,
                &verify_body(
                    &authenticator.register(RP_ID, ORIGIN, &challenge),
                    &format!("key {index}"),
                ),
                Some(&cookie),
            )
            .await;
            assert_eq!(stored.status, StatusCode::OK, "{}", stored.text());
            ids.push(stored.json()["id"].as_str().expect("id").to_owned());
        }

        // The first of two goes.
        let deleted = send(
            &kit,
            Method::DELETE,
            &format!("{CREDENTIALS}/{}", ids[0]),
            None,
            Some(&cookie),
        )
        .await;
        assert_eq!(deleted.status, StatusCode::OK, "{}", deleted.text());

        // The last one does not: it is the only way back into the account.
        let refused = send(
            &kit,
            Method::DELETE,
            &format!("{CREDENTIALS}/{}", ids[1]),
            None,
            Some(&cookie),
        )
        .await;
        assert_eq!(refused.status, StatusCode::CONFLICT);
        assert_eq!(
            refused.json()["type"],
            "https://factory0.ventures/problems/auth/last-login-method"
        );
    });
}

#[test]
fn a_suspect_credential_does_not_count_as_a_way_back_in() {
    pollster::block_on(async {
        let kit = support::kit();
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in(&user).await;

        let mut ids = Vec::new();
        for (index, credential_id) in [b"good-id".as_slice(), b"suspect-id".as_slice()]
            .into_iter()
            .enumerate()
        {
            let authenticator =
                SoftAuthenticator::new(Algorithm::Es256).with_credential_id(credential_id);
            let options = post(&kit, OPTIONS, "{}", Some(&cookie)).await.json();
            let challenge = challenge_of(&options);
            let stored = post(
                &kit,
                VERIFY,
                &verify_body(
                    &authenticator.register(RP_ID, ORIGIN, &challenge),
                    &format!("key {index}"),
                ),
                Some(&cookie),
            )
            .await;
            ids.push(stored.json()["id"].as_str().expect("id").to_owned());
        }

        // The second one is flagged as a possible clone, so it is refused at
        // login and is not a way back into the account.
        kit.mark_suspect(&ids[1]).await;

        let refused = send(
            &kit,
            Method::DELETE,
            &format!("{CREDENTIALS}/{}", ids[0]),
            None,
            Some(&cookie),
        )
        .await;
        assert_eq!(
            refused.status,
            StatusCode::CONFLICT,
            "deleting the only working passkey stranded the account: {}",
            refused.text()
        );
    });
}

#[test]
fn one_person_cannot_delete_another_persons_passkey() {
    pollster::block_on(async {
        let kit = support::kit();
        let owner = kit.user("owner@example.com").await;
        let stranger = kit.user("stranger@example.com").await;
        let owner_cookie = kit.sign_in(&owner).await;
        let stranger_cookie = kit.sign_in(&stranger).await;
        let authenticator = SoftAuthenticator::new(Algorithm::Es256);

        let options = post(&kit, OPTIONS, "{}", Some(&owner_cookie)).await.json();
        let challenge = challenge_of(&options);
        let stored = post(
            &kit,
            VERIFY,
            &verify_body(
                &authenticator.register(RP_ID, ORIGIN, &challenge),
                "owner key",
            ),
            Some(&owner_cookie),
        )
        .await;
        let id = stored.json()["id"].as_str().expect("id").to_owned();

        let response = send(
            &kit,
            Method::DELETE,
            &format!("{CREDENTIALS}/{id}"),
            None,
            Some(&stranger_cookie),
        )
        .await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);
    });
}

// --- Step-up: changing how you sign in needs a recent login (issue #31) ---

const REAUTH: &str = "https://factory0.ventures/problems/auth/reauthentication-required";

/// Registers one passkey and returns (session cookie, credential row id),
/// with the clock still at the moment of the login.
async fn a_registered_passkey(kit: &support::Kit) -> (String, String) {
    let user = kit.user("nick@example.com").await;
    let cookie = kit.sign_in(&user).await;
    let options = post(kit, OPTIONS, "{}", Some(&cookie)).await;
    assert_eq!(options.status, StatusCode::OK, "{}", options.text());
    let authenticator = SoftAuthenticator::new(Algorithm::Es256);
    let credential = authenticator.register(RP_ID, ORIGIN, &challenge_of(&options.json()));
    let verified = post(
        kit,
        VERIFY,
        &verify_body(&credential, "laptop"),
        Some(&cookie),
    )
    .await;
    assert_eq!(verified.status, StatusCode::OK, "{}", verified.text());
    let listed = send(kit, Method::GET, CREDENTIALS, None, Some(&cookie))
        .await
        .json();
    let id = listed["passkeys"][0]["id"]
        .as_str()
        .expect("a credential id")
        .to_owned();
    (cookie, id)
}

#[test]
fn a_session_older_than_the_window_cannot_add_a_passkey() {
    // The attack: a session cookie that was stolen, or left open on a
    // shared machine, adds a passkey. That passkey then outlives the
    // password change and the session revocation the person does when they
    // notice, and nothing about it looks unusual on the account page.
    pollster::block_on(async {
        let kit = support::kit();
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in(&user).await;

        kit.clock
            .advance_secs(factory0_auth_core::DEFAULT_STEP_UP_WINDOW_SECS + 1);

        let response = post(&kit, OPTIONS, "{}", Some(&cookie)).await;
        assert_eq!(
            response.status,
            StatusCode::FORBIDDEN,
            "a stale session was allowed to start a registration: {}",
            response.text()
        );
        // 403 and its own type, not the 401 a signed-out caller gets: the
        // client should re-authenticate and retry, not start a full login.
        assert_eq!(response.json()["type"], REAUTH);
    });
}

#[test]
fn a_session_older_than_the_window_cannot_finish_a_registration() {
    // The second half of the same door. Guarding only `options` would let a
    // caller collect a challenge while fresh and spend it later.
    pollster::block_on(async {
        let kit = support::kit();
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in(&user).await;

        let options = post(&kit, OPTIONS, "{}", Some(&cookie)).await;
        assert_eq!(options.status, StatusCode::OK, "{}", options.text());
        let authenticator = SoftAuthenticator::new(Algorithm::Es256);
        let credential = authenticator.register(RP_ID, ORIGIN, &challenge_of(&options.json()));

        kit.clock
            .advance_secs(factory0_auth_core::DEFAULT_STEP_UP_WINDOW_SECS + 1);

        let response = post(
            &kit,
            VERIFY,
            &verify_body(&credential, "laptop"),
            Some(&cookie),
        )
        .await;
        assert_eq!(
            response.status,
            StatusCode::FORBIDDEN,
            "a challenge taken while fresh was spent after the window: {}",
            response.text()
        );
        assert_eq!(response.json()["type"], REAUTH);
    });
}

#[test]
fn a_session_older_than_the_window_cannot_remove_a_passkey() {
    // Removal matters as much as addition: stripping somebody's only
    // passkey is how you force them onto a weaker method you control.
    pollster::block_on(async {
        let kit = support::kit();
        let (cookie, id) = a_registered_passkey(&kit).await;

        kit.clock
            .advance_secs(factory0_auth_core::DEFAULT_STEP_UP_WINDOW_SECS + 1);

        let response = send(
            &kit,
            Method::DELETE,
            &format!("{CREDENTIALS}/{id}"),
            None,
            Some(&cookie),
        )
        .await;
        assert_eq!(
            response.status,
            StatusCode::FORBIDDEN,
            "a stale session removed a passkey: {}",
            response.text()
        );
        assert_eq!(response.json()["type"], REAUTH);
    });
}

#[test]
fn a_session_inside_the_window_still_works() {
    // The other half, and the one that would make this feature useless if
    // it were wrong: the rule must not refuse a person who signed in a
    // moment ago.
    pollster::block_on(async {
        let kit = support::kit();
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in(&user).await;

        // One second short of the window: still allowed.
        kit.clock
            .advance_secs(factory0_auth_core::DEFAULT_STEP_UP_WINDOW_SECS - 1);

        let response = post(&kit, OPTIONS, "{}", Some(&cookie)).await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "a session inside the window was refused: {}",
            response.text()
        );
    });
}

#[test]
fn listing_passkeys_does_not_need_a_recent_login() {
    // Deliberate asymmetry: reading which passkeys exist changes nothing,
    // and making the account page demand a re-authentication to render
    // would train people to re-authenticate for no reason.
    pollster::block_on(async {
        let kit = support::kit();
        let (cookie, _) = a_registered_passkey(&kit).await;

        kit.clock
            .advance_secs(factory0_auth_core::DEFAULT_STEP_UP_WINDOW_SECS + 1);

        let response = send(&kit, Method::GET, CREDENTIALS, None, Some(&cookie)).await;
        assert_eq!(
            response.status,
            StatusCode::OK,
            "listing was refused: {}",
            response.text()
        );
        assert_eq!(
            response.json()["passkeys"]
                .as_array()
                .expect("passkeys")
                .len(),
            1
        );
    });
}

#[test]
fn the_window_is_configurable_and_validated() {
    // A deployment can widen or narrow it, and a typo is a build failure
    // rather than a silent default.
    use cratefield_core::Module as _;

    let mut pairs = support::config_pairs();
    pairs.push((
        "AUTH_CORE_STEP_UP_WINDOW_SECS".to_owned(),
        "not-a-number".to_owned(),
    ));
    let config = cratefield_core::MapConfig::from_pairs(pairs);
    let refused = factory0_auth_passkeys::Passkeys::new()
        .validate_config(&config)
        .expect_err("a non-numeric window was accepted");
    assert!(
        format!("{refused:?}").contains("AUTH_CORE_STEP_UP_WINDOW_SECS"),
        "the error does not name the key: {refused:?}"
    );

    for bad in ["0", "59", "86401", "-900"] {
        let mut pairs = support::config_pairs();
        pairs.push(("AUTH_CORE_STEP_UP_WINDOW_SECS".to_owned(), bad.to_owned()));
        assert!(
            factory0_auth_passkeys::Passkeys::new()
                .validate_config(&cratefield_core::MapConfig::from_pairs(pairs))
                .is_err(),
            "{bad} was accepted as a step-up window"
        );
    }

    // And a sane value is taken.
    let mut pairs = support::config_pairs();
    pairs.push(("AUTH_CORE_STEP_UP_WINDOW_SECS".to_owned(), "300".to_owned()));
    assert!(
        factory0_auth_passkeys::Passkeys::new()
            .validate_config(&cratefield_core::MapConfig::from_pairs(pairs))
            .is_ok()
    );
}

#[test]
fn a_narrower_window_is_enforced_not_merely_accepted() {
    // Configuration that parses but does nothing is the usual way a
    // security setting fails, so assert the number reaches the guard.
    pollster::block_on(async {
        let mut pairs = support::config_pairs();
        pairs.push(("AUTH_CORE_STEP_UP_WINDOW_SECS".to_owned(), "60".to_owned()));
        let kit = support::kit_with(pairs);
        let user = kit.user("nick@example.com").await;
        let cookie = kit.sign_in(&user).await;

        // Well inside the default window, well outside the configured one.
        kit.clock.advance_secs(61);

        let response = post(&kit, OPTIONS, "{}", Some(&cookie)).await;
        assert_eq!(
            response.status,
            StatusCode::FORBIDDEN,
            "the configured 60s window was not applied: {}",
            response.text()
        );
        assert_eq!(response.json()["type"], REAUTH);
    });
}
