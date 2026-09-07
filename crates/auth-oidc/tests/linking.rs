//! Issue #22's rules, exercised through a real provider flow: what happens
//! when the address Google reports already belongs to an account here.

mod support;

use factory0_auth_core::{UserRow, insert_user};
use http::StatusCode;
use support::provider::TokenClaims;
use support::{Kit, callback, count, kit, start};

async fn seed_user(kit: &Kit, email: &str, verified: bool) -> String {
    let id = kit.id_gen.ulid();
    insert_user(
        &*kit.db,
        &UserRow {
            id: id.clone(),
            display_name: None,
            primary_email: Some(email.to_owned()),
            primary_email_verified: verified,
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
fn a_verified_address_on_both_sides_links_to_the_existing_account() {
    pollster::block_on(async {
        let kit = kit();
        let existing = seed_user(&kit, "nick@example.com", true).await;

        let started = start(&kit, "").await;
        let response = callback(&kit, &started, "auth-code", &started.state).await;
        assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());

        // One account, not two: the person who already had one gets it back
        // rather than a duplicate they cannot see.
        assert_eq!(count(&kit, "users"), 1);
        assert_eq!(count(&kit, "identities"), 1);
        assert_eq!(
            support::column(&kit, "SELECT user_id FROM identities", "user_id").as_deref(),
            Some(existing.as_str())
        );
        assert_eq!(
            support::column(&kit, "SELECT user_id FROM sessions", "user_id").as_deref(),
            Some(existing.as_str())
        );
    });
}

#[test]
fn an_unverified_address_on_either_side_is_not_guessed() {
    pollster::block_on(async {
        // The account holds the address but nobody has proved it. Linking on
        // that basis is how one person takes over another's account by
        // registering their email at a provider.
        let kit = kit();
        seed_user(&kit, "nick@example.com", false).await;

        let started = start(&kit, "").await;
        let response = callback(&kit, &started, "auth-code", &started.state).await;

        // A page, not a session: the person is told to sign in the way they
        // already can and link from there.
        assert_eq!(response.status, StatusCode::OK);
        assert!(
            response.cookie("__Host-fz_session").is_none(),
            "issued a session"
        );
        assert_eq!(count(&kit, "users"), 1, "created a second account");
        assert_eq!(count(&kit, "identities"), 0);
        assert_eq!(count(&kit, "sessions"), 0);
        assert!(
            response.text().contains("already uses that email"),
            "{}",
            response.text()
        );
    });
}

#[test]
fn a_provider_that_does_not_vouch_for_the_address_gets_a_new_account() {
    pollster::block_on(async {
        let kit = kit();
        seed_user(&kit, "nick@example.com", true).await;
        // Same address, but Google says it has not verified it. That is not
        // evidence about who this is.
        kit.provider.set_claims(TokenClaims {
            email_verified: false,
            ..TokenClaims::default()
        });

        let started = start(&kit, "").await;
        let response = callback(&kit, &started, "auth-code", &started.state).await;
        assert_eq!(response.status, StatusCode::OK);
        assert!(response.cookie("__Host-fz_session").is_none());
        assert_eq!(count(&kit, "identities"), 0);
    });
}

#[test]
fn a_new_account_records_what_the_provider_vouched_for() {
    pollster::block_on(async {
        let kit = kit();
        kit.provider.set_claims(TokenClaims {
            email: Some("someone@example.com".to_owned()),
            email_verified: false,
            name: Some("Someone".to_owned()),
            ..TokenClaims::default()
        });

        let started = start(&kit, "").await;
        let response = callback(&kit, &started, "auth-code", &started.state).await;
        assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
        assert_eq!(count(&kit, "users"), 1);

        // Unverified stays unverified. Recording it as verified would let
        // the next provider auto-link a stranger's account to this one.
        let verified = support::column(
            &kit,
            "SELECT CAST(primary_email_verified AS TEXT) AS v FROM users",
            "v",
        );
        assert_eq!(
            verified.as_deref(),
            Some("0"),
            "an unverified address was stored as verified"
        );
        assert_eq!(
            support::column(&kit, "SELECT display_name FROM users", "display_name").as_deref(),
            Some("Someone")
        );
    });
}

#[test]
fn a_disabled_account_cannot_sign_in_through_a_provider() {
    pollster::block_on(async {
        let kit = kit();
        // First login creates the account.
        let started = start(&kit, "").await;
        assert_eq!(
            callback(&kit, &started, "auth-code", &started.state)
                .await
                .status,
            StatusCode::FOUND
        );

        // An administrator switches it off. `users.status` is the service's
        // one kill switch, and a login method that ignored it would make
        // the switch useless.
        pollster::block_on(kit.db.execute(&factory0_core::Statement::new(
            "UPDATE users SET status = 'disabled'",
        )))
        .expect("status updates");

        let started = start(&kit, "").await;
        let response = callback(&kit, &started, "auth-code", &started.state).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(
            response.cookie("__Host-fz_session").is_none(),
            "issued a session"
        );
        assert_eq!(
            count(&kit, "sessions"),
            1,
            "a disabled account got a second session"
        );
    });
}

#[test]
fn a_google_account_with_no_email_still_signs_in() {
    pollster::block_on(async {
        let kit = kit();
        // Rare, but allowed: an ID token without an email claim. It must not
        // take the whole flow down.
        kit.provider.set_claims(TokenClaims {
            email: None,
            name: None,
            ..TokenClaims::default()
        });

        let started = start(&kit, "").await;
        let response = callback(&kit, &started, "auth-code", &started.state).await;
        assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
        assert_eq!(count(&kit, "users"), 1);
        assert_eq!(count(&kit, "identities"), 1);
    });
}

/// Issue #37: the kill switch has to stop the writes, not only the session.
///
/// `issue` refused a disabled account from the start, so no session was
/// ever handed out. But the outcome was carried out first, so every
/// attempt still recorded a login on the identity or inserted a new one,
/// and a disabled account accrued rows and events indefinitely.
#[test]
fn a_disabled_account_gains_nothing_from_a_provider_sign_in() {
    pollster::block_on(async {
        let kit = kit();

        // Two sign-ins while the account is fine. Two, because the first
        // is a `NewUser` outcome and only a `Known` one records a login.
        for _ in 0..2 {
            let started = start(&kit, "").await;
            let response = callback(&kit, &started, "auth-code", &started.state).await;
            assert_eq!(response.status, StatusCode::FOUND, "{}", response.text());
            kit.clock.advance_secs(60);
        }
        assert_eq!(count(&kit, "identities"), 1);

        let before = support::column(
            &kit,
            "SELECT last_login_at FROM identities",
            "last_login_at",
        );
        assert!(before.is_some(), "a repeat login should be recorded");

        pollster::block_on(kit.db.execute(&factory0_core::Statement::new(
            "UPDATE users SET status = 'disabled'",
        )))
        .expect("status updates");
        // Enough for a new `last_login_at` to be visibly different, and not
        // so much that the fake's ID token expires: past that, the callback
        // fails at token verification and never reaches the linking rules,
        // which would make this test pass for the wrong reason.
        kit.clock.advance_secs(60);

        // A third attempt: refused, and it writes nothing.
        let started = start(&kit, "").await;
        let response = callback(&kit, &started, "auth-code", &started.state).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(
            response.cookie("__Host-fz_session").is_none(),
            "issued a session"
        );
        assert_eq!(
            support::column(
                &kit,
                "SELECT last_login_at FROM identities",
                "last_login_at"
            ),
            before,
            "a disabled account still recorded a login"
        );
        assert_eq!(count(&kit, "identities"), 1);
    });
}

/// The same switch on the path that would otherwise *add* a provider: a
/// verified-address match onto a disabled account must not write the
/// identity row either.
#[test]
fn a_disabled_account_gains_no_identity_from_an_auto_link() {
    pollster::block_on(async {
        let kit = kit();
        let existing = seed_user(&kit, "nick@example.com", true).await;
        pollster::block_on(kit.db.execute(&factory0_core::Statement::new(
            "UPDATE users SET status = 'disabled'",
        )))
        .expect("status updates");

        let started = start(&kit, "").await;
        let response = callback(&kit, &started, "auth-code", &started.state).await;

        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert!(response.cookie("__Host-fz_session").is_none());
        assert_eq!(
            count(&kit, "identities"),
            0,
            "a disabled account gained a way in"
        );
        // And the account itself is untouched.
        assert_eq!(count(&kit, "users"), 1);
        let _ = existing;
    });
}
