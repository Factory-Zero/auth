//! Issue #22 acceptance: one user, many identities.
//!
//! The table below is the whole point. Linking too eagerly is an account
//! takeover, and linking too rarely splits a person across duplicate
//! accounts, so each rule is asserted for each provider shape rather
//! than assumed from the code reading correctly.

use factory0_auth_core::linking::{
    IncomingIdentity, Outcome, UnlinkError, create_user, is_apple_private_relay, link, resolve,
    unlink,
};
use factory0_auth_core::{
    AuthCore, CredentialRow, PROVIDER_APPLE, PROVIDER_GOOGLE, PROVIDER_META, PROVIDER_PASSWORD,
    Redacted, UserRow, identities_by_user, insert_credential, insert_user,
};
use factory0_core::UlidIdGen;
use factory0_testing::{FixedClock, TestHarness};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const EPOCH: i64 = 1_800_000_000;

fn at() -> FixedClock {
    FixedClock(OffsetDateTime::from_unix_timestamp(EPOCH).expect("in range"))
}

fn iso() -> String {
    OffsetDateTime::from_unix_timestamp(EPOCH)
        .expect("in range")
        .replace_nanosecond(0)
        .expect("in range")
        .format(&Rfc3339)
        .expect("rfc3339")
}

fn kit() -> TestHarness {
    TestHarness::new(vec![Box::new(AuthCore::new())])
}

fn incoming<'a>(
    provider: &'a str,
    subject: &'a str,
    email: Option<&'a str>,
    verified: bool,
) -> IncomingIdentity<'a> {
    IncomingIdentity {
        provider,
        subject,
        email,
        email_verified: verified,
        name: None,
    }
}

/// Seeds a user whose primary address is or is not verified by us.
async fn seed_user(kit: &TestHarness, id: &str, email: Option<&str>, verified: bool) {
    insert_user(
        &*kit.db,
        &UserRow {
            id: id.to_owned(),
            display_name: None,
            primary_email: email.map(str::to_owned),
            primary_email_verified: verified,
            status: "active".to_owned(),
            created_at: iso(),
            updated_at: iso(),
        },
    )
    .await
    .expect("user");
}

// ---------------------------------------------------------------------
// Rule 1 — a known identity

#[pollster::test]
async fn the_same_provider_subject_always_returns_the_same_user() {
    let kit = kit();
    seed_user(&kit, "u1", Some("a@example.com"), true).await;
    let identity = incoming(PROVIDER_GOOGLE, "google-sub-1", Some("a@example.com"), true);
    link(&*kit.db, &at(), &UlidIdGen, "u1", &identity)
        .await
        .expect("first link");

    let outcome = resolve(&*kit.db, &identity, None).await.expect("resolve");

    assert_eq!(
        outcome,
        Outcome::Known {
            user_id: "u1".to_owned()
        }
    );
}

/// A known identity wins even while somebody else is signed in: signing
/// into a second account from a first must not merge them.
#[pollster::test]
async fn a_known_identity_beats_the_current_session() {
    let kit = kit();
    seed_user(&kit, "u1", Some("a@example.com"), true).await;
    seed_user(&kit, "u2", Some("b@example.com"), true).await;
    let identity = incoming(PROVIDER_GOOGLE, "google-sub-1", Some("a@example.com"), true);
    link(&*kit.db, &at(), &UlidIdGen, "u1", &identity)
        .await
        .expect("link");

    let outcome = resolve(&*kit.db, &identity, Some("u2"))
        .await
        .expect("resolve");

    assert_eq!(
        outcome,
        Outcome::Known {
            user_id: "u1".to_owned()
        },
        "the identity's own user wins, not the session's"
    );
}

// ---------------------------------------------------------------------
// Rule 2 — linking while signed in

#[pollster::test]
async fn a_signed_in_user_is_offered_the_link_confirmation() {
    let kit = kit();
    seed_user(&kit, "u1", Some("a@example.com"), true).await;

    // A brand new provider, an address that matches nothing.
    let identity = incoming(PROVIDER_META, "meta-1", Some("other@example.com"), false);
    let outcome = resolve(&*kit.db, &identity, Some("u1"))
        .await
        .expect("resolve");

    assert_eq!(
        outcome,
        Outcome::ConfirmLink {
            user_id: "u1".to_owned()
        },
        "being signed in is the only way to link without an email match"
    );
}

// ---------------------------------------------------------------------
// Rule 3 — the verified email match

#[pollster::test]
async fn a_verified_match_on_both_sides_links_and_notifies() {
    let kit = kit();
    seed_user(&kit, "u1", Some("a@example.com"), true).await;

    let identity = incoming(PROVIDER_GOOGLE, "google-1", Some("a@example.com"), true);
    let outcome = resolve(&*kit.db, &identity, None).await.expect("resolve");

    assert_eq!(
        outcome,
        Outcome::AutoLinked {
            user_id: "u1".to_owned(),
            notify_email: "a@example.com".to_owned(),
        }
    );
}

/// **The takeover this whole module exists to prevent.**
///
/// An attacker registers the victim's address at a provider that does
/// not verify addresses. If the provider's word alone were enough, they
/// would be handed the victim's account.
#[pollster::test]
async fn an_unverified_provider_email_never_links_to_an_existing_account() {
    let kit = kit();
    seed_user(&kit, "victim", Some("victim@example.com"), true).await;

    let attacker = incoming(
        PROVIDER_META,
        "meta-attacker",
        Some("victim@example.com"),
        false,
    );
    let outcome = resolve(&*kit.db, &attacker, None).await.expect("resolve");

    assert_eq!(
        outcome,
        Outcome::ExistingAccountUnverified,
        "an unverified provider address must never reach the victim's account"
    );
    assert_ne!(
        outcome,
        Outcome::AutoLinked {
            user_id: "victim".to_owned(),
            notify_email: "victim@example.com".to_owned()
        }
    );
}

/// The mirror case: the provider verified it, but we never did. Our own
/// unverified address is no evidence either, so it does not link.
#[pollster::test]
async fn our_own_unverified_address_does_not_link_either() {
    let kit = kit();
    seed_user(&kit, "u1", Some("a@example.com"), false).await;

    let identity = incoming(PROVIDER_GOOGLE, "google-1", Some("a@example.com"), true);
    let outcome = resolve(&*kit.db, &identity, None).await.expect("resolve");

    assert_eq!(outcome, Outcome::ExistingAccountUnverified);
}

// ---------------------------------------------------------------------
// Apple private relay

#[test]
fn relay_addresses_are_recognised_whatever_their_case() {
    assert!(is_apple_private_relay("abc123@privaterelay.appleid.com"));
    assert!(is_apple_private_relay("abc123@PrivateRelay.AppleID.com"));
    assert!(!is_apple_private_relay("someone@example.com"));
    assert!(
        !is_apple_private_relay("privaterelay.appleid.com@example.com"),
        "the domain must be the domain, not part of the local part"
    );
}

/// A relay address is a per-app alias, so it is not evidence about who
/// holds any mailbox. It never matches an existing account — even one
/// whose verified address is character-for-character the same.
#[pollster::test]
async fn an_apple_relay_address_never_links_even_when_it_matches() {
    let kit = kit();
    let relay = "xyz@privaterelay.appleid.com";
    seed_user(&kit, "u1", Some(relay), true).await;

    let identity = incoming(PROVIDER_APPLE, "apple-2", Some(relay), true);
    let outcome = resolve(&*kit.db, &identity, None).await.expect("resolve");

    assert_eq!(
        outcome,
        Outcome::NewUser,
        "relay addresses are aliases, not identities"
    );
}

// ---------------------------------------------------------------------
// Rule 4 — new users

#[pollster::test]
async fn an_unmatched_address_creates_a_new_user() {
    let kit = kit();
    seed_user(&kit, "u1", Some("someone@example.com"), true).await;

    let identity = incoming(
        PROVIDER_GOOGLE,
        "google-1",
        Some("nobody@example.com"),
        true,
    );
    assert_eq!(
        resolve(&*kit.db, &identity, None).await.expect("resolve"),
        Outcome::NewUser
    );
}

/// A provider that reports no address at all (Meta may not) still works;
/// it simply cannot match anyone.
#[pollster::test]
async fn a_provider_without_an_email_creates_a_new_user() {
    let kit = kit();
    seed_user(&kit, "u1", Some("a@example.com"), true).await;

    let identity = incoming(PROVIDER_META, "meta-1", None, false);
    assert_eq!(
        resolve(&*kit.db, &identity, None).await.expect("resolve"),
        Outcome::NewUser
    );
}

#[pollster::test]
async fn a_created_user_is_only_verified_when_the_provider_vouched() {
    let kit = kit();

    let vouched = incoming(PROVIDER_GOOGLE, "g1", Some("v@example.com"), true);
    let user = create_user(&*kit.db, &at(), &UlidIdGen, &vouched)
        .await
        .expect("user");
    assert!(user.primary_email_verified);

    let unvouched = incoming(PROVIDER_META, "m1", Some("u@example.com"), false);
    let user = create_user(&*kit.db, &at(), &UlidIdGen, &unvouched)
        .await
        .expect("user");
    assert!(
        !user.primary_email_verified,
        "a provider that does not verify cannot hand us a verified address"
    );
}

// ---------------------------------------------------------------------
// The whole shape: one user, many identities

#[pollster::test]
async fn one_user_accumulates_many_identities() {
    let kit = kit();
    seed_user(&kit, "u1", Some("a@example.com"), true).await;

    for (provider, subject) in [
        (PROVIDER_GOOGLE, "g1"),
        (PROVIDER_APPLE, "a1"),
        (PROVIDER_META, "m1"),
    ] {
        let identity = incoming(provider, subject, Some("a@example.com"), true);
        link(&*kit.db, &at(), &UlidIdGen, "u1", &identity)
            .await
            .expect("link");
    }

    let identities = identities_by_user(&*kit.db, "u1").await.expect("query");
    assert_eq!(identities.len(), 3);
    // And every one of them now resolves to the same user.
    for (provider, subject) in [
        (PROVIDER_GOOGLE, "g1"),
        (PROVIDER_APPLE, "a1"),
        (PROVIDER_META, "m1"),
    ] {
        assert_eq!(
            resolve(&*kit.db, &incoming(provider, subject, None, false), None)
                .await
                .expect("resolve"),
            Outcome::Known {
                user_id: "u1".to_owned()
            }
        );
    }
}

// ---------------------------------------------------------------------
// Unlinking

#[pollster::test]
async fn unlinking_the_last_way_in_is_refused() {
    let kit = kit();
    seed_user(&kit, "u1", Some("a@example.com"), true).await;
    let identity = incoming(PROVIDER_GOOGLE, "g1", Some("a@example.com"), true);
    let row = link(&*kit.db, &at(), &UlidIdGen, "u1", &identity)
        .await
        .expect("link");

    assert_eq!(
        unlink(&*kit.db, "u1", &row.id).await.expect("query"),
        Err(UnlinkError::LastMethod),
        "removing the only provider would lock the account"
    );
}

#[pollster::test]
async fn unlinking_is_allowed_while_another_way_in_remains() {
    let kit = kit();
    seed_user(&kit, "u1", Some("a@example.com"), true).await;
    let first = link(
        &*kit.db,
        &at(),
        &UlidIdGen,
        "u1",
        &incoming(PROVIDER_GOOGLE, "g1", Some("a@example.com"), true),
    )
    .await
    .expect("link");
    link(
        &*kit.db,
        &at(),
        &UlidIdGen,
        "u1",
        &incoming(PROVIDER_APPLE, "a1", Some("a@example.com"), true),
    )
    .await
    .expect("link");

    assert_eq!(
        unlink(&*kit.db, "u1", &first.id).await.expect("query"),
        Ok(())
    );
    assert_eq!(
        identities_by_user(&*kit.db, "u1")
            .await
            .expect("query")
            .len(),
        1
    );
}

/// A password counts as a way in, so the last provider may go.
#[pollster::test]
async fn a_password_lets_the_last_provider_be_unlinked() {
    let kit = kit();
    seed_user(&kit, "u1", Some("a@example.com"), true).await;
    let row = link(
        &*kit.db,
        &at(),
        &UlidIdGen,
        "u1",
        &incoming(PROVIDER_GOOGLE, "g1", Some("a@example.com"), true),
    )
    .await
    .expect("link");
    insert_credential(
        &*kit.db,
        &CredentialRow {
            id: "c1".to_owned(),
            user_id: "u1".to_owned(),
            kind: PROVIDER_PASSWORD.to_owned(),
            passkey_credential_id: None,
            passkey_public_key_cose: None,
            passkey_sign_count: None,
            passkey_aaguid: None,
            passkey_transports: None,
            password_hash: Some(Redacted("argon2-placeholder".to_owned())),
            label: None,
            created_at: iso(),
            last_used_at: None,
            passkey_suspect_at: None,
            failed_attempts: 0,
            failed_window_started_at: None,
            locked_until: None,
        },
    )
    .await
    .expect("credential");

    assert_eq!(
        unlink(&*kit.db, "u1", &row.id).await.expect("query"),
        Ok(())
    );
}

#[pollster::test]
async fn unlinking_someone_elses_identity_is_refused() {
    let kit = kit();
    seed_user(&kit, "u1", Some("a@example.com"), true).await;
    seed_user(&kit, "u2", Some("b@example.com"), true).await;
    let row = link(
        &*kit.db,
        &at(),
        &UlidIdGen,
        "u1",
        &incoming(PROVIDER_GOOGLE, "g1", Some("a@example.com"), true),
    )
    .await
    .expect("link");

    assert_eq!(
        unlink(&*kit.db, "u2", &row.id).await.expect("query"),
        Err(UnlinkError::NotFound)
    );
}
