//! Issue #5 acceptance, store half: live uniqueness enforcement
//! (`identities` per `(provider, subject)`, passkey credential ids), the
//! single-use consume guard (one winner), the purge of expired
//! `single_use_tokens` and `sessions`, and `Debug` redaction on every
//! hash column.

use factory0_adapter_sqlite::SqliteDatabase;
use factory0_auth_core::{
    AuthCore, Bytes, ClientRedirectUriRow, ClientRow, CredentialRow, IdentityRow, Redacted,
    SessionRow, SingleUseTokenRow, UserRow,
};
use factory0_core::{Module, Ports, UlidIdGen};
use factory0_testing::TestHarness;
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;

/// The `TestHarness` fixed clock epoch: 2027-01-15T06:40:00Z.
const NOW_SECS: i64 = 1_800_000_000;
const DAY: i64 = 86_400;

fn iso(secs: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(secs)
        .expect("epoch in range")
        .replace_nanosecond(0)
        .expect("truncation stays in range")
        .format(&Rfc3339)
        .expect("rfc3339 formats")
}

fn db() -> SqliteDatabase {
    let db = SqliteDatabase::in_memory().expect("in-memory database");
    db.apply_migrations("auth-core", AuthCore::new().migrations().sqlite)
        .expect("migrations apply");
    db
}

fn user(id: &str) -> UserRow {
    UserRow {
        id: id.to_owned(),
        display_name: Some(format!("User {id}")),
        primary_email: Some(format!("{id}@example.com")),
        primary_email_verified: true,
        status: "active".to_owned(),
        created_at: iso(NOW_SECS),
        updated_at: iso(NOW_SECS),
    }
}

fn identity(id: &str, user_id: &str, provider: &str, subject: &str) -> IdentityRow {
    IdentityRow {
        id: id.to_owned(),
        user_id: user_id.to_owned(),
        provider: provider.to_owned(),
        provider_subject: subject.to_owned(),
        email: Some(format!("{user_id}@example.com")),
        email_verified: true,
        name_at_link: None,
        created_at: iso(NOW_SECS),
        last_login_at: None,
    }
}

fn passkey(id: &str, user_id: &str, credential_id: &[u8]) -> CredentialRow {
    CredentialRow {
        id: id.to_owned(),
        user_id: user_id.to_owned(),
        kind: "passkey".to_owned(),
        passkey_credential_id: Some(Bytes(credential_id.to_vec())),
        passkey_public_key_cose: Some(Bytes(vec![0xA5, 0x01, 0x02])),
        passkey_sign_count: Some(1),
        passkey_aaguid: Some(Bytes(vec![0; 16])),
        passkey_transports: Some("internal".to_owned()),
        password_hash: None,
        label: Some("Yubikey".to_owned()),
        created_at: iso(NOW_SECS),
        last_used_at: None,
        passkey_suspect_at: None,
        failed_attempts: 0,
        failed_window_started_at: None,
        locked_until: None,
    }
}

fn password_credential(id: &str, user_id: &str, phc: &str) -> CredentialRow {
    CredentialRow {
        id: id.to_owned(),
        user_id: user_id.to_owned(),
        kind: "password".to_owned(),
        passkey_credential_id: None,
        passkey_public_key_cose: None,
        passkey_sign_count: None,
        passkey_aaguid: None,
        passkey_transports: None,
        password_hash: Some(Redacted(phc.to_owned())),
        label: None,
        created_at: iso(NOW_SECS),
        last_used_at: None,
        passkey_suspect_at: None,
        failed_attempts: 0,
        failed_window_started_at: None,
        locked_until: None,
    }
}

fn session(id: &str, user_id: &str, hash: &[u8], expires_in_secs: i64) -> SessionRow {
    SessionRow {
        id: id.to_owned(),
        user_id: user_id.to_owned(),
        token_hash: Redacted(hash.to_vec()),
        created_at: iso(NOW_SECS),
        last_seen_at: iso(NOW_SECS),
        expires_at: iso(NOW_SECS + expires_in_secs),
        revoked_at: None,
        ip_hash: Some(Redacted("9f86d081884c7d659a2feaa0c55ad015".to_owned())),
        ua_family: Some("chrome".to_owned()),
        amr: None,
    }
}

fn token(id: &str, kind: &str, hash: &[u8], expires_in_secs: i64) -> SingleUseTokenRow {
    SingleUseTokenRow {
        id: id.to_owned(),
        kind: kind.to_owned(),
        token_hash: Redacted(hash.to_vec()),
        user_id: Some("u1".to_owned()),
        client_id: None,
        payload: Some(r#"{"nonce":"n1"}"#.to_owned()),
        expires_at: iso(NOW_SECS + expires_in_secs),
        consumed_at: None,
    }
}

#[pollster::test]
async fn user_lookups_roundtrip() {
    let db = db();
    factory0_auth_core::insert_user(&db, &user("u1"))
        .await
        .expect("insert user");

    let by_id = factory0_auth_core::user_by_id(&db, "u1")
        .await
        .expect("select");
    let found = by_id.expect("user found");
    assert_eq!(found.primary_email.as_deref(), Some("u1@example.com"));
    assert!(found.primary_email_verified);
    assert_eq!(found.status, "active");

    let by_email = factory0_auth_core::user_by_primary_email(&db, "u1@example.com")
        .await
        .expect("select");
    assert_eq!(by_email.expect("found by email").id, "u1");

    assert!(
        factory0_auth_core::user_by_id(&db, "nope")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        factory0_auth_core::user_by_primary_email(&db, "none@example.com")
            .await
            .unwrap()
            .is_none()
    );
}

#[pollster::test]
async fn identity_is_unique_per_provider_subject() {
    let db = db();
    factory0_auth_core::insert_user(&db, &user("u1"))
        .await
        .unwrap();
    factory0_auth_core::insert_user(&db, &user("u2"))
        .await
        .unwrap();

    factory0_auth_core::insert_identity(&db, &identity("i1", "u1", "google", "g-sub-1"))
        .await
        .expect("first identity");

    let duplicate =
        factory0_auth_core::insert_identity(&db, &identity("i2", "u2", "google", "g-sub-1")).await;
    assert!(duplicate.is_err(), "one row per (provider, subject)");

    factory0_auth_core::insert_identity(&db, &identity("i3", "u2", "password", "g-sub-1"))
        .await
        .expect("same subject under another provider is a different identity");

    let login = factory0_auth_core::identity_by_provider_subject(&db, "google", "g-sub-1")
        .await
        .expect("select")
        .expect("found");
    assert_eq!(login.user_id, "u1");

    let touched = factory0_auth_core::touch_identity_login(&db, "i1", &iso(NOW_SECS + 60))
        .await
        .expect("touch");
    assert_eq!(touched, 1);
    let linked = factory0_auth_core::identities_by_user(&db, "u1")
        .await
        .unwrap();
    assert_eq!(linked.len(), 1);
    assert_eq!(
        linked[0].last_login_at.as_deref(),
        Some(iso(NOW_SECS + 60).as_str())
    );
}

#[pollster::test]
async fn passkey_credential_ids_are_unique_and_passwords_coexist() {
    let db = db();
    factory0_auth_core::insert_user(&db, &user("u1"))
        .await
        .unwrap();

    factory0_auth_core::insert_credential(&db, &passkey("c1", "u1", b"cred-id-1"))
        .await
        .expect("first passkey");
    let duplicate =
        factory0_auth_core::insert_credential(&db, &passkey("c2", "u1", b"cred-id-1")).await;
    assert!(duplicate.is_err(), "unique passkey credential ids");

    factory0_auth_core::insert_credential(
        &db,
        &password_credential("c3", "u1", "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA"),
    )
    .await
    .expect("password credential");
    factory0_auth_core::insert_credential(
        &db,
        &password_credential("c4", "u1", "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$b3RoZXI"),
    )
    .await
    .expect("second password credential: NULL passkey ids do not collide");

    let found = factory0_auth_core::passkey_by_credential_id(&db, b"cred-id-1")
        .await
        .expect("select")
        .expect("passkey found");
    assert_eq!(found.user_id, "u1");
    assert_eq!(found.passkey_sign_count, Some(1));

    assert_eq!(
        factory0_auth_core::update_passkey_sign_count(&db, "c1", 2, &iso(NOW_SECS + 30))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        factory0_auth_core::update_passkey_sign_count(&db, "c3", 2, &iso(NOW_SECS + 30))
            .await
            .unwrap(),
        0,
        "password credentials have no sign count"
    );
    assert_eq!(
        factory0_auth_core::touch_credential_used(&db, "c3", &iso(NOW_SECS + 30))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        factory0_auth_core::credentials_by_user(&db, "u1")
            .await
            .unwrap()
            .len(),
        3
    );
}

#[pollster::test]
async fn session_lookup_touch_and_revocation() {
    let db = db();
    factory0_auth_core::insert_user(&db, &user("u1"))
        .await
        .unwrap();
    factory0_auth_core::insert_session(&db, &session("s1", "u1", b"hash-of-cookie-1", DAY))
        .await
        .expect("insert session");

    let found = factory0_auth_core::session_by_token_hash(&db, b"hash-of-cookie-1")
        .await
        .expect("select")
        .expect("session found");
    assert_eq!(found.user_id, "u1");
    assert!(found.revoked_at.is_none());

    assert_eq!(
        factory0_auth_core::touch_session_seen(&db, "s1", &iso(NOW_SECS + 99))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        factory0_auth_core::revoke_session(&db, "s1", &iso(NOW_SECS + 100))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        factory0_auth_core::revoke_session(&db, "s1", &iso(NOW_SECS + 200))
            .await
            .unwrap(),
        0,
        "revocation is guarded"
    );
    assert_eq!(
        factory0_auth_core::session_by_token_hash(&db, b"hash-of-cookie-1")
            .await
            .unwrap()
            .expect("still readable")
            .revoked_at
            .as_deref(),
        Some(iso(NOW_SECS + 100).as_str())
    );
}

#[pollster::test]
async fn a_single_use_token_is_consumed_exactly_once() {
    let db = db();
    factory0_auth_core::insert_single_use_token(
        &db,
        &token("t1", "magic_link", b"hash-of-token-1", DAY),
    )
    .await
    .expect("insert");
    factory0_auth_core::insert_single_use_token(
        &db,
        &token("t2", "magic_link", b"hash-of-token-2", -1),
    )
    .await
    .expect("insert already-expired");

    let found = factory0_auth_core::single_use_token_by_hash(&db, b"hash-of-token-1")
        .await
        .unwrap()
        .expect("found by hash");
    assert_eq!(found.payload.as_deref(), Some(r#"{"nonce":"n1"}"#));

    let now = iso(NOW_SECS + 10);
    let won = factory0_auth_core::consume_single_use_token(&db, "t1", &now)
        .await
        .expect("consume")
        .expect("first consume wins");
    assert_eq!(won.consumed_at.as_deref(), Some(now.as_str()));

    let replay = factory0_auth_core::consume_single_use_token(&db, "t1", &now)
        .await
        .expect("consume");
    assert!(replay.is_none(), "the second consume loses");

    let expired = factory0_auth_core::consume_single_use_token(&db, "t2", &now)
        .await
        .expect("consume");
    assert!(expired.is_none(), "expired tokens never win");
}

#[pollster::test]
async fn purge_removes_only_expired_rows() {
    let db = db();
    factory0_auth_core::insert_user(&db, &user("u1"))
        .await
        .unwrap();
    factory0_auth_core::insert_session(&db, &session("s-old", "u1", b"h1", -1))
        .await
        .unwrap();
    factory0_auth_core::insert_session(&db, &session("s-live", "u1", b"h2", DAY))
        .await
        .unwrap();
    factory0_auth_core::insert_single_use_token(&db, &token("t-old", "magic_link", b"h3", -1))
        .await
        .unwrap();
    factory0_auth_core::insert_single_use_token(&db, &token("t-live", "magic_link", b"h4", DAY))
        .await
        .unwrap();

    let now = iso(NOW_SECS);
    assert_eq!(
        factory0_auth_core::purge_expired_single_use_tokens(&db, &now)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        factory0_auth_core::purge_expired_sessions(&db, &now)
            .await
            .unwrap(),
        1
    );

    assert!(
        factory0_auth_core::session_by_token_hash(&db, b"h2")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        factory0_auth_core::session_by_token_hash(&db, b"h1")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        factory0_auth_core::single_use_token_by_hash(&db, b"h4")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        factory0_auth_core::single_use_token_by_hash(&db, b"h3")
            .await
            .unwrap()
            .is_none()
    );
}

#[pollster::test]
async fn scheduled_purge_runs_against_the_clock_port() {
    let kit = TestHarness::new(vec![Box::new(AuthCore::new())]);
    let db = kit.db.as_ref();
    factory0_auth_core::insert_user(db, &user("u1"))
        .await
        .unwrap();
    factory0_auth_core::insert_session(db, &session("s-old", "u1", b"h1", -1))
        .await
        .unwrap();
    factory0_auth_core::insert_session(db, &session("s-live", "u1", b"h2", DAY))
        .await
        .unwrap();
    factory0_auth_core::insert_single_use_token(db, &token("t-old", "magic_link", b"h3", -1))
        .await
        .unwrap();

    let mut ports = Ports::empty();
    ports.db = Some(kit.db.clone());
    ports.clock = Some(Arc::new(kit.clock.clone()));
    ports.id_gen = Some(Arc::new(UlidIdGen));

    let module = kit.modules[0].clone();
    let ctx = kit.harness.module_context(module.as_ref(), &ports);
    module
        .scheduled(&ctx, "0 3 * * *")
        .await
        .expect("scheduled run");

    assert!(
        factory0_auth_core::session_by_token_hash(db, b"h1")
            .await
            .unwrap()
            .is_none(),
        "expired session purged"
    );
    assert!(
        factory0_auth_core::session_by_token_hash(db, b"h2")
            .await
            .unwrap()
            .is_some(),
        "live session kept"
    );
    assert!(
        factory0_auth_core::single_use_token_by_hash(db, b"h3")
            .await
            .unwrap()
            .is_none(),
        "expired token purged"
    );
}

#[pollster::test]
async fn client_and_redirect_uri_lookups() {
    let db = db();
    factory0_auth_core::insert_client(
        &db,
        &ClientRow {
            id: "app1".to_owned(),
            name: "Undercover Rockstars".to_owned(),
            secret_hash: Redacted("hash-of-client-secret".to_owned()),
            previous_secret_hash: None,
            previous_hash_expires_at: None,
            kind: "confidential".to_owned(),
            status: "active".to_owned(),
            created_at: iso(NOW_SECS),
        },
    )
    .await
    .expect("insert client");
    factory0_auth_core::insert_redirect_uri(
        &db,
        &ClientRedirectUriRow {
            client_id: "app1".to_owned(),
            uri: "https://undercoverrockstars.com/auth/callback".to_owned(),
        },
    )
    .await
    .expect("insert uri");

    let client = factory0_auth_core::client_by_id(&db, "app1")
        .await
        .unwrap()
        .expect("client found");
    assert_eq!(client.name, "Undercover Rockstars");
    assert_eq!(client.kind, "confidential");
    assert!(client.previous_secret_hash.is_none());

    let uris = factory0_auth_core::redirect_uris_for_client(&db, "app1")
        .await
        .unwrap();
    assert_eq!(uris.len(), 1);
    assert_eq!(uris[0].uri, "https://undercoverrockstars.com/auth/callback");

    let duplicate = factory0_auth_core::insert_redirect_uri(
        &db,
        &ClientRedirectUriRow {
            client_id: "app1".to_owned(),
            uri: "https://undercoverrockstars.com/auth/callback".to_owned(),
        },
    )
    .await;
    assert!(duplicate.is_err(), "exact URIs only, no duplicates");
}

#[pollster::test]
async fn client_rotation_status_and_uri_replacement() {
    let db = db();
    factory0_auth_core::insert_client(
        &db,
        &ClientRow {
            id: "app1".to_owned(),
            name: "Kontinuum".to_owned(),
            secret_hash: Redacted("old-hash".to_owned()),
            previous_secret_hash: None,
            previous_hash_expires_at: None,
            kind: "confidential".to_owned(),
            status: "active".to_owned(),
            created_at: iso(NOW_SECS),
        },
    )
    .await
    .expect("insert client");

    assert_eq!(
        factory0_auth_core::rotate_client_secret(&db, "app1", "new-hash", &iso(NOW_SECS + 3600))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        factory0_auth_core::rotate_client_secret(&db, "ghost", "x", &iso(NOW_SECS)).await,
        Ok(0),
        "unknown ids affect nothing"
    );

    let rotated = factory0_auth_core::client_by_id(&db, "app1")
        .await
        .unwrap()
        .expect("client");
    assert_eq!(rotated.secret_hash.0, "new-hash");
    assert_eq!(
        rotated.previous_secret_hash.as_ref().map(|h| h.0.clone()),
        Some("old-hash".to_owned()),
        "the current hash slides into the previous slot"
    );
    assert_eq!(
        rotated.previous_hash_expires_at.as_deref(),
        Some(iso(NOW_SECS + 3600).as_str())
    );

    assert_eq!(
        factory0_auth_core::update_client_status(&db, "app1", "disabled")
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        factory0_auth_core::update_client_name(&db, "app1", "Kontinuum Audio")
            .await
            .unwrap(),
        1
    );
    let listed = factory0_auth_core::list_clients(&db).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].status, "disabled");
    assert_eq!(listed[0].name, "Kontinuum Audio");

    factory0_auth_core::replace_redirect_uris(
        &db,
        "app1",
        &[
            "https://kontinuum.audio/cb".to_owned(),
            "https://kontinuum.audio/cb2".to_owned(),
        ],
    )
    .await
    .expect("replace");
    let uris = factory0_auth_core::redirect_uris_for_client(&db, "app1")
        .await
        .unwrap()
        .iter()
        .map(|row| row.uri.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        uris,
        vec![
            "https://kontinuum.audio/cb".to_owned(),
            "https://kontinuum.audio/cb2".to_owned()
        ],
        "replacement is wholesale"
    );

    factory0_auth_core::replace_redirect_uris(&db, "app1", &["https://kontinuum.audio/cb".into()])
        .await
        .expect("replace again");
    let after = factory0_auth_core::redirect_uris_for_client(&db, "app1")
        .await
        .unwrap();
    assert_eq!(after.len(), 1, "the stale URI is gone");
}

#[test]
fn debug_never_prints_a_hash_column() {
    let secret_bytes: Vec<u8> = (0xB0..=0xBF).collect();
    let session = session("s1", "u1", &secret_bytes, DAY);
    let credential = password_credential("c1", "u1", "PHC-SECRET-PAYLOAD-DO-NOT-PRINT");
    let client = ClientRow {
        id: "app1".to_owned(),
        name: "App".to_owned(),
        secret_hash: Redacted("CLIENT-SECRET-HASH-DO-NOT-PRINT".to_owned()),
        previous_secret_hash: Some(Redacted("PREVIOUS-SECRET-HASH-DO-NOT-PRINT".to_owned())),
        previous_hash_expires_at: Some(iso(NOW_SECS + 3600)),
        kind: "confidential".to_owned(),
        status: "active".to_owned(),
        created_at: iso(NOW_SECS),
    };
    let token = token("t1", "webauthn_challenge", &secret_bytes, DAY);

    for debug in [
        format!("{session:?}"),
        format!("{credential:?}"),
        format!("{client:?}"),
        format!("{token:?}"),
    ] {
        assert!(
            debug.contains("Redacted([redacted])"),
            "marker present: {debug}"
        );
        assert!(!debug.contains("176, 177"), "no hash bytes: {debug}");
        assert!(!debug.contains("PHC-SECRET"), "no password hash: {debug}");
        assert!(
            !debug.contains("CLIENT-SECRET"),
            "no client secret hash: {debug}"
        );
        assert!(
            !debug.contains("PREVIOUS-SECRET"),
            "no previous secret hash: {debug}"
        );
    }

    // Values stay readable by code — only Debug is redacted.
    assert_eq!(client.secret_hash.0, "CLIENT-SECRET-HASH-DO-NOT-PRINT");
    assert_eq!(session.token_hash.0, secret_bytes);

    // Public passkey blobs print their length, not their bytes.
    let passkey = passkey("c9", "u1", &[0xDE, 0xAD, 0xBE, 0xEF]);
    let debug = format!("{passkey:?}");
    assert!(debug.contains("Bytes(4 bytes)"), "{debug}");
    assert!(!debug.contains("222, 173"), "{debug}");
}
