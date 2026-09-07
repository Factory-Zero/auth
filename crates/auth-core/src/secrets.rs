//! Client-secret cryptography (issue #6). Plaintext secrets exist once,
//! in the create/rotate response; the database stores only argon2id PHC
//! strings. Parameters are the ADR 0100 recommendation (m=19456 KiB,
//! t=2, p=1 — OWASP minimal, measured on a Worker).
//!
//! Verification re-derives the hash with the parameters read back from
//! the stored PHC string and compares digests with the harness
//! [`constant_time_eq`](factory0_core::constant_time_eq) helper, so no
//! secret comparison is timing-sensitive.

use argon2::{Algorithm, Argon2, Params, Version, password_hash::phc::PasswordHash};
use base64ct::{Base64Unpadded as PhcB64, Base64UrlUnpadded, Encoding};
use factory0_core::constant_time_eq;

use crate::store::{CLIENT_CONFIDENTIAL, ClientRow};

/// Random bytes in a generated secret or session value.
pub const SECRET_BYTES: usize = 32;

const M_COST: u32 = 19_456;
const T_COST: u32 = 2;
const P_COST: u32 = 1;
const SALT_BYTES: usize = 16;

/// A generated secret that could not be hashed (OS entropy or argon2
/// failure). The plaintext never leaves the failing call.
#[derive(Debug, thiserror::Error)]
#[error("secret hashing failed: {0}")]
pub struct SecretError(String);

/// 32 random bytes, base64url, no padding: the shape of every client
/// secret this module hands out.
///
/// # Errors
///
/// [`SecretError`] when the OS entropy source fails.
pub fn generate_secret() -> Result<String, SecretError> {
    let mut bytes = [0u8; SECRET_BYTES];
    getrandom::fill(&mut bytes).map_err(|err| SecretError(err.to_string()))?;
    Ok(Base64UrlUnpadded::encode_string(&bytes))
}

/// Hashes a secret as an argon2id PHC string with a fresh random salt.
///
/// # Errors
///
/// [`SecretError`] when the OS entropy source or argon2 fails.
pub fn hash_secret(secret: &str) -> Result<String, SecretError> {
    let mut salt = [0u8; SALT_BYTES];
    getrandom::fill(&mut salt).map_err(|err| SecretError(err.to_string()))?;
    let params = Params::new(M_COST, T_COST, P_COST, Some(SECRET_BYTES))
        .map_err(|err| SecretError(err.to_string()))?;
    let mut out = [0u8; SECRET_BYTES];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(secret.as_bytes(), &salt, &mut out)
        .map_err(|err| SecretError(err.to_string()))?;
    Ok(format!(
        "$argon2id$v={v}$m={m},t={t},p={p}${salt}${hash}",
        v = Version::V0x13 as u32,
        m = M_COST,
        t = T_COST,
        p = P_COST,
        salt = PhcB64::encode_string(&salt),
        hash = PhcB64::encode_string(&out),
    ))
}

/// Verifies a presented secret against one stored PHC string: parses the
/// PHC, re-derives with its own parameters and salt, and compares the
/// digests in constant time. Malformed stored strings and non-argon2id
/// algorithms verify as `false`, never panic.
#[must_use]
pub fn verify_secret(presented: &str, stored_phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored_phc) else {
        return false;
    };
    if parsed.algorithm.as_str() != Algorithm::Argon2id.as_str() {
        return false;
    }
    let (Some(salt), Some(expected)) = (parsed.salt, parsed.hash) else {
        return false;
    };
    let Ok(params) = Params::try_from(&parsed) else {
        return false;
    };
    let mut derived = vec![0u8; expected.as_ref().len()];
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into(presented.as_bytes(), salt.as_ref(), &mut derived)
        .is_ok()
        && constant_time_eq(&derived, expected.as_ref())
}

/// Verifies a presented secret against a client, honoring the rotation
/// overlap: the current secret always verifies; the previous one
/// verifies only while `previous_hash_expires_at` is still in the
/// future (`now`, RFC 3339, from the `Clock` port). Public clients hold
/// a hash of a discarded secret, so nothing ever verifies — they have no
/// secret by construction.
#[must_use]
pub fn verify_client_secret(client: &ClientRow, presented: &str, now: &str) -> bool {
    if verify_secret(presented, &client.secret_hash.0) {
        return true;
    }
    match (
        client.previous_secret_hash.as_ref(),
        &client.previous_hash_expires_at,
    ) {
        (Some(previous), Some(expires_at)) if expires_at.as_str() > now => {
            verify_secret(presented, &previous.0)
        }
        _ => false,
    }
}

/// Whether a client may take part in any runtime flow. Disabled clients
/// fail every flow with one stable problem type (issue #6).
///
/// # Errors
///
/// The `auth/client-disabled` problem when the client is disabled.
pub fn ensure_client_usable(client: &ClientRow) -> Result<(), factory0_core::Problem> {
    if client.status != crate::store::STATUS_ACTIVE {
        return Err(factory0_core::Problem::new(&CLIENT_DISABLED));
    }
    Ok(())
}

/// Stable problem for a disabled client, refused at `/authorize` and
/// `/token` (wired there by issues #9 and #10).
pub const CLIENT_DISABLED: factory0_core::ProblemDef = factory0_core::ProblemDef {
    slug: "auth/client-disabled",
    status: axum::http::StatusCode::FORBIDDEN,
    title: "Client is disabled",
    description: "A disabled client is refused by every flow",
};

/// A confidential client authenticates with a secret; a public client
/// (browser or native app) has none and relies on PKCE.
#[must_use]
pub fn kind_allows_secret(kind: &str) -> bool {
    kind == CLIENT_CONFIDENTIAL
}

// ---------------------------------------------------------------------------
// Passwords (issues #19, #20)

/// Hashes a password as an argon2id PHC string.
///
/// The same parameters and the same code path as a client secret, on
/// purpose: ADR 0100 measured one set of parameters on Workers and there
/// is no reason a password should get weaker ones. Wrapping rather than
/// duplicating means the ADR's numbers live in exactly one place.
///
/// # Errors
///
/// [`SecretError`] when the OS entropy source or argon2 fails.
pub fn hash_password(password: &str) -> Result<String, SecretError> {
    hash_secret(password)
}

/// Verifies a password against a stored PHC string, in constant time.
///
/// `false` for a malformed or non-argon2id stored value, which is what
/// makes it safe to call with a dummy hash when no credential exists.
#[must_use]
pub fn verify_password(presented: &str, stored_phc: &str) -> bool {
    verify_secret(presented, stored_phc)
}

/// Whether a stored hash was written with parameters we no longer use.
///
/// Login is the only moment the plaintext is available, so it is the only
/// moment a hash can be upgraded. A stored hash that cannot be parsed says
/// `false`: it will fail verification anyway, and rehashing on the strength
/// of an unreadable value would be guessing.
#[must_use]
pub fn password_needs_rehash(stored_phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored_phc) else {
        return false;
    };
    if parsed.algorithm.as_str() != Algorithm::Argon2id.as_str() {
        return true;
    }
    let Ok(params) = Params::try_from(&parsed) else {
        return true;
    };
    params.m_cost() != M_COST || params.t_cost() != T_COST || params.p_cost() != P_COST
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{CLIENT_PUBLIC, Redacted};

    // Never a real secret: fixed test material, obviously fake.
    const SECRET: &str = "test-client-secret-0123456789abcdef";
    const OTHER: &str = "totally-different-secret";

    fn client_with_hashes(
        current: &str,
        previous: Option<&str>,
        expires: Option<&str>,
    ) -> ClientRow {
        ClientRow {
            id: "app1".to_owned(),
            name: "App".to_owned(),
            secret_hash: Redacted(current.to_owned()),
            previous_secret_hash: previous.map(|phc| Redacted(phc.to_owned())),
            previous_hash_expires_at: expires.map(str::to_owned),
            kind: CLIENT_CONFIDENTIAL.to_owned(),
            status: crate::store::STATUS_ACTIVE.to_owned(),
            created_at: "2027-01-15T06:40:00Z".to_owned(),
        }
    }

    #[test]
    fn hash_verifies_and_mismatches_reject() {
        let phc = hash_secret(SECRET).expect("hash");
        assert!(phc.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(verify_secret(SECRET, &phc));
        assert!(!verify_secret(OTHER, &phc));
    }

    #[test]
    fn salts_differ_so_identical_secrets_hash_differently() {
        let a = hash_secret(SECRET).expect("hash a");
        let b = hash_secret(SECRET).expect("hash b");
        assert_ne!(a, b);
        assert!(verify_secret(SECRET, &a) && verify_secret(SECRET, &b));
    }

    #[test]
    fn malformed_stored_strings_verify_false() {
        assert!(!verify_secret(SECRET, "not-a-phc-string"));
        assert!(!verify_secret(
            SECRET,
            "$argon2i$v=19$m=8,t=1,p=1$c2FsdA$aGFzaA"
        ));
        assert!(!verify_secret(SECRET, ""));
    }

    #[test]
    fn rotation_overlap_honors_the_expiry_instant() {
        let old = hash_secret("old-secret-abcdef").expect("old hash");
        let new = hash_secret("new-secret-abcdef").expect("new hash");
        let expires = "2027-01-16T06:40:00Z";
        let client = client_with_hashes(&new, Some(&old), Some(expires));

        assert!(verify_client_secret(
            &client,
            "new-secret-abcdef",
            "2027-01-15T07:00:00Z"
        ));
        assert!(verify_client_secret(
            &client,
            "old-secret-abcdef",
            "2027-01-15T07:00:00Z"
        ));
        assert!(
            !verify_client_secret(&client, "old-secret-abcdef", "2027-01-16T06:40:00Z"),
            "the overlap ends at the instant itself"
        );
        assert!(verify_client_secret(
            &client,
            "new-secret-abcdef",
            "2027-01-16T06:40:00Z"
        ));
        assert!(!verify_client_secret(
            &client,
            "unrelated",
            "2027-01-15T07:00:00Z"
        ));
    }

    #[test]
    fn expired_overlap_only_ever_held_the_previous_hash() {
        let old = hash_secret("old-secret-abcdef").expect("old hash");
        let client = client_with_hashes(&old, None, None);
        assert!(verify_client_secret(
            &client,
            "old-secret-abcdef",
            "2099-01-01T00:00:00Z"
        ));
    }

    #[test]
    fn public_clients_hold_only_discarded_secrets() {
        let discarded =
            hash_secret(&generate_secret().expect("generate")).expect("hash of a discarded secret");
        let mut client = client_with_hashes(&discarded, None, None);
        client.kind = CLIENT_PUBLIC.to_owned();
        assert!(
            !verify_client_secret(&client, "anything-at-all", "2027-01-15T07:00:00Z"),
            "nobody can know a discarded secret's preimage"
        );
    }

    #[test]
    fn disabled_clients_fail_the_usability_check_with_the_stable_problem() {
        let phc = hash_secret(SECRET).expect("hash");
        let mut client = client_with_hashes(&phc, None, None);
        assert!(ensure_client_usable(&client).is_ok());
        client.status = crate::store::STATUS_DISABLED.to_owned();
        let problem = ensure_client_usable(&client).expect_err("disabled");
        assert_eq!(problem.slug, "auth/client-disabled");
        assert_eq!(problem.status, axum::http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn generated_secrets_are_43_chars_of_base64url() {
        let secret = generate_secret().expect("generate");
        assert_eq!(secret.len(), 43);
        assert!(!secret.contains(['+', '/', '=']));
        assert_ne!(secret, generate_secret().expect("second"));
        assert!(kind_allows_secret(CLIENT_CONFIDENTIAL));
        assert!(!kind_allows_secret(CLIENT_PUBLIC));
    }
}
