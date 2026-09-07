//! Meta's `signed_request` (issue #18).
//!
//! The data deletion callback is the one endpoint here that is not started
//! by a person in a browser: Meta posts to it directly, and the only thing
//! establishing that a request came from Meta is an HMAC over the payload
//! with the app secret. So this is the module's most exposed surface and
//! the verification comes before anything is read.
//!
//! The format is `<base64url signature>.<base64url payload>`, and the
//! signature is HMAC-SHA256 over the **payload's base64url text**, not
//! over the decoded bytes. Getting that wrong fails every request in a way
//! that looks like a wrong secret.

use base64ct::{Base64UrlUnpadded, Encoding as _};
use factory0_core::constant_time_eq;
use hmac::{KeyInit, Mac, SimpleHmac};
use serde::Deserialize;
use sha2::Sha256;

/// The only algorithm accepted.
///
/// Checked rather than trusted. `algorithm` arrives inside the payload,
/// which is to say from the caller, and a verifier that switched on it
/// would let a caller nominate one — the JWT `alg: none` mistake wearing
/// Facebook's clothes.
const REQUIRED_ALGORITHM: &str = "HMAC-SHA256";

/// A `signed_request` longer than this is not one. Meta's payload is a
/// handful of fields; the cap is what stops an unauthenticated caller
/// making us base64-decode something enormous before the HMAC even runs.
const MAX_LEN: usize = 8 * 1024;

/// What a verified payload carries. Meta documents more fields; these are
/// the ones this service acts on.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SignedRequest {
    /// Named `algorithm` by Meta. Verified, then ignored.
    pub algorithm: String,
    /// The app-scoped user id: the same value stored as the identity's
    /// `provider_subject`.
    pub user_id: String,
    /// Unix seconds. Meta sends it; nothing here rejects on age, and the
    /// reason is written down in [`verify`].
    #[serde(default)]
    pub issued_at: Option<i64>,
}

/// Why a `signed_request` was refused.
///
/// One variant reaches the caller as one status; the distinction exists
/// for the log, because an operator debugging a callback needs to know
/// whether the secret is wrong or the body is.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SignedRequestError {
    #[error("the signed_request is not two base64url parts")]
    Malformed,
    #[error("the signed_request is longer than anything Meta sends")]
    TooLong,
    #[error("the signature does not match")]
    BadSignature,
    #[error("the payload is not the json Meta sends")]
    BadPayload,
    #[error("the payload nominates an algorithm we do not accept")]
    BadAlgorithm,
}

/// Verifies a `signed_request` and returns what it says.
///
/// The order matters and is the point of this function: length, shape,
/// **signature**, then payload. Nothing about the payload is believed —
/// not the algorithm, not the user id — until the HMAC has matched, and
/// nothing is acted on at all until this returns `Ok`.
///
/// # On not checking `issued_at`
///
/// A replayed deletion request asks us to delete data we have already
/// deleted, which is what the job's own idempotence handles: the second
/// run finds no identity and records `nothing_to_do`. Rejecting on age
/// would instead mean a request Meta retried after an outage is refused,
/// which is the failure that gets an app suspended. The timestamp is
/// parsed and logged, not enforced.
///
/// # Errors
///
/// Any of [`SignedRequestError`]. The caller answers all of them the same
/// way and logs which.
pub(crate) fn verify(raw: &str, app_secret: &str) -> Result<SignedRequest, SignedRequestError> {
    if raw.len() > MAX_LEN {
        return Err(SignedRequestError::TooLong);
    }
    let (signature_b64, payload_b64) = raw.split_once('.').ok_or(SignedRequestError::Malformed)?;
    if signature_b64.is_empty() || payload_b64.is_empty() {
        return Err(SignedRequestError::Malformed);
    }

    // Meta sends base64url without padding, but has been known to send it
    // with. Accepting both costs nothing and refusing one costs a day.
    let signature = decode_b64url(signature_b64).ok_or(SignedRequestError::Malformed)?;

    let mut mac = <SimpleHmac<Sha256> as KeyInit>::new_from_slice(app_secret.as_bytes())
        .map_err(|_| SignedRequestError::BadSignature)?;
    // Over the base64url TEXT of the payload, not its decoded bytes.
    mac.update(payload_b64.as_bytes());
    let expected = mac.finalize().into_bytes();

    // Constant time: a byte-at-a-time compare here leaks the signature one
    // byte per request, and this endpoint is unauthenticated by definition.
    if !constant_time_eq(&signature, &expected) {
        return Err(SignedRequestError::BadSignature);
    }

    let payload = decode_b64url(payload_b64).ok_or(SignedRequestError::Malformed)?;
    let parsed: SignedRequest =
        serde_json::from_slice(&payload).map_err(|_| SignedRequestError::BadPayload)?;

    if parsed.algorithm != REQUIRED_ALGORITHM {
        return Err(SignedRequestError::BadAlgorithm);
    }
    if parsed.user_id.trim().is_empty() {
        return Err(SignedRequestError::BadPayload);
    }
    Ok(parsed)
}

/// base64url with or without padding.
fn decode_b64url(value: &str) -> Option<Vec<u8>> {
    if let Ok(bytes) = Base64UrlUnpadded::decode_vec(value) {
        return Some(bytes);
    }
    let trimmed = value.trim_end_matches('=');
    Base64UrlUnpadded::decode_vec(trimmed).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SECRET: &str = "the-app-secret";

    /// Builds a `signed_request` the way Meta does.
    fn sign(payload: &serde_json::Value, secret: &str) -> String {
        let payload_b64 =
            Base64UrlUnpadded::encode_string(&serde_json::to_vec(payload).expect("json"));
        let mut mac = <SimpleHmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes())
            .expect("any key length");
        mac.update(payload_b64.as_bytes());
        let signature = Base64UrlUnpadded::encode_string(&mac.finalize().into_bytes());
        format!("{signature}.{payload_b64}")
    }

    fn valid_payload() -> serde_json::Value {
        json!({
            "algorithm": "HMAC-SHA256",
            "issued_at": 1_788_775_200,
            "user_id": "meta-subject-1",
        })
    }

    #[test]
    fn a_request_meta_signed_verifies() {
        let raw = sign(&valid_payload(), SECRET);
        let parsed = verify(&raw, SECRET).expect("verifies");
        assert_eq!(parsed.user_id, "meta-subject-1");
        assert_eq!(parsed.algorithm, "HMAC-SHA256");
        assert_eq!(parsed.issued_at, Some(1_788_775_200));
    }

    #[test]
    fn the_signature_is_over_the_base64_text_not_the_decoded_bytes() {
        // The mistake that fails every request and looks like a wrong
        // secret. This asserts the convention rather than the code path.
        let payload = valid_payload();
        let payload_b64 =
            Base64UrlUnpadded::encode_string(&serde_json::to_vec(&payload).expect("json"));

        let mut over_bytes =
            <SimpleHmac<Sha256> as KeyInit>::new_from_slice(SECRET.as_bytes()).expect("key");
        over_bytes.update(&serde_json::to_vec(&payload).expect("json"));
        let wrong = Base64UrlUnpadded::encode_string(&over_bytes.finalize().into_bytes());

        assert_eq!(
            verify(&format!("{wrong}.{payload_b64}"), SECRET).unwrap_err(),
            SignedRequestError::BadSignature,
            "a signature over the decoded bytes must not verify"
        );
    }

    #[test]
    fn a_tampered_payload_is_refused() {
        let raw = sign(&valid_payload(), SECRET);
        let (signature, payload) = raw.split_once('.').expect("two parts");

        // The whole point: swap the user id, keep the signature.
        let hostile = Base64UrlUnpadded::encode_string(
            &serde_json::to_vec(&json!({
                "algorithm": "HMAC-SHA256",
                "user_id": "somebody-elses-subject",
            }))
            .expect("json"),
        );
        assert_eq!(
            verify(&format!("{signature}.{hostile}"), SECRET).unwrap_err(),
            SignedRequestError::BadSignature
        );

        // And a flipped bit in the payload we did sign.
        let mut flipped = payload.to_owned();
        flipped.push('x');
        assert_eq!(
            verify(&format!("{signature}.{flipped}"), SECRET).unwrap_err(),
            SignedRequestError::BadSignature
        );
    }

    #[test]
    fn another_apps_secret_does_not_verify() {
        let raw = sign(&valid_payload(), "a-different-app-secret");
        assert_eq!(
            verify(&raw, SECRET).unwrap_err(),
            SignedRequestError::BadSignature
        );
    }

    #[test]
    fn a_nominated_algorithm_is_refused_rather_than_believed() {
        // `algorithm` comes from the caller. A verifier that switched on
        // it would let the caller pick — the `alg: none` mistake in
        // Facebook's clothes. Note this payload is *correctly signed*:
        // the refusal is the algorithm check, not the HMAC.
        for algorithm in ["none", "HMAC-SHA1", "", "hmac-sha256"] {
            let raw = sign(
                &json!({ "algorithm": algorithm, "user_id": "meta-subject-1" }),
                SECRET,
            );
            assert_eq!(
                verify(&raw, SECRET).unwrap_err(),
                SignedRequestError::BadAlgorithm,
                "{algorithm:?} was accepted"
            );
        }
    }

    #[test]
    fn a_payload_without_a_user_id_is_not_actionable() {
        for payload in [
            json!({ "algorithm": "HMAC-SHA256" }),
            json!({ "algorithm": "HMAC-SHA256", "user_id": "" }),
            json!({ "algorithm": "HMAC-SHA256", "user_id": "   " }),
        ] {
            let raw = sign(&payload, SECRET);
            assert_eq!(
                verify(&raw, SECRET).unwrap_err(),
                SignedRequestError::BadPayload,
                "{payload} was accepted"
            );
        }
    }

    #[test]
    fn rubbish_where_a_signed_request_should_be_is_refused() {
        for bad in ["", ".", "no-dot", "a.", ".b", "!!!.###"] {
            assert!(verify(bad, SECRET).is_err(), "{bad:?} was accepted");
        }
        // Never a panic, whatever the bytes.
        assert!(verify("\u{0}.\u{0}", SECRET).is_err());
    }

    #[test]
    fn an_enormous_body_is_refused_before_any_work() {
        // The HMAC and the base64 decode both cost time proportional to
        // the input, on an endpoint anyone can post to.
        let huge = format!("{}.{}", "a".repeat(MAX_LEN), "b".repeat(MAX_LEN));
        assert_eq!(
            verify(&huge, SECRET).unwrap_err(),
            SignedRequestError::TooLong
        );
    }

    #[test]
    fn padded_base64_is_accepted() {
        // Meta documents unpadded and has sent padded. Refusing one costs
        // a day of debugging for no security gain.
        let payload = serde_json::to_vec(&valid_payload()).expect("json");
        let payload_b64 = Base64UrlUnpadded::encode_string(&payload);
        let mut mac =
            <SimpleHmac<Sha256> as KeyInit>::new_from_slice(SECRET.as_bytes()).expect("key");
        mac.update(payload_b64.as_bytes());
        let signature = Base64UrlUnpadded::encode_string(&mac.finalize().into_bytes());
        let padded = format!("{signature}==.{payload_b64}");
        assert!(verify(&padded, SECRET).is_ok(), "padded signature refused");
    }
}
