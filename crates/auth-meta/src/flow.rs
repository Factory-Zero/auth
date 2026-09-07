//! The in-flight authorization, carried in a signed cookie (issue #17).
//!
//! The same shape auth-oidc uses, and for the same reason: between
//! `/start` and `/callback` this module must remember the `state` it will
//! compare, the PKCE verifier, and where to send the browser afterwards.
//! They live in a signed cookie rather than a row because they belong to
//! *this browser*: a row keyed by state would be spendable by anyone who
//! saw the state in a redirect chain or a referrer.
//!
//! No nonce, because there is no ID token to echo one. Meta's callback is
//! a plain redirect, so the cookie is `SameSite=Lax` — the `SameSite=None`
//! that Apple's `form_post` needs would be a widening with nothing asking
//! for it.

use factory0_core::{Clock, Kid, Payload, Signer};
use serde::{Deserialize, Serialize};

/// The signed payload's purpose (ADR 0006), so a flow cookie can never be
/// replayed as any other signed token this service issues.
pub(crate) const PURPOSE: &str = "auth-meta.flow";

/// `__Host-` so the cookie is origin-locked: no domain, path `/`, secure.
pub(crate) const COOKIE_NAME: &str = "__Host-fz_meta";

/// How long a person has to finish at Meta.
pub(crate) const TTL_SECS: i64 = 600;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Flow {
    pub state: String,
    /// The PKCE code verifier. It never leaves this cookie and the token
    /// request. Meta supports PKCE, and using it means a leaked
    /// authorization code is not enough on its own.
    pub verifier: String,
    /// Where to send the browser afterwards: always a path on this
    /// service, never an absolute URL.
    pub return_to: String,
    /// Unix seconds, checked against the `Clock` port rather than the
    /// signer's own `exp`, which reads the wall clock directly and so
    /// cannot be driven by a test clock.
    pub expires_at: i64,
    /// The user who was signed in when `/start` ran, if anyone was.
    ///
    /// Meta's callback is a redirect, so the `SameSite=Lax` session cookie
    /// does arrive on it and this is usually redundant. It is carried
    /// anyway because the session may be revoked mid-flow and because the
    /// callback should not have to care which providers happen to redirect:
    /// the answer `/start` saw is the one the linking rules asked about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_in_user: Option<String>,
}

impl Flow {
    /// Signs the flow into a cookie value.
    pub(crate) fn seal(&self, signer: &dyn Signer) -> String {
        let payload = serde_json::to_string(self).unwrap_or_default();
        signer.sign(&Payload {
            purpose: PURPOSE.to_owned(),
            subject: payload,
            // Deliberately none: `Signer::verify` compares `exp` against
            // the wall clock rather than the Clock port, which would make
            // the expiry untestable. It lives in the payload instead.
            exp: None,
            kid: Kid::Cur,
        })
    }

    /// Recovers a flow from a cookie value, or `None` for anything that is
    /// not a live flow: unsigned, tampered, malformed or expired.
    pub(crate) fn open(signer: &dyn Signer, clock: &dyn Clock, cookie: &str) -> Option<Self> {
        let payload = signer.verify(cookie, PURPOSE)?;
        let flow: Flow = serde_json::from_str(&payload.subject).ok()?;
        if flow.expires_at <= clock.now().unix_timestamp() {
            return None;
        }
        Some(flow)
    }
}

/// The `Set-Cookie` value that carries a flow.
pub(crate) fn set_cookie(value: &str) -> String {
    // `Lax` and not `Strict`: the callback arrives as a top-level
    // navigation from Meta, and `Strict` would withhold the cookie on
    // exactly that request.
    format!("{COOKIE_NAME}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={TTL_SECS}")
}

/// The `Set-Cookie` value that clears it, sent once the flow is spent.
pub(crate) fn clear_cookie() -> String {
    format!(
        "{COOKIE_NAME}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0; \
         Expires=Thu, 01 Jan 1970 00:00:00 GMT"
    )
}

/// The flow cookie's value from a `Cookie` header.
pub(crate) fn cookie_value(headers: &http::HeaderMap) -> Option<String> {
    for header in headers.get_all(http::header::COOKIE) {
        let Ok(raw) = header.to_str() else {
            continue;
        };
        for pair in raw.split(';') {
            let Some(value) = pair.trim().strip_prefix(COOKIE_NAME) else {
                continue;
            };
            if let Some(value) = value.strip_prefix('=') {
                return Some(value.to_owned());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory0_core::HmacSigner;
    use time::OffsetDateTime;

    struct FixedClock(i64);
    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            OffsetDateTime::from_unix_timestamp(self.0).expect("in range")
        }
    }

    fn signer() -> HmacSigner {
        HmacSigner::new("a-test-secret-that-is-long-enough-32", None).expect("a long enough secret")
    }

    fn flow(expires_at: i64) -> Flow {
        Flow {
            state: "the-state".to_owned(),
            verifier: "the-verifier".to_owned(),
            return_to: "/".to_owned(),
            expires_at,
            signed_in_user: None,
        }
    }

    #[test]
    fn a_sealed_flow_reopens_and_a_tampered_one_does_not() {
        let signer = signer();
        let sealed = flow(1000).seal(&signer);
        let opened = Flow::open(&signer, &FixedClock(500), &sealed).expect("opens");
        assert_eq!(opened.state, "the-state");
        assert_eq!(opened.verifier, "the-verifier");

        let tampered = format!("{sealed}x");
        assert_eq!(Flow::open(&signer, &FixedClock(500), &tampered), None);
        assert_eq!(Flow::open(&signer, &FixedClock(500), ""), None);
        assert_eq!(Flow::open(&signer, &FixedClock(500), "not.a.token"), None);
    }

    #[test]
    fn an_expired_flow_does_not_open() {
        let signer = signer();
        let sealed = flow(1000).seal(&signer);
        assert!(Flow::open(&signer, &FixedClock(999), &sealed).is_some());
        assert_eq!(Flow::open(&signer, &FixedClock(1000), &sealed), None);
        assert_eq!(Flow::open(&signer, &FixedClock(2000), &sealed), None);
    }

    #[test]
    fn a_flow_from_another_purpose_does_not_open() {
        // The purpose is what stops a signed value this service issued for
        // something else being presented here (ADR 0006).
        let signer = signer();
        let foreign = signer.sign(&Payload {
            purpose: "auth-oidc.flow".to_owned(),
            subject: serde_json::to_string(&flow(1000)).expect("json"),
            exp: None,
            kid: Kid::Cur,
        });
        assert_eq!(Flow::open(&signer, &FixedClock(500), &foreign), None);
    }

    #[test]
    fn the_cookie_is_origin_locked_and_survives_metas_redirect() {
        let header = set_cookie("value");
        assert!(header.starts_with("__Host-fz_meta="), "{header}");
        assert!(header.contains("Secure"), "{header}");
        assert!(header.contains("HttpOnly"), "{header}");
        // Meta redirects, so `Lax` arrives and nothing needs widening.
        assert!(header.contains("SameSite=Lax"), "{header}");
        assert!(!header.contains("SameSite=None"), "{header}");
        assert!(!header.contains("Domain="), "__Host- forbids a domain");
    }

    #[test]
    fn the_cookie_reads_past_its_neighbours() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            "theme=dark; __Host-fz_meta=abc; other=1"
                .parse()
                .expect("header"),
        );
        assert_eq!(cookie_value(&headers).as_deref(), Some("abc"));
    }
}
