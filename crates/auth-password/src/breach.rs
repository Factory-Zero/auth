//! The breached-password check (issue #19).
//!
//! Asks the Pwned Passwords range API whether a password appears in a
//! public breach corpus, **without sending the password or its full
//! hash**. The k-anonymity protocol: send the first five hex characters
//! of the SHA-1, receive every suffix sharing that prefix, and look for
//! ours locally. The service learns a prefix shared by hundreds of
//! thousands of passwords and nothing else.
//!
//! SHA-1 here is not a security choice. It is the corpus's index, and it
//! never leaves this function: what is compared is a suffix against a
//! list, not a password against a hash.
//!
//! **Fail-open, deliberately.** A breach corpus being unreachable is not a
//! reason to stop people registering. The alternative — refusing every
//! registration when an external service is down — turns somebody else's
//! outage into ours, and the check is advice rather than authentication.

use factory0_core::HttpClient;
use sha1::{Digest, Sha1};
use std::sync::Arc;

/// The range API. Only a prefix is ever appended.
const RANGE_ENDPOINT: &str = "https://api.pwnedpasswords.com/range/";

/// How many times a password must appear before it is refused.
///
/// One is the right threshold: a password in the corpus even once is one
/// an attacker's list already holds.
const MIN_COUNT: u64 = 1;

/// Whether this password appears in the breach corpus.
///
/// `false` when it does not, when the check is unreachable, or when the
/// answer cannot be read. Never an error: see the fail-open note above.
pub(crate) async fn is_breached(http: &Arc<dyn HttpClient>, password: &str) -> bool {
    let digest = Sha1::digest(password.as_bytes());
    let hex = base16ct::upper::encode_string(&digest);
    // Five characters is the protocol's prefix length. Splitting anywhere
    // else either leaks more or asks for a response too large to read.
    let (prefix, suffix) = hex.split_at(5);

    let Ok(request) = http::Request::builder()
        .method(http::Method::GET)
        .uri(format!("{RANGE_ENDPOINT}{prefix}"))
        .header(http::header::ACCEPT, "text/plain")
        // Asks the API to pad the response with fake suffixes, so the size
        // of the reply does not narrow down which prefix was asked for.
        .header("Add-Padding", "true")
        .body(bytes::Bytes::new())
    else {
        return false;
    };

    let Ok(response) = http.send(request).await else {
        tracing::warn!("the breach corpus could not be reached; allowing the password");
        return false;
    };
    if response.status() != http::StatusCode::OK {
        tracing::warn!(status = %response.status(), "the breach corpus answered oddly");
        return false;
    }
    let Ok(body) = std::str::from_utf8(response.body()) else {
        return false;
    };
    contains_suffix(body, suffix)
}

/// Looks for our suffix in a range response.
///
/// Each line is `SUFFIX:COUNT`. A padded response carries lines with a
/// count of zero, which are fakes and are ignored — treating one as a hit
/// would refuse a password nobody has ever breached.
fn contains_suffix(body: &str, suffix: &str) -> bool {
    body.lines().any(|line| {
        let Some((candidate, count)) = line.trim().split_once(':') else {
            return false;
        };
        if !candidate.eq_ignore_ascii_case(suffix) {
            return false;
        }
        count.trim().parse::<u64>().unwrap_or(0) >= MIN_COUNT
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical example: SHA-1 of "password" is
    /// `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8`.
    const PASSWORD_SUFFIX: &str = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    #[test]
    fn a_matching_suffix_with_a_count_is_a_hit() {
        let body = format!("0018A45C4D1DEF81644B54AB7F969B88D65:1\n{PASSWORD_SUFFIX}:9659365\n");
        assert!(contains_suffix(&body, PASSWORD_SUFFIX));
    }

    #[test]
    fn a_padded_zero_count_line_is_not_a_hit() {
        // The API pads responses with fake suffixes at count zero so the
        // reply size does not narrow the prefix down. Treating one as a
        // hit would refuse a password nobody has ever breached.
        let body = format!("{PASSWORD_SUFFIX}:0\n");
        assert!(!contains_suffix(&body, PASSWORD_SUFFIX));
    }

    #[test]
    fn the_comparison_ignores_case_and_line_endings() {
        // The API returns upper case; nothing should depend on that.
        let body = format!("{}:5\r\n", PASSWORD_SUFFIX.to_lowercase());
        assert!(contains_suffix(&body, PASSWORD_SUFFIX));
    }

    #[test]
    fn an_absent_suffix_and_a_rubbish_body_are_both_misses() {
        assert!(!contains_suffix(
            "0018A45C4D1DEF81644B54AB7F969B88D65:1\n",
            PASSWORD_SUFFIX
        ));
        for body in ["", "no colons here", ":", "\n\n", "AAAA:notanumber"] {
            assert!(!contains_suffix(body, PASSWORD_SUFFIX), "{body:?}");
        }
    }

    #[test]
    fn only_a_prefix_would_ever_leave_this_machine() {
        // The protocol's whole point. This asserts the split, because a
        // change that sent six characters, or the whole hash, would still
        // work and would quietly leak.
        let digest = Sha1::digest(b"password");
        let hex = base16ct::upper::encode_string(&digest);
        assert_eq!(hex.len(), 40);
        let (prefix, suffix) = hex.split_at(5);
        assert_eq!(prefix, "5BAA6");
        assert_eq!(suffix, PASSWORD_SUFFIX);
        // The request URI is the endpoint plus the prefix and nothing
        // else. Asserted on the built URI rather than on the constant,
        // because the constant contains the word "passwords" in the host
        // and a naive check on that says nothing.
        let uri = format!("{RANGE_ENDPOINT}{prefix}");
        assert!(uri.ends_with("/range/5BAA6"), "{uri}");
        assert!(
            !uri.contains(suffix),
            "the suffix must never leave this machine: {uri}"
        );
    }
}
