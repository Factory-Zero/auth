//! The per-account lockout (issue #12).
//!
//! The `RateLimiter` port is keyed on the request, so it slows one
//! attacker down and does nothing about one with a botnet. This is keyed
//! on the credential, so it survives an attacker rotating IP addresses.
//!
//! It locks the **password**, not the account. Somebody locked out here
//! can still sign in with a passkey or a provider, which is what keeps a
//! lockout from being a denial of service an attacker can aim at a person
//! by guessing their password wrongly on purpose. An account whose only
//! login method is a password is stuck for the lockout window, and that
//! window is short for exactly that reason.

use factory0_auth_core::CredentialRow;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::Settings;

/// What the lockout says about an attempt, before the password is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    /// Not locked. The attempt proceeds.
    Open,
    /// Locked until the instant carried by the caller. The attempt is
    /// refused with the same answer a wrong password gets.
    Locked,
}

/// Whether this credential may be tried right now.
pub(crate) fn state(credential: &CredentialRow, now: OffsetDateTime) -> State {
    match credential.locked_until.as_deref().and_then(parse) {
        Some(until) if until > now => State::Locked,
        // A lock that has passed is not a lock. It is cleared lazily, on
        // the next attempt, rather than by a scheduled sweep: the row is
        // only interesting when somebody tries to use it.
        _ => State::Open,
    }
}

/// The counter state to write after a failed attempt.
///
/// Returns the new count, the window it belongs to, and the lock if this
/// failure crossed the threshold.
pub(crate) fn after_failure(
    credential: &CredentialRow,
    settings: &Settings,
    now: OffsetDateTime,
) -> (i64, String, Option<String>) {
    let window_start = credential
        .failed_window_started_at
        .as_deref()
        .and_then(parse);

    // A count with no window is a lifetime total, which eventually locks
    // out anyone who has ever mistyped enough times across years.
    let within_window = window_start.is_some_and(|started| {
        now.unix_timestamp() - started.unix_timestamp() < settings.lockout_window_secs
    });

    let (count, started) = if within_window {
        (
            credential.failed_attempts.saturating_add(1),
            window_start.unwrap_or(now),
        )
    } else {
        (1, now)
    };

    let locked_until = (count >= settings.lockout_threshold)
        .then(|| iso(now.saturating_add(time::Duration::seconds(settings.lockout_secs))));

    (count, iso(started), locked_until)
}

fn parse(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).ok()
}

pub(crate) fn iso(at: OffsetDateTime) -> String {
    at.replace_nanosecond(0)
        .unwrap_or(at)
        .format(&Rfc3339)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory0_auth_core::{CREDENTIAL_PASSWORD, Redacted};

    fn at(secs: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(secs).expect("in range")
    }

    fn credential(
        failed_attempts: i64,
        window: Option<&str>,
        locked_until: Option<&str>,
    ) -> CredentialRow {
        CredentialRow {
            id: "c1".into(),
            user_id: "u1".into(),
            kind: CREDENTIAL_PASSWORD.into(),
            passkey_credential_id: None,
            passkey_public_key_cose: None,
            passkey_sign_count: None,
            passkey_aaguid: None,
            passkey_transports: None,
            password_hash: Some(Redacted("hash".into())),
            label: None,
            created_at: "2026-09-07T00:00:00Z".into(),
            last_used_at: None,
            passkey_suspect_at: None,
            failed_attempts,
            failed_window_started_at: window.map(str::to_owned),
            locked_until: locked_until.map(str::to_owned),
        }
    }

    #[test]
    fn a_fresh_credential_is_open() {
        assert_eq!(state(&credential(0, None, None), at(1000)), State::Open);
    }

    #[test]
    fn a_live_lock_refuses_and_an_expired_one_does_not() {
        let locked = credential(10, None, Some(&iso(at(2000))));
        assert_eq!(state(&locked, at(1999)), State::Locked);
        // The instant it passes, it is open again. Cleared lazily on the
        // next attempt rather than by a sweep: the row is only interesting
        // when somebody tries to use it.
        assert_eq!(state(&locked, at(2000)), State::Open);
        assert_eq!(state(&locked, at(9999)), State::Open);
    }

    #[test]
    fn a_malformed_timestamp_does_not_lock_anybody_out_forever() {
        // A row that cannot be parsed must fail open. Failing closed would
        // mean one bad write locks a person out permanently, with the only
        // remedy a database edit.
        let broken = credential(10, None, Some("not a timestamp"));
        assert_eq!(state(&broken, at(1000)), State::Open);
    }

    #[test]
    fn failures_accumulate_inside_the_window_and_reset_outside_it() {
        let settings = Settings::default();
        let start = at(1000);

        let (count, window, locked) = after_failure(&credential(0, None, None), &settings, start);
        assert_eq!(count, 1);
        assert_eq!(window, iso(start));
        assert!(locked.is_none());

        // A second failure inside the window continues the count.
        let (count, window, locked) = after_failure(
            &credential(1, Some(&iso(start)), None),
            &settings,
            at(1000 + 60),
        );
        assert_eq!(count, 2);
        assert_eq!(window, iso(start), "the window start does not move");
        assert!(locked.is_none());

        // One past the window starts a new count of one.
        let (count, window, locked) = after_failure(
            &credential(9, Some(&iso(start)), None),
            &settings,
            at(1000 + settings.lockout_window_secs),
        );
        assert_eq!(count, 1, "an old window must not carry its count forward");
        assert_eq!(window, iso(at(1000 + settings.lockout_window_secs)));
        assert!(locked.is_none());
    }

    #[test]
    fn the_threshold_locks_and_the_lock_is_the_configured_length() {
        let settings = Settings::default();
        let start = at(1000);
        let (count, _, locked) = after_failure(
            &credential(settings.lockout_threshold - 1, Some(&iso(start)), None),
            &settings,
            at(1100),
        );
        assert_eq!(count, settings.lockout_threshold);
        assert_eq!(
            locked.as_deref(),
            Some(iso(at(1100 + settings.lockout_secs)).as_str()),
            "the lock runs from the failure, not from the window start"
        );
    }

    #[test]
    fn a_count_that_has_somehow_run_away_still_locks_rather_than_overflowing() {
        let settings = Settings::default();
        let start = at(1000);
        let (count, _, locked) = after_failure(
            &credential(i64::MAX, Some(&iso(start)), None),
            &settings,
            at(1100),
        );
        assert_eq!(count, i64::MAX, "saturating, not wrapping");
        assert!(locked.is_some());
    }
}
