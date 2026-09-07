//! Turning a Meta profile into a session (issue #17).
//!
//! Almost nothing happens here. `auth-core::federated` owns the step every
//! federated method shares; this file says what Meta vouched for, which is
//! `["federated"]` and an address nobody verified, and announces the result
//! under this module's own event names.

use factory0_auth_core::federated::{
    self, Caller, CompleteError, Completed as CoreCompleted, FederatedIdentity, Ports,
};
use factory0_auth_core::{IssuedSession, set_cookie};
use factory0_core::{ModuleContext, Problem, Scope};
use serde_json::json;

pub(crate) const EVENT_LOGGED_IN: &str = "auth-meta.logged_in";
pub(crate) const EVENT_AUTO_LINKED: &str = "auth-meta.auto_linked";

/// RFC 8176: a federated assertion from a third party. No `mfa`, whatever
/// Meta did behind its own door, because we did not see it.
const AMR: [&str; 1] = ["federated"];

/// The provider slug, which is also the `identities.provider` value.
pub(crate) const PROVIDER: &str = factory0_auth_core::PROVIDER_META;

pub(crate) enum Completed {
    SignedIn { session: IssuedSession },
    NeedsPerson { message: &'static str },
}

/// Applies the linking rules to a Meta profile and, when they say so,
/// issues a session.
pub(crate) async fn complete(
    ctx: &ModuleContext,
    scope: &Scope,
    ports: &Ports<'_>,
    profile: &crate::graph::Profile,
    caller: &Caller<'_>,
) -> Result<Completed, Problem> {
    let outcome = federated::complete(
        ports,
        &FederatedIdentity {
            provider: PROVIDER,
            subject: &profile.id,
            email: profile.email.as_deref(),
            // Never true. Meta does not assert verification in a form this
            // service can rely on, and an address stored as verified is a
            // key: the linking rules auto-link on a verified match, so
            // believing Meta here would let anyone who can get an address
            // onto a Facebook account walk into the matching account here.
            email_verified: false,
            name: profile.name.as_deref(),
        },
        caller,
        &AMR,
    )
    .await
    .map_err(|err| match err {
        // The account exists but is switched off. Same answer as any other
        // refused callback: it is not a caller's business which.
        CompleteError::NotActive => {
            Problem::new(&crate::CALLBACK_REFUSED).instance(&scope.request_id)
        }
        CompleteError::Internal(message) => {
            tracing::error!(error = %message, "could not complete the Meta login");
            Problem::internal().instance(&scope.request_id)
        }
    })?;

    let signed_in = match outcome {
        CoreCompleted::SignedIn(signed_in) => signed_in,
        CoreCompleted::NeedsPerson { message } => return Ok(Completed::NeedsPerson { message }),
    };

    if let Some(notify_email) = &signed_in.auto_linked_notify {
        ctx.events.emit_in(
            scope,
            EVENT_AUTO_LINKED,
            json!({
                "user_id": signed_in.user_id,
                "provider": PROVIDER,
                "notify_email": notify_email,
            }),
        );
    }
    ctx.events.emit_in(
        scope,
        EVENT_LOGGED_IN,
        json!({
            "user_id": signed_in.user_id,
            "provider": PROVIDER,
            "session_id": signed_in.session.session_id,
        }),
    );

    Ok(Completed::SignedIn {
        session: signed_in.session,
    })
}

/// The `Set-Cookie` value for an issued session.
pub(crate) fn session_cookie(session: &IssuedSession) -> String {
    set_cookie(&session.value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_provider_slug_is_the_one_auth_core_stores() {
        // The route segment and the row written into `identities` are the
        // same string; if they ever drift, a second login makes a second
        // account instead of matching the first.
        assert_eq!(PROVIDER, "meta");
    }

    #[test]
    fn a_meta_login_claims_only_a_federated_assertion() {
        assert_eq!(AMR, ["federated"]);
        assert!(
            !AMR.contains(&"mfa"),
            "we did not see whatever Meta did behind its own door"
        );
    }
}
