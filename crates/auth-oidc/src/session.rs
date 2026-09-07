//! Turning a verified provider identity into a session (issues #15, #22).
//!
//! The decision of *which* account an identity belongs to is not made here,
//! and neither is carrying it out. `auth-core::federated` owns both — the
//! rules and the schema are auth-core's, and every federated method needs
//! the identical step — so this module's job is to say what the provider
//! vouched for and to announce what happened under its own event names.

use factory0_auth_core::federated::{
    self, Caller as CoreCaller, CompleteError, Completed as CoreCompleted, FederatedIdentity,
    Ports as CorePorts,
};
use factory0_auth_core::{IssuedSession, set_cookie};
use factory0_core::{Clock, Database, IdGen, ModuleContext, Problem, Scope};
use serde_json::json;

use crate::provider::Provider;

pub(crate) const EVENT_LOGGED_IN: &str = "auth-oidc.logged_in";
pub(crate) const EVENT_AUTO_LINKED: &str = "auth-oidc.auto_linked";

/// RFC 8176: this login was a federated assertion from a third party. No
/// `mfa`, whatever the provider did behind its own door: we did not see it.
const AMR: [&str; 1] = ["federated"];

/// What the provider told us, already normalized.
pub(crate) struct Identity {
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
}

/// Where a completed callback should send the browser, or what to tell the
/// person when there is nothing to send them to yet.
pub(crate) enum Completed {
    /// Signed in. The caller sets the cookie and redirects.
    SignedIn { session: IssuedSession },
    /// The linking rules will not guess (`ExistingAccountUnverified`), or
    /// the person must approve a link (`ConfirmLink`). Both need a page and
    /// a decision this module does not own.
    NeedsPerson { message: &'static str },
}

/// What the callback knows about the browser at the other end.
pub(crate) struct Caller<'a> {
    /// The signed-in user, when the callback arrived from somebody already
    /// signed in: that is a person adding a provider.
    pub current_user: Option<&'a str>,
    /// The session cookie the request presented, revoked before a new
    /// session exists (auth-core's fixation defence).
    pub presented_cookie: Option<&'a str>,
    pub ip: Option<&'a str>,
    pub user_agent: Option<&'a str>,
}

/// The ports this step needs, gathered so the signature stays readable.
pub(crate) struct Ports<'a> {
    pub db: &'a dyn Database,
    pub clock: &'a dyn Clock,
    pub id_gen: &'a dyn IdGen,
}

/// Applies the linking rules and, when they say so, issues a session.
pub(crate) async fn complete(
    ctx: &ModuleContext,
    scope: &Scope,
    ports: &Ports<'_>,
    provider: &Provider,
    identity: &Identity,
    caller: &Caller<'_>,
) -> Result<Completed, Problem> {
    let outcome = federated::complete(
        &CorePorts {
            db: ports.db,
            clock: ports.clock,
            id_gen: ports.id_gen,
        },
        &FederatedIdentity {
            provider: provider.slug,
            subject: &identity.subject,
            email: identity.email.as_deref(),
            email_verified: identity.email_verified,
            name: identity.name.as_deref(),
        },
        &CoreCaller {
            current_user: caller.current_user,
            presented_cookie: caller.presented_cookie,
            ip: caller.ip,
            user_agent: caller.user_agent,
        },
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
            tracing::error!(error = %message, "could not complete the login");
            Problem::internal().instance(&scope.request_id)
        }
    })?;

    let signed_in = match outcome {
        CoreCompleted::SignedIn(signed_in) => signed_in,
        CoreCompleted::NeedsPerson { message } => return Ok(Completed::NeedsPerson { message }),
    };

    // The events are this module's, because their names are and because
    // `emits()` declares them. auth-core did the work; saying so is ours.
    if let Some(notify_email) = &signed_in.auto_linked_notify {
        // The account just gained a way in, so somebody has to be told.
        // Sending the mail is not this module's job; saying it happened is.
        ctx.events.emit_in(
            scope,
            EVENT_AUTO_LINKED,
            json!({
                "user_id": signed_in.user_id,
                "provider": provider.slug,
                "notify_email": notify_email,
            }),
        );
    }
    ctx.events.emit_in(
        scope,
        EVENT_LOGGED_IN,
        json!({
            "user_id": signed_in.user_id,
            "provider": provider.slug,
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
