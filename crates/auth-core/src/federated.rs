//! Turning a verified third-party identity into a session.
//!
//! Every federated login method does the same thing once its provider has
//! spoken: hand what the provider vouched for to the linking rules (#22),
//! carry out what they return, and issue a session. Google, Apple and Meta
//! differ entirely in how they establish the identity and not at all in
//! what happens next.
//!
//! This lives in auth-core rather than in each login method because the
//! rules and the schema are auth-core's, and because a fix here — the
//! account-creation race below is one, and the disabled-account ordering in
//! issue #37 will be another — has to reach every method rather than the
//! one whose copy somebody remembered to edit.
//!
//! What stays with the caller is what is genuinely its own: how the
//! identity was established, its RFC 8176 `amr` values, and its event
//! names, which are `<module>.<event>` and must match the module's
//! `emits()`. So this returns what happened and the module announces it.

use factory0_core::{Clock, Database, IdGen};

use crate::linking::{IncomingIdentity, Outcome, create_user, link, resolve};
use crate::sessions::{IssuedSession, Login, SessionError, issue};
use crate::store::{delete_user, identity_by_provider_subject, touch_identity_login};

/// What a provider told us about the person, already normalized.
#[derive(Debug, Clone)]
pub struct FederatedIdentity<'a> {
    /// The `identities.provider` value, e.g. `google`.
    pub provider: &'a str,
    /// The provider's own id for this person.
    pub subject: &'a str,
    pub email: Option<&'a str>,
    /// Whether the **provider** vouched for the address. Never assume:
    /// an address stored as verified that nobody verified lets the next
    /// provider auto-link a stranger's account to it.
    pub email_verified: bool,
    pub name: Option<&'a str>,
}

/// What the callback knows about the browser at the other end.
#[derive(Debug, Clone, Default)]
pub struct Caller<'a> {
    /// The signed-in user, when the request arrived from somebody who is
    /// already signed in: that is a person adding a provider, and the
    /// linking rules need to know.
    pub current_user: Option<&'a str>,
    /// The session cookie the request presented, revoked before a new
    /// session exists (the fixation defence in [`issue`]).
    pub presented_cookie: Option<&'a str>,
    pub ip: Option<&'a str>,
    pub user_agent: Option<&'a str>,
}

/// A completed sign-in, and what the caller should announce.
pub struct SignedIn {
    pub session: IssuedSession,
    pub user_id: String,
    /// Present when the linking rules attached this identity to an
    /// existing account on a verified-email match. The account just gained
    /// a way in, so somebody has to be told; the address to tell is here,
    /// and sending the mail is not this layer's job.
    pub auto_linked_notify: Option<String>,
}

/// Where a completed login should go, or what to tell the person when
/// there is nothing to send them to yet.
pub enum Completed {
    SignedIn(Box<SignedIn>),
    /// The rules will not guess. The caller renders the message.
    NeedsPerson {
        message: &'static str,
    },
}

/// An account that gained a way in, whether or not a session followed.
///
/// The link is written before the account's status is read, so this is
/// returned on the refusal path as well as the success one: the caller
/// announces it either way.
#[derive(Debug, Clone)]
pub struct AutoLinked {
    pub user_id: String,
    pub notify_email: String,
}

/// Why a login could not be completed.
#[derive(Debug, thiserror::Error)]
pub enum CompleteError {
    /// The account exists and is switched off. Callers answer this the
    /// same way they answer any other refused callback: which one it was
    /// is not a caller's business.
    ///
    /// Carries the auto-link when the rules made one, because the link is
    /// written before the account's status is read: without this, an
    /// identity row appears on somebody's account and nobody is told,
    /// which is the worst of both.
    #[error("the account is not active")]
    NotActive(Option<Box<AutoLinked>>),
    /// The database, or a rule, failed in a way nobody can act on.
    #[error("{0}")]
    Internal(String),
}

/// The ports this step needs, gathered so the signature stays readable.
pub struct Ports<'a> {
    pub db: &'a dyn Database,
    pub clock: &'a dyn Clock,
    pub id_gen: &'a dyn IdGen,
}

/// Applies the linking rules to a verified identity and, when they say so,
/// issues a session.
///
/// `amr` is the caller's, because only the login method knows what it
/// actually saw: a federated assertion is `["federated"]`, a passkey with
/// user verification is more.
///
/// # Errors
///
/// [`CompleteError::NotActive`] for a disabled account, [`CompleteError::Internal`]
/// for anything the caller cannot act on.
pub async fn complete(
    ports: &Ports<'_>,
    identity: &FederatedIdentity<'_>,
    caller: &Caller<'_>,
    amr: &[&str],
) -> Result<Completed, CompleteError> {
    let Ports { db, clock, id_gen } = *ports;
    let incoming = IncomingIdentity {
        provider: identity.provider,
        subject: identity.subject,
        email: identity.email,
        email_verified: identity.email_verified,
        name: identity.name,
    };

    let outcome = resolve(db, &incoming, caller.current_user)
        .await
        .map_err(|err| CompleteError::Internal(format!("linking could not be resolved: {err}")))?;

    let mut auto_linked_notify = None;
    let user_id = match outcome {
        Outcome::Known { user_id } => {
            // The column exists so an account page can say when a provider
            // was last used; nothing else writes it, and failing to write
            // it must not fail the sign-in.
            match identity_by_provider_subject(db, identity.provider, identity.subject).await {
                Ok(Some(row)) => {
                    if let Err(err) = touch_identity_login(db, &row.id, &iso(clock)).await {
                        tracing::warn!(error = %err, "could not record the last login");
                    }
                }
                Ok(None) => {}
                Err(err) => tracing::warn!(error = %err, "could not read the identity"),
            }
            user_id
        }
        Outcome::AutoLinked {
            user_id,
            notify_email,
        } => {
            link(db, clock, id_gen, &user_id, &incoming)
                .await
                .map_err(|err| {
                    CompleteError::Internal(format!("could not link the identity: {err}"))
                })?;
            auto_linked_notify = Some(notify_email);
            user_id
        }
        Outcome::NewUser => new_user(ports, &incoming).await?,
        // Both of these need a person to decide something, and the page
        // that would let them does not exist yet (#22 owns the confirm
        // step). Say so plainly rather than guessing an account.
        Outcome::ConfirmLink { .. } => {
            return Ok(Completed::NeedsPerson {
                message: "That account is already signed in here. Linking this provider needs \
                          confirming from your account page, which is not built yet.",
            });
        }
        Outcome::ExistingAccountUnverified => {
            return Ok(Completed::NeedsPerson {
                message: "An account already uses that email address, and neither side has \
                          verified it. Sign in the way you already can, then link this provider \
                          from there.",
            });
        }
    };

    let session = issue(
        db,
        clock,
        id_gen,
        Login {
            user_id: &user_id,
            ip: caller.ip,
            user_agent: caller.user_agent,
            presented_cookie: caller.presented_cookie,
            amr,
        },
    )
    .await
    .map_err(|err| match err {
        SessionError::NotActive => {
            tracing::warn!(user = %user_id, "a disabled account signed in through a provider");
            CompleteError::NotActive(auto_linked_notify.as_ref().map(|notify_email| {
                Box::new(AutoLinked {
                    user_id: user_id.clone(),
                    notify_email: notify_email.clone(),
                })
            }))
        }
        err => CompleteError::Internal(format!("could not issue a session: {err}")),
    })?;

    Ok(Completed::SignedIn(Box::new(SignedIn {
        session,
        user_id,
        auto_linked_notify,
    })))
}

fn iso(clock: &dyn Clock) -> String {
    crate::sessions::iso(clock.now())
}

/// Creates the account a first sign-in earns, and links the identity to it.
///
/// Not atomic, because the `Database` port has no transaction that spans
/// two statements. Two first logins for the same provider subject can race,
/// and the loser's `link` hits the unique constraint *after* its user row
/// exists. That row would carry an email, no identity, and no way to reach
/// it — and a later verified-email match from another provider would link a
/// stranger to it. So the loser cleans up after itself and takes the
/// winner's account.
async fn new_user(
    ports: &Ports<'_>,
    incoming: &IncomingIdentity<'_>,
) -> Result<String, CompleteError> {
    let Ports { db, clock, id_gen } = *ports;
    // auth-core's own `create_user`, rather than a second copy of the same
    // insert: it is where the rule that an absent address is never
    // "verified" lives.
    let user = create_user(db, clock, id_gen, incoming)
        .await
        .map_err(|err| CompleteError::Internal(format!("could not create the user: {err}")))?;

    if let Err(err) = link(db, clock, id_gen, &user.id, incoming).await {
        tracing::warn!(error = %err, "linking a new user failed; undoing the account");
        if let Err(err) = delete_user(db, &user.id).await {
            tracing::error!(error = %err, "could not undo the orphaned account");
        }
        // Somebody else got there first. Ask again: by now the identity
        // exists and the answer is their account.
        return match resolve(db, incoming, None).await {
            Ok(Outcome::Known { user_id }) => Ok(user_id),
            _ => Err(CompleteError::Internal(
                "lost an account-creation race and could not recover".to_owned(),
            )),
        };
    }
    Ok(user.id)
}
