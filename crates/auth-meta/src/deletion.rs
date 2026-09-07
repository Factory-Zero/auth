//! Meta's data deletion callback (issue #18).
//!
//! Meta will not approve an app for public use without one. It posts a
//! `signed_request` naming an app-scoped user id, and expects a synchronous
//! answer carrying a status URL and a confirmation code.
//!
//! **The work does not happen in that request.** It is recorded as a job and
//! drained by the scheduled handler, because doing it inline would mean
//! either a slow callback or a deletion that silently failed after the
//! answer had already gone out. The confirmation code is what ties the two
//! together.
//!
//! What "deletion" means is ADR 0104's decision: unlink the Meta identity,
//! and delete the account entirely only when no other identity and no other
//! credential remains. Anything more would let a request from one provider
//! destroy an account somebody still reaches another way; Meta's request is
//! about Meta's data.

use base64ct::{Base64UrlUnpadded, Encoding as _};
use factory0_auth_core::{
    DELETION_DELETED_USER, DELETION_NOTHING_TO_DO, DELETION_PENDING, DELETION_UNLINKED,
    DeletionJobRow, complete_deletion_job, credentials_by_user, delete_identity,
    identities_by_user, identity_by_provider_subject, insert_deletion_job, pending_deletion_jobs,
    purge_user,
};
use factory0_core::{AnyError, Clock, Database, IdGen, ModuleContext};

use crate::session::PROVIDER;

/// How many jobs one scheduled run drains. A cap rather than "all of them"
/// because the Workers runtime bounds how long a scheduled invocation may
/// take, and a backlog is better drained across runs than abandoned
/// half-way through one.
const BATCH: u64 = 50;

/// 32 random bytes, base64url. Not a secret — it identifies a request, and
/// the status it reveals is the requester's own — but it is unguessable so
/// that a status page cannot be enumerated to learn whether a given person
/// asked to be deleted.
fn confirmation_code() -> Option<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).ok()?;
    Some(Base64UrlUnpadded::encode_string(&bytes))
}

/// Records a deletion request. Returns the confirmation code.
///
/// # Errors
///
/// Any database failure, or an exhausted entropy source.
pub(crate) async fn record(
    db: &dyn Database,
    clock: &dyn Clock,
    id_gen: &dyn IdGen,
    provider_subject: &str,
) -> Result<String, AnyError> {
    let code = confirmation_code()
        .ok_or_else(|| -> AnyError { Box::new(std::io::Error::other("entropy source failed")) })?;
    let row = DeletionJobRow {
        id: id_gen.ulid(),
        provider: PROVIDER.to_owned(),
        provider_subject: provider_subject.to_owned(),
        confirmation_code: code.clone(),
        status: DELETION_PENDING.to_owned(),
        outcome: None,
        created_at: iso(clock),
        completed_at: None,
    };
    insert_deletion_job(db, &row)
        .await
        .map_err(|err| Box::new(err) as AnyError)?;
    Ok(code)
}

/// Carries out one job. Idempotent: a subject with no identity left is
/// `nothing_to_do` rather than an error, which is what makes a replayed or
/// retried request harmless.
async fn carry_out(db: &dyn Database, job: &DeletionJobRow) -> Result<&'static str, AnyError> {
    let Some(identity) = identity_by_provider_subject(db, &job.provider, &job.provider_subject)
        .await
        .map_err(|err| Box::new(err) as AnyError)?
    else {
        // Already gone, or never existed. Both are the same answer, and
        // neither is a failure.
        return Ok(DELETION_NOTHING_TO_DO);
    };
    let user_id = identity.user_id.clone();

    // The identity goes first, whatever else happens. `linking::unlink` is
    // deliberately not used: it refuses to remove an account's last way in,
    // which is right for a person tidying their account and wrong here,
    // where the whole request is to remove the data.
    delete_identity(db, &identity.id)
        .await
        .map_err(|err| Box::new(err) as AnyError)?;

    let identities = identities_by_user(db, &user_id)
        .await
        .map_err(|err| Box::new(err) as AnyError)?;
    let credentials = credentials_by_user(db, &user_id)
        .await
        .map_err(|err| Box::new(err) as AnyError)?;

    if !identities.is_empty() || !credentials.is_empty() {
        // Somebody still reaches this account another way. Meta's data is
        // gone; the account is not Meta's to take.
        return Ok(DELETION_UNLINKED);
    }

    // Nothing left to sign in with, so the account goes.
    //
    // `purge_user` and not `delete_user`: sessions, credentials and
    // identities all carry a foreign key to `users` with no cascade, so
    // deleting the user first simply fails — which is how the test below
    // found this. Revoking the sessions instead would not have helped
    // either: a revoked session is still a row, and this is an erasure.
    purge_user(db, &user_id)
        .await
        .map_err(|err| Box::new(err) as AnyError)?;
    Ok(DELETION_DELETED_USER)
}

/// Drains pending deletion jobs. Called from `Module::scheduled`.
///
/// # Errors
///
/// A database failure reading the queue. A failure carrying out one job is
/// logged and leaves that job pending for the next run, so one bad row does
/// not stop the queue.
pub(crate) async fn run_pending(ctx: &ModuleContext, cron: &str) -> Result<(), AnyError> {
    let (Some(db), Some(clock)) = (ctx.ports.db.clone(), ctx.ports.clock.clone()) else {
        return Ok(());
    };
    let jobs = pending_deletion_jobs(&*db, BATCH)
        .await
        .map_err(|err| Box::new(err) as AnyError)?;
    if jobs.is_empty() {
        return Ok(());
    }

    let mut done = 0_usize;
    for job in &jobs {
        match carry_out(&*db, job).await {
            Ok(outcome) => {
                // The update is conditional on the job still being pending,
                // so two schedulers racing the same row cannot both report
                // success. The work above is idempotent, which is what makes
                // that safe rather than merely tidy.
                match complete_deletion_job(&*db, &job.id, outcome, &iso(&*clock)).await {
                    Ok(_) => done += 1,
                    Err(err) => {
                        tracing::error!(error = %err, job = %job.id, "could not close a deletion job");
                    }
                }
            }
            Err(err) => {
                // Left pending on purpose: the next run tries again, and a
                // job that can never succeed shows up as a row that never
                // completes rather than as a silent loss.
                tracing::error!(error = %err, job = %job.id, "a deletion job failed");
            }
        }
    }
    tracing::info!(cron, done, queued = jobs.len(), "drained deletion jobs");
    Ok(())
}

fn iso(clock: &dyn Clock) -> String {
    clock
        .now()
        .replace_nanosecond(0)
        .unwrap_or_else(|_| clock.now())
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_confirmation_code_is_unguessable_and_url_safe() {
        let first = confirmation_code().expect("entropy");
        let second = confirmation_code().expect("entropy");
        assert_ne!(first, second);
        // It goes in a URL the person is given.
        assert!(
            first
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        // 32 bytes: a status page that could be enumerated would say who
        // has asked to be deleted.
        assert!(first.len() >= 43, "{first}");
    }
}
