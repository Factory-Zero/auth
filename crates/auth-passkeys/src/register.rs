//! Registration: options, verify, list and delete (issue #13).
//!
//! Registration always happens inside a session. A passkey is added to an
//! account that already exists, which is what keeps this endpoint from being
//! an account-creation path with no identity behind it.

use axum::extract::{Path, State};
use axum::response::Response;
use axum::routing::{get, post};
use factory0_auth_core::{
    Bytes, CREDENTIAL_PASSKEY, CredentialRow, credentials_by_user, identities_by_user,
    insert_credential, passkey_by_credential_id, user_by_id,
};
use factory0_core::{Json, Problem, Scope};
use http::HeaderMap;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use webauthn_rs_proto::{
    AttestationConveyancePreference, AuthenticatorSelectionCriteria, CreationChallengeResponse,
    PubKeyCredParams, PublicKeyCredentialCreationOptions, PublicKeyCredentialDescriptor,
    RegisterPublicKeyCredential, RelyingParty as ProtoRelyingParty, ResidentKeyRequirement, User,
    UserVerificationPolicy,
};

use crate::challenge::{self, PURPOSE_REGISTER};
use crate::request::{b64u, ceremony_failed, hex, internal, ok, ports, require_session};
use crate::webauthn::{UserVerification, verify_registration};
use crate::{COSE_EDDSA, COSE_ES256, COSE_RS256, ModuleState};

pub(crate) const EVENT_REGISTERED: &str = "auth-passkeys.registered";

pub(crate) fn router() -> axum::Router<Arc<ModuleState>> {
    axum::Router::new()
        .route("/register/options", post(options))
        .route("/register/verify", post(verify))
        .route("/credentials", get(list))
        .route("/credentials/{id}", axum::routing::delete(remove))
}

fn policy(policy: UserVerification) -> UserVerificationPolicy {
    match policy {
        UserVerification::Required => UserVerificationPolicy::Required,
        UserVerification::Preferred => UserVerificationPolicy::Preferred,
    }
}

/// Step one: a challenge the authenticator will sign, plus everything the
/// browser needs to decide which authenticators may answer.
async fn options(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
) -> Result<Response, Problem> {
    let session = require_session(&state, &headers, &scope).await?;
    let rp = state.rp()?;
    let (db, clock, id_gen) = ports(&state)?;

    let user = user_by_id(db, &session.user_id)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "could not read the user");
            internal(&scope)
        })?
        .ok_or_else(|| internal(&scope))?;

    // Registering the same authenticator twice would leave the account with
    // two credentials it cannot tell apart, so the browser is told which
    // ones it already holds.
    let existing = credentials_by_user(db, &session.user_id)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "could not read existing credentials");
            internal(&scope)
        })?;
    let exclude: Vec<PublicKeyCredentialDescriptor> = existing
        .iter()
        .filter(|row| row.kind == CREDENTIAL_PASSKEY)
        .filter_map(|row| row.passkey_credential_id.as_ref())
        .map(|id| PublicKeyCredentialDescriptor {
            type_: "public-key".to_owned(),
            id: challenge::credential_id_bytes(id).to_vec().into(),
            transports: None,
        })
        .collect();

    let issued = challenge::issue(
        db,
        clock,
        id_gen,
        PURPOSE_REGISTER,
        Some(&session.user_id),
        rp.challenge_ttl_secs,
    )
    .await
    .map_err(|err| {
        tracing::error!(error = %err, "could not issue a registration challenge");
        internal(&scope)
    })?;

    let response = CreationChallengeResponse {
        public_key: PublicKeyCredentialCreationOptions {
            rp: ProtoRelyingParty {
                name: rp.rp_name.clone(),
                id: rp.rp_id.clone(),
            },
            user: User {
                // The user handle is the account id, so a discoverable
                // credential can name the account without an email.
                id: session.user_id.as_bytes().to_vec().into(),
                name: user
                    .primary_email
                    .clone()
                    .unwrap_or_else(|| user.id.clone()),
                display_name: user
                    .display_name
                    .or(user.primary_email)
                    .unwrap_or_else(|| user.id.clone()),
            },
            challenge: issued.clone().into(),
            pub_key_cred_params: [COSE_ES256, COSE_RS256, COSE_EDDSA]
                .into_iter()
                .map(|alg| PubKeyCredParams {
                    type_: "public-key".to_owned(),
                    alg,
                })
                .collect(),
            timeout: Some(rp.timeout_ms),
            exclude_credentials: Some(exclude),
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                authenticator_attachment: None,
                // Discoverable where the authenticator can manage it, so
                // login without an email works, but never a hard requirement:
                // security keys with little storage would be shut out.
                resident_key: Some(ResidentKeyRequirement::Preferred),
                require_resident_key: false,
                user_verification: policy(rp.user_verification),
            }),
            hints: None,
            attestation: Some(AttestationConveyancePreference::None),
            attestation_formats: None,
            extensions: None,
        },
    };
    Ok(ok(serde_json::to_value(response).unwrap_or_default()))
}

#[derive(Debug, Deserialize)]
pub(crate) struct VerifyBody {
    credential: RegisterPublicKeyCredential,
    /// What the person calls this authenticator. Trimmed and capped;
    /// it is displayed back to them on the account page.
    label: Option<String>,
}

const MAX_LABEL_CHARS: usize = 64;

/// Step two: check the ceremony and store the credential.
async fn verify(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    Json(body): Json<VerifyBody>,
) -> Result<Response, Problem> {
    let session = require_session(&state, &headers, &scope).await?;
    let rp = state.rp()?;
    let (db, clock, id_gen) = ports(&state)?;

    let label = body
        .label
        .as_deref()
        .map(str::trim)
        .filter(|l| !l.is_empty());
    if let Some(label) = label
        && label.chars().count() > MAX_LABEL_CHARS
    {
        return Err(Problem::validation_failed(format!(
            "label must be at most {MAX_LABEL_CHARS} characters"
        )));
    }

    let presented = body.credential.response.client_data_json.as_slice();
    let challenge = challenge_from_client_data(presented).ok_or_else(|| ceremony_failed(&scope))?;

    let consumed = challenge::consume(db, clock, PURPOSE_REGISTER, &challenge)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "could not consume the registration challenge");
            internal(&scope)
        })?
        .ok_or_else(|| ceremony_failed(&scope))?;

    // The challenge was issued to this session's user. Without this check a
    // challenge handed to one account could be spent to add a passkey to
    // another.
    if consumed.user_id.as_deref() != Some(session.user_id.as_str()) {
        tracing::warn!("a registration challenge was presented by a different session");
        return Err(ceremony_failed(&scope));
    }

    let registered = verify_registration(
        &rp.rp_id,
        &rp.origins,
        &challenge,
        rp.user_verification,
        &body.credential,
    )
    .map_err(|err| {
        tracing::warn!(error = %err, "passkey registration refused");
        ceremony_failed(&scope)
    })?;

    // `excludeCredentials` is advice to the browser, not a guarantee. The
    // server enforces it.
    if passkey_by_credential_id(db, &registered.credential_id)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "could not check for an existing credential");
            internal(&scope)
        })?
        .is_some()
    {
        return Err(Problem::new(&crate::CREDENTIAL_ALREADY_REGISTERED).instance(&scope.request_id));
    }

    let now = crate::iso(clock.now());
    let credential_id = id_gen.ulid();
    insert_credential(
        db,
        &CredentialRow {
            id: credential_id.clone(),
            user_id: session.user_id.clone(),
            kind: CREDENTIAL_PASSKEY.to_owned(),
            passkey_credential_id: Some(Bytes(registered.credential_id.clone())),
            passkey_public_key_cose: Some(Bytes(registered.cose_key_raw.clone())),
            passkey_sign_count: Some(i64::from(registered.sign_count)),
            passkey_aaguid: registered.aaguid.map(|id| Bytes(id.to_vec())),
            passkey_transports: transports_of(&body.credential),
            password_hash: None,
            label: label.map(str::to_owned),
            created_at: now.clone(),
            last_used_at: None,
            passkey_suspect_at: None,
            failed_attempts: 0,
            failed_window_started_at: None,
            locked_until: None,
        },
    )
    .await
    .map_err(|err| {
        tracing::error!(error = %err, "could not store the passkey");
        internal(&scope)
    })?;

    if registered.attestation_unverified {
        // Deliberate per ADR 0100, and worth a line in the log so it is
        // visible rather than silent.
        tracing::info!(
            format = %registered.attestation_format,
            "stored a passkey whose attestation statement was not verified"
        );
    }

    state.ctx.events.emit_in(
        &scope,
        EVENT_REGISTERED,
        json!({
            "user_id": session.user_id,
            "credential_id": credential_id,
            "user_verified": registered.user_verified,
        }),
    );

    Ok(ok(json!({
        "id": credential_id,
        "label": label,
        "created_at": now,
        "aaguid": registered.aaguid.map(|id| hex(&id)),
    })))
}

/// The challenge the authenticator actually signed, read back out of the
/// client data. Verification checks it against the stored one; this only
/// finds the row.
fn challenge_from_client_data(raw: &[u8]) -> Option<Vec<u8>> {
    let parsed: webauthn_rs_proto::CollectedClientData = serde_json::from_slice(raw).ok()?;
    Some(parsed.challenge.as_slice().to_vec())
}

/// How the browser says this authenticator can be reached (`usb`,
/// `internal`, `hybrid`), stored so a later login can hint the same route.
fn transports_of(credential: &RegisterPublicKeyCredential) -> Option<String> {
    let transports = credential.response.transports.as_ref()?;
    let names: Vec<String> = transports
        .iter()
        .map(|transport| format!("{transport:?}").to_ascii_lowercase())
        .collect();
    (!names.is_empty()).then(|| names.join(","))
}

/// The account's passkeys, for the account page.
async fn list(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
) -> Result<Response, Problem> {
    let session = require_session(&state, &headers, &scope).await?;
    let (db, _, _) = ports(&state)?;
    let rows = credentials_by_user(db, &session.user_id)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "could not list credentials");
            internal(&scope)
        })?;

    let passkeys: Vec<serde_json::Value> = rows
        .iter()
        .filter(|row| row.kind == CREDENTIAL_PASSKEY)
        .map(|row| {
            json!({
                "id": row.id,
                "label": row.label,
                "created_at": row.created_at,
                "last_used_at": row.last_used_at,
                "aaguid": row.passkey_aaguid.as_ref().map(|id| hex(&id.0)),
                "transports": row.passkey_transports,
                // Surfaced rather than hidden: a person whose authenticator
                // was flagged deserves to know why it stopped working.
                "suspect_at": row.passkey_suspect_at,
                "credential_id": row
                    .passkey_credential_id
                    .as_ref()
                    .map(|id| b64u(&id.0)),
            })
        })
        .collect();
    Ok(ok(json!({ "passkeys": passkeys })))
}

/// Deleting a passkey, unless it is the way back in.
async fn remove(
    State(state): State<Arc<ModuleState>>,
    scope: Scope,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, Problem> {
    let session = require_session(&state, &headers, &scope).await?;
    let (db, _, _) = ports(&state)?;

    let credentials = credentials_by_user(db, &session.user_id)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "could not read credentials");
            internal(&scope)
        })?;
    let target = credentials
        .iter()
        .find(|row| row.id == id && row.kind == CREDENTIAL_PASSKEY)
        .ok_or_else(Problem::not_found)?;

    // A credential flagged as a possible clone is refused at login, so it is
    // not a way back into the account and must not count as one.
    let other_credentials = credentials
        .iter()
        .filter(|row| row.id != target.id && row.passkey_suspect_at.is_none())
        .count();
    let identities = identities_by_user(db, &session.user_id)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "could not read identities");
            internal(&scope)
        })?
        .len();
    if other_credentials == 0 && identities == 0 {
        return Err(Problem::new(&crate::LAST_LOGIN_METHOD).instance(&scope.request_id));
    }

    factory0_auth_core::delete_credential(db, &target.id, &session.user_id)
        .await
        .map_err(|err| {
            tracing::error!(error = %err, "could not delete the passkey");
            internal(&scope)
        })?;
    Ok(ok(json!({ "deleted": id })))
}
