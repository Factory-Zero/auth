//! Sea-query data access for the auth-core tables (harness ADR 0004:
//! queries are built, migrations are SQL). All timestamps are fixed-width
//! RFC 3339 UTC strings, so lexicographic order is chronological order,
//! and every read of the wall clock goes through the `Clock` port.
//!
//! Hash columns (`token_hash`, `password_hash`, `secret_hash`, `ip_hash`)
//! are [`Redacted`] in the row model: their `Debug` never prints the
//! digest, so a logged row cannot leak a value that can log a user in.

use factory0_core::{AnyError, Clock, Database, DbError, ModuleContext, Row, Statement};
use sea_query::{Alias, Expr, Query};
use time::format_description::well_known::Rfc3339;

pub const STATUS_ACTIVE: &str = "active";
pub const STATUS_DISABLED: &str = "disabled";

pub const PROVIDER_GOOGLE: &str = "google";
pub const PROVIDER_APPLE: &str = "apple";
pub const PROVIDER_META: &str = "meta";
pub const PROVIDER_PASSWORD: &str = "password";
pub const PROVIDER_MAGIC_LINK: &str = "magic_link";
pub const PROVIDER_PASSKEY: &str = "passkey";

pub const CREDENTIAL_PASSKEY: &str = "passkey";
pub const CREDENTIAL_PASSWORD: &str = "password";

pub const TOKEN_MAGIC_LINK: &str = "magic_link";
pub const TOKEN_WEBAUTHN_CHALLENGE: &str = "webauthn_challenge";
pub const TOKEN_AUTHORIZATION_CODE: &str = "authorization_code";
/// Opaque single-use refresh tokens (issue #9): rows of
/// `single_use_tokens` bound to a session; reuse of a consumed one
/// revokes the session.
pub const TOKEN_REFRESH: &str = "refresh_token";

pub const CLIENT_CONFIDENTIAL: &str = "confidential";
pub const CLIENT_PUBLIC: &str = "public";

/// A public binary column value (passkey credential ids, COSE keys,
/// AAGUIDs — public by design). `Debug` prints only the length.
#[derive(Clone, PartialEq, Eq)]
pub struct Bytes(pub Vec<u8>);

impl std::fmt::Debug for Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Bytes({} bytes)", self.0.len())
    }
}

/// A stored hash. The inner value is public to code but never to `Debug`,
/// so `tracing` and `{:?}` cannot leak a session hash, password hash,
/// client secret hash or IP hash.
#[derive(Clone, PartialEq, Eq)]
pub struct Redacted<T>(pub T);

impl<T> std::fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Redacted([redacted])")
    }
}

trait FromSeaValue: Sized {
    fn from_sea(value: &sea_query::Value) -> Option<Self>;
}

impl FromSeaValue for Vec<u8> {
    fn from_sea(value: &sea_query::Value) -> Option<Self> {
        match value {
            sea_query::Value::Bytes(Some(bytes)) => Some((**bytes).clone()),
            _ => None,
        }
    }
}

impl FromSeaValue for String {
    fn from_sea(value: &sea_query::Value) -> Option<Self> {
        match value {
            sea_query::Value::String(Some(s)) => Some((**s).clone()),
            sea_query::Value::Char(Some(c)) => Some(c.to_string()),
            _ => None,
        }
    }
}

/// A NOT NULL column of type `T`.
fn required<T: FromSeaValue + Default>(row: &Row, column: &str) -> T {
    row.get::<sea_query::Value>(column)
        .as_ref()
        .and_then(T::from_sea)
        .unwrap_or_default()
}

/// A nullable column of type `T`. The sqlite adapter returns every SQL
/// NULL as `Value::String(None)`, so both NULL spellings map to `None`.
fn optional<T: FromSeaValue>(row: &Row, column: &str) -> Option<T> {
    let value = row.get::<sea_query::Value>(column)?;
    match &value {
        sea_query::Value::String(None) | sea_query::Value::Bytes(None) => None,
        other => T::from_sea(other),
    }
}

fn optional_i64(row: &Row, column: &str) -> Option<i64> {
    let value = row.get::<sea_query::Value>(column)?;
    match &value {
        sea_query::Value::BigInt(Some(v)) => Some(*v),
        sea_query::Value::Int(Some(v)) => Some(i64::from(*v)),
        sea_query::Value::SmallInt(Some(v)) => Some(i64::from(*v)),
        sea_query::Value::TinyInt(Some(v)) => Some(i64::from(*v)),
        _ => None,
    }
}

/// A NOT NULL INTEGER flag. The sqlite adapter hands INTEGER columns back
/// as `Value::BigInt`, which core's `bool` conversion does not match, so
/// booleans are read through the integer path.
fn boolean(row: &Row, column: &str) -> bool {
    optional_i64(row, column).unwrap_or(0) != 0
}

fn iden(name: &str) -> Alias {
    Alias::new(name)
}

fn now_iso(clock: &dyn Clock) -> String {
    clock
        .now()
        .replace_nanosecond(0)
        .expect("truncation stays in range")
        .format(&Rfc3339)
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// users

/// One `users` row.
#[derive(Debug, Clone)]
pub struct UserRow {
    pub id: String,
    pub display_name: Option<String>,
    pub primary_email: Option<String>,
    pub primary_email_verified: bool,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

fn user_from(row: &Row) -> UserRow {
    UserRow {
        id: row.get::<String>("id").unwrap_or_default(),
        display_name: row.get::<Option<String>>("display_name").flatten(),
        primary_email: row.get::<Option<String>>("primary_email").flatten(),
        primary_email_verified: boolean(row, "primary_email_verified"),
        status: row.get::<String>("status").unwrap_or_default(),
        created_at: row.get::<String>("created_at").unwrap_or_default(),
        updated_at: row.get::<String>("updated_at").unwrap_or_default(),
    }
}

fn select_users() -> sea_query::SelectStatement {
    let mut select = Query::select();
    select
        .columns([
            "id",
            "display_name",
            "primary_email",
            "primary_email_verified",
            "status",
            "created_at",
            "updated_at",
        ])
        .from(iden("users"));
    select
}

/// Inserts a user.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails (e.g. a duplicate id).
pub async fn insert_user(db: &dyn Database, row: &UserRow) -> Result<(), DbError> {
    let mut insert = Query::insert();
    insert
        .into_table(iden("users"))
        .columns([
            "id",
            "display_name",
            "primary_email",
            "primary_email_verified",
            "status",
            "created_at",
            "updated_at",
        ])
        .values_panic([
            row.id.clone().into(),
            row.display_name.clone().into(),
            row.primary_email.clone().into(),
            row.primary_email_verified.into(),
            row.status.as_str().into(),
            row.created_at.clone().into(),
            row.updated_at.clone().into(),
        ]);
    db.execute(&Statement::render(&insert)).await?;
    Ok(())
}

/// Deletes a user row. Used for exactly one thing: undoing a user that was
/// created moments ago when linking its first identity then failed, which
/// happens when two first logins for the same provider subject race. A row
/// left behind that way carries an email and no identity, and the next
/// verified-email match would link a stranger's provider to it.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails.
pub async fn delete_user(db: &dyn Database, id: &str) -> Result<u64, DbError> {
    let mut delete = Query::delete();
    delete
        .from_table(iden("users"))
        .and_where(Expr::col(iden("id")).eq(id));
    db.execute(&Statement::render(&delete)).await
}

/// Finds a user by id.
///
/// # Errors
///
/// [`DbError::Query`] when the statement fails.
pub async fn user_by_id(db: &dyn Database, id: &str) -> Result<Option<UserRow>, DbError> {
    let query = select_users()
        .and_where(Expr::col(iden("id")).eq(id))
        .limit(1)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.first().map(user_from))
}

/// Finds a user by primary email (exact match; normalize before calling).
///
/// # Errors
///
/// [`DbError::Query`] when the statement fails.
pub async fn user_by_primary_email(
    db: &dyn Database,
    email: &str,
) -> Result<Option<UserRow>, DbError> {
    let query = select_users()
        .and_where(Expr::col(iden("primary_email")).eq(email))
        .limit(1)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.first().map(user_from))
}

// ---------------------------------------------------------------------------
// identities

/// One `identities` row: one linked provider for one user.
#[derive(Debug, Clone)]
pub struct IdentityRow {
    pub id: String,
    pub user_id: String,
    pub provider: String,
    pub provider_subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name_at_link: Option<String>,
    pub created_at: String,
    pub last_login_at: Option<String>,
}

fn identity_from(row: &Row) -> IdentityRow {
    IdentityRow {
        id: row.get::<String>("id").unwrap_or_default(),
        user_id: row.get::<String>("user_id").unwrap_or_default(),
        provider: row.get::<String>("provider").unwrap_or_default(),
        provider_subject: row.get::<String>("provider_subject").unwrap_or_default(),
        email: row.get::<Option<String>>("email").flatten(),
        email_verified: boolean(row, "email_verified"),
        name_at_link: row.get::<Option<String>>("name_at_link").flatten(),
        created_at: row.get::<String>("created_at").unwrap_or_default(),
        last_login_at: row.get::<Option<String>>("last_login_at").flatten(),
    }
}

fn select_identities() -> sea_query::SelectStatement {
    let mut select = Query::select();
    select
        .columns([
            "id",
            "user_id",
            "provider",
            "provider_subject",
            "email",
            "email_verified",
            "name_at_link",
            "created_at",
            "last_login_at",
        ])
        .from(iden("identities"));
    select
}

/// Inserts an identity. The `UNIQUE (provider, provider_subject)`
/// constraint makes a second link of the same provider subject an error,
/// which is the "one user, many identities" login lookup.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails, including a duplicate
/// `(provider, provider_subject)`.
pub async fn insert_identity(db: &dyn Database, row: &IdentityRow) -> Result<(), DbError> {
    let mut insert = Query::insert();
    insert
        .into_table(iden("identities"))
        .columns([
            "id",
            "user_id",
            "provider",
            "provider_subject",
            "email",
            "email_verified",
            "name_at_link",
            "created_at",
            "last_login_at",
        ])
        .values_panic([
            row.id.clone().into(),
            row.user_id.clone().into(),
            row.provider.as_str().into(),
            row.provider_subject.clone().into(),
            row.email.clone().into(),
            row.email_verified.into(),
            row.name_at_link.clone().into(),
            row.created_at.clone().into(),
            row.last_login_at.clone().into(),
        ]);
    db.execute(&Statement::render(&insert)).await?;
    Ok(())
}

/// The login lookup: the identity for `(provider, provider_subject)`.
///
/// # Errors
///
/// [`DbError::Query`] when the statement fails.
pub async fn identity_by_provider_subject(
    db: &dyn Database,
    provider: &str,
    provider_subject: &str,
) -> Result<Option<IdentityRow>, DbError> {
    let query = select_identities()
        .and_where(Expr::col(iden("provider")).eq(provider))
        .and_where(Expr::col(iden("provider_subject")).eq(provider_subject))
        .limit(1)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.first().map(identity_from))
}

/// Deletes one identity row by id. The caller checks first that it
/// belongs to the user and is not their last way in (issue #22).
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails.
pub async fn delete_identity(db: &dyn Database, id: &str) -> Result<u64, DbError> {
    let mut delete = Query::delete();
    delete
        .from_table(iden("identities"))
        .and_where(Expr::col(iden("id")).eq(id));
    db.execute(&Statement::render(&delete)).await
}

/// Every identity linked to a user (the account-linking view).
///
/// # Errors
///
/// [`DbError::Query`] when the statement fails.
pub async fn identities_by_user(
    db: &dyn Database,
    user_id: &str,
) -> Result<Vec<IdentityRow>, DbError> {
    let query = select_identities()
        .and_where(Expr::col(iden("user_id")).eq(user_id))
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.rows.iter().map(identity_from).collect())
}

/// Records a successful login on an identity; `0` when the id is gone.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails.
pub async fn touch_identity_login(
    db: &dyn Database,
    id: &str,
    last_login_at: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden("identities"))
        .values([(iden("last_login_at"), last_login_at.into())])
        .and_where(Expr::col(iden("id")).eq(id));
    db.execute(&Statement::render(&update)).await
}

// ---------------------------------------------------------------------------
// credentials

/// One `credentials` row: a passkey or a password hash.
#[derive(Debug, Clone)]
pub struct CredentialRow {
    pub id: String,
    pub user_id: String,
    pub kind: String,
    pub passkey_credential_id: Option<Bytes>,
    pub passkey_public_key_cose: Option<Bytes>,
    pub passkey_sign_count: Option<i64>,
    pub passkey_aaguid: Option<Bytes>,
    pub passkey_transports: Option<String>,
    pub password_hash: Option<Redacted<String>>,
    pub label: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    /// When a signature-counter regression was seen on this passkey
    /// (issue #14). Set means the credential is refused at login: the
    /// counter going backwards is the one clone signal `WebAuthn` offers.
    pub passkey_suspect_at: Option<String>,
    /// Failed password attempts in the current window (issue #12).
    pub failed_attempts: i64,
    /// When the current failure window began. A count with no window is a
    /// lifetime total, which locks out anyone who has ever mistyped enough
    /// times across years.
    pub failed_window_started_at: Option<String>,
    /// Set once the count crosses the threshold. Until it passes, even a
    /// correct password is refused: that is the point.
    pub locked_until: Option<String>,
}

fn credential_from(row: &Row) -> CredentialRow {
    CredentialRow {
        id: row.get::<String>("id").unwrap_or_default(),
        user_id: row.get::<String>("user_id").unwrap_or_default(),
        kind: row.get::<String>("kind").unwrap_or_default(),
        passkey_credential_id: optional::<Vec<u8>>(row, "passkey_credential_id").map(Bytes),
        passkey_public_key_cose: optional::<Vec<u8>>(row, "passkey_public_key_cose").map(Bytes),
        passkey_sign_count: optional_i64(row, "passkey_sign_count"),
        passkey_aaguid: optional::<Vec<u8>>(row, "passkey_aaguid").map(Bytes),
        passkey_transports: row.get::<Option<String>>("passkey_transports").flatten(),
        password_hash: optional::<String>(row, "password_hash").map(Redacted),
        label: row.get::<Option<String>>("label").flatten(),
        created_at: row.get::<String>("created_at").unwrap_or_default(),
        last_used_at: row.get::<Option<String>>("last_used_at").flatten(),
        passkey_suspect_at: row.get::<Option<String>>("passkey_suspect_at").flatten(),
        failed_attempts: optional_i64(row, "failed_attempts").unwrap_or_default(),
        failed_window_started_at: row
            .get::<Option<String>>("failed_window_started_at")
            .flatten(),
        locked_until: row.get::<Option<String>>("locked_until").flatten(),
    }
}

fn select_credentials() -> sea_query::SelectStatement {
    let mut select = Query::select();
    select
        .columns([
            "id",
            "user_id",
            "kind",
            "passkey_credential_id",
            "passkey_public_key_cose",
            "passkey_sign_count",
            "passkey_aaguid",
            "passkey_transports",
            "password_hash",
            "label",
            "created_at",
            "last_used_at",
            "passkey_suspect_at",
            "failed_attempts",
            "failed_window_started_at",
            "locked_until",
        ])
        .from(iden("credentials"));
    select
}

/// Inserts a credential.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails, including a duplicate
/// `passkey_credential_id`.
pub async fn insert_credential(db: &dyn Database, row: &CredentialRow) -> Result<(), DbError> {
    let mut insert = Query::insert();
    insert
        .into_table(iden("credentials"))
        .columns([
            "id",
            "user_id",
            "kind",
            "passkey_credential_id",
            "passkey_public_key_cose",
            "passkey_sign_count",
            "passkey_aaguid",
            "passkey_transports",
            "password_hash",
            "label",
            "created_at",
            "last_used_at",
        ])
        .values_panic([
            row.id.clone().into(),
            row.user_id.clone().into(),
            row.kind.as_str().into(),
            row.passkey_credential_id
                .as_ref()
                .map(|bytes| bytes.0.clone())
                .into(),
            row.passkey_public_key_cose
                .as_ref()
                .map(|bytes| bytes.0.clone())
                .into(),
            row.passkey_sign_count.into(),
            row.passkey_aaguid
                .as_ref()
                .map(|bytes| bytes.0.clone())
                .into(),
            row.passkey_transports.clone().into(),
            row.password_hash.as_ref().map(|hash| hash.0.clone()).into(),
            row.label.clone().into(),
            row.created_at.clone().into(),
            row.last_used_at.clone().into(),
        ]);
    db.execute(&Statement::render(&insert)).await?;
    Ok(())
}

/// The assertion lookup: the passkey credential row for a credential id.
///
/// # Errors
///
/// [`DbError::Query`] when the statement fails.
pub async fn passkey_by_credential_id(
    db: &dyn Database,
    credential_id: &[u8],
) -> Result<Option<CredentialRow>, DbError> {
    let query = select_credentials()
        .and_where(Expr::col(iden("passkey_credential_id")).eq(credential_id.to_vec()))
        .limit(1)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.first().map(credential_from))
}

/// Every credential of a user (passkeys and the password hash).
///
/// # Errors
///
/// [`DbError::Query`] when the statement fails.
pub async fn credentials_by_user(
    db: &dyn Database,
    user_id: &str,
) -> Result<Vec<CredentialRow>, DbError> {
    let query = select_credentials()
        .and_where(Expr::col(iden("user_id")).eq(user_id))
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.rows.iter().map(credential_from).collect())
}

/// Updates a passkey's signature counter and `last_used_at`; `0` when the
/// row is gone or not a passkey.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails.
pub async fn update_passkey_sign_count(
    db: &dyn Database,
    id: &str,
    sign_count: i64,
    last_used_at: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden("credentials"))
        .values([
            (iden("passkey_sign_count"), sign_count.into()),
            (iden("last_used_at"), last_used_at.into()),
        ])
        .and_where(Expr::col(iden("id")).eq(id))
        .and_where(Expr::col(iden("kind")).eq(CREDENTIAL_PASSKEY))
        // Monotonic, and never on a credential already flagged as a possible
        // clone. Two assertions in flight together can arrive out of order,
        // and storing the lower counter would hand back the advance that the
        // clone check depends on.
        .and_where(Expr::col(iden("passkey_suspect_at")).is_null())
        .cond_where(
            sea_query::Cond::any()
                .add(Expr::col(iden("passkey_sign_count")).is_null())
                .add(Expr::col(iden("passkey_sign_count")).lte(sign_count)),
        );
    db.execute(&Statement::render(&update)).await
}

/// Deletes one of a user's credentials, returning the affected-row count.
/// The owner is part of the statement rather than checked beforehand, so a
/// caller cannot delete somebody else's credential by passing the wrong id.
/// Whether removing it strands the account is the caller's judgement.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails.
pub async fn delete_credential(db: &dyn Database, id: &str, user_id: &str) -> Result<u64, DbError> {
    let mut delete = Query::delete();
    delete
        .from_table(iden("credentials"))
        .and_where(Expr::col(iden("id")).eq(id))
        .and_where(Expr::col(iden("user_id")).eq(user_id));
    db.execute(&Statement::render(&delete)).await
}

/// Marks a passkey as suspect after a signature-counter regression
/// (issue #14), and returns the affected-row count. Set once: the first
/// regression is the signal, and later attempts are refused before they
/// reach verification.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails.
pub async fn mark_passkey_suspect(
    db: &dyn Database,
    id: &str,
    suspect_at: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden("credentials"))
        .values([(iden("passkey_suspect_at"), suspect_at.into())])
        .and_where(Expr::col(iden("id")).eq(id))
        .and_where(Expr::col(iden("passkey_suspect_at")).is_null());
    db.execute(&Statement::render(&update)).await
}

/// Records a credential use; `0` when the id is gone.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails.
pub async fn touch_credential_used(
    db: &dyn Database,
    id: &str,
    last_used_at: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden("credentials"))
        .values([(iden("last_used_at"), last_used_at.into())])
        .and_where(Expr::col(iden("id")).eq(id));
    db.execute(&Statement::render(&update)).await
}

// ---------------------------------------------------------------------------
// sessions

/// One `sessions` row. `token_hash` is the sha256 of the cookie value;
/// the value itself is never stored. `amr` is the JSON array of
/// authentication-method references recorded at login (issue #9),
/// `None` until a login method exists.
#[derive(Debug, Clone)]
pub struct SessionRow {
    pub id: String,
    pub user_id: String,
    pub token_hash: Redacted<Vec<u8>>,
    pub created_at: String,
    pub last_seen_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
    pub ip_hash: Option<Redacted<String>>,
    pub ua_family: Option<String>,
    pub amr: Option<String>,
}

fn session_from(row: &Row) -> SessionRow {
    SessionRow {
        id: row.get::<String>("id").unwrap_or_default(),
        user_id: row.get::<String>("user_id").unwrap_or_default(),
        token_hash: Redacted(required(row, "token_hash")),
        created_at: row.get::<String>("created_at").unwrap_or_default(),
        last_seen_at: row.get::<String>("last_seen_at").unwrap_or_default(),
        expires_at: row.get::<String>("expires_at").unwrap_or_default(),
        revoked_at: row.get::<Option<String>>("revoked_at").flatten(),
        ip_hash: optional::<String>(row, "ip_hash").map(Redacted),
        ua_family: row.get::<Option<String>>("ua_family").flatten(),
        amr: row.get::<Option<String>>("amr").flatten(),
    }
}

fn select_sessions() -> sea_query::SelectStatement {
    let mut select = Query::select();
    select
        .columns([
            "id",
            "user_id",
            "token_hash",
            "created_at",
            "last_seen_at",
            "expires_at",
            "revoked_at",
            "ip_hash",
            "ua_family",
            "amr",
        ])
        .from(iden("sessions"));
    select
}

/// Inserts a session.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails, including a duplicate
/// `token_hash`.
pub async fn insert_session(db: &dyn Database, row: &SessionRow) -> Result<(), DbError> {
    let mut insert = Query::insert();
    insert
        .into_table(iden("sessions"))
        .columns([
            "id",
            "user_id",
            "token_hash",
            "created_at",
            "last_seen_at",
            "expires_at",
            "revoked_at",
            "ip_hash",
            "ua_family",
            "amr",
        ])
        .values_panic([
            row.id.clone().into(),
            row.user_id.clone().into(),
            row.token_hash.0.clone().into(),
            row.created_at.clone().into(),
            row.last_seen_at.clone().into(),
            row.expires_at.clone().into(),
            row.revoked_at.clone().into(),
            row.ip_hash.as_ref().map(|hash| hash.0.clone()).into(),
            row.ua_family.clone().into(),
            row.amr.clone().into(),
        ]);
    db.execute(&Statement::render(&insert)).await?;
    Ok(())
}

/// The cookie lookup: the session for a token hash.
///
/// # Errors
///
/// [`DbError::Query`] when the statement fails.
pub async fn session_by_token_hash(
    db: &dyn Database,
    token_hash: &[u8],
) -> Result<Option<SessionRow>, DbError> {
    let query = select_sessions()
        .and_where(Expr::col(iden("token_hash")).eq(token_hash.to_vec()))
        .limit(1)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.first().map(session_from))
}

/// The id lookup: the session row for a session id (issue #9 — the
/// token endpoints read liveness, user and `amr` from the session a
/// grant is bound to).
///
/// # Errors
///
/// [`DbError::Query`] when the statement fails.
pub async fn session_by_id(db: &dyn Database, id: &str) -> Result<Option<SessionRow>, DbError> {
    let query = select_sessions()
        .and_where(Expr::col(iden("id")).eq(id))
        .limit(1)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.first().map(session_from))
}

/// Records activity on a session; `0` when the id is gone.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails.
pub async fn touch_session_seen(
    db: &dyn Database,
    id: &str,
    last_seen_at: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden("sessions"))
        .values([(iden("last_seen_at"), last_seen_at.into())])
        .and_where(Expr::col(iden("id")).eq(id));
    db.execute(&Statement::render(&update)).await
}

/// Slides a live session: refreshes `last_seen_at` and pushes
/// `expires_at` out, in one guarded update that loses cleanly when the
/// session was revoked or expired in the same instant. `0` rows means
/// the slide did not land.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails.
pub async fn slide_session(
    db: &dyn Database,
    id: &str,
    last_seen_at: &str,
    expires_at: &str,
    now: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden("sessions"))
        .values([
            (iden("last_seen_at"), last_seen_at.into()),
            (iden("expires_at"), expires_at.into()),
        ])
        .and_where(Expr::col(iden("id")).eq(id))
        .and_where(Expr::col(iden("revoked_at")).is_null())
        .and_where(Expr::col(iden("expires_at")).gt(now));
    db.execute(&Statement::render(&update)).await
}

/// Every session of a user (live and revoked), oldest first — the
/// account-page listing; callers filter what they show.
///
/// # Errors
///
/// [`DbError::Query`] when the statement fails.
pub async fn sessions_by_user(
    db: &dyn Database,
    user_id: &str,
) -> Result<Vec<SessionRow>, DbError> {
    let query = select_sessions()
        .and_where(Expr::col(iden("user_id")).eq(user_id))
        .order_by(iden("created_at"), sea_query::Order::Asc)
        .order_by(iden("id"), sea_query::Order::Asc)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.rows.iter().map(session_from).collect())
}

/// Revokes a session; guarded, so a second revoke reports `0`.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails.
pub async fn revoke_session(db: &dyn Database, id: &str, revoked_at: &str) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden("sessions"))
        .values([(iden("revoked_at"), revoked_at.into())])
        .and_where(Expr::col(iden("id")).eq(id))
        .and_where(Expr::col(iden("revoked_at")).is_null());
    db.execute(&Statement::render(&update)).await
}

/// Revokes every live session of a user at once — the password-change
/// and account-disable path. Returns how many rows flipped.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails.
pub async fn revoke_all_sessions(
    db: &dyn Database,
    user_id: &str,
    revoked_at: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden("sessions"))
        .values([(iden("revoked_at"), revoked_at.into())])
        .and_where(Expr::col(iden("user_id")).eq(user_id))
        .and_where(Expr::col(iden("revoked_at")).is_null());
    db.execute(&Statement::render(&update)).await
}

/// Deletes sessions whose `expires_at` has passed; returns the count.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails.
pub async fn purge_expired_sessions(db: &dyn Database, now: &str) -> Result<u64, DbError> {
    let mut delete = Query::delete();
    delete
        .from_table(iden("sessions"))
        .and_where(Expr::col(iden("expires_at")).lte(now));
    db.execute(&Statement::render(&delete)).await
}

// ---------------------------------------------------------------------------
// single_use_tokens

/// One `single_use_tokens` row: a magic link, `WebAuthn` challenge or
/// authorization code, stored as a hash with a `kind`.
#[derive(Debug, Clone)]
pub struct SingleUseTokenRow {
    pub id: String,
    pub kind: String,
    pub token_hash: Redacted<Vec<u8>>,
    pub user_id: Option<String>,
    pub client_id: Option<String>,
    pub payload: Option<String>,
    pub expires_at: String,
    pub consumed_at: Option<String>,
}

fn single_use_token_from(row: &Row) -> SingleUseTokenRow {
    SingleUseTokenRow {
        id: row.get::<String>("id").unwrap_or_default(),
        kind: row.get::<String>("kind").unwrap_or_default(),
        token_hash: Redacted(required(row, "token_hash")),
        user_id: row.get::<Option<String>>("user_id").flatten(),
        client_id: row.get::<Option<String>>("client_id").flatten(),
        payload: row.get::<Option<String>>("payload").flatten(),
        expires_at: row.get::<String>("expires_at").unwrap_or_default(),
        consumed_at: row.get::<Option<String>>("consumed_at").flatten(),
    }
}

fn select_single_use_tokens() -> sea_query::SelectStatement {
    let mut select = Query::select();
    select
        .columns([
            "id",
            "kind",
            "token_hash",
            "user_id",
            "client_id",
            "payload",
            "expires_at",
            "consumed_at",
        ])
        .from(iden("single_use_tokens"));
    select
}

/// Inserts a single-use token.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails, including a duplicate
/// `token_hash`.
pub async fn insert_single_use_token(
    db: &dyn Database,
    row: &SingleUseTokenRow,
) -> Result<(), DbError> {
    let mut insert = Query::insert();
    insert
        .into_table(iden("single_use_tokens"))
        .columns([
            "id",
            "kind",
            "token_hash",
            "user_id",
            "client_id",
            "payload",
            "expires_at",
            "consumed_at",
        ])
        .values_panic([
            row.id.clone().into(),
            row.kind.as_str().into(),
            row.token_hash.0.clone().into(),
            row.user_id.clone().into(),
            row.client_id.clone().into(),
            row.payload.clone().into(),
            row.expires_at.clone().into(),
            row.consumed_at.clone().into(),
        ]);
    db.execute(&Statement::render(&insert)).await?;
    Ok(())
}

/// Finds a single-use token by its hash (to learn the id and payload; the
/// consume guard is [`consume_single_use_token`]).
///
/// # Errors
///
/// [`DbError::Query`] when the statement fails.
pub async fn single_use_token_by_hash(
    db: &dyn Database,
    token_hash: &[u8],
) -> Result<Option<SingleUseTokenRow>, DbError> {
    let query = select_single_use_tokens()
        .and_where(Expr::col(iden("token_hash")).eq(token_hash.to_vec()))
        .limit(1)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.first().map(single_use_token_from))
}

async fn single_use_token_by_id(
    db: &dyn Database,
    id: &str,
) -> Result<Option<SingleUseTokenRow>, DbError> {
    let query = select_single_use_tokens()
        .and_where(Expr::col(iden("id")).eq(id))
        .limit(1)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.first().map(single_use_token_from))
}

/// Consumes a single-use token: a guarded update that stamps
/// `consumed_at` only when the row is unconsumed and unexpired, with the
/// affected-row count checked — so of two concurrent consumes, at most
/// one sees `Some` and wins. `None` means already consumed, expired or
/// gone; the caller must treat the token as invalid either way.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails.
pub async fn consume_single_use_token(
    db: &dyn Database,
    id: &str,
    now: &str,
) -> Result<Option<SingleUseTokenRow>, DbError> {
    let mut update = Query::update();
    update
        .table(iden("single_use_tokens"))
        .values([(iden("consumed_at"), now.into())])
        .and_where(Expr::col(iden("id")).eq(id))
        .and_where(Expr::col(iden("consumed_at")).is_null())
        .and_where(Expr::col(iden("expires_at")).gt(now));
    let won = db.execute(&Statement::render(&update)).await?;
    if won == 0 {
        return Ok(None);
    }
    single_use_token_by_id(db, id).await
}

/// Deletes single-use tokens whose `expires_at` has passed (consumed or
/// not); returns the count.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails.
pub async fn purge_expired_single_use_tokens(db: &dyn Database, now: &str) -> Result<u64, DbError> {
    let mut delete = Query::delete();
    delete
        .from_table(iden("single_use_tokens"))
        .and_where(Expr::col(iden("expires_at")).lte(now));
    db.execute(&Statement::render(&delete)).await
}

// ---------------------------------------------------------------------------
// clients

/// One `clients` row: a registered consuming app. `secret_hash` is a
/// hash of the client secret; the secret itself is never stored. After
/// a rotation, `previous_secret_hash` keeps verifying until
/// `previous_hash_expires_at` passes (issue #6).
#[derive(Debug, Clone)]
pub struct ClientRow {
    pub id: String,
    pub name: String,
    pub secret_hash: Redacted<String>,
    pub previous_secret_hash: Option<Redacted<String>>,
    pub previous_hash_expires_at: Option<String>,
    pub kind: String,
    pub status: String,
    pub created_at: String,
}

fn client_from(row: &Row) -> ClientRow {
    ClientRow {
        id: row.get::<String>("id").unwrap_or_default(),
        name: row.get::<String>("name").unwrap_or_default(),
        secret_hash: Redacted(required(row, "secret_hash")),
        previous_secret_hash: optional::<String>(row, "previous_secret_hash").map(Redacted),
        previous_hash_expires_at: optional::<String>(row, "previous_hash_expires_at"),
        kind: row.get::<String>("kind").unwrap_or_default(),
        status: row.get::<String>("status").unwrap_or_default(),
        created_at: row.get::<String>("created_at").unwrap_or_default(),
    }
}

/// One `client_redirect_uris` row. No wildcards: the PKCE `redirect_uri`
/// must equal one of these exactly (later issues).
#[derive(Debug, Clone)]
pub struct ClientRedirectUriRow {
    pub client_id: String,
    pub uri: String,
}

fn select_clients() -> sea_query::SelectStatement {
    let mut select = Query::select();
    select
        .columns([
            "id",
            "name",
            "secret_hash",
            "previous_secret_hash",
            "previous_hash_expires_at",
            "kind",
            "status",
            "created_at",
        ])
        .from(iden("clients"));
    select
}

/// Inserts a client.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails.
pub async fn insert_client(db: &dyn Database, row: &ClientRow) -> Result<(), DbError> {
    let mut insert = Query::insert();
    insert
        .into_table(iden("clients"))
        .columns([
            "id",
            "name",
            "secret_hash",
            "previous_secret_hash",
            "previous_hash_expires_at",
            "kind",
            "status",
            "created_at",
        ])
        .values_panic([
            row.id.clone().into(),
            row.name.clone().into(),
            row.secret_hash.0.clone().into(),
            row.previous_secret_hash
                .as_ref()
                .map(|hash| hash.0.clone())
                .into(),
            row.previous_hash_expires_at.clone().into(),
            row.kind.as_str().into(),
            row.status.as_str().into(),
            row.created_at.clone().into(),
        ]);
    db.execute(&Statement::render(&insert)).await?;
    Ok(())
}

/// Finds a client by id.
///
/// # Errors
///
/// [`DbError::Query`] when the statement fails.
pub async fn client_by_id(db: &dyn Database, id: &str) -> Result<Option<ClientRow>, DbError> {
    let query = select_clients()
        .and_where(Expr::col(iden("id")).eq(id))
        .limit(1)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.first().map(client_from))
}

/// Every client, oldest first (display order for the admin list).
///
/// # Errors
///
/// [`DbError::Query`] when the statement fails.
pub async fn list_clients(db: &dyn Database) -> Result<Vec<ClientRow>, DbError> {
    let query = select_clients()
        .order_by(iden("created_at"), sea_query::Order::Asc)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.rows.iter().map(client_from).collect())
}

/// Rotates a client secret in one guarded statement: the current hash
/// becomes the previous hash, expiring at `previous_hash_expires_at`,
/// and the new hash takes over. Returns `0` when the id is gone.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails.
pub async fn rotate_client_secret(
    db: &dyn Database,
    id: &str,
    new_secret_hash: &str,
    previous_hash_expires_at: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden("clients"))
        .values([
            (
                iden("previous_secret_hash"),
                Expr::col(iden("secret_hash")).into(),
            ),
            (
                iden("previous_hash_expires_at"),
                previous_hash_expires_at.into(),
            ),
            (iden("secret_hash"), new_secret_hash.into()),
        ])
        .and_where(Expr::col(iden("id")).eq(id));
    db.execute(&Statement::render(&update)).await
}

/// Updates a client's display name; `0` when the id is gone.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails.
pub async fn update_client_name(db: &dyn Database, id: &str, name: &str) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden("clients"))
        .values([(iden("name"), name.into())])
        .and_where(Expr::col(iden("id")).eq(id));
    db.execute(&Statement::render(&update)).await
}

/// Updates a client's status (`active`/`disabled`); `0` when the id is
/// gone. A disabled client fails every flow.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails.
pub async fn update_client_status(
    db: &dyn Database,
    id: &str,
    status: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden("clients"))
        .values([(iden("status"), status.into())])
        .and_where(Expr::col(iden("id")).eq(id));
    db.execute(&Statement::render(&update)).await
}

/// Replaces a client's redirect URIs wholesale in one batch, so a
/// reader never sees half the list. Issue #7's validator runs before
/// this is called; the database itself keeps only the exact strings.
///
/// # Errors
///
/// [`DbError::Batch`] when the batch fails (e.g. a duplicate URI).
pub async fn replace_redirect_uris(
    db: &dyn Database,
    client_id: &str,
    uris: &[String],
) -> Result<(), DbError> {
    let mut stmts = Vec::with_capacity(uris.len() + 1);
    let mut delete = Query::delete();
    delete
        .from_table(iden("client_redirect_uris"))
        .and_where(Expr::col(iden("client_id")).eq(client_id));
    stmts.push(Statement::render(&delete));
    for uri in uris {
        let mut insert = Query::insert();
        insert
            .into_table(iden("client_redirect_uris"))
            .columns(["client_id", "uri"])
            .values_panic([client_id.to_owned().into(), uri.clone().into()]);
        stmts.push(Statement::render(&insert));
    }
    db.batch(&stmts).await
}

/// Inserts one exact redirect URI for a client.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails, including a duplicate
/// `(client_id, uri)`.
pub async fn insert_redirect_uri(
    db: &dyn Database,
    row: &ClientRedirectUriRow,
) -> Result<(), DbError> {
    let mut insert = Query::insert();
    insert
        .into_table(iden("client_redirect_uris"))
        .columns(["client_id", "uri"])
        .values_panic([row.client_id.clone().into(), row.uri.clone().into()]);
    db.execute(&Statement::render(&insert)).await?;
    Ok(())
}

/// The exact redirect URIs registered for a client.
///
/// # Errors
///
/// [`DbError::Query`] when the statement fails.
pub async fn redirect_uris_for_client(
    db: &dyn Database,
    client_id: &str,
) -> Result<Vec<ClientRedirectUriRow>, DbError> {
    let mut select = Query::select();
    select
        .columns(["client_id", "uri"])
        .from(iden("client_redirect_uris"))
        .and_where(Expr::col(iden("client_id")).eq(client_id));
    let rows = db.query(&Statement::render(&select)).await?;
    Ok(rows
        .rows
        .iter()
        .map(|row| ClientRedirectUriRow {
            client_id: row.get::<String>("client_id").unwrap_or_default(),
            uri: row.get::<String>("uri").unwrap_or_default(),
        })
        .collect())
}

// ---------------------------------------------------------------------------
// scheduled purge

/// The module's scheduled work: delete expired `single_use_tokens` and
/// expired `sessions`. The cutoff comes from the `Clock` port — never a
/// wall clock read (ADR 0100).
pub(crate) async fn scheduled_purge(ctx: &ModuleContext, cron: &str) -> Result<(), AnyError> {
    let (Some(db), Some(clock)) = (ctx.ports.db.clone(), ctx.ports.clock.clone()) else {
        return Ok(());
    };
    let now = now_iso(&*clock);
    let tokens = purge_expired_single_use_tokens(&*db, &now)
        .await
        .map_err(|err| Box::new(err) as AnyError)?;
    let sessions = purge_expired_sessions(&*db, &now)
        .await
        .map_err(|err| Box::new(err) as AnyError)?;
    if tokens + sessions > 0 {
        tracing::info!(cron, tokens, sessions, "purged expired auth rows");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// deletion_jobs (issue #18)

pub const DELETION_PENDING: &str = "pending";
pub const DELETION_DONE: &str = "done";

/// What carrying out a deletion request actually did.
pub const DELETION_UNLINKED: &str = "unlinked";
pub const DELETION_DELETED_USER: &str = "deleted_user";
pub const DELETION_NOTHING_TO_DO: &str = "nothing_to_do";

/// A provider's request to delete a person's data, recorded before it is
/// carried out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletionJobRow {
    pub id: String,
    pub provider: String,
    pub provider_subject: String,
    pub confirmation_code: String,
    pub status: String,
    pub outcome: Option<String>,
    pub created_at: String,
    pub completed_at: Option<String>,
}

fn deletion_job_from(row: &Row) -> DeletionJobRow {
    DeletionJobRow {
        id: row.get::<String>("id").unwrap_or_default(),
        provider: row.get::<String>("provider").unwrap_or_default(),
        provider_subject: row.get::<String>("provider_subject").unwrap_or_default(),
        confirmation_code: row.get::<String>("confirmation_code").unwrap_or_default(),
        status: row.get::<String>("status").unwrap_or_default(),
        outcome: row.get::<String>("outcome"),
        created_at: row.get::<String>("created_at").unwrap_or_default(),
        completed_at: row.get::<String>("completed_at"),
    }
}

fn select_deletion_jobs() -> sea_query::SelectStatement {
    Query::select()
        .columns([
            iden("id"),
            iden("provider"),
            iden("provider_subject"),
            iden("confirmation_code"),
            iden("status"),
            iden("outcome"),
            iden("created_at"),
            iden("completed_at"),
        ])
        .from(iden("deletion_jobs"))
        .to_owned()
}

/// Records a deletion request.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails, including the unique
/// constraint on `confirmation_code`.
pub async fn insert_deletion_job(db: &dyn Database, row: &DeletionJobRow) -> Result<(), DbError> {
    let mut insert = Query::insert();
    insert
        .into_table(iden("deletion_jobs"))
        .columns([
            iden("id"),
            iden("provider"),
            iden("provider_subject"),
            iden("confirmation_code"),
            iden("status"),
            iden("outcome"),
            iden("created_at"),
            iden("completed_at"),
        ])
        .values_panic([
            row.id.clone().into(),
            row.provider.clone().into(),
            row.provider_subject.clone().into(),
            row.confirmation_code.clone().into(),
            row.status.clone().into(),
            row.outcome.clone().into(),
            row.created_at.clone().into(),
            row.completed_at.clone().into(),
        ]);
    db.execute(&Statement::render(&insert)).await?;
    Ok(())
}

/// The job a confirmation code names, for the status page.
///
/// # Errors
///
/// [`DbError::Query`] when the statement fails.
pub async fn deletion_job_by_code(
    db: &dyn Database,
    confirmation_code: &str,
) -> Result<Option<DeletionJobRow>, DbError> {
    let query = select_deletion_jobs()
        .and_where(Expr::col(iden("confirmation_code")).eq(confirmation_code))
        .limit(1)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.first().map(deletion_job_from))
}

/// Pending jobs, oldest first, for the scheduled handler.
///
/// # Errors
///
/// [`DbError::Query`] when the statement fails.
pub async fn pending_deletion_jobs(
    db: &dyn Database,
    limit: u64,
) -> Result<Vec<DeletionJobRow>, DbError> {
    let query = select_deletion_jobs()
        .and_where(Expr::col(iden("status")).eq(DELETION_PENDING))
        .order_by(iden("created_at"), sea_query::Order::Asc)
        .limit(limit)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.rows.iter().map(deletion_job_from).collect())
}

/// Marks a job done and records what it did.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails.
pub async fn complete_deletion_job(
    db: &dyn Database,
    id: &str,
    outcome: &str,
    completed_at: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden("deletion_jobs"))
        .values([
            (iden("status"), DELETION_DONE.into()),
            (iden("outcome"), outcome.into()),
            (iden("completed_at"), completed_at.into()),
        ])
        .and_where(Expr::col(iden("id")).eq(id))
        // Only a pending job completes. Two schedulers racing the same row
        // would otherwise both do the work and both report success.
        .and_where(Expr::col(iden("status")).eq(DELETION_PENDING));
    db.execute(&Statement::render(&update)).await
}

/// Removes a user and everything that points at them.
///
/// `delete_user` alone cannot do this: `identities`, `credentials` and
/// `sessions` all carry `user_id TEXT NOT NULL REFERENCES users(id)` with
/// no cascade, so deleting the user first fails the constraint. Revoking
/// sessions is not deleting them either — a revoked row is still a row,
/// and this is an erasure.
///
/// The order is the foreign keys' order, children first. `single_use_tokens`
/// has no constraint but does carry `user_id`, and a half-spent magic link
/// is the person's data as much as anything else.
///
/// **This function is part of the schema.** A table that gains a `user_id`
/// and is not added here leaves rows behind that an erasure was supposed to
/// remove, and nothing will fail to say so.
///
/// # Errors
///
/// [`DbError::Execute`] when any statement fails. Not a transaction: the
/// `Database` port has none that spans statements, so a failure part-way
/// leaves the rows it already removed removed. The caller retries, and the
/// retry is harmless because every step is a delete.
pub async fn purge_user(db: &dyn Database, user_id: &str) -> Result<u64, DbError> {
    let mut removed = 0;
    for table in ["single_use_tokens", "sessions", "credentials", "identities"] {
        let mut delete = Query::delete();
        delete
            .from_table(iden(table))
            .and_where(Expr::col(iden("user_id")).eq(user_id));
        removed += db.execute(&Statement::render(&delete)).await?;
    }
    removed += delete_user(db, user_id).await?;
    Ok(removed)
}

/// The password credential for a user, if they have one.
///
/// # Errors
///
/// [`DbError::Query`] when the statement fails.
pub async fn password_credential(
    db: &dyn Database,
    user_id: &str,
) -> Result<Option<CredentialRow>, DbError> {
    let query = select_credentials()
        .and_where(Expr::col(iden("user_id")).eq(user_id))
        .and_where(Expr::col(iden("kind")).eq(CREDENTIAL_PASSWORD))
        .limit(1)
        .to_owned();
    let rows = db.query(&Statement::render(&query)).await?;
    Ok(rows.first().map(credential_from))
}

/// Replaces a password credential's hash and clears its lockout.
///
/// Used by a password change and by a rehash on login, which is why it
/// resets the counter: both mean the person proved they hold the password.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails.
pub async fn set_password_hash(
    db: &dyn Database,
    id: &str,
    password_hash: &str,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden("credentials"))
        .values([
            (iden("password_hash"), password_hash.into()),
            (iden("failed_attempts"), 0.into()),
            (
                iden("failed_window_started_at"),
                sea_query::Value::String(None).into(),
            ),
            (iden("locked_until"), sea_query::Value::String(None).into()),
        ])
        .and_where(Expr::col(iden("id")).eq(id));
    db.execute(&Statement::render(&update)).await
}

/// Records the lockout state after an attempt.
///
/// One statement rather than a read-modify-write from the caller, so two
/// concurrent failures cannot both read `4` and both write `5`. It is
/// still not atomic — the `Database` port has no compare-and-set — so the
/// worst case is one lost increment under exactly simultaneous requests,
/// which costs an attacker nothing and a person nothing.
///
/// # Errors
///
/// [`DbError::Execute`] when the statement fails.
pub async fn set_password_lockout(
    db: &dyn Database,
    id: &str,
    failed_attempts: i64,
    window_started_at: Option<&str>,
    locked_until: Option<&str>,
) -> Result<u64, DbError> {
    let mut update = Query::update();
    update
        .table(iden("credentials"))
        .values([
            (iden("failed_attempts"), failed_attempts.into()),
            (
                iden("failed_window_started_at"),
                window_started_at.map_or(sea_query::Value::String(None).into(), Into::into),
            ),
            (
                iden("locked_until"),
                locked_until.map_or(sea_query::Value::String(None).into(), Into::into),
            ),
        ])
        .and_where(Expr::col(iden("id")).eq(id));
    db.execute(&Statement::render(&update)).await
}
