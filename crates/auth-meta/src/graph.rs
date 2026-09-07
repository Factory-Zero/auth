//! The two calls Facebook Login actually needs, and the bridge that lets
//! `oauth2` make one of them through the harness `HttpClient` port.
//!
//! There is no discovery document and no ID token: the endpoints are
//! constants, and the profile is a Graph call whose answer is trusted
//! because the access token behind it came from our own back-channel
//! exchange, authenticated with the app secret. See ADR 0104.

use bytes::Bytes;
use factory0_core::HttpClient;
use serde::Deserialize;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// The Graph API version every endpoint is built from.
///
/// Meta retires a version roughly two years after release and an expired
/// one starts answering errors, so this is configurable
/// (`AUTH_META_GRAPH_VERSION`) rather than compiled in alone: an operator
/// must be able to move it without waiting for a release. **Check it
/// before a deployment**; the default is the version this was written
/// against, not a promise about today.
pub(crate) const DEFAULT_GRAPH_VERSION: &str = "v21.0";

pub(crate) fn authorization_endpoint(version: &str) -> String {
    format!("https://www.facebook.com/{version}/dialog/oauth")
}

pub(crate) fn token_endpoint(version: &str) -> String {
    format!("https://graph.facebook.com/{version}/oauth/access_token")
}

/// The profile call. `email` is requested and may simply not come back.
pub(crate) fn profile_endpoint(version: &str) -> String {
    format!("https://graph.facebook.com/{version}/me?fields=id,name,email")
}

/// What `/me` gives us, with everything optional but the id.
#[derive(Debug, Deserialize)]
pub(crate) struct Profile {
    /// App-scoped: this id identifies the person **to this app** and is not
    /// portable to another Meta app. Stored as returned.
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    /// Absent when the person declined the permission, or has no verified
    /// address on file. Never treated as verified either way (ADR 0104).
    #[serde(default)]
    pub email: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum GraphError {
    #[error("http port: {0}")]
    Port(#[from] factory0_core::HttpError),
    #[error("the graph api answered {status}")]
    Status { status: u16 },
    #[error("the graph api answered something that is not a profile")]
    Malformed,
}

/// Fetches the profile behind an access token.
///
/// # Errors
///
/// Any transport failure, a non-200, or a body that is not a profile.
pub(crate) async fn profile(
    http: &Arc<dyn HttpClient>,
    version: &str,
    access_token: &str,
) -> Result<Profile, GraphError> {
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri(profile_endpoint(version))
        // The token goes in the header, never the query string: a URL is
        // logged by proxies and lands in referrers, and Meta accepts both.
        .header(
            http::header::AUTHORIZATION,
            format!("Bearer {access_token}"),
        )
        .header(http::header::ACCEPT, "application/json")
        .body(Bytes::new())
        .map_err(|_| GraphError::Malformed)?;

    let response = http.send(request).await?;
    let status = response.status().as_u16();
    if status != 200 {
        return Err(GraphError::Status { status });
    }
    serde_json::from_slice(response.body()).map_err(|_| GraphError::Malformed)
}

/// `oauth2`'s async client over the harness `HttpClient` port.
///
/// The same shape auth-oidc uses for `openidconnect`, which is the same
/// crate underneath. Duplicated rather than shared because the two traits
/// are nominally different types and the bridge is twenty lines; if a
/// third method needs one, it moves to auth-core.
pub(crate) struct PortHttpClient {
    port: Arc<dyn HttpClient>,
}

impl PortHttpClient {
    pub(crate) fn new(port: Arc<dyn HttpClient>) -> Self {
        Self { port }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PortHttpError {
    #[error("http port: {0}")]
    Port(#[from] factory0_core::HttpError),
}

impl<'c> oauth2::AsyncHttpClient<'c> for PortHttpClient {
    type Error = PortHttpError;
    type Future =
        Pin<Box<dyn Future<Output = Result<oauth2::HttpResponse, Self::Error>> + Send + 'c>>;

    fn call(&'c self, request: oauth2::HttpRequest) -> Self::Future {
        let port = Arc::clone(&self.port);
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let response = port
                .send(http::Request::from_parts(parts, Bytes::from(body)))
                .await?;
            let (parts, body) = response.into_parts();
            Ok(http::Response::from_parts(parts, body.to_vec()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_endpoint_is_built_from_one_version() {
        // A mixed-version flow is the kind of thing that works until Meta
        // retires one of them.
        let v = "v21.0";
        assert!(authorization_endpoint(v).starts_with("https://www.facebook.com/v21.0/"));
        assert!(token_endpoint(v).starts_with("https://graph.facebook.com/v21.0/"));
        assert!(profile_endpoint(v).starts_with("https://graph.facebook.com/v21.0/"));
    }

    #[test]
    fn the_profile_needs_only_an_id() {
        // Meta returns what the person granted. An absent email is the
        // ordinary case, not a failure.
        let profile: Profile = serde_json::from_str(r#"{"id":"123"}"#).expect("parses");
        assert_eq!(profile.id, "123");
        assert!(profile.email.is_none());
        assert!(profile.name.is_none());

        let full: Profile =
            serde_json::from_str(r#"{"id":"123","name":"Ada","email":"a@example.com"}"#)
                .expect("parses");
        assert_eq!(full.email.as_deref(), Some("a@example.com"));

        // No id is not a profile.
        assert!(serde_json::from_str::<Profile>(r#"{"name":"Ada"}"#).is_err());
    }

    #[test]
    fn the_profile_request_carries_the_token_in_a_header() {
        // Not the query string: a URL reaches proxy logs and referrers.
        let url = profile_endpoint("v21.0");
        assert!(!url.contains("access_token"), "{url}");
        assert!(url.contains("fields=id,name,email"), "{url}");
    }
}
