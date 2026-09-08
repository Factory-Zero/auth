//! The deployable auth Worker (issue #41): composes every merged auth module
//! into one harness venture and exposes the Cloudflare `fetch`/`scheduled`
//! entry points. Before this, the repository was library crates with no
//! artifact to deploy, so `auth.factory0.ventures` did not exist and every
//! consumer (Yoginini, the Cratefield control plane) was blocked.
//!
//! It is an ordinary harness venture — one Worker, one D1 — following the
//! `venture-backend-template` layout. Which login methods ship is simply which
//! modules are mounted here; the rest mount later without redeploying consumers.
//!
//! **Owner-only (needs-human):** `wrangler d1 create` for each environment, the
//! `HARNESS_SECRET`/signing material, the `auth.factory0.ventures` route on the
//! Kontinuum Cloudflare account, and the first production tag (auth#41).

#![forbid(unsafe_code)]

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use cratefield_adapter_resend::Resend;
use cratefield_core::{Harness, MailError, Mailer, Message, SendOutcome, Venture};
use cratefield_runtime_cloudflare::{Cloudflare, FetchClient, serve, serve_scheduled};
use worker::{Context, Env, Request, Response, event};

/// The verified sending address (a `send.` subdomain verified in Resend).
const MAIL_FROM: &str = "no-reply@auth.factory0.ventures";

/// Reports a send as done without sending — used until `RESEND_API_KEY` is set,
/// so magic-link/verification requests still create their rows rather than
/// failing the whole flow. Real delivery begins the moment the key is present.
struct NoopMailer;

#[async_trait]
impl Mailer for NoopMailer {
    async fn send(&self, _message: Message) -> Result<SendOutcome, MailError> {
        Ok(SendOutcome::Sent {
            id: "noop".to_owned(),
        })
    }
}

/// Resend when `RESEND_API_KEY` is present on the Worker `Env` (read from the
/// binding, since `std::env` is empty on Workers), else the capture-only no-op.
fn build_mailer(env: &Env) -> Arc<dyn Mailer> {
    let key = env
        .secret("RESEND_API_KEY")
        .ok()
        .map(|secret| secret.to_string())
        .filter(|key| !key.is_empty());
    match key {
        Some(key) => Arc::new(Resend::new(
            Arc::new(FetchClient),
            Some(key),
            MAIL_FROM,
            None,
        )),
        None => Arc::new(NoopMailer),
    }
}

static INSTANCE: OnceLock<(Harness, Cloudflare)> = OnceLock::new();

/// The composed auth venture: `auth-core` plus every merged login method, over
/// the Cloudflare runtime. Built once per isolate (ADR 0007: no ambient
/// request state).
fn instance(env: &Env) -> &'static (Harness, Cloudflare) {
    INSTANCE.get_or_init(|| {
        let mailer = build_mailer(env);
        let harness = Harness::builder()
            .venture(
                Venture::new("factory0-auth", "auth.factory0.ventures")
                    .public_url("https://auth.factory0.ventures")
                    // Consumers call the discovery/JWKS documents (public GETs);
                    // the browser-facing authorize flow is a top-level redirect,
                    // not CORS. These are the first-party app origins.
                    .cors_origins([
                        "https://app.cratefield.com",
                        "https://cratefield.com",
                        "https://yoginini.us",
                    ]),
            )
            // Magic-link renders its mail through the shared registry.
            .templates(factory0_auth_magic_link::default_templates())
            .module(factory0_auth_core::AuthCore::new())
            .module(factory0_auth_oidc::Oidc::new())
            .module(factory0_auth_passkeys::Passkeys::new())
            .module(factory0_auth_magic_link::MagicLink::new())
            .module(factory0_auth_password::Password::new())
            .module(factory0_auth_meta::Meta::new())
            .runtime(Cloudflare::new().db("DB").mailer_arc(Arc::clone(&mailer)))
            .build()
            .expect("the auth venture is a valid harness");
        // The runtime `serve` resolves ports from must carry the mailer too.
        let runtime = Cloudflare::new().db("DB").mailer_arc(mailer);
        (harness, runtime)
    })
}

#[event(fetch)]
/// Worker fetch entry point.
///
/// # Errors
///
/// Propagates `worker::Error` from the harness router.
pub async fn fetch(req: Request, env: Env, ctx: Context) -> worker::Result<Response> {
    let (harness, runtime) = instance(&env);
    serve(harness, runtime, req, env, ctx).await
}

#[event(scheduled)]
pub async fn scheduled(event: worker::ScheduledEvent, env: Env, ctx: worker::ScheduleContext) {
    let (harness, runtime) = instance(&env);
    serve_scheduled(harness, runtime, event, env, ctx).await;
}
