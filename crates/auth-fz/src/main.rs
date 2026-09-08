//! The auth venture's `fz` (auth#41). `fz migrations collect`, `doctor`, etc.
//! need to link the venture's *own* harness to see its modules — the
//! standalone `cratefield-cli` binary cannot. This composes the same modules
//! as the deployed Worker (a native `AllPorts` runtime, since `fz` only reads
//! module metadata, not live bindings) and hands them to the CLI.

use cratefield_core::{Harness, Port, Runtime, Venture};

/// A runtime that claims every port, so `Harness::build` succeeds for `fz`
/// without real adapters — `collect`/`doctor` read module migrations and
/// config, not live ports.
struct AllPorts;

impl Runtime for AllPorts {
    fn provides(&self) -> Vec<Port> {
        Port::ALL.to_vec()
    }
}

/// The auth venture's harness — the same modules the Worker mounts.
fn harness() -> Harness {
    Harness::builder()
        .venture(
            Venture::new("factory0-auth", "auth.factory0.ventures")
                .cors_origins(["https://app.cratefield.com"]),
        )
        .templates(factory0_auth_magic_link::default_templates())
        .module(factory0_auth_core::AuthCore::new())
        .module(factory0_auth_oidc::Oidc::new())
        .module(factory0_auth_passkeys::Passkeys::new())
        .module(factory0_auth_magic_link::MagicLink::new())
        .module(factory0_auth_password::Password::new())
        .module(factory0_auth_meta::Meta::new())
        .runtime(AllPorts)
        .build()
        .expect("the auth venture is a valid harness")
}

fn main() {
    cratefield_cli::main_for(harness);
}
