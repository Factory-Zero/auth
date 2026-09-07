//! The shared conformance suite plus the wasm dependency boundary.

use factory0_auth_password::Password;
use factory0_testing::{assert_wasm_safe_deps, conformance};

#[test]
fn auth_password_conforms() {
    conformance(Box::new(Password::new()));
}

#[test]
fn auth_password_deps_are_wasm_safe() {
    // argon2 and sha1 are pure Rust with default features off. The CPU
    // cost is the deployment constraint (ADR 0100), not the build.
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
