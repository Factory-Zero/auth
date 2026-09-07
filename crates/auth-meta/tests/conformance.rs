//! The shared conformance suite plus the wasm dependency boundary, as for
//! every Factory Zero module.

use factory0_auth_meta::Meta;
use factory0_testing::{assert_wasm_safe_deps, conformance};

#[test]
fn auth_meta_conforms() {
    conformance(Box::new(Meta::new()));
}

#[test]
fn auth_meta_deps_are_wasm_safe() {
    // ADR 0100 Q3: `oauth2` reaches wasm32 with default features off — no
    // reqwest and no OpenSSL. This is the check that keeps it there.
    assert_wasm_safe_deps(env!("CARGO_PKG_NAME"));
}
