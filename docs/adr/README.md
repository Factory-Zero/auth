# Architecture decision records

Numbered from 0100 to keep them distinct from the harness ADRs, which apply here as well. The three spikes each produce one.

| ADR | Decision |
|---|---|
| [0100](0100-wasm-crypto-and-webauthn.md) | Pure-Rust WebAuthn verification, because `webauthn-rs` cannot reach wasm32 |
| [0101](0101-token-issuing.md) | Signed ES256 JWTs with a published JWKS, over opaque tokens |
| [0102](0102-sign-in-with-apple.md) | Apple's minted client secret, `form_post` cookie policy and one-time name |
| [0103](0103-the-login-chooser-and-browser-side-methods.md) | The login chooser lists configured methods, and this service ships the passkey page because nothing else can |
