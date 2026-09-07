# Architecture decision records

Numbered from 0100 to keep them distinct from the harness ADRs, which apply here as well. Each spike produces one, and so does any decision a login method forces.

| ADR | Decision |
|---|---|
| [0100](0100-wasm-crypto-and-webauthn.md) | Pure-Rust WebAuthn verification, because `webauthn-rs` cannot reach wasm32 |
| [0101](0101-token-issuing.md) | Signed ES256 JWTs with a published JWKS, over opaque tokens |
| [0102](0102-sign-in-with-apple.md) | Apple's minted client secret, `form_post` cookie policy and one-time name |
| [0103](0103-the-login-chooser-and-browser-side-methods.md) | The login chooser lists configured methods, and this service ships the passkey page because nothing else can |
| [0104](0104-facebook-login-without-openid-connect.md) | Meta is OAuth 2.0 with a Graph profile call, and its email is never stored as verified |
