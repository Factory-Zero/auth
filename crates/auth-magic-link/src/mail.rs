//! The sign-in mail (issue #21).
//!
//! Rendered through the harness template registry so a venture can
//! override the wording, with the compiled default as the fallback — the
//! same shape `module-email-signup` uses, and the reason the conformance
//! kit (which registers nothing) still works.

use askama::Template as _;
use cratefield_core::{Rendered, Template, TemplateError, TemplateRegistry};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The registry id a venture overrides.
pub const TEMPLATE_MAGIC_LINK: &str = "auth-magic-link/sign-in";

/// What the template is given. Serialized through the registry, so it is
/// a wire format: adding a field is fine, renaming one breaks overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicLinkMail {
    /// The venture's display name.
    pub venture: String,
    /// The full consume URL, token included.
    pub link: String,
    /// How long the link lasts, for the sentence that says so.
    pub minutes: i64,
}

#[derive(askama::Template)]
#[template(path = "magic_link.html")]
struct MagicLinkHtml<'a> {
    venture: &'a str,
    link: &'a str,
    minutes: i64,
}

#[derive(askama::Template)]
#[template(path = "magic_link.txt")]
struct MagicLinkText<'a> {
    venture: &'a str,
    link: &'a str,
    minutes: i64,
}

struct MagicLinkTemplate;

impl Template for MagicLinkTemplate {
    fn render(&self, data: &Value, _locale: &str) -> Result<Rendered, TemplateError> {
        let data: MagicLinkMail =
            serde_json::from_value(data.clone()).map_err(|_| TemplateError::RenderFailed {
                id: TEMPLATE_MAGIC_LINK.to_owned(),
                reason: "the mail data is not the shape this template takes".to_owned(),
            })?;
        Ok(Rendered {
            subject: format!("Sign in to {}", data.venture),
            html: MagicLinkHtml {
                venture: &data.venture,
                link: &data.link,
                minutes: data.minutes,
            }
            .render()
            .map_err(|err| askama_failed(&err))?,
            text: MagicLinkText {
                venture: &data.venture,
                link: &data.link,
                minutes: data.minutes,
            }
            .render()
            .map_err(|err| askama_failed(&err))?,
        })
    }
}

fn askama_failed(err: &askama::Error) -> TemplateError {
    TemplateError::RenderFailed {
        id: TEMPLATE_MAGIC_LINK.to_owned(),
        reason: err.to_string(),
    }
}

/// The module's default template, for `Harness::builder().templates(..)`.
#[must_use]
pub fn default_templates() -> Vec<(String, Box<dyn Template>)> {
    vec![(
        TEMPLATE_MAGIC_LINK.to_owned(),
        Box::new(MagicLinkTemplate) as Box<dyn Template>,
    )]
}

/// Renders through the venture's registry, falling back to the compiled
/// default when the registry misses.
///
/// # Errors
///
/// Whatever the template returns.
pub(crate) fn render(
    registry: &TemplateRegistry,
    data: &MagicLinkMail,
    locale: &str,
) -> Result<Rendered, TemplateError> {
    let value = serde_json::to_value(data).map_err(|err| TemplateError::RenderFailed {
        id: TEMPLATE_MAGIC_LINK.to_owned(),
        reason: err.to_string(),
    })?;
    match registry.render(TEMPLATE_MAGIC_LINK, &value, locale) {
        Err(TemplateError::UnknownTemplate { .. }) => MagicLinkTemplate.render(&value, locale),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data() -> MagicLinkMail {
        MagicLinkMail {
            venture: "Factory Zero".to_owned(),
            link: "https://auth.factory0.ventures/v1/auth-magic-link/consume?token=abc123"
                .to_owned(),
            minutes: 15,
        }
    }

    #[test]
    fn the_text_part_carries_the_raw_link() {
        // The acceptance criterion, and it matters: a mail client that
        // shows only the text part must still be usable, and a person
        // copying the link out of it must get the whole thing.
        let rendered = MagicLinkTemplate
            .render(&serde_json::to_value(data()).expect("json"), "en")
            .expect("renders");
        assert!(rendered.text.contains(&data().link), "{}", rendered.text);
        assert!(rendered.subject.contains("Factory Zero"));
        assert!(rendered.text.contains("15 minutes"));
        // No HTML in the text part.
        assert!(!rendered.text.contains('<'), "{}", rendered.text);
    }

    #[test]
    fn the_html_part_carries_the_link_twice_and_says_it_expires() {
        let rendered = MagicLinkTemplate
            .render(&serde_json::to_value(data()).expect("json"), "en")
            .expect("renders");
        // Once as the button, once as copyable text: a mail client that
        // strips the anchor still leaves something usable.
        assert_eq!(
            rendered.html.matches(&data().link).count(),
            2,
            "{}",
            rendered.html
        );
        assert!(rendered.html.contains("expires in 15 minutes"));
    }

    #[test]
    fn a_venture_override_wins_and_a_missing_one_falls_back() {
        struct Override;
        impl Template for Override {
            fn render(&self, _data: &Value, _locale: &str) -> Result<Rendered, TemplateError> {
                Ok(Rendered {
                    subject: "the venture's own subject".to_owned(),
                    html: "<p>theirs</p>".to_owned(),
                    text: "theirs".to_owned(),
                })
            }
        }

        // Empty registry: the compiled default answers, which is what
        // makes the conformance kit work.
        let empty = TemplateRegistry::new();
        let fallback = render(&empty, &data(), "en").expect("falls back");
        assert!(fallback.subject.contains("Factory Zero"));

        let mut registry = TemplateRegistry::new();
        registry.register(TEMPLATE_MAGIC_LINK, Box::new(Override));
        let overridden = render(&registry, &data(), "en").expect("renders");
        assert_eq!(overridden.subject, "the venture's own subject");
    }

    #[test]
    fn nothing_from_the_link_can_break_out_of_the_html() {
        // The link is built by this service, not by a caller, but askama
        // escapes it anyway and this asserts that it does: a future change
        // that let a `return_to` reach the link must not become an
        // injection into somebody's inbox.
        let hostile = MagicLinkMail {
            link: "https://auth.example/x?t=a\"><script>alert(1)</script>".to_owned(),
            ..data()
        };
        let rendered = MagicLinkTemplate
            .render(&serde_json::to_value(&hostile).expect("json"), "en")
            .expect("renders");
        assert!(
            !rendered.html.contains("<script>alert(1)"),
            "{}",
            rendered.html
        );
    }
}
