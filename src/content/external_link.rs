//! Native links request activation from the application rather than asking
//! Blitz to create an unsupported new browsing context.
use glory::prelude::*;
use glory::render::Event;

fn destination(value: &str, base: Option<&str>) -> std::result::Result<url::Url, String> {
    if value.chars().any(char::is_control) {
        return Err("The link contains a control character.".into());
    }
    let parsed = url::Url::parse(value)
        .or_else(|_| {
            let base = base.ok_or(url::ParseError::RelativeUrlWithoutBase)?;
            url::Url::parse(base)?.join(value)
        })
        .map_err(|_| "The link destination is unavailable.".to_owned())?;
    match parsed.scheme() {
        "http" | "https" if parsed.host_str().is_some() => Ok(parsed),
        "mailto" => Ok(parsed),
        _ => Err("This link cannot be opened by the system browser.".into()),
    }
}

fn report_open_failure(error: String) {
    tracing::warn!(%error, "external link could not be opened");
    crate::components::feedback::toast_error("feedback.external_link_failed", vec![], Some(error));
}

pub(super) fn activation(scope: &Scope, href: String) -> impl FnMut(Event) + 'static {
    let owner = scope.downgrade();
    let base =
        crate::presentation::current_context().map(|context| context.base_url.get_untracked());
    move |_| {
        let Some(scope) = owner.upgrade() else {
            return;
        };
        let href = match destination(&href, base.as_deref()) {
            Ok(href) => href,
            Err(error) => {
                report_open_failure(error);
                return;
            }
        };
        // ShellExecuteW on Windows, argument-based launchers on other supported
        // platforms. The URL is never interpolated into a command shell.
        let (sender, receiver) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let _ = sender.send(opener::open(href.as_str()).map_err(|error| error.to_string()));
        });
        let _ = scope.spawn(async move {
            match receiver.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => report_open_failure(error),
                Err(_) => report_open_failure("The system browser launcher stopped.".into()),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::destination;
    #[test]
    fn native_link_destinations_keep_safe_web_schemes_without_launching_an_application() {
        assert_eq!(
            destination("https://example.com/a?b=1&c=two", None)
                .unwrap()
                .as_str(),
            "https://example.com/a?b=1&c=two"
        );
        assert_eq!(
            destination("/docs", Some("https://station.example/app/"))
                .unwrap()
                .as_str(),
            "https://station.example/docs"
        );
        assert_eq!(
            destination("mailto:member@example.com", None)
                .unwrap()
                .as_str(),
            "mailto:member@example.com"
        );
        for unsafe_url in [
            "javascript:alert(1)",
            "data:text/html,bad",
            "file:///D:/private.txt",
            "shell:AppsFolder",
            "https://example.com/\n",
        ] {
            assert!(
                destination(unsafe_url, Some("https://station.example/")).is_err(),
                "{unsafe_url}"
            );
        }
    }
}
