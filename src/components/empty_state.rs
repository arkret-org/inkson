//! Shared list placeholders for empty, filtered, failed and signed-out views.
use std::rc::Rc;

use glory::prelude::*;

use crate::presentation::{InksonContext, View};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmptyStateKind {
    Empty,
    Filtered,
    Error,
    SignedOut,
}

impl EmptyStateKind {
    fn class(self) -> &'static str {
        match self {
            Self::Empty => "is-empty",
            Self::Filtered => "is-filtered",
            Self::Error => "is-error",
            Self::SignedOut => "is-signed-out",
        }
    }

    fn fallback_description(self) -> Option<&'static str> {
        match self {
            Self::Empty => None,
            Self::Filtered => Some("search.no_results"),
            Self::Error => Some("error.generic"),
            Self::SignedOut => Some("account.not_signed_in"),
        }
    }
}

#[derive(Clone)]
pub struct EmptyStateProps {
    pub title: String,
    pub kind: EmptyStateKind,
    pub message: Option<String>,
    pub test_id: Option<String>,
}

pub fn empty_state(scope: &Scope, context: Rc<InksonContext>, props: EmptyStateProps) -> View {
    let mut state = sapid::empty_state()
        .unstyled()
        .class(format!(
            "event list-empty-state {} {}",
            props.kind.class(),
            props.test_id.unwrap_or_default()
        ))
        .title(props.title);
    if let Some(message) = props.message.filter(|text| !text.trim().is_empty()) {
        state = state.description(message);
    } else if let Some(key) = props.kind.fallback_description() {
        state = state.description(context.translated(scope, key));
    }
    Box::new(state)
}
