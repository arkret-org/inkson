//! Section / wizard-step enums for the setup surface.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SetupSection {
    Overview,
    /// Realm bootstrap strand; the form creates a Realm and emits
    /// `ak.realm.create`.
    Realms,
    /// Phase 3 — `ak.space.create` form: pick a Realm, pick a kind,
    /// optionally pick a parent Space. The Space lives inside the
    /// Realm and inherits all security semantics from it.
    NewSpace,
}

impl SetupSection {
    pub(super) fn from_slug(slug: Option<&str>) -> Self {
        match slug.unwrap_or_default() {
            "" => Self::Realms,
            "overview" => Self::Overview,
            "realms" => Self::Realms,
            "new-space" => Self::NewSpace,
            _ => Self::Overview,
        }
    }

    pub(super) fn slug(self) -> &'static str {
        match self {
            Self::Overview => "overview",
            Self::Realms => "realms",
            Self::NewSpace => "new-space",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum NewRealmStep {
    Basics,
    Boundary,
    Seed,
    Done,
}

pub(super) const NEW_REALM_STEPS: [NewRealmStep; 4] = [
    NewRealmStep::Basics,
    NewRealmStep::Boundary,
    NewRealmStep::Seed,
    NewRealmStep::Done,
];

impl NewRealmStep {
    /// i18n key for the step's short name. Call sites resolve it through
    /// [`crate::i18n::tr`]; this enum stays runtime-free.
    pub(super) fn label_key(self) -> &'static str {
        match self {
            Self::Basics => "setup.step.basics.label",
            Self::Boundary => "setup.step.boundary.label",
            Self::Seed => "setup.step.seed.label",
            Self::Done => "setup.step.done.label",
        }
    }

    /// i18n key for the step's one-line subtitle.
    pub(super) fn subtitle_key(self) -> &'static str {
        match self {
            Self::Basics => "setup.step.basics.subtitle",
            Self::Boundary => "setup.step.boundary.subtitle",
            Self::Seed => "setup.step.seed.subtitle",
            Self::Done => "setup.step.done.subtitle",
        }
    }

    pub(super) fn number(self) -> &'static str {
        match self {
            Self::Basics => "1",
            Self::Boundary => "2",
            Self::Seed => "3",
            Self::Done => "4",
        }
    }

    pub(super) fn next(self) -> Self {
        match self {
            Self::Basics => Self::Boundary,
            Self::Boundary => Self::Seed,
            Self::Seed | Self::Done => Self::Done,
        }
    }

    pub(super) fn previous(self) -> Self {
        match self {
            Self::Basics | Self::Boundary => Self::Basics,
            Self::Seed => Self::Boundary,
            Self::Done => Self::Seed,
        }
    }
}
