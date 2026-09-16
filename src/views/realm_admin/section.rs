use crate::routes::Route;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RealmAdminSection {
    Overview,
    Profile,
    Access,
    Security,
    Federation,
    Moderation,
    Repair,
}

impl RealmAdminSection {
    pub(crate) fn from_slug(slug: Option<&str>) -> Self {
        match slug.unwrap_or_default() {
            "profile" => Self::Profile,
            "access" => Self::Access,
            "security" => Self::Security,
            "federation" => Self::Federation,
            "moderation" => Self::Moderation,
            "repair" => Self::Repair,
            _ => Self::Overview,
        }
    }

    pub(crate) fn slug(self) -> Option<&'static str> {
        match self {
            Self::Overview => None,
            Self::Profile => Some("profile"),
            Self::Access => Some("access"),
            Self::Security => Some("security"),
            Self::Federation => Some("federation"),
            Self::Moderation => Some("moderation"),
            Self::Repair => Some("repair"),
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Profile => "Profile",
            Self::Access => "Access",
            Self::Security => "Security & MLS",
            Self::Federation => "Federation",
            Self::Moderation => "Moderation",
            Self::Repair => "Repair & Danger",
        }
    }

    pub(crate) fn route(self, realm_id: String) -> Route {
        match self.slug() {
            Some(slug) => Route::RealmAdminSection {
                realm_id,
                section: slug.to_owned(),
            },
            None => Route::RealmAdmin { realm_id },
        }
    }
}

pub(crate) const REALM_ADMIN_REALM_GROUP: &[RealmAdminSection] =
    &[RealmAdminSection::Overview, RealmAdminSection::Profile];
pub(crate) const REALM_ADMIN_POLICY_GROUP: &[RealmAdminSection] = &[
    RealmAdminSection::Access,
    RealmAdminSection::Security,
    RealmAdminSection::Federation,
    RealmAdminSection::Moderation,
];
pub(crate) const REALM_ADMIN_OPERATIONS_GROUP: &[RealmAdminSection] = &[RealmAdminSection::Repair];
pub(crate) const REALM_ADMIN_NAV_GROUPS: &[(&str, &[RealmAdminSection])] = &[
    ("Realm", REALM_ADMIN_REALM_GROUP),
    ("Policy", REALM_ADMIN_POLICY_GROUP),
    ("Operations", REALM_ADMIN_OPERATIONS_GROUP),
];
