use crate::views::AppView;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    Dashboard,
    Login,
    Register,
    AuthCallback,
    RealmsManage,
    PrincipalControl,
    Realm {
        realm_id: String,
    },

    /// Optional `?message=` deep-links a single message: the ChatPanel
    /// scrolls it into view and flashes it on arrival. Empty (the common
    /// case) keeps the plain per-realm behavior. See design/route-view-ia.md
    /// §3.2.
    Chat {
        realm_id: String,
        message: String,
    },
    DirectConversation {
        realm_id: String,
        strand_id: String,
    },
    Directory,
    ContactsManage,
    Contacts,
    Setup,
    SetupSection {
        section: String,
    },
    Settings,

    /// G3.Y1 — device management (list + revoke). Static segment so
    /// the route parser matches this before `/settings/:section` falls
    /// through to the generic `SettingsPanel`.
    SettingsDevices,

    /// G3.Y1 — QR-driven pairing for a sibling device. Live on its
    /// own URL so the e2e harness can deep-link into the pair flow
    /// without scrolling through the device list.
    SettingsDevicesPair,

    /// Recovery settings. Hosts the broader recovery-options aggregator
    /// under the Settings shell.
    SettingsRecovery,
    SettingsSection {
        section: String,
        filter: String,
    },
    RealmMembers {
        realm_id: String,
    },
    Circles {
        realm_id: String,
    },
    CircleDetail {
        realm_id: String,
        circle_id: String,
    },
    RealmAdmin {
        realm_id: String,
    },
    RealmAdminSection {
        realm_id: String,
        section: String,
    },
    Audit,

    /// T7.1 — Developer Tools / Diagnostics aggregator. Hosts the
    /// protocol-level details (schema ids, event kinds, raw event log,
    /// profile id, conformance) that used to leak into the main flow.
    Developer,
    Kanban,
    KanbanRealm {
        realm_id: String,
    },

    /// AKP board-persistence — the selected Board id is part of the URL
    /// so a page refresh (or a deep link) restores the exact board the
    /// user was looking at instead of falling back to
    /// `board_options.first()`. `realm_id` is the Realm id; `board_id`
    /// is the board Space-container id.
    KanbanBoard {
        realm_id: String,
        board_id: String,
    },

    /// Board + card-detail deep link. Carries the board id alongside the
    /// strand id so a refresh on an open card restores the right board
    /// even when the card is a locally-queued draft the server
    /// projection does not yet know about.
    KanbanBoardTask {
        realm_id: String,
        board_id: String,
        task_id: String,
        tab: String,
    },

    /// Board-less card deep link. Retained for share links / global
    /// search results that only know the strand id; the board is resolved
    /// from the projection (or local queue) on arrival.
    KanbanTask {
        realm_id: String,
        task_id: String,
        tab: String,
    },
    Notifications,
    NotificationsSettings,

    /// Live call surface. Optional query parameters deep-link an in-progress
    /// or outgoing call: `call_id` (the `ak:call:…` id), `peer` (the 1:1
    /// callee DID, empty for SFU group calls), `realm_id`, `video` (`1`
    /// for a video call, else audio-only), and `incoming` (`1` when this
    /// is an inbound ring being answered).
    Call {
        call_id: String,
        peer: String,
        realm_id: String,
        video: String,
        incoming: String,
    },
    Recovery,
    Onboarding,
    Quarantine,
    Applets,

    /// A6.1 — global cross-Space message search. Triggered by Cmd+F
    /// (Ctrl+F on non-Mac), the topbar `topbar-search-button`, or by
    /// directly navigating to `/search`. The current Arkret catalog has no
    /// spec-defined HTTP endpoint for global index search, so the panel fails
    /// closed until a catalog entry lands.
    Search,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteParseError;

impl std::fmt::Display for RouteParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("unknown or malformed application route")
    }
}
impl std::error::Error for RouteParseError {}

fn encode_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b':') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn decode_segment(value: &str) -> Result<String, RouteParseError> {
    let mut bytes = Vec::new();
    let mut remaining = value.as_bytes();
    while let Some((&byte, rest)) = remaining.split_first() {
        if byte == b'%' {
            if rest.len() < 2 {
                return Err(RouteParseError);
            }
            let hex = std::str::from_utf8(&rest[..2]).map_err(|_| RouteParseError)?;
            bytes.push(u8::from_str_radix(hex, 16).map_err(|_| RouteParseError)?);
            remaining = &rest[2..];
        } else {
            bytes.push(byte);
            remaining = rest;
        }
    }
    String::from_utf8(bytes).map_err(|_| RouteParseError)
}

impl std::fmt::Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (path, query): (String, Vec<(&str, &str)>) = match self {
            Self::Dashboard => ("/".to_owned(), vec![]),
            Self::Login => ("/login".to_owned(), vec![]),
            Self::Register => ("/register".to_owned(), vec![]),
            Self::AuthCallback => ("/auth/callback".to_owned(), vec![]),
            Self::RealmsManage => ("/realms/manage".to_owned(), vec![]),
            Self::PrincipalControl => ("/realms/principal-control".to_owned(), vec![]),
            Self::Realm { realm_id } => (
                format!("/realms/{realm_id}", realm_id = encode_segment(realm_id)),
                vec![],
            ),
            Self::Chat { realm_id, message } => (
                format!("/chat/{realm_id}", realm_id = encode_segment(realm_id)),
                vec![("message", message.as_str())],
            ),
            Self::DirectConversation {
                realm_id,
                strand_id,
            } => (
                format!(
                    "/direct/{realm_id}/{strand_id}",
                    realm_id = encode_segment(realm_id),
                    strand_id = encode_segment(strand_id)
                ),
                vec![],
            ),
            Self::Directory => ("/directory".to_owned(), vec![]),
            Self::ContactsManage => ("/contacts/manage".to_owned(), vec![]),
            Self::Contacts => ("/contacts".to_owned(), vec![]),
            Self::Setup => ("/setup".to_owned(), vec![]),
            Self::SetupSection { section } => (
                format!("/setup/{section}", section = encode_segment(section)),
                vec![],
            ),
            Self::Settings => ("/settings".to_owned(), vec![]),
            Self::SettingsDevices => ("/settings/devices".to_owned(), vec![]),
            Self::SettingsDevicesPair => ("/settings/devices/pair".to_owned(), vec![]),
            Self::SettingsRecovery => ("/settings/recovery".to_owned(), vec![]),
            Self::SettingsSection { section, filter } => (
                format!("/settings/{section}", section = encode_segment(section)),
                vec![("filter", filter.as_str())],
            ),
            Self::RealmMembers { realm_id } => (
                format!(
                    "/realms/{realm_id}/members",
                    realm_id = encode_segment(realm_id)
                ),
                vec![],
            ),
            Self::Circles { realm_id } => (
                format!(
                    "/realms/{realm_id}/circles",
                    realm_id = encode_segment(realm_id)
                ),
                vec![],
            ),
            Self::CircleDetail {
                realm_id,
                circle_id,
            } => (
                format!(
                    "/realms/{realm_id}/circles/{circle_id}",
                    realm_id = encode_segment(realm_id),
                    circle_id = encode_segment(circle_id)
                ),
                vec![],
            ),
            Self::RealmAdmin { realm_id } => (
                format!(
                    "/realms/{realm_id}/settings",
                    realm_id = encode_segment(realm_id)
                ),
                vec![],
            ),
            Self::RealmAdminSection { realm_id, section } => (
                format!(
                    "/realms/{realm_id}/settings/{section}",
                    realm_id = encode_segment(realm_id),
                    section = encode_segment(section)
                ),
                vec![],
            ),
            Self::Audit => ("/audit".to_owned(), vec![]),
            Self::Developer => ("/developer".to_owned(), vec![]),
            Self::Kanban => ("/kanban".to_owned(), vec![]),
            Self::KanbanRealm { realm_id } => (
                format!("/kanban/{realm_id}", realm_id = encode_segment(realm_id)),
                vec![],
            ),
            Self::KanbanBoard { realm_id, board_id } => (
                format!(
                    "/kanban/{realm_id}/board/{board_id}",
                    realm_id = encode_segment(realm_id),
                    board_id = encode_segment(board_id)
                ),
                vec![],
            ),
            Self::KanbanBoardTask {
                realm_id,
                board_id,
                task_id,
                tab,
            } => (
                format!(
                    "/kanban/{realm_id}/board/{board_id}/task/{task_id}",
                    realm_id = encode_segment(realm_id),
                    board_id = encode_segment(board_id),
                    task_id = encode_segment(task_id)
                ),
                vec![("tab", tab.as_str())],
            ),
            Self::KanbanTask {
                realm_id,
                task_id,
                tab,
            } => (
                format!(
                    "/kanban/{realm_id}/task/{task_id}",
                    realm_id = encode_segment(realm_id),
                    task_id = encode_segment(task_id)
                ),
                vec![("tab", tab.as_str())],
            ),
            Self::Notifications => ("/notifications".to_owned(), vec![]),
            Self::NotificationsSettings => ("/notifications/settings".to_owned(), vec![]),
            Self::Call {
                call_id,
                peer,
                realm_id,
                video,
                incoming,
            } => (
                "/call".to_owned(),
                vec![
                    ("call_id", call_id.as_str()),
                    ("peer", peer.as_str()),
                    ("realm_id", realm_id.as_str()),
                    ("video", video.as_str()),
                    ("incoming", incoming.as_str()),
                ],
            ),
            Self::Recovery => ("/recovery".to_owned(), vec![]),
            Self::Onboarding => ("/onboarding".to_owned(), vec![]),
            Self::Quarantine => ("/quarantine".to_owned(), vec![]),
            Self::Applets => ("/applets".to_owned(), vec![]),
            Self::Search => ("/search".to_owned(), vec![]),
        };
        f.write_str(&path)?;
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (name, value) in query {
            if !value.is_empty() {
                serializer.append_pair(name, value);
            }
        }
        let query = serializer.finish();
        if !query.is_empty() {
            write!(f, "?{query}")?;
        }
        Ok(())
    }
}

impl std::str::FromStr for Route {
    type Err = RouteParseError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.split('#').next().unwrap_or(value);
        let (path, query) = value.split_once('?').unwrap_or((value, ""));
        let parts = path.trim_start_matches('/').split('/').collect::<Vec<_>>();
        let query = url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect::<std::collections::HashMap<_, _>>();
        match parts.as_slice() {
            ["kanban", realm_id, "board", board_id, "task", task_id] => Ok(Self::KanbanBoardTask {
                realm_id: decode_segment(realm_id)?,
                board_id: decode_segment(board_id)?,
                task_id: decode_segment(task_id)?,
                tab: query.get("tab").cloned().unwrap_or_default(),
            }),
            ["realms", realm_id, "circles", circle_id] => Ok(Self::CircleDetail {
                realm_id: decode_segment(realm_id)?,
                circle_id: decode_segment(circle_id)?,
            }),
            ["realms", realm_id, "settings", section] => Ok(Self::RealmAdminSection {
                realm_id: decode_segment(realm_id)?,
                section: decode_segment(section)?,
            }),
            ["kanban", realm_id, "board", board_id] => Ok(Self::KanbanBoard {
                realm_id: decode_segment(realm_id)?,
                board_id: decode_segment(board_id)?,
            }),
            ["kanban", realm_id, "task", task_id] => Ok(Self::KanbanTask {
                realm_id: decode_segment(realm_id)?,
                task_id: decode_segment(task_id)?,
                tab: query.get("tab").cloned().unwrap_or_default(),
            }),
            ["settings", "devices", "pair"] => Ok(Self::SettingsDevicesPair),
            ["realms", realm_id, "members"] => Ok(Self::RealmMembers {
                realm_id: decode_segment(realm_id)?,
            }),
            ["realms", realm_id, "circles"] => Ok(Self::Circles {
                realm_id: decode_segment(realm_id)?,
            }),
            ["realms", realm_id, "settings"] => Ok(Self::RealmAdmin {
                realm_id: decode_segment(realm_id)?,
            }),
            ["direct", realm_id, strand_id] => Ok(Self::DirectConversation {
                realm_id: decode_segment(realm_id)?,
                strand_id: decode_segment(strand_id)?,
            }),
            ["auth", "callback"] => Ok(Self::AuthCallback),
            ["realms", "manage"] => Ok(Self::RealmsManage),
            ["realms", "principal-control"] => Ok(Self::PrincipalControl),
            ["contacts", "manage"] => Ok(Self::ContactsManage),
            ["settings", "devices"] => Ok(Self::SettingsDevices),
            ["settings", "recovery"] => Ok(Self::SettingsRecovery),
            ["notifications", "settings"] => Ok(Self::NotificationsSettings),
            ["realms", realm_id] => Ok(Self::Realm {
                realm_id: decode_segment(realm_id)?,
            }),
            ["chat", realm_id] => Ok(Self::Chat {
                realm_id: decode_segment(realm_id)?,
                message: query.get("message").cloned().unwrap_or_default(),
            }),
            ["setup", section] => Ok(Self::SetupSection {
                section: decode_segment(section)?,
            }),
            ["settings", section] => Ok(Self::SettingsSection {
                section: decode_segment(section)?,
                filter: query.get("filter").cloned().unwrap_or_default(),
            }),
            ["kanban", realm_id] => Ok(Self::KanbanRealm {
                realm_id: decode_segment(realm_id)?,
            }),
            [""] => Ok(Self::Dashboard),
            ["login"] => Ok(Self::Login),
            ["register"] => Ok(Self::Register),
            ["directory"] => Ok(Self::Directory),
            ["contacts"] => Ok(Self::Contacts),
            ["setup"] => Ok(Self::Setup),
            ["settings"] => Ok(Self::Settings),
            ["audit"] => Ok(Self::Audit),
            ["developer"] => Ok(Self::Developer),
            ["kanban"] => Ok(Self::Kanban),
            ["notifications"] => Ok(Self::Notifications),
            ["call"] => Ok(Self::Call {
                call_id: query.get("call_id").cloned().unwrap_or_default(),
                peer: query.get("peer").cloned().unwrap_or_default(),
                realm_id: query.get("realm_id").cloned().unwrap_or_default(),
                video: query.get("video").cloned().unwrap_or_default(),
                incoming: query.get("incoming").cloned().unwrap_or_default(),
            }),
            ["recovery"] => Ok(Self::Recovery),
            ["onboarding"] => Ok(Self::Onboarding),
            ["quarantine"] => Ok(Self::Quarantine),
            ["applets"] => Ok(Self::Applets),
            ["search"] => Ok(Self::Search),
            _ => Err(RouteParseError),
        }
    }
}
impl Route {
    /// Convert a Route to the corresponding View enum variant.
    pub fn to_view(&self) -> AppView {
        match self {
            Route::Dashboard => AppView::Dashboard,
            Route::Login | Route::Register | Route::AuthCallback => AppView::Login,
            Route::RealmsManage | Route::PrincipalControl => AppView::RealmsManage,
            // `/realms/:id` is an entry point, not a surface: it resolves the
            // user's RealmSurface preference and renders the board
            // (design/route-view-ia.md §3.1, plan A). It shares the Kanban view.
            Route::Realm { .. } => AppView::Kanban,
            Route::Chat { .. } | Route::DirectConversation { .. } => AppView::Chat,
            Route::Contacts | Route::ContactsManage => AppView::Contacts,
            Route::Directory => AppView::Directory,
            Route::Setup | Route::SetupSection { .. } => AppView::Setup,
            Route::Settings
            | Route::SettingsSection { .. }
            | Route::NotificationsSettings
            | Route::SettingsDevices
            | Route::SettingsDevicesPair
            | Route::SettingsRecovery
            | Route::Recovery
            | Route::Audit
            | Route::Developer => AppView::Settings,
            Route::Circles { .. } | Route::CircleDetail { .. } => AppView::Circles,
            Route::RealmMembers { .. }
            | Route::RealmAdmin { .. }
            | Route::RealmAdminSection { .. } => AppView::RealmAdmin,
            Route::Call { .. } => AppView::Call,
            Route::Applets => AppView::Applets,
            Route::Kanban
            | Route::KanbanRealm { .. }
            | Route::KanbanBoard { .. }
            | Route::KanbanBoardTask { .. }
            | Route::KanbanTask { .. } => AppView::Kanban,
            Route::Notifications => AppView::Notifications,
            Route::Onboarding => AppView::Onboarding,
            Route::Quarantine => AppView::Quarantine,
            Route::Search => AppView::Search,
        }
    }

    /// Extract realm_id from routes that carry a Realm context.
    pub fn realm_id(&self) -> Option<&str> {
        match self {
            Route::Realm { realm_id }
            | Route::Chat { realm_id, .. }
            | Route::DirectConversation { realm_id, .. }
            | Route::KanbanRealm { realm_id }
            | Route::KanbanBoard { realm_id, .. }
            | Route::KanbanBoardTask { realm_id, .. }
            | Route::KanbanTask { realm_id, .. }
            | Route::RealmMembers { realm_id }
            | Route::Circles { realm_id }
            | Route::CircleDetail { realm_id, .. }
            | Route::RealmAdmin { realm_id }
            | Route::RealmAdminSection { realm_id, .. } => Some(realm_id.as_str()),
            _ => None,
        }
    }

    /// Extract setup section from routes that carry one.
    pub fn setup_section(&self) -> Option<&str> {
        match self {
            Route::SetupSection { section } => Some(section.as_str()),
            _ => None,
        }
    }

    /// Extract settings section from routes that carry one.
    pub fn settings_section(&self) -> Option<&str> {
        match self {
            Route::SettingsSection { section, .. } => Some(section.as_str()),
            Route::NotificationsSettings => Some("notifications"),
            Route::SettingsDevices | Route::SettingsDevicesPair => Some("devices"),
            Route::SettingsRecovery | Route::Recovery => Some("recovery"),
            Route::Audit => Some("audit"),
            Route::Developer => Some("developer"),
            _ => None,
        }
    }

    /// Extract Realm admin section from routes that carry one.
    pub fn realm_admin_section(&self) -> Option<&str> {
        match self {
            Route::RealmAdminSection { section, .. } => Some(section.as_str()),
            _ => None,
        }
    }
}

/// Convert a View enum variant to the default Route for that view.
impl From<AppView> for Route {
    fn from(view: AppView) -> Self {
        match view {
            AppView::Dashboard => Route::Dashboard,
            AppView::Login => Route::Login,
            AppView::Chat => Route::Chat {
                realm_id: String::new(),
                message: String::new(),
            },
            AppView::Contacts => Route::Contacts,
            AppView::Directory => Route::Directory,
            AppView::Setup => Route::Setup,
            AppView::Settings => Route::Settings,
            AppView::SettingsDevices => Route::SettingsDevices,
            AppView::SettingsRecovery => Route::SettingsRecovery,
            AppView::RealmAdmin => Route::RealmAdmin {
                realm_id: String::new(),
            },
            AppView::Circles => Route::Circles {
                realm_id: String::new(),
            },
            AppView::Kanban => Route::Kanban,
            AppView::RealmsManage => Route::RealmsManage,
            AppView::Call => Route::Call {
                call_id: String::new(),
                peer: String::new(),
                realm_id: String::new(),
                video: String::new(),
                incoming: String::new(),
            },
            AppView::Applets => Route::Applets,
            AppView::Notifications => Route::Notifications,
            AppView::Recovery => Route::Recovery,
            AppView::Onboarding => Route::Onboarding,
            AppView::Quarantine => Route::Quarantine,
            AppView::Search => Route::Search,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_links_preserve_encoded_segments_and_query_values() {
        let routes = [
            Route::Chat {
                realm_id: "ak:realm:escaped/path 中文".into(),
                message: "ak:message:a&b+c/#".into(),
            },
            Route::KanbanBoardTask {
                realm_id: "ak:realm:a".into(),
                board_id: "ak:space:b".into(),
                task_id: "ak:strand:c".into(),
                tab: "discussion".into(),
            },
            Route::SettingsSection {
                section: "account".into(),
                filter: "needs review + mine".into(),
            },
            Route::Call {
                call_id: "ak:call:a".into(),
                peer: "did:web:example.org".into(),
                realm_id: String::new(),
                video: "1".into(),
                incoming: "1".into(),
            },
        ];
        for route in routes {
            assert_eq!(route.to_string().parse::<Route>(), Ok(route));
        }
    }

    #[test]
    fn static_paths_and_malformed_identifiers_do_not_become_dynamic_routes() {
        assert_eq!(
            "/settings/devices/pair".parse::<Route>(),
            Ok(Route::SettingsDevicesPair)
        );
        assert_eq!(
            "/settings/recovery".parse::<Route>(),
            Ok(Route::SettingsRecovery)
        );
        assert_eq!("/realms/manage".parse::<Route>(), Ok(Route::RealmsManage));
        assert!("/chat/%GG".parse::<Route>().is_err());
        assert!("/chat/%FF".parse::<Route>().is_err());
        assert!("/unknown".parse::<Route>().is_err());
    }

    #[test]
    fn test_route_to_view_roundtrip() {
        let routes = vec![
            Route::Dashboard,
            Route::Login,
            Route::Register,
            Route::Realm {
                realm_id: "ak:realm:Ah-TN8ceKyXkuwRp9fuEVw7pwATVHa-ISAbDJQgUm9hA".to_owned(),
            },
            Route::Directory,
            Route::Setup,
            Route::SetupSection {
                // Canonical Realm bootstrap slug.
                section: "realms".to_owned(),
            },
            Route::Settings,
            Route::RealmAdminSection {
                realm_id: "ak:realm:Ah-TN8ceKyXkuwRp9fuEVw7pwATVHa-ISAbDJQgUm9hA".to_owned(),
                section: "access".to_owned(),
            },
            Route::RealmMembers {
                realm_id: "ak:realm:Ah-TN8ceKyXkuwRp9fuEVw7pwATVHa-ISAbDJQgUm9hA".to_owned(),
            },
            Route::Audit,
            Route::Developer,
            Route::RealmsManage,
            Route::PrincipalControl,
            Route::Call {
                call_id: String::new(),
                peer: String::new(),
                realm_id: String::new(),
                video: String::new(),
                incoming: String::new(),
            },
            Route::Applets,
            Route::Kanban,
            Route::Notifications,
            Route::Recovery,
            Route::Onboarding,
            Route::Quarantine,
            // G3.Y1 settings subroutes all round-trip through AppView::Settings.
            Route::SettingsDevices,
            Route::SettingsDevicesPair,
            Route::SettingsRecovery,
        ];

        for route in routes {
            let view = route.to_view();
            let back: Route = view.into();
            // The round-trip should produce the same variant (without parameters)
            assert_eq!(route.to_view(), back.to_view());
        }
    }

    #[test]
    fn test_realm_id_extraction() {
        assert_eq!(
            Route::Realm {
                realm_id: "ak:realm:A28oJpDpEI80mVokdt5Yo0vuv0Z1SXEPt1X593Rirmn8".to_owned()
            }
            .realm_id(),
            Some("ak:realm:A28oJpDpEI80mVokdt5Yo0vuv0Z1SXEPt1X593Rirmn8")
        );
        assert_eq!(
            Route::RealmAdminSection {
                realm_id: "ak:realm:AgQ3wZKVHQtgzsB-kFz2dtmKzjMrfywHYcRpK4h4_jbo".to_owned(),
                section: "access".to_owned(),
            }
            .realm_id(),
            Some("ak:realm:AgQ3wZKVHQtgzsB-kFz2dtmKzjMrfywHYcRpK4h4_jbo")
        );
        assert_eq!(
            Route::RealmMembers {
                realm_id: "ak:realm:AwwMJvEXGOqIP4f1n5k7Youiz7BKg0kUqt_LIVo22FFk".to_owned()
            }
            .realm_id(),
            Some("ak:realm:AwwMJvEXGOqIP4f1n5k7Youiz7BKg0kUqt_LIVo22FFk")
        );
    }

    #[test]
    fn test_setup_section_extraction() {
        assert_eq!(
            Route::SetupSection {
                section: "realms".to_owned()
            }
            .setup_section(),
            Some("realms")
        );
        assert_eq!(Route::Setup.setup_section(), None);
    }

    #[test]
    fn test_settings_section_extraction() {
        assert_eq!(
            Route::SettingsSection {
                section: "encryption".to_owned(),
                filter: String::new(),
            }
            .settings_section(),
            Some("encryption")
        );
        assert_eq!(Route::SettingsDevices.settings_section(), Some("devices"));
        assert_eq!(Route::SettingsRecovery.settings_section(), Some("recovery"));
        assert_eq!(Route::Audit.settings_section(), Some("audit"));
        assert_eq!(Route::Developer.settings_section(), Some("developer"));
        assert_eq!(Route::Settings.settings_section(), None);
    }

    #[test]
    fn test_realm_admin_section_extraction() {
        assert_eq!(
            Route::RealmAdminSection {
                realm_id: "ak:realm:At9cQzHAltYPBAr08k50aWUnPgEYe-038vPA2q3wBT5U".to_owned(),
                section: "repair".to_owned(),
            }
            .realm_admin_section(),
            Some("repair")
        );
        assert_eq!(
            Route::RealmAdmin {
                realm_id: "ak:realm:At9cQzHAltYPBAr08k50aWUnPgEYe-038vPA2q3wBT5U".to_owned()
            }
            .realm_admin_section(),
            None
        );
    }
}
