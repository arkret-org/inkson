pub mod agent_runs;
pub mod audit;
pub mod call;
pub mod chat;
pub mod contacts;
pub mod dashboard;
pub mod devices;
pub mod directory;
pub mod document;
pub mod forum;
pub mod helpers;
pub mod kanban;
pub mod login;
pub mod memory_review;
pub mod notifications;
pub mod product;
pub mod readiness;
pub mod register;
pub mod settings;
pub mod social_feed;
pub mod space_admin;
pub mod timeline;
pub mod verify_device;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum View {
    Login,
    Register,
    Dashboard,
    Timeline,
    Directory,
    Product,
    Settings,
    Devices,
    Readiness,
    VerifyDevice,
    Contacts,
    SpaceAdmin,
    Audit,
    Kanban,
    Chat,
    Forum,
    SocialFeed,
    MemoryReview,
    AgentRuns,
    Notifications,
    Document,
    Call,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    Offline,
    Loading,
    Online,
    Reconnecting,
    Empty,
    Error,
}

impl ConnectionState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Offline => "Offline",
            Self::Loading => "Loading",
            Self::Online => "Online",
            Self::Reconnecting => "Reconnecting",
            Self::Empty => "Empty",
            Self::Error => "Error",
        }
    }
}
