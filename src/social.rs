use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::entity::{Relation, RelationType};
use crate::hlc::Hlc;

/// Social entity types as defined by the spec.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SocialEntityType {
    /// A social post (microblog, status update, etc.).
    SocialPost,
    /// A feed of social posts.
    SocialFeed,
    /// A circle/group for audience control.
    SocialCircle,
    /// Custom social entity type with reverse-domain naming.
    Custom(String),
}

impl SocialEntityType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::SocialPost => "social_post",
            Self::SocialFeed => "social_feed",
            Self::SocialCircle => "social_circle",
            Self::Custom(s) => s,
        }
    }
}

/// Social relation types as defined by the spec.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SocialRelationType {
    /// Actor follows another actor.
    Follows,
    /// Contact relationship (mutual).
    Contact,
    /// Member of a circle.
    CircleMember,
    /// Blocks social interaction.
    BlocksSocial,
    /// Reposts/shares content.
    Reposts,
    /// Quotes content.
    Quotes,
    /// Likes content.
    Likes,
    /// Replies to content.
    RepliesTo,
    /// Custom social relation type.
    Custom(String),
}

impl SocialRelationType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Follows => "follows",
            Self::Contact => "contact",
            Self::CircleMember => "circle_member",
            Self::BlocksSocial => "blocks_social",
            Self::Reposts => "reposts",
            Self::Quotes => "quotes",
            Self::Likes => "likes",
            Self::RepliesTo => "replies_to",
            Self::Custom(s) => s,
        }
    }

    /// Convert to the generic RelationType enum.
    pub fn to_relation_type(&self) -> RelationType {
        match self {
            Self::Follows => RelationType::Follows,
            Self::Contact => RelationType::Contact,
            Self::CircleMember => RelationType::CircleMember,
            Self::BlocksSocial => RelationType::BlocksSocial,
            Self::Reposts => RelationType::Reposts,
            Self::Likes => RelationType::Likes,
            Self::RepliesTo => RelationType::RepliesTo,
            _ => RelationType::Custom(self.as_str().to_owned()),
        }
    }
}

/// Audience strategies as defined by the spec.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AudienceStrategy {
    /// Visible to everyone.
    Public,
    /// Visible to followers.
    Followers,
    /// Visible to contacts (mutual follows).
    Contacts,
    /// Visible to members of specific circles.
    Circle(Vec<String>),
    /// Visible to organization members.
    Organization(String),
    /// Visible to space members.
    SpaceMembers(String),
    /// Direct message to specific actors.
    Direct(Vec<String>),
    /// Private (only the author).
    Private,
}

impl AudienceStrategy {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Public => "public",
            Self::Followers => "followers",
            Self::Contacts => "contacts",
            Self::Circle(_) => "circle",
            Self::Organization(_) => "organization",
            Self::SpaceMembers(_) => "space_members",
            Self::Direct(_) => "direct",
            Self::Private => "private",
        }
    }
}

/// A social post entity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SocialPost {
    /// Post ID.
    pub post_id: String,
    /// Author DID.
    pub author: String,
    /// Post content.
    pub content: StructuredContent,
    /// Audience strategy.
    pub audience: AudienceStrategy,
    /// When the post was published.
    pub published_at: Hlc,
    /// Space this post belongs to (if any).
    pub space_id: Option<String>,
    /// Thread ID (if this is a reply).
    pub thread_id: Option<String>,
    /// Parent post ID (if this is a reply).
    pub parent_post_id: Option<String>,
    /// Mentions in this post.
    pub mentions: Vec<Mention>,
    /// Hashtags.
    pub hashtags: Vec<String>,
    /// Attachments.
    pub attachments: Vec<Attachment>,
    /// Whether this post is a repost.
    pub is_repost: bool,
    /// Original post ID (if this is a repost).
    pub original_post_id: Option<String>,
    /// Edit history.
    pub edit_history: Vec<PostEdit>,
}

/// A mention in a post.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Mention {
    /// The mentioned actor DID.
    pub actor_did: String,
    /// Display name.
    pub display_name: Option<String>,
    /// Start position in content.
    pub start: usize,
    /// End position in content.
    pub end: usize,
}

/// An attachment in a post.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attachment {
    /// Attachment ID.
    pub attachment_id: String,
    /// Attachment type.
    pub attachment_type: AttachmentType,
    /// Media type (MIME).
    pub media_type: String,
    /// URL or blob reference.
    pub url: String,
    /// Alt text for accessibility.
    pub alt_text: Option<String>,
    /// Width (for images/videos).
    pub width: Option<u32>,
    /// Height (for images/videos).
    pub height: Option<u32>,
    /// Duration in seconds (for audio/video).
    pub duration: Option<f64>,
}

/// Attachment types.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttachmentType {
    Image,
    Video,
    Audio,
    File,
    Link,
    Location,
    Poll,
}

/// Edit history entry for a post.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostEdit {
    /// When the edit was made.
    pub edited_at: Hlc,
    /// Previous content.
    pub previous_content: StructuredContent,
    /// Edit reason.
    pub reason: Option<String>,
}

/// A social feed entity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SocialFeed {
    /// Feed ID.
    pub feed_id: String,
    /// Feed owner.
    pub owner: String,
    /// Feed name.
    pub name: String,
    /// Feed description.
    pub description: Option<String>,
    /// Feed type.
    pub feed_type: FeedType,
    /// Default audience for posts in this feed.
    pub default_audience: AudienceStrategy,
    /// Snapshot at publish (whether to capture audience at publish time).
    pub snapshot_at_publish: bool,
    /// Space this feed belongs to.
    pub space_id: Option<String>,
}

/// Feed types.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeedType {
    /// User's personal feed.
    Personal,
    /// Space feed.
    Space,
    /// Organization feed.
    Organization,
    /// Topic feed.
    Topic,
    /// Curated feed.
    Curated,
}

/// A social circle entity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SocialCircle {
    /// Circle ID.
    pub circle_id: String,
    /// Circle owner.
    pub owner: String,
    /// Circle name.
    pub name: String,
    /// Circle description.
    pub description: Option<String>,
    /// Members of this circle.
    pub members: Vec<String>,
    /// Whether this circle is public.
    pub is_public: bool,
    /// Maximum members (0 = unlimited).
    pub max_members: u32,
}

/// Structured content types as defined by the spec.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum StructuredContent {
    /// Plain text content.
    #[serde(rename = "text")]
    Text {
        text: String,
        #[serde(default)]
        language: Option<String>,
    },
    /// Formatted text (markdown, HTML, etc.).
    #[serde(rename = "formatted_text")]
    FormattedText {
        text: String,
        format: TextFormat,
        #[serde(default)]
        language: Option<String>,
    },
    /// Image content.
    #[serde(rename = "image")]
    Image {
        url: String,
        #[serde(default)]
        alt: Option<String>,
        #[serde(default)]
        width: Option<u32>,
        #[serde(default)]
        height: Option<u32>,
        #[serde(default)]
        caption: Option<String>,
        #[serde(default)]
        blurhash: Option<String>,
    },
    /// Video content.
    #[serde(rename = "video")]
    Video {
        url: String,
        #[serde(default)]
        poster: Option<String>,
        #[serde(default)]
        duration: Option<f64>,
        #[serde(default)]
        width: Option<u32>,
        #[serde(default)]
        height: Option<u32>,
        #[serde(default)]
        caption: Option<String>,
    },
    /// Audio content.
    #[serde(rename = "audio")]
    Audio {
        url: String,
        #[serde(default)]
        duration: Option<f64>,
        #[serde(default)]
        title: Option<String>,
        #[serde(default)]
        artist: Option<String>,
    },
    /// File content.
    #[serde(rename = "file")]
    File {
        url: String,
        name: String,
        size: u64,
        mime_type: String,
        #[serde(default)]
        description: Option<String>,
    },
    /// Location content.
    #[serde(rename = "location")]
    Location {
        latitude: f64,
        longitude: f64,
        #[serde(default)]
        altitude: Option<f64>,
        #[serde(default)]
        accuracy: Option<f64>,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        address: Option<String>,
    },
    /// Code content.
    #[serde(rename = "code")]
    Code {
        code: String,
        language: String,
        #[serde(default)]
        filename: Option<String>,
        #[serde(default)]
        highlight_lines: Option<Vec<u32>>,
    },
    /// Poll content.
    #[serde(rename = "poll")]
    Poll {
        question: String,
        options: Vec<PollOption>,
        #[serde(default)]
        expires_at: Option<String>,
        #[serde(default)]
        multiple_choice: bool,
        #[serde(default)]
        max_choices: Option<u32>,
    },
    /// Custom content type.
    #[serde(rename = "custom")]
    Custom {
        type_name: String,
        data: serde_json::Value,
    },
}

/// Text format options.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TextFormat {
    Plain,
    Markdown,
    Html,
    Bbcode,
    Custom(String),
}

/// Poll option.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PollOption {
    pub option_id: String,
    pub text: String,
    #[serde(default)]
    pub vote_count: u64,
}

/// Custom type registry for reverse-domain naming.
#[derive(Clone, Debug, Default)]
pub struct CustomTypeRegistry {
    /// Registered entity types: reverse_domain -> type_definition.
    entity_types: HashMap<String, CustomTypeDefinition>,
    /// Registered relation types.
    relation_types: HashMap<String, CustomTypeDefinition>,
    /// Registered content types.
    content_types: HashMap<String, CustomTypeDefinition>,
}

/// Definition of a custom type.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CustomTypeDefinition {
    /// Reverse-domain name (e.g., "com.example.mycustomtype").
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Version.
    pub version: String,
    /// Schema for validation (JSON Schema format).
    pub schema: Option<serde_json::Value>,
    /// Whether this type is public.
    pub is_public: bool,
    /// Creator DID.
    pub creator: String,
    /// When this type was registered.
    pub registered_at: Hlc,
}

impl CustomTypeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a custom entity type.
    pub fn register_entity_type(&mut self, def: CustomTypeDefinition) -> Result<(), String> {
        Self::validate_reverse_domain(&def.name)?;
        self.entity_types.insert(def.name.clone(), def);
        Ok(())
    }

    /// Register a custom relation type.
    pub fn register_relation_type(&mut self, def: CustomTypeDefinition) -> Result<(), String> {
        Self::validate_reverse_domain(&def.name)?;
        self.relation_types.insert(def.name.clone(), def);
        Ok(())
    }

    /// Register a custom content type.
    pub fn register_content_type(&mut self, def: CustomTypeDefinition) -> Result<(), String> {
        Self::validate_reverse_domain(&def.name)?;
        self.content_types.insert(def.name.clone(), def);
        Ok(())
    }

    /// Look up a custom entity type.
    pub fn get_entity_type(&self, name: &str) -> Option<&CustomTypeDefinition> {
        self.entity_types.get(name)
    }

    /// Look up a custom relation type.
    pub fn get_relation_type(&self, name: &str) -> Option<&CustomTypeDefinition> {
        self.relation_types.get(name)
    }

    /// Look up a custom content type.
    pub fn get_content_type(&self, name: &str) -> Option<&CustomTypeDefinition> {
        self.content_types.get(name)
    }

    /// List all registered entity types.
    pub fn list_entity_types(&self) -> Vec<&CustomTypeDefinition> {
        self.entity_types.values().collect()
    }

    /// List all registered relation types.
    pub fn list_relation_types(&self) -> Vec<&CustomTypeDefinition> {
        self.relation_types.values().collect()
    }

    /// List all registered content types.
    pub fn list_content_types(&self) -> Vec<&CustomTypeDefinition> {
        self.content_types.values().collect()
    }

    /// Validate reverse-domain naming convention.
    fn validate_reverse_domain(name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("type name cannot be empty".to_owned());
        }

        let parts: Vec<&str> = name.split('.').collect();
        if parts.len() < 2 {
            return Err(
                "type name must use reverse-domain notation (e.g., 'com.example.type')".to_owned(),
            );
        }

        for part in &parts {
            if part.is_empty() {
                return Err("type name cannot have empty segments".to_owned());
            }
            if !part
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
            {
                return Err(format!(
                    "type name segment '{part}' contains invalid characters"
                ));
            }
        }

        Ok(())
    }
}

/// Helper to create social entity objects.
pub mod social_ops {
    use super::*;

    /// Create a social post entity.
    pub fn create_post(
        author: &str,
        content: StructuredContent,
        audience: AudienceStrategy,
        space_id: Option<&str>,
    ) -> SocialPost {
        SocialPost {
            post_id: format!("post-{}", crate::operation::uuid_v8()),
            author: author.to_owned(),
            content,
            audience,
            published_at: Hlc::now("chask"),
            space_id: space_id.map(|s| s.to_owned()),
            thread_id: None,
            parent_post_id: None,
            mentions: Vec::new(),
            hashtags: Vec::new(),
            attachments: Vec::new(),
            is_repost: false,
            original_post_id: None,
            edit_history: Vec::new(),
        }
    }

    /// Create a social feed entity.
    pub fn create_feed(
        owner: &str,
        name: &str,
        feed_type: FeedType,
        default_audience: AudienceStrategy,
    ) -> SocialFeed {
        SocialFeed {
            feed_id: format!("feed-{}", crate::operation::uuid_v8()),
            owner: owner.to_owned(),
            name: name.to_owned(),
            description: None,
            feed_type,
            default_audience,
            snapshot_at_publish: true,
            space_id: None,
        }
    }

    /// Create a social circle entity.
    pub fn create_circle(owner: &str, name: &str) -> SocialCircle {
        SocialCircle {
            circle_id: format!("circle-{}", crate::operation::uuid_v8()),
            owner: owner.to_owned(),
            name: name.to_owned(),
            description: None,
            members: Vec::new(),
            is_public: false,
            max_members: 0,
        }
    }

    /// Create a follow relation.
    pub fn follow_relation(follower: &str, following: &str) -> Relation {
        Relation::new(
            &format!("rel-{}", crate::operation::uuid_v8()),
            "social",
            RelationType::Follows,
            follower,
            following,
            follower,
        )
    }

    /// Create a like relation.
    pub fn like_relation(actor: &str, post_id: &str) -> Relation {
        Relation::new(
            &format!("rel-{}", crate::operation::uuid_v8()),
            "social",
            RelationType::Likes,
            actor,
            post_id,
            actor,
        )
    }

    /// Create a repost relation.
    pub fn repost_relation(actor: &str, post_id: &str) -> Relation {
        Relation::new(
            &format!("rel-{}", crate::operation::uuid_v8()),
            "social",
            RelationType::Reposts,
            actor,
            post_id,
            actor,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_social_entity_types() {
        assert_eq!(SocialEntityType::SocialPost.as_str(), "social_post");
        assert_eq!(SocialEntityType::SocialFeed.as_str(), "social_feed");
        assert_eq!(SocialEntityType::SocialCircle.as_str(), "social_circle");
        assert_eq!(
            SocialEntityType::Custom("com.example.mypost".to_owned()).as_str(),
            "com.example.mypost"
        );
    }

    #[test]
    fn test_social_relation_types() {
        assert_eq!(SocialRelationType::Follows.as_str(), "follows");
        assert_eq!(SocialRelationType::Likes.as_str(), "likes");
        assert_eq!(SocialRelationType::Reposts.as_str(), "reposts");
    }

    #[test]
    fn test_audience_strategy() {
        assert_eq!(AudienceStrategy::Public.as_str(), "public");
        assert_eq!(AudienceStrategy::Followers.as_str(), "followers");
        assert_eq!(AudienceStrategy::Private.as_str(), "private");
    }

    #[test]
    fn test_structured_content_text() {
        let content = StructuredContent::Text {
            text: "Hello, world!".to_owned(),
            language: Some("en".to_owned()),
        };
        let json = serde_json::to_string(&content).unwrap();
        let parsed: StructuredContent = serde_json::from_str(&json).unwrap();
        match parsed {
            StructuredContent::Text { text, language } => {
                assert_eq!(text, "Hello, world!");
                assert_eq!(language, Some("en".to_owned()));
            }
            _ => panic!("expected Text"),
        }
    }

    #[test]
    fn test_structured_content_image() {
        let content = StructuredContent::Image {
            url: "https://example.com/image.jpg".to_owned(),
            alt: Some("Test image".to_owned()),
            width: Some(800),
            height: Some(600),
            caption: None,
            blurhash: None,
        };
        let json = serde_json::to_string(&content).unwrap();
        let parsed: StructuredContent = serde_json::from_str(&json).unwrap();
        match parsed {
            StructuredContent::Image {
                url, width, height, ..
            } => {
                assert_eq!(url, "https://example.com/image.jpg");
                assert_eq!(width, Some(800));
                assert_eq!(height, Some(600));
            }
            _ => panic!("expected Image"),
        }
    }

    #[test]
    fn test_structured_content_code() {
        let content = StructuredContent::Code {
            code: "fn main() { println!(\"Hello\"); }".to_owned(),
            language: "rust".to_owned(),
            filename: Some("main.rs".to_owned()),
            highlight_lines: Some(vec![1]),
        };
        let json = serde_json::to_string(&content).unwrap();
        let parsed: StructuredContent = serde_json::from_str(&json).unwrap();
        match parsed {
            StructuredContent::Code { language, .. } => {
                assert_eq!(language, "rust");
            }
            _ => panic!("expected Code"),
        }
    }

    #[test]
    fn test_structured_content_poll() {
        let content = StructuredContent::Poll {
            question: "What's your favorite language?".to_owned(),
            options: vec![
                PollOption {
                    option_id: "opt-1".to_owned(),
                    text: "Rust".to_owned(),
                    vote_count: 0,
                },
                PollOption {
                    option_id: "opt-2".to_owned(),
                    text: "Go".to_owned(),
                    vote_count: 0,
                },
            ],
            expires_at: None,
            multiple_choice: false,
            max_choices: None,
        };
        let json = serde_json::to_string(&content).unwrap();
        let parsed: StructuredContent = serde_json::from_str(&json).unwrap();
        match parsed {
            StructuredContent::Poll {
                question, options, ..
            } => {
                assert_eq!(question, "What's your favorite language?");
                assert_eq!(options.len(), 2);
            }
            _ => panic!("expected Poll"),
        }
    }

    #[test]
    fn test_custom_type_registry() {
        let mut registry = CustomTypeRegistry::new();

        let def = CustomTypeDefinition {
            name: "com.example.mypost".to_owned(),
            description: "Custom post type".to_owned(),
            version: "1.0.0".to_owned(),
            schema: None,
            is_public: true,
            creator: "did:web:alice".to_owned(),
            registered_at: Hlc::now("chask"),
        };

        registry.register_entity_type(def).unwrap();
        assert!(registry.get_entity_type("com.example.mypost").is_some());
        assert!(registry.get_entity_type("com.example.other").is_none());
    }

    #[test]
    fn test_custom_type_invalid_name() {
        let mut registry = CustomTypeRegistry::new();

        let def = CustomTypeDefinition {
            name: "invalid".to_owned(),
            description: "Bad name".to_owned(),
            version: "1.0.0".to_owned(),
            schema: None,
            is_public: true,
            creator: "did:web:alice".to_owned(),
            registered_at: Hlc::now("chask"),
        };

        assert!(registry.register_entity_type(def).is_err());
    }

    #[test]
    fn test_custom_type_empty_segment() {
        let mut registry = CustomTypeRegistry::new();

        let def = CustomTypeDefinition {
            name: "com..example".to_owned(),
            description: "Bad name".to_owned(),
            version: "1.0.0".to_owned(),
            schema: None,
            is_public: true,
            creator: "did:web:alice".to_owned(),
            registered_at: Hlc::now("chask"),
        };

        assert!(registry.register_entity_type(def).is_err());
    }

    #[test]
    fn test_social_ops_create_post() {
        let post = social_ops::create_post(
            "did:web:alice",
            StructuredContent::Text {
                text: "Hello!".to_owned(),
                language: None,
            },
            AudienceStrategy::Public,
            None,
        );

        assert_eq!(post.author, "did:web:alice");
        assert!(!post.post_id.is_empty());
    }

    #[test]
    fn test_social_ops_create_feed() {
        let feed = social_ops::create_feed(
            "did:web:alice",
            "My Feed",
            FeedType::Personal,
            AudienceStrategy::Followers,
        );

        assert_eq!(feed.owner, "did:web:alice");
        assert_eq!(feed.name, "My Feed");
        assert_eq!(feed.feed_type, FeedType::Personal);
    }

    #[test]
    fn test_social_ops_create_circle() {
        let circle = social_ops::create_circle("did:web:alice", "Close Friends");

        assert_eq!(circle.owner, "did:web:alice");
        assert_eq!(circle.name, "Close Friends");
        assert!(circle.members.is_empty());
    }

    #[test]
    fn test_social_ops_follow_relation() {
        let rel = social_ops::follow_relation("did:web:alice", "did:web:bob");

        assert_eq!(rel.relation_type, RelationType::Follows);
        assert_eq!(rel.source, "did:web:alice");
        assert_eq!(rel.target, "did:web:bob");
    }
}
