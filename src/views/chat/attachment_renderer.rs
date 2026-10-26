//! Authenticated attachments retain source, historical-state and complete-content verification.
use arkret_models_crypto::{EncryptedAttachment, EncryptedAttachmentGroupStateRef};

use super::*;

pub(super) fn render_protocol_content(
    scope: &Scope,
    context: Rc<crate::presentation::InksonContext>,
    source: &AuthenticatedMessageContent,
    mentions: &[MentionNode],
    base_url: &str,
) -> View {
    let content = &source.content;
    if content.kind == arkret_sdk::ContentBlockKind::Composite {
        return super::native::block(
            "content-blocks",
            content
                .parts
                .iter()
                .map(|part| {
                    render_protocol_content(
                        scope,
                        context.clone(),
                        &AuthenticatedMessageContent {
                            content: part.clone(),
                            ..source.clone()
                        },
                        mentions,
                        base_url,
                    )
                })
                .collect(),
        );
    }
    match content.rendered_encrypted_attachment() {
        Ok(Some(descriptor)) => {
            return verified_attachment(scope, context, source.clone(), descriptor);
        }
        Err(error) => {
            return Box::new(
                view()
                    .class("attachment-error")
                    .role(glory::render::Role::Alert)
                    .fill(text().content(format!("Invalid attachment: {error}"))),
            );
        }
        Ok(None) => {}
    }
    use crate::content::ContentBlock as DisplayBlock;
    if let Some(reference) = content.blob_ref() {
        let mime = content
            .extra
            .get("mime_type")
            .and_then(Value::as_str)
            .unwrap_or("application/octet-stream")
            .to_owned();
        let block = match content.kind {
            arkret_sdk::ContentBlockKind::Image => DisplayBlock::Image {
                blob_ref: reference.into(),
                alt: Some(content.body.clone()),
            },
            arkret_sdk::ContentBlockKind::Video => DisplayBlock::Video {
                blob_ref: reference.into(),
                media_type: mime,
            },
            arkret_sdk::ContentBlockKind::Audio => DisplayBlock::Audio {
                blob_ref: reference.into(),
                media_type: mime,
            },
            arkret_sdk::ContentBlockKind::LongText => DisplayBlock::LongText {
                blob_ref: reference.into(),
                fallback: content.body.clone(),
                markdown: content
                    .long_text_media_type()
                    .is_some_and(|media| media.text_format() == arkret_sdk::TextFormat::Markdown),
            },
            _ => DisplayBlock::Attachment {
                blob_ref: reference.into(),
                media_type: Some(mime),
            },
        };
        return crate::content::render_blocks(scope, context, &[block]);
    }
    render_message_body(
        scope,
        context,
        &content.body,
        content.text_format(),
        mentions,
        base_url,
    )
}

async fn load_verified_attachment(
    session: Rc<crate::presentation::InksonContext>,
    source: &AuthenticatedMessageContent,
    descriptor: &EncryptedAttachment,
) -> anyhow::Result<std::rc::Rc<crate::attachments::artifact::Artifact>> {
    anyhow::ensure!(
        matches!(descriptor, EncryptedAttachment::Stream(s) if s.encryption_algorithm == arkret_models_crypto::StreamEncryptionAlgorithm::MlsExporterAeadXchacha20poly1305Stream),
        "unsupported_attachment_scheme"
    );
    if source.content.kind == arkret_sdk::ContentBlockKind::LongText {
        source.content.validate_long_text()?;
    }
    let generation = session.session_generation.get_untracked();
    let account = session
        .active_account
        .get_untracked()
        .clone()
        .ok_or_else(|| anyhow::anyhow!("no attachment account"))?;
    let fence = crate::transport::auth::AuthoringSessionFence::capture()?;
    let active = || {
        fence.check_session_identity().is_ok()
            && session.session_generation.get_untracked() == generation
            && session
                .active_account
                .get_untracked()
                .as_ref()
                .is_some_and(|a| {
                    a.authority == account.authority && a.device_id == account.device_id
                })
    };
    let store = session.state_store.handle();
    let base = session.base_url.get_untracked();
    let credential = session.token.get_untracked();
    let http = crate::transport::auth::authed_api_ready(&base, credential)
        .await?
        .sdk_http_client()?;
    anyhow::ensure!(active(), "attachment session changed");
    let clients = crate::transport::EndpointClients::from_http(http.clone());
    // An authenticated source read is independent from possession of its ref,
    // a cached plaintext or historical checkpoint. Withheld/redacted is denial.
    let source_view = http.committed_event_get(&source.source).await?;
    source_view.validate_shape()?;
    let source_event = source_view
        .reducer_input()
        .ok_or_else(|| anyhow::anyhow!("attachment source is no longer authorized"))?;
    anyhow::ensure!(
        source_event.event_id == source.source && source_event.scope_ref == source.scope,
        "attachment authenticated source binding differs"
    );
    source_event
        .verify_event_id_matches_content_with_digest_suite(arkret_sdk::DigestSuite::Sha256)?;
    let input = crate::mls::send_gate::MlsSendGateInput::capture(&store, &source.scope);
    let current = crate::mls::send_gate::read_durable_mls_current(&input, &source.scope)
        .await?
        .ok_or_else(|| anyhow::anyhow!("attachment scope has no authorized MLS group"))?;
    anyhow::ensure!(active(), "attachment session changed");
    let (context, checkpoint, reference) = store.read(|state| {
        crate::attachments::attachment_receive_context(
            state,
            &account.authority,
            &source.scope,
            &current,
            descriptor,
        )
    })?;
    let winning_view = http.committed_event_get(&reference).await?;
    winning_view.validate_shape()?;
    let winning = winning_view
        .reducer_input()
        .ok_or_else(|| anyhow::anyhow!("attachment historical state is not authorized"))?;
    anyhow::ensure!(
        winning.event_id == reference && winning.scope_ref == source.scope,
        "attachment state source differs"
    );
    winning.verify_event_id_matches_content_with_digest_suite(arkret_sdk::DigestSuite::Sha256)?;
    let payload = serde_json::Value::Object(winning.payload.clone().into_iter().collect());
    let epoch = match winning.kind {
        arkret_sdk::EventKind::MlsGenesis => {
            let genesis: arkret_sdk::MlsGenesisPayload = serde_json::from_value(payload)?;
            genesis.validate()?;
            anyhow::ensure!(
                winning.event_id == context.genesis_event_ref,
                "attachment immutable Genesis differs"
            );
            0
        }
        arkret_sdk::EventKind::MlsCommit => {
            let mls_commit: arkret_sdk::MlsCommitPayload = serde_json::from_value(payload)?;
            mls_commit.validate()?;
            mls_commit.next_epoch()
        }
        _ => anyhow::bail!("attachment_group_state_unresolved: reference is not an MLS state"),
    };
    anyhow::ensure!(
        epoch == context.epoch && active(),
        "attachment state epoch or authorization changed"
    );
    anyhow::ensure!(
        current.genesis_event_ref == context.genesis_event_ref
            && current.effective_scope == context.effective_scope,
        "attachment provenance changed"
    );
    let roster_request = arkret_sdk::MlsMemberRosterAuthorityReadRequestBody {
        realm_id: source
            .scope
            .realm_id_opt()
            .ok_or_else(|| anyhow::anyhow!("attachment scope has no Realm"))?
            .clone(),
        effective_scope: source.scope.clone(),
        mls_group_id: source.scope.canonical_mls_group_id()?,
        target_commit_event_ref: reference.clone(),
        target_epoch: context.epoch,
        caller_actor_id: arkret_sdk::ActorId::account(account.authority.clone()),
        cursor: None,
    };
    let pages = clients
        .mls()
        .unverified_member_roster_authority_pages(&roster_request)
        .await?;
    let peer = arkret_sdk::verify_mls_member_roster_authority_pages(&pages, &roster_request)
        .map_err(anyhow::Error::msg)?;
    let manifest = &pages
        .first()
        .ok_or_else(|| anyhow::anyhow!("attachment authority returned no roster"))?
        .roster
        .manifest;
    anyhow::ensure!(
        manifest.genesis_event_ref == context.genesis_event_ref && active(),
        "attachment Genesis or authorization changed"
    );
    let material_request = arkret_sdk::mls_roster_genesis_material_request(&peer, manifest);
    let material = http
        .self_mls_group_state_material(&material_request)
        .await?;
    anyhow::ensure!(active(), "attachment session changed");
    let mut group = crate::attachments::restore_attachment_group(
        &checkpoint,
        &account.authority,
        &account.device_id,
        &context,
    )?;
    arkret_sdk::install_verified_mls_self_roster_bindings(
        &mut group,
        &pages,
        &roster_request,
        &material,
    )
    .map_err(anyhow::Error::msg)?;
    if current.epoch == context.epoch {
        let (_, tree) = group.public_group_state_bytes()?;
        let suite =
            arkret_models_collaboration::mls_group_state_material::material_digest_from_ref(
                &current.public_tree_ref,
            )?
            .digest_suite()?;
        anyhow::ensure!(
            current.public_tree_ref.as_str()
                == format!("ak:blob:{}", arkret_sdk::canonical::digest(suite, &tree)),
            "attachment checkpoint is not the winning public tree"
        );
    }
    let key = arkret_sdk::mls::derive_attachment_content_key(&group, &context)?;
    let resolver = |r: &EncryptedAttachmentGroupStateRef| {
        r.event_id()
            .ok()
            .filter(|id| id == &reference)
            .map(|_| context.epoch)
    };
    let mut decryptor =
        arkret_crypto::blob_aead::StreamDecryptor::new(descriptor, &key, &resolver)?;
    let EncryptedAttachment::Stream(stream) = descriptor else {
        anyhow::bail!("unsupported_attachment_scheme");
    };
    anyhow::ensure!(
        stream.size_bytes <= 64 * 1024 * 1024,
        "attachment exceeds client limit"
    );
    let count = arkret_models_crypto::stream_segment_count(
        stream.size_bytes,
        u32::try_from(stream.segment_bytes)?,
    )?;
    let download_id = format!(
        "received:{}",
        arkret_crypto::blob_aead::fresh_content_key_salt()?.as_str()
    );
    let chunks = crate::state::current_index::AttachmentChunkStore::open(
        store.read(|s| s.current_index_location()),
        &account.authority,
        &account.device_id,
        &download_id,
    )
    .await?;
    let result = async {
        let mut text = (source.content.kind == arkret_sdk::ContentBlockKind::LongText)
            .then(TextIntegrity::new);
        let mut offset = 0;
        for index in 0..count {
            anyhow::ensure!(active(), "attachment session changed");
            let plaintext_len = stream
                .size_bytes
                .saturating_sub(u64::from(index) * stream.segment_bytes)
                .min(stream.segment_bytes);
            let length = usize::try_from(plaintext_len)?
                .checked_add(16)
                .ok_or_else(|| anyhow::anyhow!("attachment size overflow"))?;
            let ciphertext = clients
                .blob()
                .download_attachment_segment(&stream.blob_ref, offset, length)
                .await?;
            anyhow::ensure!(active(), "attachment session changed");
            let plaintext = zeroize::Zeroizing::new(decryptor.push_segment(index, &ciphertext)?);
            if let Some(text) = &mut text {
                text.push(&plaintext)?;
            }
            chunks.write_part("ciphertext", index, &ciphertext).await?;
            offset += length as u64;
        }
        decryptor.finish()?;
        if let Some(text) = text {
            text.finish(&source.content)?;
        }
        anyhow::ensure!(active(), "attachment session changed");
        // No plaintext sink or URL existed before the entire commitment passed.
        let inline = match source.content.kind {
            arkret_sdk::ContentBlockKind::Image => matches!(
                stream.media_type.as_str(),
                "image/png"
                    | "image/jpeg"
                    | "image/gif"
                    | "image/webp"
                    | "image/avif"
                    | "image/bmp"
                    | "image/x-icon"
            ),
            arkret_sdk::ContentBlockKind::Audio => stream.media_type.starts_with("audio/"),
            arkret_sdk::ContentBlockKind::Video => stream.media_type.starts_with("video/"),
            _ => false,
        };
        let mut builder = crate::attachments::artifact::Builder::new(&stream.media_type, inline)?;
        let mut verified =
            arkret_crypto::blob_aead::StreamDecryptor::new(descriptor, &key, &resolver)?;
        for index in 0..count {
            anyhow::ensure!(active(), "attachment session changed");
            let ciphertext = chunks.read_part("ciphertext", index).await?;
            let plaintext = zeroize::Zeroizing::new(verified.push_segment(index, &ciphertext)?);
            builder.push(&plaintext)?;
        }
        verified.finish()?;
        anyhow::ensure!(
            builder.size() == stream.size_bytes && active(),
            "attachment result changed"
        );
        let artifact = builder.finish().await?;
        anyhow::ensure!(active(), "attachment session changed");
        Ok::<_, anyhow::Error>(artifact)
    }
    .await;
    let cleanup = chunks.clear("ciphertext").await;
    match result {
        Ok(artifact) => {
            cleanup?;
            Ok(artifact)
        }
        Err(error) => {
            let _ = cleanup;
            Err(error)
        }
    }
}

struct TextIntegrity {
    carry: Vec<u8>,
    prefix: Vec<u8>,
    lines: u64,
}
impl TextIntegrity {
    fn new() -> Self {
        Self {
            carry: Vec::new(),
            prefix: Vec::new(),
            lines: 1,
        }
    }
    fn push(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        anyhow::ensure!(!bytes.contains(&b'\r'), "long text is not normalized");
        self.lines += bytes.iter().filter(|b| **b == b'\n').count() as u64;
        let take = bytes
            .len()
            .min(4099_usize.saturating_sub(self.prefix.len()));
        self.prefix.extend_from_slice(&bytes[..take]);
        let mut complete = zeroize::Zeroizing::new(std::mem::take(&mut self.carry));
        complete.extend_from_slice(bytes);
        if let Err(error) = std::str::from_utf8(&complete) {
            anyhow::ensure!(error.error_len().is_none(), "long text is not UTF-8");
            self.carry
                .extend_from_slice(&complete[error.valid_up_to()..]);
            anyhow::ensure!(
                self.carry.len() <= 3,
                "long text UTF-8 boundary exceeds its bound"
            );
        }
        Ok(())
    }
    fn finish(self, content: &arkret_sdk::ContentBlock) -> anyhow::Result<()> {
        anyhow::ensure!(self.carry.is_empty(), "long text UTF-8 is truncated");
        anyhow::ensure!(
            content.extra.get("line_count").and_then(Value::as_u64) == Some(self.lines),
            "long-text line count differs"
        );
        if content.extra.get("body_kind").and_then(Value::as_str) == Some("prefix") {
            let mut end = self.prefix.len().min(4096);
            while std::str::from_utf8(&self.prefix[..end]).is_err() && end > 0 {
                end -= 1;
            }
            anyhow::ensure!(
                content.body.as_bytes() == &self.prefix[..end],
                "long-text prefix differs"
            );
        }
        Ok(())
    }
}

fn verified_attachment(
    scope: &Scope,
    context: Rc<crate::presentation::InksonContext>,
    source: AuthenticatedMessageContent,
    descriptor: EncryptedAttachment,
) -> View {
    use crate::presentation::widgets::{paragraph, reactive_distinct, resource};
    let request_context = context.clone();
    let request_source = source.clone();
    let request_descriptor = descriptor.clone();
    let loaded = resource(scope, move || {
        let generation = request_context.session_generation.get();
        let account = request_context.active_account.get();
        let _ = request_context.token.get();
        let _ = request_context.base_url.get();
        let context = request_context.clone();
        let source = request_source.clone();
        let descriptor = request_descriptor.clone();
        async move {
            if !context.session_matches(generation, &account) {
                return Err("attachment session changed".into());
            }
            let artifact = load_verified_attachment(context.clone(), &source, &descriptor)
                .await
                .map_err(|error| format!("{error:#}"))?;
            if !context.session_matches(generation, &account) {
                return Err("attachment session changed".into());
            }
            Ok(artifact)
        }
    });
    let name = source
        .content
        .extra
        .get("filename")
        .and_then(Value::as_str)
        .unwrap_or("attachment")
        .to_owned();
    let content = reactive_distinct(loaded.data, move |scope, result| {
        let Some(result) = result else {
            return paragraph("attachment-loading", "Verifying attachment…");
        };
        let artifact = match result {
            Ok(artifact) => artifact,
            Err(error) => {
                return Box::new(
                    view()
                        .class("attachment-error")
                        .role(glory::render::Role::Alert)
                        .fill(text().content(error)),
                );
            }
        };
        let _ = scope.retain(artifact.clone());
        if source.content.kind == arkret_sdk::ContentBlockKind::LongText {
            return verified_long_text(
                scope,
                context.clone(),
                artifact,
                name.clone(),
                descriptor.media_type() == "text/markdown",
            );
        }
        match source.content.kind {
            arkret_sdk::ContentBlockKind::Image if artifact.inline => {
                verified_image(scope, context.clone(), artifact, name.clone())
            }
            arkret_sdk::ContentBlockKind::Video if artifact.inline => verified_media(
                scope,
                context.clone(),
                artifact,
                name.clone(),
                descriptor.media_type(),
                true,
            ),
            arkret_sdk::ContentBlockKind::Audio if artifact.inline => verified_media(
                scope,
                context.clone(),
                artifact,
                name.clone(),
                descriptor.media_type(),
                false,
            ),
            _ => artifact_download(scope, context.clone(), artifact, name.clone()),
        }
    });
    super::native::block("verified-attachment", vec![content])
}

#[cfg(target_arch = "wasm32")]
fn verified_image(
    _scope: &Scope,
    _context: Rc<crate::presentation::InksonContext>,
    artifact: Rc<crate::attachments::artifact::Artifact>,
    name: String,
) -> View {
    Box::new(
        image()
            .class("verified-attachment-image")
            .source(artifact.url.clone())
            .alt(name),
    )
}

#[cfg(not(target_arch = "wasm32"))]
fn verified_image(
    scope: &Scope,
    context: Rc<crate::presentation::InksonContext>,
    artifact: Rc<crate::attachments::artifact::Artifact>,
    name: String,
) -> View {
    use crate::presentation::widgets::{paragraph, reactive_distinct, resource};
    let owner = scope.downgrade();
    let request_context = context.clone();
    let request_artifact = artifact.clone();
    let generation = context.session_generation.get_untracked();
    let account = context.active_account.get_untracked();
    let registered = resource(scope, move || {
        let account = account.clone();
        let context = request_context.clone();
        let artifact = request_artifact.clone();
        let owner = owner.clone();
        async move {
            if !context.session_matches(generation, &account) || owner.upgrade().is_none() {
                return Err("attachment session changed".into());
            }
            let (mime, bytes) = artifact
                .native_image_bytes()
                .await
                .map_err(|error| format!("{error:#}"))?;
            let scope = owner.upgrade().ok_or("The image owner was retired.")?;
            if !context.session_matches(generation, &account) {
                return Err("attachment session changed".into());
            }
            context.register_native_image(&scope, &mime, bytes)
        }
    });
    reactive_distinct(registered.data, move |scope, result| match result {
        None => paragraph("attachment-loading", "Loading verified image…"),
        Some(Ok(url)) => Box::new(
            image()
                .class("verified-attachment-image")
                .source(url)
                .alt(name.clone()),
        ),
        Some(Err(error)) => super::native::block(
            "verified-attachment-image-error",
            vec![
                Box::new(
                    view()
                        .class("attachment-error")
                        .role(glory::render::Role::Alert)
                        .fill(text().content(error)),
                ),
                artifact_download(scope, context.clone(), artifact.clone(), name.clone()),
            ],
        ),
    })
}

fn verified_media(
    scope: &Scope,
    context: Rc<crate::presentation::InksonContext>,
    artifact: Rc<crate::attachments::artifact::Artifact>,
    name: String,
    mime: &str,
    video: bool,
) -> View {
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (context, name, mime);
        crate::content::media_url(scope, artifact.url.clone(), video)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let extension = match mime {
            "video/mp4" => Some("mp4"),
            "video/quicktime" => Some("mov"),
            "audio/mpeg" => Some("mp3"),
            "audio/mp4" => Some("m4a"),
            "audio/ogg" => Some("ogg"),
            "audio/wav" | "audio/x-wav" => Some("wav"),
            "audio/flac" | "audio/x-flac" => Some("flac"),
            "audio/aac" => Some("aac"),
            "audio/webm" | "video/webm" => Some("webm"),
            _ => None,
        };
        let has_extension = std::path::Path::new(&name).extension().is_some();
        let filename = match (has_extension, extension) {
            (false, Some(extension)) => format!("{name}.{extension}"),
            _ => name,
        };
        artifact_save_control(
            scope,
            context,
            artifact,
            filename,
            true,
            if video {
                "Save and open video".into()
            } else {
                "Save and open audio".into()
            },
        )
    }
}

type TextPageSelection = (String, u64);
type LoadedTextPage = Option<(TextPageSelection, std::result::Result<String, String>)>;
fn verified_text_page(
    scope: &Scope,
    artifact: impl Into<Lotus<Rc<crate::attachments::artifact::Artifact>>>,
) -> (Cage<TextPageSelection>, Cage<LoadedTextPage>) {
    let artifact = artifact.into();
    let selection = scope.cage((glory::core::untracked(|| artifact.get()).url.clone(), 0_u64));
    let loaded = scope.cage(None);
    let revision = Rc::new(std::cell::Cell::new(0_u64));
    let requested = Rc::new(std::cell::RefCell::new(None::<TextPageSelection>));
    let running = Rc::new(std::cell::RefCell::new(None::<glory::core::TaskToken>));
    let owner = scope.downgrade();
    scope.effect(move || {
        let artifact = artifact.get();
        let mut binding = selection.get();
        if binding.0 != artifact.url {
            binding = (artifact.url.clone(), 0);
            selection.revise(|value| *value = binding.clone());
        }
        if requested.borrow().as_ref() == Some(&binding) {
            return;
        }
        *requested.borrow_mut() = Some(binding.clone());
        if let Some(task) = running.borrow_mut().take() {
            task.cancel();
        }
        loaded.revise(|value| *value = None);
        let next = revision.get().wrapping_add(1);
        revision.set(next);
        let Some(scope) = owner.upgrade() else { return };
        let owner = owner.clone();
        let revision = revision.clone();
        if let Ok(task) = scope.spawn(async move {
            let text = artifact
                .text_page(binding.1, 65536)
                .await
                .map_err(|error| format!("{error:#}"));
            if owner.upgrade().is_some()
                && revision.get() == next
                && selection.get_untracked() == binding
            {
                loaded.revise(|value| *value = Some((binding, text)));
            }
        }) {
            *running.borrow_mut() = Some(task);
        }
    });
    (selection, loaded)
}

fn verified_long_text(
    scope: &Scope,
    context: Rc<crate::presentation::InksonContext>,
    artifact: Rc<crate::attachments::artifact::Artifact>,
    name: String,
    markdown: bool,
) -> View {
    use super::native::{block, button};
    use crate::presentation::widgets::{line, paragraph, reactive_distinct};
    let (selection, loaded) = verified_text_page(scope, artifact.clone());
    let last = artifact.size.saturating_sub(1) / 65536;
    let page = scope.bond(move || {
        let selected = selection.get();
        loaded
            .get()
            .and_then(|(binding, result)| (binding == selected).then_some(result))
    });
    let render_context = context.clone();
    let body = reactive_distinct(page, move |scope, result| match result {
        Some(Ok(body)) if markdown => crate::content::render_blocks(
            scope,
            render_context.clone(),
            &[crate::content::ContentBlock::Markdown(
                crate::content::renderer::markdown_to_safe_html(&body),
            )],
        ),
        Some(Ok(body)) => Box::new(
            text()
                .kind(glory::render::TextKind::Code)
                .class("verified-long-text-page")
                .content(body),
        ),
        Some(Err(error)) => Box::new(
            view()
                .role(glory::render::Role::Alert)
                .fill(text().content(error)),
        ),
        None => paragraph("muted", "Loading text…"),
    });
    let previous_identity = artifact.url.clone();
    let next_identity = artifact.url.clone();
    let last_identity = artifact.url.clone();
    block(
        "verified-long-text",
        vec![
            Box::new(
                view()
                    .class("verified-long-text-viewport")
                    .role(glory::render::Role::Section)
                    .name("Message text")
                    .fill(body),
            ),
            line(
                "actions",
                vec![
                    button(
                        "Previous page",
                        "secondary verified-long-text-previous",
                        scope.bond(move || selection.get().1 > 0),
                        move || {
                            selection.revise(|value| {
                                *value = (previous_identity.clone(), value.1.saturating_sub(1))
                            })
                        },
                    ),
                    button(
                        "Next page",
                        "secondary verified-long-text-next",
                        scope.bond(move || selection.get().1 < last),
                        move || {
                            selection.revise(|value| {
                                *value = (next_identity.clone(), (value.1 + 1).min(last))
                            })
                        },
                    ),
                    button(
                        "Last page",
                        "secondary verified-long-text-last",
                        scope.bond(move || selection.get().1 < last),
                        move || selection.revise(|value| *value = (last_identity.clone(), last)),
                    ),
                    artifact_download(scope, context, artifact, name),
                ],
            ),
        ],
    )
}

fn artifact_download(
    scope: &Scope,
    context: Rc<crate::presentation::InksonContext>,
    artifact: Rc<crate::attachments::artifact::Artifact>,
    name: String,
) -> View {
    artifact_save_control(scope, context, artifact, name.clone(), false, name)
}

#[derive(Clone)]
struct ArtifactSaveFence {
    owner: glory::ui::WeakScope,
    context: Rc<crate::presentation::InksonContext>,
    generation: u64,
    account: Option<crate::config::ActiveAccountContext>,
}

impl ArtifactSaveFence {
    fn current(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.owner.upgrade().is_some(),
            "The attachment owner was retired."
        );
        anyhow::ensure!(
            self.context.session_matches(self.generation, &self.account),
            "The attachment session changed."
        );
        Ok(())
    }
}

fn artifact_save_control(
    scope: &Scope,
    context: Rc<crate::presentation::InksonContext>,
    artifact: Rc<crate::attachments::artifact::Artifact>,
    name: String,
    open_media: bool,
    label: String,
) -> View {
    let busy = scope.cage(false);
    let status = scope.cage(String::new());
    let filename = name;
    let fence = ArtifactSaveFence {
        owner: scope.downgrade(),
        generation: context.session_generation.get_untracked(),
        account: context.active_account.get_untracked(),
        context,
    };
    let active = Rc::new(std::cell::RefCell::new(None::<glory::core::TaskToken>));
    let action = super::native::button(
        label,
        if open_media {
            "secondary verified-attachment-media-open"
        } else {
            "secondary verified-attachment-download"
        },
        scope.bond(move || !busy.get()),
        move || {
            if busy.get_untracked() {
                return;
            }
            if let Err(error) = fence.current() {
                status.revise(|value| *value = error.to_string());
                return;
            }
            let Some(scope) = fence.owner.upgrade() else {
                return;
            };
            busy.revise(|value| *value = true);
            status.revise(String::clear);
            let artifact = artifact.clone();
            let name = filename.clone();
            let current = fence.clone();
            let task = scope.spawn(async move {
                let result = save_artifact(artifact, name, &current, open_media).await;
                if current.current().is_ok() {
                    let _ = status.try_revise(|value| {
                        *value = result
                            .err()
                            .map(|error| error.to_string())
                            .unwrap_or_default()
                    });
                    let _ = busy.try_revise(|value| *value = false);
                }
            });
            match task {
                Ok(task) => {
                    if let Some(previous) = active.borrow_mut().replace(task) {
                        previous.cancel();
                    }
                }
                Err(error) => {
                    busy.revise(|value| *value = false);
                    status.revise(|value| *value = error.to_string());
                }
            }
        },
    );
    super::native::block(
        "verified-attachment-download-row",
        vec![
            action,
            crate::presentation::widgets::paragraph("muted", status),
        ],
    )
}

#[cfg(target_arch = "wasm32")]
async fn save_artifact(
    artifact: Rc<crate::attachments::artifact::Artifact>,
    name: String,
    fence: &ArtifactSaveFence,
    _open_media: bool,
) -> anyhow::Result<()> {
    use wasm_bindgen::JsCast;
    fence.current()?;
    let document = web_sys::window()
        .and_then(|window| window.document())
        .ok_or_else(|| anyhow::anyhow!("download document unavailable"))?;
    let anchor = document
        .create_element("a")
        .map_err(|error| anyhow::anyhow!("download anchor: {error:?}"))?
        .dyn_into::<web_sys::HtmlAnchorElement>()
        .map_err(|_| anyhow::anyhow!("download anchor unavailable"))?;
    anchor.set_href(&artifact.url);
    anchor.set_download(&name);
    let body = document
        .body()
        .ok_or_else(|| anyhow::anyhow!("download document body unavailable"))?;
    body.append_child(&anchor)
        .map_err(|error| anyhow::anyhow!("download anchor: {error:?}"))?;
    anchor.click();
    anchor.remove();
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
async fn save_artifact(
    artifact: Rc<crate::attachments::artifact::Artifact>,
    name: String,
    fence: &ArtifactSaveFence,
    open_media: bool,
) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;
    fence.current()?;
    let (sender, receiver) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let _ = sender.send(rfd::FileDialog::new().set_file_name(&name).save_file());
    });
    let Some(path) = receiver.await? else {
        return Ok(());
    };
    fence.current()?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("download destination unavailable"))?;
    let temporary = tempfile::NamedTempFile::new_in(parent)?;
    let (file, temporary) = temporary.into_parts();
    let mut output = tokio::fs::File::from_std(file);
    let mut response = reqwest::Client::new()
        .get(&artifact.url)
        .send()
        .await?
        .error_for_status()?;
    fence.current()?;
    let mut size = 0_u64;
    while let Some(chunk) = response.chunk().await? {
        fence.current()?;
        size = size
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| anyhow::anyhow!("download size overflow"))?;
        anyhow::ensure!(
            size <= artifact.size,
            "verified download exceeded its commitment"
        );
        output.write_all(&chunk).await?;
        fence.current()?;
    }
    anyhow::ensure!(size == artifact.size, "verified download was truncated");
    output.flush().await?;
    fence.current()?;
    output.sync_all().await?;
    fence.current()?;
    drop(output);
    temporary.persist(&path).map_err(|error| error.error)?;
    if open_media {
        fence.current()?;
        crate::content::open_saved_media(&path).map_err(anyhow::Error::msg)?;
    }
    Ok(())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod reader_tests {
    use super::*;
    async fn settle(
        app: &glory::ui::App,
        executor: &glory::core::executor::Executor,
        selection: Cage<TextPageSelection>,
        loaded: Cage<LoadedTextPage>,
        identity: &str,
        index: u64,
    ) -> String {
        for _ in 0..200 {
            for _ in 0..32 {
                executor.poll_one();
                app.flush().unwrap();
            }
            assert_eq!(selection.get_untracked(), (identity.to_owned(), index));
            if let Some((binding, result)) = loaded.get_untracked()
                && binding == (identity.to_owned(), index)
            {
                return result.unwrap();
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("verified reader did not settle to the selected artifact/page");
    }
    #[tokio::test]
    async fn verified_text_page_survives_parent_updates_and_resets_only_for_new_artifact() {
        let mut builder = crate::attachments::artifact::Builder::new("text/plain", false).unwrap();
        builder.push(&vec![b'a'; 65536]).unwrap();
        builder.push(b"last page sentinel").unwrap();
        let first = builder.finish().await.unwrap();
        let executor = Rc::new(glory::core::executor::Executor::new(256));
        let app = glory::App::with_host(executor.clone(), glory::render::memory::Memory::new);
        let artifact = app.scope().cage(first.clone());
        let pulse = app.scope().cage(0_u64);
        let (selection, loaded) = verified_text_page(app.scope(), artifact);
        assert_eq!(
            settle(&app, &executor, selection, loaded, &first.url, 0)
                .await
                .len(),
            65536
        );
        selection.revise(|value| *value = (first.url.clone(), 1));
        assert_eq!(
            settle(&app, &executor, selection, loaded, &first.url, 1).await,
            "last page sentinel"
        );
        for value in 1..=4 {
            pulse.revise(|pulse| *pulse = value);
            assert_eq!(
                settle(&app, &executor, selection, loaded, &first.url, 1).await,
                "last page sentinel"
            );
        }
        let mut builder = crate::attachments::artifact::Builder::new("text/plain", false).unwrap();
        builder.push(b"replacement artifact").unwrap();
        let replacement = builder.finish().await.unwrap();
        artifact.revise(|value| *value = replacement.clone());
        app.flush().unwrap();
        assert_eq!(
            settle(&app, &executor, selection, loaded, &replacement.url, 0).await,
            "replacement artifact"
        );
    }
}
