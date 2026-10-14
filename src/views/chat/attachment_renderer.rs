//! Structured, authenticated attachments; all network results are session fenced.
use arkret_models_crypto::{EncryptedAttachment, EncryptedAttachmentGroupStateRef};

use super::*;

pub(super) fn render_protocol_content(
    source: &AuthenticatedMessageContent,
    mentions: &[MentionNode],
    base_url: &str,
) -> Element {
    let content = &source.content;
    if content.kind == arkret_sdk::ContentBlockKind::Composite {
        return rsx! { div { class: "content-blocks", for (index, part) in content.parts.iter().enumerate() {
            div { key: "{source.source}-{index}",
                {render_protocol_content(&AuthenticatedMessageContent {content: part.clone(), ..source.clone()}, mentions, base_url)}
            }
        } } };
    }
    match content.rendered_encrypted_attachment() {
        Ok(Some(descriptor)) => {
            return rsx! { VerifiedAttachment {key: "{source.source}-{descriptor.blob_ref()}", source: source.clone(), descriptor} };
        }
        Err(error) => {
            return rsx! { p { role: "alert", "data-testid": "attachment-error", "Invalid attachment: {error}" } };
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
                    .is_some_and(|m| m.text_format() == arkret_sdk::TextFormat::Markdown),
            },
            _ => DisplayBlock::Attachment {
                blob_ref: reference.into(),
                media_type: Some(mime),
            },
        };
        return crate::content::render_blocks(&[block]);
    }
    render_message_body(&content.body, content.text_format(), mentions, base_url)
}

async fn load_verified_attachment(
    session: crate::app::SessionContext,
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
    let generation = *session.session_generation.peek();
    let account = session
        .active_account
        .peek()
        .clone()
        .ok_or_else(|| anyhow::anyhow!("no attachment account"))?;
    let fence = crate::transport::auth::AuthoringSessionFence::capture()?;
    let active = || {
        fence.check_session_identity().is_ok()
            && *session.session_generation.peek() == generation
            && session.active_account.peek().as_ref().is_some_and(|a| {
                a.authority == account.authority && a.device_id == account.device_id
            })
    };
    let store = crate::app::runtime_adapter::state_store_handle(session.state_store);
    let config = crate::config::LocalConfigStore::default().load();
    let base = config
        .server_url()
        .ok_or_else(|| anyhow::anyhow!("no authenticated attachment route"))?;
    let http =
        crate::transport::auth::authed_api_ready(base.as_str(), config.session_credential.clone())
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
            let commit: arkret_sdk::MlsCommitPayload = serde_json::from_value(payload)?;
            commit.validate()?;
            commit.next_epoch()
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

#[component]
fn VerifiedAttachment(
    source: AuthenticatedMessageContent,
    descriptor: EncryptedAttachment,
) -> Element {
    let session = consume_context::<crate::app::SessionContext>();
    let generation = *session.session_generation.read();
    let mut result =
        use_signal(|| None::<Result<std::rc::Rc<crate::attachments::artifact::Artifact>, String>>);
    let mut revision = use_signal(|| 0_u64);
    let source_for_effect = source.clone();
    let descriptor_for_effect = descriptor.clone();
    use_effect(use_reactive(
        (&source_for_effect, &descriptor_for_effect, &generation),
        move |(source, descriptor, generation)| {
            result.set(None);
            let captured = revision.peek().wrapping_add(1);
            revision.set(captured);
            spawn(async move {
                let loaded = load_verified_attachment(session, &source, &descriptor)
                    .await
                    .map_err(|e| format!("{e:#}"));
                if *revision.peek() == captured && *session.session_generation.peek() == generation
                {
                    result.set(Some(loaded));
                }
            });
        },
    ));
    let name = source
        .content
        .extra
        .get("filename")
        .and_then(Value::as_str)
        .unwrap_or("attachment")
        .to_owned();
    match result() {
        Some(Ok(artifact)) if source.content.kind == arkret_sdk::ContentBlockKind::LongText => {
            rsx! { VerifiedLongText {artifact, name, markdown: descriptor.media_type() == "text/markdown"} }
        }
        Some(Ok(artifact)) => match source.content.kind {
            arkret_sdk::ContentBlockKind::Image if artifact.inline => {
                rsx! {img {src: artifact.url.clone(), alt: name, "data-testid": "verified-attachment-image"}}
            }
            arkret_sdk::ContentBlockKind::Video if artifact.inline => {
                rsx! {video {src: artifact.url.clone(), controls: true, "data-testid": "verified-attachment-video"}}
            }
            arkret_sdk::ContentBlockKind::Audio if artifact.inline => {
                rsx! {audio {src: artifact.url.clone(), controls: true, "data-testid": "verified-attachment-audio"}}
            }
            _ => {
                rsx! {a {href: artifact.url.clone(), download: name.clone(), "data-testid": "verified-attachment-download", "{name}"}}
            }
        },
        Some(Err(error)) => rsx! {p {role: "alert", "data-testid": "attachment-error", "{error}"}},
        None => rsx! {p {"data-testid": "attachment-loading", "Verifying attachment…"}},
    }
}

type TextPageSelection = (String, u64);
type LoadedTextPage = Option<(TextPageSelection, Result<String, String>)>;

// Bind selection and results to the artifact itself. A deferred reset effect
// must not overwrite a page change, and an older read cannot publish for a
// replacement artifact or a different page.
fn use_verified_text_page(
    artifact: std::rc::Rc<crate::attachments::artifact::Artifact>,
) -> (Signal<TextPageSelection>, Signal<LoadedTextPage>) {
    const PAGE_BYTES: u64 = 65_536;
    let identity = artifact.url.clone();
    let mut selection = use_signal(|| (identity.clone(), 0_u64));
    let mut text = use_signal(|| None::<(TextPageSelection, Result<String, String>)>);
    let mut revision = use_signal(|| 0_u64);
    if selection.peek().0 != identity {
        selection.set((identity, 0));
    }
    let index = selection().1;
    use_effect(use_reactive((&artifact, &index), move |(read, index)| {
        text.set(None);
        let captured = revision.peek().wrapping_add(1);
        revision.set(captured);
        spawn(async move {
            let binding = (read.url.clone(), index);
            let loaded = read
                .text_page(index, PAGE_BYTES)
                .await
                .map_err(|e| format!("{e:#}"));
            if *revision.peek() == captured && *selection.peek() == binding {
                text.set(Some((binding, loaded)));
            }
        });
    }));
    (selection, text)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod reader_tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;

    type Handles = (
        Signal<Rc<crate::attachments::artifact::Artifact>>,
        Signal<u64>,
        Signal<TextPageSelection>,
        Signal<LoadedTextPage>,
    );

    #[derive(Clone)]
    struct Control {
        artifact: Rc<crate::attachments::artifact::Artifact>,
        handles: Rc<RefCell<Option<Handles>>>,
    }

    fn reader_harness(control: Control) -> Element {
        let artifact = use_signal(|| control.artifact);
        let pulse = use_signal(|| 0_u64);
        let (selection, text) = use_verified_text_page(artifact());
        *control.handles.borrow_mut() = Some((artifact, pulse, selection, text));
        let ready = text.read().is_some();
        rsx! {span {"{pulse}:{ready}"}}
    }

    async fn settle(dom: &mut VirtualDom, control: &Control, identity: &str, index: u64) -> String {
        for _ in 0..200 {
            dom.render_immediate_to_vec();
            let text = dom.in_runtime(|| {
                let (_, _, selection, text) = control.handles.borrow().unwrap();
                assert_eq!(*selection.peek(), (identity.to_owned(), index));
                text.peek().clone()
            });
            if let Some((binding, body)) = text
                && binding == (identity.to_owned(), index)
            {
                return body.unwrap();
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("verified reader did not settle to the selected artifact/page");
    }

    #[tokio::test]
    async fn verified_text_page_survives_parent_updates_and_resets_only_for_new_artifact() {
        // This exercises the real reader hook and native artifacts, with
        // verified bytes given. It makes no authorization/install claim.
        let mut builder = crate::attachments::artifact::Builder::new("text/plain", false).unwrap();
        builder.push(&vec![b'a'; 65_536]).unwrap();
        builder.push(b"last page sentinel").unwrap();
        let first = builder.finish().await.unwrap();
        let control = Control {
            artifact: first.clone(),
            handles: Rc::new(RefCell::new(None)),
        };
        let mut dom = VirtualDom::new_with_props(reader_harness, control.clone());
        dom.rebuild_in_place();
        assert_eq!(
            settle(&mut dom, &control, &first.url, 0).await.len(),
            65_536
        );
        dom.in_runtime(|| {
            let (_, _, mut selection, _) = control.handles.borrow().unwrap();
            selection.set((first.url.clone(), 1));
        });
        assert_eq!(
            settle(&mut dom, &control, &first.url, 1).await,
            "last page sentinel"
        );
        for value in 1..=4 {
            dom.in_runtime(|| {
                let (_, mut pulse, ..) = control.handles.borrow().unwrap();
                pulse.set(value);
            });
            assert_eq!(
                settle(&mut dom, &control, &first.url, 1).await,
                "last page sentinel"
            );
        }
        let mut builder = crate::attachments::artifact::Builder::new("text/plain", false).unwrap();
        builder.push(b"replacement artifact").unwrap();
        let replacement = builder.finish().await.unwrap();
        dom.in_runtime(|| {
            let (mut artifact, ..) = control.handles.borrow().unwrap();
            artifact.set(replacement.clone());
        });
        assert_eq!(
            settle(&mut dom, &control, &replacement.url, 0).await,
            "replacement artifact"
        );
    }
}

#[component]
fn VerifiedLongText(
    artifact: std::rc::Rc<crate::attachments::artifact::Artifact>,
    name: String,
    markdown: bool,
) -> Element {
    const PAGE_BYTES: u64 = 65_536;
    let reader_identity = use_hook(uuid_v7);
    let (mut selection, loaded) = use_verified_text_page(artifact.clone());
    let current = selection();
    let index = current.1;
    let text = loaded().and_then(|(binding, result)| (binding == current).then_some(result));
    let previous_identity = artifact.url.clone();
    let next_identity = artifact.url.clone();
    let last_identity = artifact.url.clone();
    let last = artifact.size.saturating_sub(1) / PAGE_BYTES;
    rsx! {div {"data-testid": "verified-long-text", "data-page-index": "{index}", "data-reader-id": reader_identity,
        div {class: "verified-long-text-viewport", "data-testid": "verified-long-text-viewport",
            tabindex: "0", role: "region", "aria-label": "Message text",
            match text {
                Some(Ok(body)) if markdown => {
                    let html = crate::content::renderer::markdown_to_safe_html(&body);
                    rsx! {div {"data-testid": "verified-long-text-page", class: "content-block-markdown", dangerous_inner_html: html}}
                },
                Some(Ok(body)) => rsx! {pre {"data-testid": "verified-long-text-page", "{body}"}},
                Some(Err(error)) => rsx! {p {role: "alert", "{error}"}},
                None => rsx! {p {"Loading text…"}},
            }
        }
        button {disabled: index == 0, onclick: move |_| selection.set((previous_identity.clone(), index.saturating_sub(1))), "Previous page"}
        button {"data-testid": "verified-long-text-next", disabled: index >= last, onclick: move |_|selection.set((next_identity.clone(), (index+1).min(last))), "Next page"}
        button {"data-testid": "verified-long-text-last", disabled: index >= last, onclick: move |_|selection.set((last_identity.clone(), last)), "Last page"}
        a {href: artifact.url.clone(), download: name, "Download full text"}
    }}
}
