//! Completed attachment output. No URL exists until the complete commitment passes.
use std::rc::Rc;

pub(crate) struct Artifact {
    pub url: String,
    pub size: u64,
    pub inline: bool,
    #[cfg(target_arch = "wasm32")]
    blob: web_sys::Blob,
    #[cfg(not(target_arch = "wasm32"))]
    resource: std::sync::Arc<NativeResource>,
}

impl PartialEq for Artifact {
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url && self.size == other.size
    }
}

impl Drop for Artifact {
    fn drop(&mut self) {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = web_sys::Url::revoke_object_url(&self.url);
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.resource
                .revoked
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }
}

pub(crate) struct Builder {
    size: u64,
    mime: String,
    inline: bool,
    #[cfg(target_arch = "wasm32")]
    blob: web_sys::Blob,
    #[cfg(not(target_arch = "wasm32"))]
    file: tempfile::NamedTempFile,
}

impl Builder {
    pub(crate) fn size(&self) -> u64 {
        self.size
    }
    pub(crate) fn new(mime: &str, inline: bool) -> anyhow::Result<Self> {
        let (top, sub) = mime
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("invalid attachment MIME"))?;
        let valid = |part: &str| {
            !part.is_empty()
                && part.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'+' | b'-')
                })
        };
        anyhow::ensure!(valid(top) && valid(sub), "invalid attachment MIME");
        Ok(Self {
            size: 0,
            // Download-only Blob documents must not inherit an executable
            // MIME under the application's origin.
            mime: if inline {
                mime
            } else {
                "application/octet-stream"
            }
            .into(),
            inline,
            #[cfg(target_arch = "wasm32")]
            blob: web_sys::Blob::new().map_err(|e| anyhow::anyhow!("attachment Blob: {e:?}"))?,
            #[cfg(not(target_arch = "wasm32"))]
            file: tempfile::NamedTempFile::new()?,
        })
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let parts = js_sys::Array::new();
            parts.push(self.blob.as_ref());
            parts.push(js_sys::Uint8Array::from(bytes).as_ref());
            let properties = web_sys::BlobPropertyBag::new();
            properties.set_type(&self.mime);
            self.blob = web_sys::Blob::new_with_blob_sequence_and_options(&parts, &properties)
                .map_err(|e| anyhow::anyhow!("attachment Blob part: {e:?}"))?;
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            use std::io::Write;
            self.file.write_all(bytes)?;
        }
        self.size = self
            .size
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| anyhow::anyhow!("attachment size overflow"))?;
        Ok(())
    }

    pub(crate) async fn finish(self) -> anyhow::Result<Rc<Artifact>> {
        #[cfg(target_arch = "wasm32")]
        {
            let url = web_sys::Url::create_object_url_with_blob(&self.blob)
                .map_err(|e| anyhow::anyhow!("attachment object URL: {e:?}"))?;
            Ok(Rc::new(Artifact {
                url,
                size: self.size,
                inline: self.inline,
                blob: self.blob,
            }))
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            use std::sync::Arc;
            use std::sync::atomic::AtomicBool;
            self.file.as_file().sync_all()?;
            let resource = Arc::new(NativeResource {
                file: self.file.into_temp_path(),
                size: self.size,
                mime: self.mime,
                inline: self.inline,
                revoked: AtomicBool::new(false),
            });
            let token = arkret_crypto::blob_aead::fresh_content_key_salt()?
                .as_str()
                .to_owned();
            let listener =
                tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let url = format!("http://127.0.0.1:{}/{token}", listener.local_addr()?.port());
            let weak = Arc::downgrade(&resource);
            tokio::spawn(async move {
                loop {
                    if weak
                        .upgrade()
                        .is_none_or(|r| r.revoked.load(std::sync::atomic::Ordering::Acquire))
                    {
                        break;
                    }
                    let accepted = tokio::select! {
                        accepted = listener.accept() => Some(accepted),
                        _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => None,
                    };
                    if let Some(Ok((socket, _))) = accepted {
                        let weak = weak.clone();
                        let token = token.clone();
                        tokio::spawn(async move {
                            let _ = serve(socket, weak, token).await;
                        });
                    }
                }
            });
            Ok(Rc::new(Artifact {
                url,
                size: self.size,
                inline: self.inline,
                resource,
            }))
        }
    }
}

impl Artifact {
    /// Read only this already-verified inline image, without dereferencing its
    /// transport URL or admitting arbitrary network/filesystem destinations.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) async fn native_image_bytes(&self) -> anyhow::Result<(String, Vec<u8>)> {
        use std::sync::atomic::Ordering;

        use tokio::io::AsyncReadExt;
        anyhow::ensure!(
            self.inline && self.resource.inline,
            "attachment is download-only"
        );
        anyhow::ensure!(
            self.resource.mime.starts_with("image/"),
            "attachment is not an image"
        );
        anyhow::ensure!(
            self.size > 0 && self.size <= 8 * 1024 * 1024 && self.size == self.resource.size,
            "verified image exceeds its native preview budget"
        );
        anyhow::ensure!(
            !self.resource.revoked.load(Ordering::Acquire),
            "attachment was released"
        );
        let mut file = tokio::fs::File::open(&self.resource.file).await?;
        anyhow::ensure!(
            file.metadata().await?.len() == self.size,
            "verified image length changed"
        );
        let mut bytes = vec![0_u8; usize::try_from(self.size)?];
        for part in bytes.chunks_mut(65_536) {
            anyhow::ensure!(
                !self.resource.revoked.load(Ordering::Acquire),
                "attachment was released"
            );
            file.read_exact(part).await?;
        }
        anyhow::ensure!(
            !self.resource.revoked.load(Ordering::Acquire),
            "attachment was released"
        );
        anyhow::ensure!(
            file.metadata().await?.len() == self.size,
            "verified image length changed"
        );
        Ok((self.resource.mime.clone(), bytes))
    }

    /// Byte-bounded UTF-8 pages, including at most three boundary octets.
    pub(crate) async fn text_page(&self, index: u64, page_bytes: u64) -> anyhow::Result<String> {
        let start = index
            .checked_mul(page_bytes)
            .ok_or_else(|| anyhow::anyhow!("text page overflow"))?
            .min(self.size);
        let end = start.saturating_add(page_bytes).min(self.size);
        let read_start = start.saturating_sub(3);
        let read_end = end.saturating_add(3).min(self.size);
        #[cfg(target_arch = "wasm32")]
        let bytes = {
            let slice = self
                .blob
                .slice_with_f64_and_f64(read_start as f64, read_end as f64)
                .map_err(|e| anyhow::anyhow!("text Blob slice: {e:?}"))?;
            let value = wasm_bindgen_futures::JsFuture::from(slice.array_buffer())
                .await
                .map_err(|e| anyhow::anyhow!("text Blob read: {e:?}"))?;
            js_sys::Uint8Array::new(&value).to_vec()
        };
        #[cfg(not(target_arch = "wasm32"))]
        let bytes = {
            use tokio::io::{AsyncReadExt, AsyncSeekExt};
            anyhow::ensure!(
                !self
                    .resource
                    .revoked
                    .load(std::sync::atomic::Ordering::Acquire),
                "attachment was released"
            );
            let mut file = tokio::fs::File::open(&self.resource.file).await?;
            file.seek(std::io::SeekFrom::Start(read_start)).await?;
            let mut bytes = vec![0; usize::try_from(read_end - read_start)?];
            file.read_exact(&mut bytes).await?;
            bytes
        };
        let mut local_start = usize::try_from(start - read_start)?;
        let mut local_end = usize::try_from(end - read_start)?;
        while local_start < bytes.len() && bytes[local_start] & 0xc0 == 0x80 {
            local_start += 1;
        }
        while local_end < bytes.len() && bytes[local_end] & 0xc0 == 0x80 {
            local_end += 1;
        }
        Ok(std::str::from_utf8(&bytes[local_start..local_end])?.to_owned())
    }
}

#[cfg(not(target_arch = "wasm32"))]
struct NativeResource {
    file: tempfile::TempPath,
    size: u64,
    mime: String,
    inline: bool,
    revoked: std::sync::atomic::AtomicBool,
}

/// Read-only loopback capability for the native webview; never a Station API.
#[cfg(not(target_arch = "wasm32"))]
async fn serve(
    mut socket: tokio::net::TcpStream,
    weak: std::sync::Weak<NativeResource>,
    token: String,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
    let mut headers = Vec::new();
    let mut buffer = [0; 1024];
    while !headers.windows(4).any(|b| b == b"\r\n\r\n") {
        let length =
            tokio::time::timeout(std::time::Duration::from_secs(5), socket.read(&mut buffer))
                .await??;
        anyhow::ensure!(
            length > 0 && headers.len() + length <= 8192,
            "invalid asset request"
        );
        headers.extend_from_slice(&buffer[..length]);
    }
    let headers = std::str::from_utf8(&headers)?;
    let mut lines = headers.split("\r\n");
    let request = lines
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>();
    let Some(resource) = weak
        .upgrade()
        .filter(|r| !r.revoked.load(std::sync::atomic::Ordering::Acquire))
    else {
        return Ok(());
    };
    anyhow::ensure!(
        request.len() == 3
            && matches!(request[0], "GET" | "HEAD")
            && request[1] == format!("/{token}"),
        "invalid asset capability"
    );
    let range = lines.find_map(|line| {
        line.split_once(':')
            .filter(|(name, _)| name.eq_ignore_ascii_case("range"))
            .map(|(_, value)| value.trim())
    });
    let (start, end, status) = match range {
        Some(range) => {
            let (start, end) = range
                .strip_prefix("bytes=")
                .and_then(|r| r.split_once('-'))
                .ok_or_else(|| anyhow::anyhow!("invalid asset range"))?;
            let start: u64 = start.parse()?;
            let end = if end.is_empty() {
                resource.size.saturating_sub(1)
            } else {
                end.parse::<u64>()?.min(resource.size.saturating_sub(1))
            };
            anyhow::ensure!(start <= end && end < resource.size, "invalid asset range");
            (start, end, "206 Partial Content")
        }
        None => (0, resource.size.saturating_sub(1), "200 OK"),
    };
    let length = if resource.size == 0 {
        0
    } else {
        end - start + 1
    };
    let mut response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {}\r\nContent-Length: {length}\r\nContent-Disposition: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: sandbox; default-src 'none'\r\nAccept-Ranges: bytes\r\nConnection: close\r\n",
        resource.mime,
        if resource.inline {
            "inline"
        } else {
            "attachment"
        }
    );
    if range.is_some() {
        response.push_str(&format!(
            "Content-Range: bytes {start}-{end}/{}\r\n",
            resource.size
        ));
    }
    response.push_str("\r\n");
    socket.write_all(response.as_bytes()).await?;
    if request[0] == "HEAD" {
        return Ok(());
    }
    let mut file = tokio::fs::File::open(&resource.file).await?;
    file.seek(std::io::SeekFrom::Start(start)).await?;
    let mut remaining = length;
    let mut bytes = zeroize::Zeroizing::new(vec![0; 65_536]);
    while remaining > 0 {
        anyhow::ensure!(
            !resource.revoked.load(std::sync::atomic::Ordering::Acquire),
            "asset was released"
        );
        let take = remaining.min(bytes.len() as u64) as usize;
        file.read_exact(&mut bytes[..take]).await?;
        socket.write_all(&bytes[..take]).await?;
        remaining -= take as u64;
    }
    socket.shutdown().await?;
    Ok(())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn native_image_reads_the_verified_resource_not_its_transport_url() {
        let bytes: Vec<_> = (0..150_001).map(|index| (index % 251) as u8).collect();
        let mut builder = Builder::new("image/png", true).unwrap();
        for part in bytes.chunks(65_536) {
            builder.push(part).unwrap();
        }
        let mut artifact = builder.finish().await.unwrap();
        Rc::get_mut(&mut artifact).unwrap().url =
            "https://untrusted.invalid/not-the-artifact".into();
        let (mime, loaded) = artifact.native_image_bytes().await.unwrap();
        assert_eq!(mime, "image/png");
        assert_eq!(loaded, bytes);
        tokio::fs::write(&artifact.resource.file, b"truncated")
            .await
            .unwrap();
        assert!(artifact.native_image_bytes().await.is_err());
    }

    #[tokio::test]
    async fn native_image_preview_rejects_download_documents_and_excessive_images() {
        for (mime, inline) in [("image/png", false), ("text/html", true)] {
            let mut builder = Builder::new(mime, inline).unwrap();
            builder.push(b"payload").unwrap();
            let artifact = builder.finish().await.unwrap();
            assert!(artifact.native_image_bytes().await.is_err());
        }
        let mut builder = Builder::new("image/png", true).unwrap();
        let block = vec![0_u8; 65_536];
        for _ in 0..129 {
            builder.push(&block).unwrap();
        }
        let artifact = builder.finish().await.unwrap();
        assert!(artifact.native_image_bytes().await.is_err());
    }

    #[tokio::test]
    async fn completed_attachment_asset_has_bounded_ranges_and_revokes_on_release() {
        let mut builder = Builder::new("application/octet-stream", false).unwrap();
        let part = vec![91; 262_144];
        for _ in 0..9 {
            builder.push(&part).unwrap();
        }
        let artifact = builder.finish().await.unwrap();
        let client = reqwest::Client::new();
        let response = client
            .get(&artifact.url)
            .header("range", "bytes=262144-262160")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["content-length"], "17");
        assert_eq!(response.bytes().await.unwrap().as_ref(), &[91; 17]);
        let url = artifact.url.clone();
        drop(artifact);
        assert!(client.get(url).send().await.is_err());
    }

    #[tokio::test]
    async fn downloaded_attachment_documents_have_non_executable_response_metadata() {
        let mut builder = Builder::new("text/html", false).unwrap();
        builder
            .push(b"<script>window.parent.compromised = true</script>")
            .unwrap();
        let artifact = builder.finish().await.unwrap();
        assert!(!artifact.inline);
        let response = reqwest::get(&artifact.url).await.unwrap();
        assert_eq!(
            response.headers()["content-type"],
            "application/octet-stream"
        );
        assert_eq!(response.headers()["content-disposition"], "attachment");
        assert_eq!(
            response.headers()["content-security-policy"],
            "sandbox; default-src 'none'"
        );
    }

    #[tokio::test]
    async fn large_text_pages_preserve_split_utf8_scalars_without_whole_body_reads() {
        let text = format!("{}😀€{}", "x".repeat(65_535), "y".repeat(70_000));
        let mut builder = Builder::new("text/plain", false).unwrap();
        for part in text.as_bytes().chunks(1024) {
            builder.push(part).unwrap();
        }
        let artifact = builder.finish().await.unwrap();
        let mut recovered = String::new();
        for index in 0..artifact.size.div_ceil(65_536) {
            let page = artifact.text_page(index, 65_536).await.unwrap();
            assert!(page.len() <= 65_539);
            recovered.push_str(&page);
        }
        assert_eq!(recovered, text);
    }
}
