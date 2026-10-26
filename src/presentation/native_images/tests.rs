use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::atomic::AtomicUsize;

use glory::blitz::assets::{LoadConfig, Loader, NetReady, Url};
use glory::ui::Widget;

use super::*;

fn png() -> Vec<u8> {
    vec![
        137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8, 6,
        0, 0, 0, 31, 21, 196, 137, 0, 0, 0, 13, 73, 68, 65, 84, 120, 156, 99, 248, 207, 192, 240,
        31, 0, 5, 0, 1, 255, 137, 153, 61, 29, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
    ]
}

#[derive(Default)]
struct Results {
    bytes: AtomicUsize,
    errors: AtomicUsize,
}
struct Handler {
    result: Arc<Results>,
    entered: Option<mpsc::SyncSender<()>>,
    release: Option<Arc<Notify>>,
}
impl Handler {
    fn new(result: Arc<Results>) -> Box<Self> {
        Box::new(Self {
            result,
            entered: None,
            release: None,
        })
    }
}
impl NetHandler for Handler {
    fn prepare<'a>(&'a mut self, _url: &'a str, _bytes: &'a Bytes) -> NetReady<'a> {
        Box::pin(async move {
            if let Some(entered) = self.entered.take() {
                let _ = entered.send(());
            }
            if let Some(release) = &self.release {
                release.notified().await;
            }
            Ok(())
        })
    }
    fn bytes(self: Box<Self>, _url: String, _bytes: Bytes) {
        self.result.bytes.fetch_add(1, Ordering::SeqCst);
    }
    fn error(self: Box<Self>, _url: String, _error: String) {
        self.result.errors.fetch_add(1, Ordering::SeqCst);
    }
}
fn wait_until(mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !check() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(check(), "native resource deadline");
}

#[test]
fn limits_reloads_cancel_retire_and_foreign_documents_do_not_publish() {
    let app = glory::ui::App::memory();
    let images = ScopedImageRegistry::new(Limits {
        entries: 2,
        total_bytes: png().len() * 2,
        pending: 1,
        ..Limits::default()
    })
    .unwrap();
    for _ in 0..100 {
        let url = images.register(app.scope(), "image/png", png()).unwrap();
        images.revoke(&url);
    }
    let stats = images.stats().unwrap();
    assert_eq!(
        (stats.entries, stats.bytes, stats.owners),
        (0, 0, 1),
        "reload reuses one cleanup registration per owner"
    );
    let first = images.register(app.scope(), "image/png", png()).unwrap();
    let second = images.register(app.scope(), "image/png", png()).unwrap();
    assert!(images.register(app.scope(), "image/png", png()).is_err());
    assert!(
        images
            .register(app.scope(), "image/svg+xml", b"<svg/>".to_vec())
            .is_err()
    );
    let result = Arc::new(Results::default());
    let (entered, wait) = mpsc::sync_channel(1);
    images.fetch(
        7,
        Request::get(Url::parse(&first).unwrap()),
        Box::new(Handler {
            result: result.clone(),
            entered: Some(entered),
            release: Some(Arc::new(Notify::new())),
        }),
    );
    wait.recv_timeout(Duration::from_secs(5)).unwrap();
    images.fetch(
        7,
        Request::get(Url::parse(&second).unwrap()),
        Handler::new(result.clone()),
    );
    assert_eq!(
        result.errors.load(Ordering::SeqCst),
        1,
        "active plus queued requests share a strict bound"
    );
    images.retire();
    wait_until(|| images.stats().unwrap().pending == 0);
    assert_eq!(
        result.bytes.load(Ordering::SeqCst),
        0,
        "retirement drops an already preparing handler"
    );
    assert_eq!(images.stats().unwrap().bytes, 0);
    let replacement = images.register(app.scope(), "image/png", png()).unwrap();
    assert_ne!(replacement, first);
    images.fetch(
        8,
        Request::get(Url::parse(&replacement).unwrap()),
        Handler::new(result.clone()),
    );
    assert_eq!(
        result.errors.load(Ordering::SeqCst),
        2,
        "another document cannot claim the registry"
    );
    images.fetch(
        7,
        Request::get(Url::parse(&first).unwrap()),
        Handler::new(result.clone()),
    );
    assert_eq!(
        result.errors.load(Ordering::SeqCst),
        3,
        "old epoch URLs cannot resolve"
    );
    images.close(7);
    wait_until(|| images.stats().unwrap().stopped);
    assert!(images.register(app.scope(), "image/png", png()).is_err());
}

#[test]
fn composite_delegates_static_assets_and_keeps_the_default_network_denial() {
    let app = glory::ui::App::memory();
    let images = ScopedImageRegistry::new(Limits::default()).unwrap();
    let assets = Arc::new(
        Loader::new(LoadConfig {
            package: BTreeMap::from([("/static.png".into(), Bytes::from(png()))]),
            ..Default::default()
        })
        .unwrap(),
    );
    let provider = CompositeProvider {
        images: images.clone(),
        assets,
    };
    let result = Arc::new(Results::default());
    provider.fetch(
        9,
        Request::get(Url::parse("asset://app/static.png").unwrap()),
        Handler::new(result.clone()),
    );
    wait_until(|| result.bytes.load(Ordering::SeqCst) == 1);
    provider.fetch(
        9,
        Request::get(Url::parse("https://example.invalid/private.png").unwrap()),
        Handler::new(result.clone()),
    );
    wait_until(|| result.errors.load(Ordering::SeqCst) == 1);
    let url = images.register(app.scope(), "image/png", png()).unwrap();
    let mut request = Request::get(Url::parse(&url).unwrap());
    request.method = Method::POST;
    provider.fetch(9, request, Handler::new(result.clone()));
    assert_eq!(result.errors.load(Ordering::SeqCst), 2);
    provider.close(9);
    wait_until(|| images.stats().unwrap().stopped);
}

#[test]
fn real_blitz_decodes_registered_png_and_scope_cleanup_revokes_the_lease() {
    assert_real_blitz_decode("image/png", png());
}

#[test]
fn real_blitz_uses_enabled_jpeg_webp_and_static_gif_codecs() {
    for (mime, format) in [
        ("image/jpeg", image::ImageFormat::Jpeg),
        ("image/webp", image::ImageFormat::WebP),
        ("image/gif", image::ImageFormat::Gif),
    ] {
        let raster = image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(
            1,
            1,
            image::Rgb([255, 0, 0]),
        ));
        let mut bytes = std::io::Cursor::new(Vec::new());
        raster.write_to(&mut bytes, format).unwrap();
        assert_real_blitz_decode(mime, bytes.into_inner());
    }
}

#[test]
fn real_blitz_loads_and_registers_the_self_hosted_inter_truetype_fallback() {
    struct FontRequests {
        loader: Loader,
        urls: Arc<Mutex<Vec<String>>>,
    }
    impl NetProvider for FontRequests {
        fn fetch(&self, document: usize, request: Request, handler: Box<dyn NetHandler>) {
            self.urls.lock().unwrap().push(request.url.to_string());
            self.loader.fetch(document, request, handler);
        }
        fn close(&self, document: usize) {
            self.loader.close(document);
        }
        fn cancel(&self, document: usize, url: &str) {
            self.loader.cancel(document, url);
        }
    }
    let urls = Arc::new(Mutex::new(Vec::new()));
    let assets = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("assets");
    let loader = Loader::new(LoadConfig {
        mounts: BTreeMap::from([("inkson".into(), assets.canonicalize().unwrap())]),
        ..Default::default()
    })
    .unwrap();
    let window = glory::blitz::shell::WindowApp::with_config(glory::blitz::Config {
        base_url: Url::parse("asset://inkson/").unwrap(),
        provider: Some(Arc::new(FontRequests {
            loader,
            urls: urls.clone(),
        })),
        ..Default::default()
    });
    window.renderer().set_css(concat!(
        include_str!("../../../web/fonts.css"),
        "\n.inter-font-probe { font-family: Inter; font-size: 20px; font-weight: 400; }"
    ));
    window
        .mount(
            glory::ui::text()
                .class("inter-font-probe")
                .content("Inter native registration: Members 123"),
        )
        .unwrap();
    let context = std::task::Context::from_waker(std::task::Waker::noop());
    wait_until(|| {
        window.observe(&context).unwrap();
        window.renderer().resource_stats().registered_fonts > 0
    });
    let stats = window.renderer().resource_stats();
    let requested = urls.lock().unwrap();
    assert!(
        requested
            .iter()
            .any(|url| url.starts_with("asset://inkson/fonts/inter-v20-") && url.ends_with(".ttf")),
        "the real mounted Loader must request the fallback, not a computed family string"
    );
    assert!(stats.registered_fonts > 0);
    assert!(stats.registered_font_bytes > 0);
    assert_eq!(stats.failures, 0);
    assert_eq!(stats.rejected, 0);
}

fn assert_real_blitz_decode(mime: &'static str, bytes: Vec<u8>) {
    let images = ScopedImageRegistry::new(Limits::default()).unwrap();
    let assets = Arc::new(Loader::new(LoadConfig::default()).unwrap());
    let provider = Arc::new(CompositeProvider {
        images: images.clone(),
        assets,
    });
    let window = glory::blitz::shell::WindowApp::with_config(glory::blitz::Config {
        provider: Some(provider),
        ..Default::default()
    });
    let status = Rc::new(Cell::new(None));
    let observed = status.clone();
    let captured = Rc::new(RefCell::new(String::new()));
    let url = captured.clone();
    let registry = images.clone();
    window
        .mount(glory::ui::widget(move |scope| {
            let source = registry.register(scope, mime, bytes.clone()).unwrap();
            *url.borrow_mut() = source.clone();
            let observed = observed.clone();
            glory::ui::image()
                .source(source)
                .alt("Private registered image")
                .on(glory::render::EventKind::ImageStatus, move |event| {
                    if let glory::render::Event::ImageStatus { status, .. } = event {
                        observed.set(Some(status));
                    }
                })
                .build(scope)
        }))
        .unwrap();
    let context = std::task::Context::from_waker(std::task::Waker::noop());
    wait_until(|| {
        window.observe(&context).unwrap();
        status.get().is_some()
    });
    assert_eq!(
        status.get(),
        Some(glory::render::ImageStatus::Loaded),
        "actual Blitz resource admission and image decoder, not Memory"
    );
    assert_eq!(images.stats().unwrap().completed, 1);
    window.app().clear().unwrap();
    assert_eq!(
        (
            images.stats().unwrap().entries,
            images.stats().unwrap().owners
        ),
        (0, 0)
    );
    let result = Arc::new(Results::default());
    let doc = images.inner.state.lock().unwrap().doc.unwrap();
    images.fetch(
        doc,
        Request::get(Url::parse(&captured.borrow()).unwrap()),
        Handler::new(result.clone()),
    );
    assert_eq!(result.errors.load(Ordering::SeqCst), 1);
}
