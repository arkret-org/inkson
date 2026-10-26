# Glory host ownership

`InksonContext` is allocated by the window owner, after the browser obtains
the origin's single-writer Web Lock. A follower never starts storage recovery,
MLS processing, synchronization, or scheduled sends. Native execution uses one
window with the same application context and domain runtime.

Small presentation values use Glory Cages. The authoritative local store lives
in `SharedStateStore`; its bounded `read` and `write` closures never expose a
guard or retain a borrow across an asynchronous operation. The revision channel
invalidates derived presentation values. It does not create another persisted
snapshot. Domain engines retain their existing `StateStoreHandle` contracts,
canonical carriers, signing, durability barriers, and authorization checks.

An account switch suspends the session and retires old effects and sinks before
publishing another account. It cancels in-flight Chat and Kanban pool work and
clears account projections, incoming calls, transient message previews, read
receipts, Sidecar selection, and recovery prompts. Draft pools retain their
complete Account, Device, Realm, and target identities; a result must also match the
session generation and request revision before updating presentation state.
The account owner is rebuilt after selection. Storage recovery runs again for
the newly selected account before authenticated work resumes.

The root retains an app-owned weak current-host reference for existing domain
entry points that capture the authoring store and current identity. New views
receive `Rc<InksonContext>` explicitly. Capturing the host does not keep a window
alive or replace the domain's authority and generation fences. This boundary
currently assumes one application window per UI thread; independent windows on
one thread require scoped host selection before extending the native shell.

Glory mounts a widget once. Text, control values, theme classes, and translated
labels update through bindings. `reactive_distinct` preserves an existing owner
when a route phase is unchanged, including across token maintenance and locale
updates. Hidden optional regions return `widgets::empty()`, which creates no
layout node. Reactive regions replace their children through the official Group
range, which has no physical wrapper. This preserves the original direct-child
selectors, flex/grid layout and sibling order. Hidden retained editors still
use a real hidden/inert View so their input and file-controller identity survives
a temporary missing Current view.

`web/styles.list` defines the ordered original CSS layers for both hosts. The
native host consumes the same generated sheet as the browser. Theme classes
extend the original light and dark token selectors. Sapid's unstyled controls
keep the original application CSS authoritative, so switching themes does not
rebuild an editor or capture a fixed palette on its controls.
The web host moves Glory's unchanged inline baseline before the two existing
application stylesheet links. It preserves the already-loaded CSSStyleSheets;
moving the link elements themselves can trigger another stylesheet request.
Inter v20 is packaged with its original OFL and seven subsets for both hosts.
The pinned native codec does not enable WOFF2. Each CSS font source therefore
provides its original WOFF2 first and a lossless SFNT/TTF fallback second. The
font manifest pins both hashes and records table/metrics equivalence. Browser
loads retain WOFF2; a real Blitz test verifies that the packaged TTF bytes are
registered by the native font service.

Chat common controllers are cached by the complete Account/Device/Realm/initial
Strand target in the window-owned pool. Returning to the same target reuses its
reactive handles. Session retirement cancels managed work, clears private
projections and transient request keys in place, and advances the pool revision;
it preserves draft identities without retaining old authorized read results.
Temporary missing Current data hides and makes the retained composer inert.
Official file reads wait for availability between bounded 64 KiB chunks and
fail closed when the owner or target retires.

The pinned Git host API does not expose a media widget or a file-drop wrapper
around interactive children. Browser audio/video uses an owner-scoped media
leaf; native audio/video attachments provide validated download/external playback. File
selection uses the official FileController; dropping anywhere in the composer
is not equivalent to the previous WebView surface. These are explicit platform
limits, not evidence of full cross-platform visual parity.

Native SFU calls retain the LiveKit Wry subprocess and typed, owner-scoped stdin
bridge. Native P2P retains the original `DesktopMediaUnavailable` outcome;
neither path has a new live media-connection acceptance result. Native message
actions use a supported Dialog with the seven actions; the previous right-click
context-menu gesture is not supported by that adapter.

The native window explicitly shares one bounded image registry with its
application context. A composite provider delegates packaged assets to the
official Loader and accepts only its window's opaque image leases. It does not
allow arbitrary HTTP, file URLs or data URLs through the Loader. Authenticated
blob completion rechecks the account before registering bytes; a rendering
scope owns each lease, and replacement, account retirement, cancellation and
window close revoke it. The registry admits at most 8 MiB per image, 32 MiB in
total, 128 entries and 16 pending requests. Its worker awaits the renderer's
prepare phase, then rechecks cancellation and the document/epoch before
publishing bytes. PNG, JPEG, WebP and GIF first frames use the pinned native
codec. Native SVG and animated GIF playback are not established by this path.

Native choice controls use real buttons and an anchored Dialog with the original
domain values and enabled guards. Help and self-attribution controls likewise
use a supported native Dialog; web controls retain their tooltip semantics.
External content links preserve the URL sanitizer and request real operating
system activation instead of mounting native NewContext descriptors.

The pinned native adapter still rejects RichEditor. The native default rich
mode therefore renders an explicit unsupported preview, keeps the draft, and
offers a user-selected manual Markdown editor. The browser retains its real
RichEditor. The manual path is not native WYSIWYG support; that requires a
capable native backend. Headless Memory/Blitz checks do not establish physical
window acceptance, and no further desktop interaction ran after the user
stopped computer use.
