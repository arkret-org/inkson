# Desktop dependency maintenance

The native application uses Glory/Blitz and Sapid. The browser application uses Glory Web. Both consume the same application state and typed protocol clients. Glory and Sapid use their GitHub `main` branches, locked by Cargo. `.ci/checkout-ui-dependencies.sh` verifies the actual Git package graph and asset source; local path overrides are not used.

Cargo.lock records the exact renderer graph, including the Glory-owned Blitz and Taffy revisions. The SDK continues to own OpenMLS and Secret Service dependencies. Renderer or D-Bus changes must preserve their package identities and original licenses; do not copy or relabel dependency source inside Inkson.

Review the exact dependency revision before updating it, resolve the lockfile, and run both browser and native checks. Native evidence must include the actual application binary, its assets and visible process-owned window on the affected operating system. Window startup alone does not establish visual parity or authenticated behavior. Metadata, library tests and Web builds cannot replace the platform checks.

All Windows build/cache output belongs under `D:/BuildCache/inkson-glory`; verify Cargo’s resolved target directory. WSL requires the verified D-drive mount. Docker builder storage must be verified separately before a local image build. Historical desktop receipts retain their original source scope and are not receipts for the Glory migration.

The native asset layout is `assets` beside the binary on Windows/Linux and `Contents/Resources/assets` in a macOS application bundle. Development uses an explicit `INKSON_ASSET_DIR`. Clipboard, image selection and notifications use OS services. The media transport and its isolated process remain bounded by their call owner.

The desktop SFU media process retains the existing LiveKit/SFrame JavaScript in a separate Wry/tao host. Linux therefore still requires GTK 4.12+, WebKitGTK 6 (WebKit 2.42+), libsoup 3, and the WebKit sandbox runtime in addition to the Glory/Blitz libraries. Native notification playback uses paplay (pulseaudio-utils on Debian/Ubuntu). The main product surface remains Glory/Blitz.

The tested remote sources are Glory b9d06545c701510ba18d5cdb7cd363c102cad906 and Sapid c5c4e23aeb6d37b3f2537545116bac43dbb40a64. Sapid currently declares its sibling Glory path internally; the application uses a remote-to-remote Cargo patch so both resolve to the same Git Glory package.

At these revisions, Sapid TextField has no placeholder method and Glory InputAssist has no placeholder member. Product hints therefore use persistent input owners with real associated labels or noninteractive empty-value hint layers. The DOM placeholder attribute is not claimed. The shared local framework checkouts remain untouched.
