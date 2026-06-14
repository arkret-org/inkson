# yougen — Install

> Step-by-step install guide for desktop (macOS / Windows / Linux) and the web build.
> Mobile native artifacts are out of the local 1.0 milestone.

This document targets end users. Builders looking for source instructions
should read [`build-per-platform.md`](../build-per-platform.md).

---

## 1. Choose a platform

yougen ships two surfaces that share the same Rust core:

| Surface | Runtime | Recommended for |
| --- | --- | --- |
| Desktop (Tauri-style native) | macOS / Windows / Linux | Strongest security tier — OS keychain handoff, native push, full file system. |
| Web | Any modern Chromium / Firefox / Safari | Quick smoke testing, headless deployments, dogfooding. Falls back to browser storage; no symmetric-secret tier. |

<!-- TODO(screenshot): platform-picker.png — three OS cards + web card -->

If you only need to test a strand once, use the web build. For day-to-day use,
install the desktop build so your signing keys land in the OS keychain instead
of `localStorage` / IndexedDB.

---

## 2. Desktop install

### macOS

1. Download the `yougen-macos.zip` artifact from your release channel.
2. Open the archive; drag `yougen.app` to `/Applications`.
3. First launch: macOS Gatekeeper may warn the artifact is unsigned (the
   release process keeps codesign / notarization in **dry-run** mode — see
   [`SECURITY.md`](../../SECURITY.md#concrete-protections-shipped-today)). Right-click → **Open** to bypass once.
4. Approve any Keychain prompt; this is the OS-keychain handoff that the
   `KeyringSecureKeyStore` uses for signing-key persistence.

<!-- TODO(screenshot): macos-gatekeeper-prompt.png -->
<!-- TODO(screenshot): macos-keychain-prompt.png -->

### Windows

1. Download the `yougen-windows.msi` (or zipped `yougen.exe`).
2. Double-click to install. SmartScreen will warn for unsigned binaries;
   click **More info → Run anyway**.
3. Launch from the Start menu. The first signing operation prompts the
   Windows Credential Manager.

<!-- TODO(screenshot): windows-smartscreen.png -->
<!-- TODO(screenshot): windows-credential-manager.png -->

### Linux

1. Download the `.tar.gz`, `.deb`, `.rpm`, `.AppImage`, or Flatpak bundle
   that matches your distro.
2. Install via your package manager or run the AppImage directly. The
   freedesktop Secret Service (gnome-keyring / kwallet) provides the
   keychain backend.
3. Launch via the desktop entry or `./yougen` from the extracted folder.

<!-- TODO(screenshot): linux-keyring-prompt.png -->

---

## 3. Web build

The web build is served from the local docker image
(`scripts/prepare-docker-context.ps1` + `Dockerfile`). To run locally:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/prepare-docker-context.ps1
docker build -f docker-context/yougen/Dockerfile -t yougen-web:local docker-context
docker run --rm -p 4527:80 yougen-web:local
```

Open `http://127.0.0.1:4527` in a browser. The UI will surface a small
warning banner:

> Using browser storage fallback — recommend Tauri desktop for full security.

This is expected. The web build still runs the live MLS encrypted-history
path, but the browser has no OS keychain tier; keys live in LocalStorage /
IndexedDB and survive cross-tab use without hardware-backed protection.

<!-- TODO(screenshot): web-fallback-banner.png -->

---

## 4. First launch checklist

- [ ] Settings page loads without an error toast.
- [ ] The connection-status pill shows **Online** within 5 seconds.
- [ ] The crash-telemetry toggle is **OFF** (default — see [Telemetry
      default OFF](../../SECURITY.md#telemetry-default-off)).
- [ ] You can open `/onboarding` and see the four-step wizard.

If any of the above fails, jump to
[`faq-troubleshooting.md`](../faq-troubleshooting.md).

---

## 5. Uninstall

| Platform | Steps |
| --- | --- |
| macOS | Drag `yougen.app` to Trash. Optionally remove the keychain entry under "yougen". |
| Windows | Settings → Apps → yougen → Uninstall. Credential Manager entries can be deleted manually. |
| Linux | `apt remove yougen` / `dnf remove yougen` / delete AppImage. Use `secret-tool clear` to remove keyring entries. |
| Web | Clear site data in your browser DevTools (Application → Storage). |

Removing the app does **not** revoke the device on the Principal Server.
Use **Settings → Devices → Revoke** before uninstalling so the revocation
envelope is published while you still have signing material.

<!-- TODO(screenshot): settings-devices-revoke.png -->
