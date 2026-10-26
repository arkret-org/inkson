#!/usr/bin/env python3
"""Probe actual candidate Windows/macOS renderer startup; no authenticated UI claim."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument('--binary', type=Path, required=True)
args = parser.parse_args()
binary = args.binary.resolve(strict=True)
platform = sys.platform
if platform not in ('darwin', 'win32'):
    raise RuntimeError('this probe is only for the actual Windows/macOS desktop')
out = Path('dist/desktop-platform-runtime')
out.mkdir(parents=True, exist_ok=True)
result = {'platform': platform, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
          'test': 'real owning Glory/Blitz process window visible and remains live; visual and authenticated acceptance are separate'}


temporary_root = Path("D:/BuildCache/inkson-glory/tmp") if platform == "win32" else Path(tempfile.gettempdir())
temporary_root.mkdir(parents=True, exist_ok=True)
private_directory = tempfile.TemporaryDirectory(prefix="inkson-desktop-runtime-", dir=temporary_root)
with private_directory as private:
    env = dict(os.environ)
    env['RUST_LOG'] = 'inkson=info,glory_blitz=debug,warn'
    env.update(APPDATA=private + '/roaming', LOCALAPPDATA=private + '/local',
               XDG_CONFIG_HOME=private + '/config', XDG_DATA_HOME=private + '/data',
               XDG_CACHE_HOME=private + '/cache')
    env['INKSON_CONFIG_PATH'] = private + '/config.json'
    env['INKSON_STATE_PATH'] = private + '/state.json'
    env['INKSON_MEDIA_DATA_DIR'] = private + '/media'
    env['INKSON_CRASH_TELEMETRY_OPT_IN'] = '0'
    for name in ('APPDATA', 'LOCALAPPDATA', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME'):
        Path(env[name]).mkdir(parents=True, exist_ok=True)
    probe = None
    if platform == 'darwin':
        source = Path(private) / 'windows.swift'
        source.write_text('''import Foundation
import CoreGraphics
let pid = Int(CommandLine.arguments[1])!
let windows = CGWindowListCopyWindowInfo([.optionAll, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] ?? []
let own = windows.filter { ($0[kCGWindowOwnerPID as String] as? Int) == pid }
let rows = own.map { ["id": $0[kCGWindowNumber as String] ?? 0, "title": $0[kCGWindowName as String] ?? "", "layer": $0[kCGWindowLayer as String] ?? -1, "onscreen": $0[kCGWindowIsOnscreen as String] ?? false, "bounds": $0[kCGWindowBounds as String] ?? [:]] }
print(String(data: try JSONSerialization.data(withJSONObject: rows), encoding: .utf8)!)
''')
        probe = Path(private) / 'windows-probe'
        subprocess.run(['swiftc', str(source), '-o', str(probe)], check=True)
    else:
        user32 = ctypes.WinDLL('user32', use_last_error=True)
        callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        user32.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]
        user32.IsWindowVisible.argtypes = [wintypes.HWND]
        user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
        user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]

    def own_windows(pid):
        if platform == 'darwin':
            rows = json.loads(subprocess.check_output([str(probe), str(pid)], text=True))
            result['macos_owned_window_inventory'] = rows
            # Floating application windows can have a nonzero layer on macOS.
            # Identify the actual app window, excluding its hidden helper windows.
            # macOS may omit titles when screen recording access is unavailable.
            return [row for row in rows if row['onscreen']
                    and (not row['title'] or 'Inkson' in row['title'] or 'Arkret' in row['title'])
                    and row['bounds'].get('Width', 0) >= 200
                    and row['bounds'].get('Height', 0) >= 100]
        windows = []
        @callback_type
        def visit(hwnd, unused):
            owner = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
            if owner.value == pid and user32.IsWindowVisible(hwnd):
                title = ctypes.create_unicode_buffer(512)
                user32.GetWindowTextW(hwnd, title, len(title))
                if 'Inkson' in title.value or 'Arkret' in title.value:
                    windows.append({'id': hwnd, 'title': title.value})
            return True
        user32.EnumWindows(visit, 0)
        return windows

    app = None
    try:
        with (out / (platform + '-application.log')).open('w') as app_output:
            app = subprocess.Popen([str(binary)], env=env, stdout=app_output, stderr=subprocess.STDOUT)
            result['application_pid'] = app.pid
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                if app.poll() is not None:
                    raise RuntimeError('desktop exited before real window initialization: ' + str(app.returncode))
                windows = own_windows(app.pid)
                result['last_window_observation'] = windows
                if windows:
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError('the application owning process did not expose its visible window')
            time.sleep(3)
            if app.poll() is not None:
                raise RuntimeError('desktop did not remain live after initialization')
            result.update(own_visible_window=True, native_host="Glory/Blitz", startup_remained_live=True)
            if platform == 'win32':
                for window in windows:
                    if not user32.PostMessageW(window['id'], 0x0010, 0, 0):
                        raise RuntimeError('could not request normal native window close')
                app.wait(timeout=15)
                if app.returncode != 0:
                    raise RuntimeError('normal window close failed: ' + str(app.returncode))
                result['normal_window_close_exit'] = app.returncode
                result['owned_window_close_completed'] = True
            else:
                app.send_signal(signal.SIGTERM)
                app.wait(timeout=15)
                result['controlled_probe_shutdown_signal'] = 'SIGTERM'
            result['passed'] = True
    except BaseException as error:
        result.update(passed=False, error=str(error))
        raise
    finally:
        if app is not None and app.poll() is None:
            app.terminate()
            app.wait(timeout=15)
        # Keep cleanup fatal and include it in the result. Windows can briefly
        # retain filesystem handles after the native host closes.
        deadline = time.monotonic() + 30
        try:
            while True:
                try:
                    private_directory.cleanup()
                    result['private_profile_cleanup_completed'] = True
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.25)
        except OSError as error:
            result.update(passed=False, cleanup_error=str(error))
            raise
        finally:
            (out / (platform + '-result.json')).write_text(json.dumps(result, indent=2) + '\n')
