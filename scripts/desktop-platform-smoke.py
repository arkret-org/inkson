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
          'test': 'real owning process window visible after Dioxus initialize and real renderer; not authenticated acceptance'}


def renderer_ids():
    if platform == 'darwin':
        rows = subprocess.check_output(['ps', '-eo', 'pid=,args='], text=True).splitlines()
        return {int(row.split(None, 1)[0]) for row in rows if 'WebKit.WebContent' in row or 'WebKit WebContent' in row}
    rows = json.loads(subprocess.check_output(['powershell', '-NoProfile', '-Command',
        'Get-CimInstance Win32_Process | Where-Object Name -eq msedgewebview2.exe | Select-Object ProcessId | ConvertTo-Json -Compress'], text=True) or '[]')
    if isinstance(rows, dict):
        rows = [rows]
    return {row['ProcessId'] for row in rows}


private_directory = tempfile.TemporaryDirectory(prefix='inkson-desktop-runtime-')
with private_directory as private:
    env = dict(os.environ)
    env.update(HOME=private, APPDATA=private + '/roaming', LOCALAPPDATA=private + '/local',
               XDG_CONFIG_HOME=private + '/config', XDG_DATA_HOME=private + '/data',
               XDG_CACHE_HOME=private + '/cache')
    for name in ('APPDATA', 'LOCALAPPDATA', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME'):
        Path(env[name]).mkdir(parents=True, exist_ok=True)
    probe = None
    if platform == 'darwin':
        source = Path(private) / 'windows.swift'
        source.write_text('''import Foundation
import CoreGraphics
let pid = Int(CommandLine.arguments[1])!
let windows = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] ?? []
let own = windows.filter { ($0[kCGWindowOwnerPID as String] as? Int) == pid && ($0[kCGWindowLayer as String] as? Int) == 0 }
let rows = own.map { ["id": $0[kCGWindowNumber as String] ?? 0, "title": $0[kCGWindowName as String] ?? ""] }
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
            return json.loads(subprocess.check_output([str(probe), str(pid)], text=True))
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

    baseline = renderer_ids()
    app = None
    try:
        with (out / (platform + '-application.log')).open('w') as app_output:
            app = subprocess.Popen([str(binary)], env=env, stdout=app_output, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                if app.poll() is not None:
                    raise RuntimeError('desktop exited before real window initialization: ' + str(app.returncode))
                windows = own_windows(app.pid)
                renderers = renderer_ids() - baseline
                if windows and renderers:
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError('real initialized window and new renderer were not both observed')
            time.sleep(3)
            if app.poll() is not None:
                raise RuntimeError('desktop did not remain live after initialization')
            result.update(own_visible_window=True, renderer_started=True, startup_remained_live=True,
                          dioxus_initialize_observed_by_native_window_visibility=True)
            if platform == 'win32':
                for window in windows:
                    if not user32.PostMessageW(window['id'], 0x0010, 0, 0):
                        raise RuntimeError('could not request normal native window close')
                app.wait(timeout=15)
                if app.returncode != 0:
                    raise RuntimeError('normal window close failed: ' + str(app.returncode))
                result['normal_window_close_exit'] = app.returncode
                # The owning window can close before WebView2 has flushed its
                # private profile. Observe natural subprocess shutdown before
                # deleting it; a surviving renderer is an actual failure.
                deadline = time.monotonic() + 30
                while renderer_ids() - baseline:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('WebView2 subprocesses did not exit after normal native close')
                    time.sleep(0.25)
                result['renderer_subprocesses_exited'] = True
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
        # retain filesystem handles after the last WebView2 process exits.
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
