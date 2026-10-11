#!/usr/bin/env python3
"""Run the actual candidate desktop executable in isolated Linux displays."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument('--backend', choices=['x11', 'wayland'], required=True)
parser.add_argument('--binary', type=Path, required=True)
args = parser.parse_args()
binary = args.binary.resolve(strict=True)
out = Path('dist/linux-gtk4-runtime')
out.mkdir(parents=True, exist_ok=True)
result = {'backend': args.backend, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
          'test': 'real desktop window and WebKit process smoke, not authenticated product acceptance'}
with tempfile.TemporaryDirectory(prefix='inkson-gtk4-runtime-') as private:
    env = dict(os.environ)
    env.update(HOME=private, XDG_CONFIG_HOME=private + '/config', XDG_DATA_HOME=private + '/data',
               XDG_CACHE_HOME=private + '/cache', XDG_RUNTIME_DIR=private + '/runtime',
               GDK_BACKEND=args.backend, LIBGL_ALWAYS_SOFTWARE='1', WEBKIT_DISABLE_DMABUF_RENDERER='1')
    Path(env['XDG_RUNTIME_DIR']).mkdir(mode=0o700)
    background = None
    app = None
    app_log = out / (args.backend + '-application.log')
    display_log = out / (args.backend + '-display.log')
    try:
        with display_log.open('w') as display_output:
            if args.backend == 'wayland':
                env['WAYLAND_DISPLAY'] = 'inkson-gtk4-test'
                background = subprocess.Popen(['weston', '--backend=headless-backend.so',
                    '--socket=' + env['WAYLAND_DISPLAY'], '--idle-time=0', '--width=1280', '--height=800'],
                    env=env, stdout=display_output, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 30
                while not (Path(env['XDG_RUNTIME_DIR']) / env['WAYLAND_DISPLAY']).exists():
                    if background.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError('real Weston display failed to become ready')
                    time.sleep(0.1)
                env['WAYLAND_DEBUG'] = 'client'
            else:
                background = subprocess.Popen(['openbox'], env=env, stdout=display_output, stderr=subprocess.STDOUT)
            with app_log.open('w') as app_output:
                app = subprocess.Popen([str(binary)], env=env, stdout=app_output, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 60
                window = None
                while time.monotonic() < deadline:
                    if app.poll() is not None:
                        raise RuntimeError('desktop application exited before renderer readiness: ' + str(app.returncode))
                    text = app_log.read_text(errors='replace')
                    processes = subprocess.check_output(['ps', '-eo', 'args'], text=True)
                    renderer = 'WebKitWebProcess' in processes
                    if args.backend == 'x11':
                        query = subprocess.run(['xdotool', 'search', '--onlyvisible', '--pid', str(app.pid)],
                            text=True, capture_output=True)
                        if query.returncode == 0:
                            window = query.stdout.splitlines()[0]
                        ready = renderer and bool(window)
                    else:
                        ready = renderer and 'xdg_toplevel' in text and 'wl_surface' in text and 'commit(' in text
                    if ready:
                        break
                    time.sleep(0.25)
                else:
                    raise RuntimeError('actual GTK window and WebKit renderer were not both ready')
                time.sleep(3)
                if app.poll() is not None:
                    raise RuntimeError('renderer startup did not remain live')
                result.update(real_window=True, webkit_web_process=True, startup_remained_live=True)
                if args.backend == 'x11':
                    subprocess.run(['xdotool', 'windowactivate', '--sync', window], check=True, env=env)
                    subprocess.run(['xdotool', 'key', '--clearmodifiers', 'alt+F4'], check=True, env=env)
                    app.wait(timeout=15)
                    if app.returncode != 0:
                        raise RuntimeError('window-close shutdown failed: ' + str(app.returncode))
                    result['normal_window_close_exit'] = app.returncode
                else:
                    # The compositor probe is bounded and deliberately stops
                    # its app after observing a mapped Wayland surface.
                    app.send_signal(signal.SIGTERM)
                    app.wait(timeout=15)
                    result['controlled_probe_shutdown_signal'] = 'SIGTERM'
                result['passed'] = True
    except BaseException as error:
        result.update(passed=False, error=str(error))
        raise
    finally:
        for process in [app, background]:
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=15)
        (out / (args.backend + '-result.json')).write_text(json.dumps(result, indent=2) + '\n')
