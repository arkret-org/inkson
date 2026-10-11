#!/usr/bin/env python3
"""Run the actual candidate desktop executable in isolated Linux displays."""
import argparse
import pyatspi
from gi.repository import GLib
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

# AT-SPI reads and edits the actual WebKit accessibility document. No JS,
# fake request acknowledgement, alternate app storage, or product test hook.
STATION_NAMES = {'Sign-in server URL', '登录服务器地址'}
STATION_MARKER = 'http://127.0.0.1:18932'

def station_field(process_id):
    rows = subprocess.check_output(['ps', '-eo', 'pid=,ppid='], text=True).splitlines()
    relations = [tuple(map(int, row.split())) for row in rows]
    process_ids = {process_id}
    while True:
        children = {pid for pid, parent in relations if parent in process_ids}
        if children.issubset(process_ids):
            break
        process_ids.update(children)
    desktop = pyatspi.Registry.getDesktop(0)
    stack = []
    for i in range(desktop.childCount):
        try:
            node = desktop.getChildAtIndex(i)
            if node.get_process_id() in process_ids:
                stack.append(node)
        except (AttributeError, RuntimeError, GLib.Error):
            continue
    visited = 0
    while stack and visited < 4096:
        node = stack.pop()
        visited += 1
        try:
            if node.name in STATION_NAMES:
                node.queryEditableText()
                return node
            stack.extend(node.getChildAtIndex(i) for i in range(node.childCount))
        except (AttributeError, RuntimeError, NotImplementedError, GLib.Error):
            continue
    return None

def diagnostic_tree(process_id):
    rows = subprocess.check_output(['ps', '-eo', 'pid=,ppid=,args='], text=True)
    (out / (args.backend + '-processes.log')).write_text(rows)
    desktop = pyatspi.Registry.getDesktop(0)
    stack = [(desktop, 0)]
    nodes = []
    while stack and len(nodes) < 2048:
        node, depth = stack.pop()
        record = {'depth': depth}
        try:
            record.update(name=node.name, role=node.getRoleName(), child_count=node.childCount)
            for label, getter in [('pid', node.get_process_id), ('attributes', node.getAttributes)]:
                try:
                    record[label] = getter()
                except (AttributeError, RuntimeError, NotImplementedError, GLib.Error) as error:
                    record[label + '_error'] = str(error)
            nodes.append(record)
            if depth < 32:
                stack.extend((node.getChildAtIndex(i), depth + 1)
                             for i in reversed(range(min(node.childCount, 256))))
        except (AttributeError, RuntimeError, NotImplementedError, GLib.Error) as error:
            record['error'] = str(error)
            nodes.append(record)
    (out / (args.backend + '-accessibility-tree.json')).write_text(
        json.dumps({'own_pid': process_id, 'nodes': nodes}, indent=2) + '\n')
    if args.backend == 'x11':
        subprocess.run(['scrot', '--overwrite', str(out / 'x11-screen.png')],
                       check=False, capture_output=True)

def wait_station(app, expected=None):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if app.poll() is not None:
            raise RuntimeError('application exited before real login document readiness')
        field = station_field(app.pid)
        if field is not None:
            value = field.queryText().getText(0, -1)
            if expected is None or value == expected:
                return field
        time.sleep(0.25)
    diagnostic_tree(app.pid)
    raise RuntimeError('actual accessible login Station field did not reach expected state')

binary = args.binary.resolve(strict=True)
out = Path('dist/linux-gtk4-runtime')
out.mkdir(parents=True, exist_ok=True)
result = {'diagnostic_probe_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          'product_source': 'cb47de3210b094d45863f5f4d9a797b1a5aecf68', 'backend': args.backend, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
          'test': 'actual GTK4/WebKit login DOM, input callback, same-home cold restart; not authenticated product acceptance'}
with tempfile.TemporaryDirectory(prefix='inkson-gtk4-runtime-') as private:
    env = dict(os.environ)
    env.update(HOME=private, XDG_CONFIG_HOME=private + '/config', XDG_DATA_HOME=private + '/data',
               XDG_CACHE_HOME=private + '/cache', XDG_RUNTIME_DIR=private + '/runtime',
               GDK_BACKEND=args.backend, GTK_A11Y='atspi', LANG='en_US.UTF-8', LIBGL_ALWAYS_SOFTWARE='1', WEBKIT_DISABLE_DMABUF_RENDERER='1')
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
                field = wait_station(app)
                result['actual_login_dom'] = True
                if not field.queryEditableText().setTextContents(STATION_MARKER):
                    raise RuntimeError('real accessible Station input rejected editing')
                wait_station(app, STATION_MARKER)
                # Allow normal production config persistence to finish before close.
                time.sleep(1)
                result['actual_station_input'] = True
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
                # A new real process reads the original persisted configuration.
                app = subprocess.Popen([str(binary)], env=env, stdout=app_output, stderr=subprocess.STDOUT)
                wait_station(app, STATION_MARKER)
                result['cold_restart_station_input_retained'] = True
                app.send_signal(signal.SIGTERM)
                app.wait(timeout=15)
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
