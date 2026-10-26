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
parser.add_argument('--backend', choices=['x11', 'wayland'])
parser.add_argument('--binary', type=Path)
parser.add_argument('--secret-service-probe', action='store_true')
args = parser.parse_args()

def secret_service_probe():
    output = Path('dist/linux-native-runtime')
    output.mkdir(parents=True, exist_ok=True)
    result = {'probe_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'scope': 'actual Linux SecretService through the production adapter in a Tokio test; not authenticated desktop sign-in',
              'passed': False, 'daemon_cleanup': False, 'private_state_cleanup': False}
    daemon = None
    private_path = None
    try:
        with tempfile.TemporaryDirectory(prefix='inkson-secret-service-') as private:
            private_path = Path(private)
            environment = os.environ.copy()
            environment.update(XDG_DATA_HOME=str(private_path / 'data'),
                               XDG_CONFIG_HOME=str(private_path / 'config'),
                               XDG_RUNTIME_DIR=str(private_path / 'runtime'),
                               COTEST_LINUX_KEYSTORE_PROBE='1')
            for name in ['data', 'config', 'runtime']:
                (private_path / name).mkdir(mode=0o700)
            with (output / 'secret-service-daemon.log').open('wb') as daemon_log:
                try:
                    daemon = subprocess.Popen(
                        ['gnome-keyring-daemon', '--foreground', '--components=secrets', '--unlock'],
                        env=environment, stdin=subprocess.PIPE, stdout=daemon_log, stderr=subprocess.STDOUT)
                    result['owned_daemon_pid'] = daemon.pid
                    daemon.stdin.write(b'\n')
                    daemon.stdin.close()
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline:
                        if daemon.poll() is not None:
                            raise RuntimeError('private SecretService daemon exited before readiness')
                        owner = subprocess.run(
                            ['gdbus', 'call', '--session', '--dest', 'org.freedesktop.DBus',
                             '--object-path', '/org/freedesktop/DBus', '--method',
                             'org.freedesktop.DBus.GetConnectionUnixProcessID', 'org.freedesktop.secrets'],
                            env=environment, capture_output=True, text=True, timeout=5)
                        if owner.returncode != 0:
                            time.sleep(0.25)
                            continue
                        if owner.stdout.strip() != f'(uint32 {daemon.pid},)':
                            raise RuntimeError('SecretService bus owner is not the private owned daemon')
                        result['actual_bus_owner_matches_owned_daemon'] = True
                        ready = subprocess.run(
                            ['gdbus', 'call', '--session', '--dest', 'org.freedesktop.secrets',
                             '--object-path', '/org/freedesktop/secrets', '--method',
                             'org.freedesktop.Secret.Service.ReadAlias', 'default'],
                            env=environment, capture_output=True, text=True, timeout=5)
                        if ready.returncode == 0 and 'collection/' in ready.stdout:
                            result['actual_default_collection_ready'] = True
                            break
                        time.sleep(0.25)
                    else:
                        raise RuntimeError('private unlocked default collection did not become ready')
                    command = ['cargo', 'test', '--locked', '--release', '--features', 'desktop', '--lib',
                               'secure_key_store::keyring::linux_runtime_tests::secret_service_round_trip_from_the_ui_tokio_runtime',
                               '--', '--ignored', '--exact']
                    result['command'] = command
                    started = time.monotonic()
                    with (output / 'secret-service-test.log').open('wb') as test_log:
                        tested = subprocess.run(command, env=environment, stdout=test_log,
                                                stderr=subprocess.STDOUT)
                    result['test_exit_code'] = tested.returncode
                    result['duration_seconds'] = round(time.monotonic() - started, 3)
                    test_output = (output / 'secret-service-test.log').read_text()
                    result['test_log_sha256'] = hashlib.sha256(
                        (output / 'secret-service-test.log').read_bytes()).hexdigest()
                    result['passed'] = tested.returncode == 0 and (
                        'test result: ok. 1 passed; 0 failed; 0 ignored;' in test_output)
                    if not result['passed']:
                        raise RuntimeError('actual SecretService Tokio round-trip failed or executed zero tests')
                finally:
                    if daemon is not None:
                        if daemon.poll() is None:
                            daemon.terminate()
                            try:
                                daemon.wait(timeout=10)
                            except subprocess.TimeoutExpired:
                                daemon.kill()
                                daemon.wait(timeout=10)
                        result['owned_daemon_exit_code'] = daemon.returncode
                        result['daemon_cleanup'] = daemon.poll() is not None
    except Exception as error:
        result['passed'] = False
        result['error'] = str(error)
    finally:
        result['private_state_cleanup'] = private_path is not None and not private_path.exists()
        result['passed'] = result['passed'] and result['daemon_cleanup'] and result['private_state_cleanup']
        (output / 'secret-service-result.json').write_text(json.dumps(result, indent=2) + '\n')
    return 0 if result['passed'] else 1

if args.secret_service_probe:
    if args.backend is not None or args.binary is not None:
        parser.error('the SecretService lease is independent of the desktop display probe')
    raise SystemExit(secret_service_probe())
if args.backend is None or args.binary is None:
    parser.error('--backend and --binary are required for the complete desktop oracle')

# AT-SPI reads and edits the actual native application accessibility tree. No JS,
# fake request acknowledgement, alternate app storage, or product test hook.
STATION_NAMES = {'Sign-in server URL', '登录服务器地址'}
STATION_MARKER = 'http://127.0.0.1:18932'
TYPED_STATION = 'http://127.0.0.1:18931'
COMMITTED_STATION = STATION_MARKER + '/'

def dispatch_accessibility_events():
    context = GLib.MainContext.default()
    for _ in range(256):
        if not context.pending():
            break
        context.iteration(False)

def station_field(process_id):
    dispatch_accessibility_events()
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
    # Event sources can become observable before the application subtree is grafted.
    # Preserve the exact same owning-process/descendant restriction.
    for source in document_event_sources:
        try:
            if source.get_process_id() in process_ids:
                stack.append(source)
        except (AttributeError, RuntimeError, GLib.Error):
            continue
    visited = 0
    while stack and visited < 4096:
        node = stack.pop()
        visited += 1
        try:
            if node.name in STATION_NAMES:
                node.queryText()
                return node
            stack.extend(node.getChildAtIndex(i) for i in range(node.childCount))
        except (AttributeError, RuntimeError, NotImplementedError, GLib.Error):
            continue
    return None

def diagnostic_tree(process_id):
    rows = subprocess.check_output(['ps', '-eo', 'pid=,ppid=,args='], text=True)
    (out / (args.backend + '-processes.log')).write_text(rows)
    desktop = pyatspi.Registry.getDesktop(0)
    stack = [(desktop, 0)] + [(source, 0) for source in document_event_sources]
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
    subprocess.run(['scrot', '--overwrite', str(out / (args.backend + '-screen.png'))],
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
out = Path('dist/linux-native-runtime')
out.mkdir(parents=True, exist_ok=True)
result = {'diagnostic_probe_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          'product_source': os.environ.get('GITHUB_SHA'), 'backend': args.backend, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
          'test': 'actual Glory/Blitz login accessibility, input callback and same-home cold restart; not authenticated product acceptance'}
with tempfile.TemporaryDirectory(prefix='inkson-native-runtime-') as private:
    env = dict(os.environ)
    env.update(HOME=private, XDG_CONFIG_HOME=private + '/config', XDG_DATA_HOME=private + '/data',
               XDG_CACHE_HOME=private + '/cache', XDG_RUNTIME_DIR=private + '/runtime',
               WINIT_UNIX_BACKEND=args.backend, LANG='en_US.UTF-8', LIBGL_ALWAYS_SOFTWARE='1')
    if args.backend == 'x11':
        env.pop('WAYLAND_DISPLAY', None)
    Path(env['XDG_RUNTIME_DIR']).mkdir(mode=0o700)
    background = None
    app = None
    accessibility_events = {}
    document_event_sources = []
    document_event_metadata = []
    def observed_accessibility_event(event):
        accessibility_events[event.type] = accessibility_events.get(event.type, 0) + 1
        if event.type.startswith('document:') and len(document_event_sources) < 16:
            source = event.source
            if source not in document_event_sources:
                document_event_sources.append(source)
                metadata = {'event': event.type}
                for label, getter in [('pid', source.get_process_id), ('name', source.get_name),
                                      ('role', source.get_role_name)]:
                    try:
                        metadata[label] = getter()
                    except (AttributeError, RuntimeError, GLib.Error) as error:
                        metadata[label + '_error'] = str(error)
                document_event_metadata.append(metadata)
    # Register a real assistive client before waiting for native accessibility.
    # Polling the Registry alone does not register such a client.
    listener_names = ('object', 'document')
    pyatspi.Registry.registerEventListener(observed_accessibility_event, *listener_names)
    result['registered_real_atspi_listener_names'] = list(listener_names)
    app_log = out / (args.backend + '-application.log')
    display_log = out / (args.backend + '-display.log')
    try:
        with display_log.open('w') as display_output:
            if args.backend == 'wayland':
                env['WAYLAND_DISPLAY'] = 'inkson-native-test'
                background = subprocess.Popen(['weston', '--backend=x11-backend.so',
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
                    if args.backend == 'x11':
                        query = subprocess.run(['xdotool', 'search', '--onlyvisible', '--pid', str(app.pid)],
                            text=True, capture_output=True)
                        if query.returncode == 0:
                            window = query.stdout.splitlines()[0]
                        ready = bool(window)
                    else:
                        ready = 'xdg_toplevel' in text and 'wl_surface' in text and 'commit(' in text
                    if ready:
                        break
                    time.sleep(0.25)
                else:
                    raise RuntimeError('actual native window or Wayland surface did not become ready')
                time.sleep(3)
                if app.poll() is not None:
                    raise RuntimeError('renderer startup did not remain live')
                result.update(real_window=True, native_host="Glory/Blitz", startup_remained_live=True)
                field = wait_station(app)
                result['actual_login_accessibility'] = True
                if not field.queryComponent().grabFocus():
                    raise RuntimeError('real accessible Station input rejected focus')
                if args.backend == 'x11':
                    input_window = window
                else:
                    # Official nested backend receives physical X11 keys and
                    # dispatches them to the real Wayland application's seat.
                    query = subprocess.run(['xdotool', 'search', '--onlyvisible', '--class', '^Weston Compositor$'],
                                           text=True, capture_output=True, check=True)
                    candidates = query.stdout.splitlines()
                    if len(candidates) != 1:
                        raise RuntimeError('expected one actual Weston compositor X11 output window')
                    input_window = candidates[0]
                subprocess.run(['xdotool', 'windowfocus', '--sync', input_window], check=True, env=env)
                subprocess.run(['xdotool', 'key', '--clearmodifiers', 'ctrl+a'], check=True, env=env)
                subprocess.run(['xdotool', 'key', '--clearmodifiers', 'BackSpace'], check=True, env=env)
                wait_station(app, '')
                typed_prefix = ''
                for character in TYPED_STATION:
                    subprocess.run(['xdotool', 'type', '--clearmodifiers', '--delay', '30', character], check=True, env=env)
                    typed_prefix += character
                    wait_station(app, typed_prefix)
                result['actual_per_character_raw_station_input'] = True
                subprocess.run(['xdotool', 'key', '--clearmodifiers', 'ctrl+a'], check=True, env=env)
                clipboard = subprocess.Popen(
                    ['xclip', '-selection', 'clipboard', '-quiet'] if args.backend == 'x11' else ['wl-copy', '--foreground'],
                    stdin=subprocess.PIPE, env=env)
                try:
                    clipboard.stdin.write(STATION_MARKER.encode())
                    clipboard.stdin.close()
                    time.sleep(0.5)
                    if clipboard.poll() is not None:
                        raise RuntimeError('real platform clipboard owner exited before keyboard paste')
                    if args.backend == 'wayland':
                        # wl-copy's fallback surface can receive keyboard focus.
                        # Weston 13 desktop-shell registers its real window
                        # switcher on Super+Tab (the default binding modifier).
                        # Return the actual seat to the app before pasting.
                        subprocess.run(['xdotool', 'key', '--clearmodifiers', 'super+Tab'], check=True, env=env)
                        time.sleep(0.5)
                        if not field.queryComponent().grabFocus():
                            raise RuntimeError('Station rejected focus after real Weston window switch')
                        subprocess.run(['xdotool', 'key', '--clearmodifiers', 'ctrl+a'], check=True, env=env)
                        result['actual_wayland_focus_transport'] = 'Weston 13 desktop-shell physical Super+Tab and real Component focus'
                    subprocess.run(['xdotool', 'key', '--clearmodifiers', 'ctrl+v'], check=True, env=env)
                    wait_station(app, STATION_MARKER)
                finally:
                    if clipboard.poll() is None:
                        clipboard.terminate()
                    clipboard.wait(timeout=15)
                result['actual_input_transport'] = 'X11 clipboard and physical Ctrl+V' if args.backend == 'x11' else 'Wayland clipboard and Weston native Wayland seat Ctrl+V'
                wait_station(app, STATION_MARKER)
                result['actual_station_input'] = True
                subprocess.run(['xdotool', 'key', '--clearmodifiers', 'Tab'], check=True, env=env)
                wait_station(app, COMMITTED_STATION)
                result['actual_blur_canonical_station_input'] = True
                # Normal production blur commits the existing neutral config.
                time.sleep(1)
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
                wait_station(app, COMMITTED_STATION)
                result['cold_restart_station_input_retained'] = True
                app.send_signal(signal.SIGTERM)
                app.wait(timeout=15)
                result['passed'] = True
    except BaseException as error:
        result.update(passed=False, error=str(error))
        raise
    finally:
        pyatspi.Registry.deregisterEventListener(observed_accessibility_event, *listener_names)
        result['actual_atspi_event_counts'] = accessibility_events
        result['actual_document_event_sources'] = document_event_metadata
        for process in [app, background]:
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=15)
        (out / (args.backend + '-result.json')).write_text(json.dumps(result, indent=2) + '\n')
