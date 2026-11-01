#!/usr/bin/env python3
"""Build and serve Glory/Sapid while watching application and sibling sources."""
from __future__ import annotations
import argparse
from http.server import SimpleHTTPRequestHandler,ThreadingHTTPServer
import json
import os
from pathlib import Path
from queue import Empty,SimpleQueue
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit
import sdk_registry as registry
from build_web import build_environment

PROJECT_ROOT=Path(__file__).resolve().parents[1]
CHILD_STOP_TIMEOUT_SECONDS=3


def dependency_watch_loop(roots,build_dirs,stop,rebuild,initial_snapshot=None):
    snapshot=registry.watched_files(roots,build_dirs,stop) if initial_snapshot is None else initial_snapshot
    pending_since=None
    while not stop.wait(0.5):
        current=registry.watched_files(roots,build_dirs,stop)
        if stop.is_set():return
        if current!=snapshot:
            snapshot=current;pending_since=time.monotonic();continue
        if pending_since is None or time.monotonic()-pending_since<2.0:
            continue
        pending_since=None
        try:
            registry.ensure_registry_alignment()
        except Exception as error:
            print(f"[inkson-dev] rebuild withheld: {error}",file=sys.stderr,flush=True)
            continue
        # Enumeration failures are fatal, including the post-repair snapshot.
        snapshot=registry.watched_files(roots,build_dirs,stop)
        if stop.is_set():return
        try:
            rebuild()
        except Exception as error:
            print(f"[inkson-dev] rebuild withheld: {error}",file=sys.stderr,flush=True)


def parse_args():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform',choices=['web','desktop'],default='web')
    parser.add_argument('--port',type=int,default=8080)
    parser.add_argument('--check',action='store_true',help='read-only registry and dependency check')
    return parser.parse_args()


def stop_owned_process(process):
    """Reap only a process returned by this launcher's Popen."""
    if process.poll() is None:process.terminate()
    try:return process.wait(timeout=CHILD_STOP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        return process.wait(timeout=CHILD_STOP_TIMEOUT_SECONDS)


class OwnedProcesses:
    """Serialize launch registration with shutdown; never discover other PIDs."""
    def __init__(self,stop):
        self.stop=stop
        self.lock=threading.Lock()
        self.processes={}

    def start(self,name,command,**options):
        with self.lock:
            if self.stop.is_set():return None
            if name in self.processes:raise RuntimeError('owned process slot is occupied')
            process=subprocess.Popen(command,**options)
            self.processes[name]=process
            return process

    def poll_slot(self,name):
        # Do not let main retain a Popen after the watcher replaces its slot.
        with self.lock:
            process=self.processes.get(name)
            return None if process is None else process.poll()

    def close(self,name):
        with self.lock:
            process=self.processes.get(name)
            if process is None:return None
            try:return stop_owned_process(process)
            finally:self.processes.pop(name,None)

    def close_all(self):
        # stop is already set, so start cannot add a process after this snapshot.
        with self.lock:names=list(self.processes)
        first_error=None
        for name in names:
            try:self.close(name)
            except Exception as error:
                if first_error is None:first_error=error
        if first_error is not None:raise first_error


def run_owned_build(owner,stop,command,**options):
    process=owner.start('build',command,**options)
    if process is None:return False
    try:
        while not stop.is_set():
            try:code=process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:continue
            if stop.is_set():return False
            if code:raise subprocess.CalledProcessError(code,command)
            return True
        return False
    finally:owner.close('build')


def main():
    args=parse_args()
    try:
        env=build_environment();env["INKSON_ASSET_DIR"]=str((PROJECT_ROOT/"assets").resolve());os.environ.update(env)
        if args.check:registry.require_registry_alignment()
        else:registry.ensure_registry_alignment()
        metadata=registry.cargo_metadata()
        target=Path(metadata['target_directory']).resolve()
        if os.name=='nt' and target.drive.lower()!='d:':raise RuntimeError(f'Cargo output must be on D: {target}')
        roots=[PROJECT_ROOT,*registry.local_dependency_roots(metadata)]
        build_dirs=registry.build_directories(metadata)
        print(f'Cargo target directory: {target}',flush=True)
    except Exception as error:
        print(f'[inkson-dev] {error}',file=sys.stderr);return 1
    if args.check:
        expected,_=registry.registry_identities();print(f'registry={expected}')
        for root in roots:print(f'watching={root}')
        return 0
    stopped=threading.Event();revision=[0];owner=OwnedProcesses(stopped)
    output=target/'web'
    def rebuild():
        if args.platform=='web':
            if not run_owned_build(owner,stopped,[sys.executable,str(PROJECT_ROOT/'scripts/build_web.py'),'--out-dir',str(output)],cwd=PROJECT_ROOT,env=env):return
        else:
            owner.close('desktop')
            if not run_owned_build(owner,stopped,['cargo','build','--locked','--features','desktop','--bin','inkson'],cwd=PROJECT_ROOT,env=env):return
            executable=target/'debug'/('inkson.exe' if os.name=='nt' else 'inkson')
            if owner.start('desktop',[str(executable)],cwd=PROJECT_ROOT,env=env) is None:return
        revision[0]+=1
        print(f'[inkson-dev] build {revision[0]} ready',flush=True)
    failures=SimpleQueue()
    def watch_dependencies():
        try:dependency_watch_loop(roots,build_dirs,stopped,rebuild,initial_snapshot)
        except Exception as error:
            failures.put(error);stopped.set()
    watcher=None;watcher_started=False;server=None;exit_code=1
    try:
        initial_snapshot=registry.watched_files(roots,build_dirs,stopped)
        rebuild()
        watcher=threading.Thread(target=watch_dependencies,daemon=True,name='inkson-source-watch')
        watcher.start();watcher_started=True
        if stopped.is_set():exit_code=1
        elif args.platform=='web':
            class Handler(SimpleHTTPRequestHandler):
                def __init__(self,*values,**options):super().__init__(*values,directory=str(output),**options)
                def end_headers(self):self.send_header('Cache-Control','no-store');super().end_headers()
                def do_GET(self):
                    path=urlsplit(self.path).path
                    if path=='/__inkson_reload':
                        payload=json.dumps({'revision':revision[0]}).encode();mime='application/json'
                    elif path=='/__inkson_dev.js':
                        payload=b"let seen;setInterval(async()=>{try{const r=await fetch('/__inkson_reload',{cache:'no-store'});const n=(await r.json()).revision;if(seen!==undefined&&n!==seen)location.reload();seen=n;}catch{}},1000);";mime='application/javascript'
                    elif path.startswith(('/assets/','/pkg/')) or (output/path.lstrip('/')).is_file() and path!='/index.html':
                        return super().do_GET()
                    else:
                        payload=(output/'index.html').read_bytes().replace(b'</body>',b'<script type="module" src="/__inkson_dev.js"></script></body>');mime='text/html; charset=utf-8'
                    self.send_response(200);self.send_header('Content-Type',mime);self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
            server=ThreadingHTTPServer(('127.0.0.1',args.port),Handler)
            server.timeout=0.5
            print(f'[inkson-dev] http://127.0.0.1:{args.port}',flush=True)
            while not stopped.is_set():server.handle_request()
            exit_code=0
        else:
            while not stopped.wait(0.5):
                code=owner.poll_slot('desktop')
                if code is not None:
                    exit_code=code;break
    except KeyboardInterrupt:exit_code=0
    except (OSError,subprocess.SubprocessError) as error:
        print(f'[inkson-dev] {error}',file=sys.stderr);exit_code=1
    finally:
        stopped.set()
        try:
            if server is not None:server.server_close()
        except Exception as error:
            print(f'[inkson-dev] server cleanup failed: {error}',file=sys.stderr);exit_code=1
        try:owner.close_all()
        except Exception as error:
            print(f'[inkson-dev] child cleanup failed: {error}',file=sys.stderr);exit_code=1
        if watcher_started:watcher.join(timeout=3)
    if watcher_started and watcher.is_alive():
        print('[inkson-dev] source watcher did not stop',file=sys.stderr);exit_code=1
    try:failure=failures.get_nowait()
    except Empty:failure=None
    if failure is not None:
        print(f'[inkson-dev] dependency watch failed: {failure}',file=sys.stderr,flush=True);exit_code=1
    return exit_code
if __name__=='__main__':raise SystemExit(main())
