#!/usr/bin/env python3
"""Build and serve Glory/Sapid while watching application and sibling sources."""
from __future__ import annotations
import argparse
from http.server import SimpleHTTPRequestHandler,ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit
import sdk_registry as registry
from build_web import build_environment

PROJECT_ROOT=Path(__file__).resolve().parents[1]

def dependency_watch_loop(roots,build_dirs,stop,rebuild):
    snapshot=registry.watched_files(roots,build_dirs)
    pending_since=None
    while not stop.wait(0.5):
        current=registry.watched_files(roots,build_dirs)
        if current!=snapshot:
            snapshot=current;pending_since=time.monotonic();continue
        if pending_since is None or time.monotonic()-pending_since<2.0:
            continue
        pending_since=None
        try:
            registry.ensure_registry_alignment()
            snapshot=registry.watched_files(roots,build_dirs)
            rebuild()
        except Exception as error:
            print(f"[inkson-dev] rebuild withheld: {error}",file=sys.stderr,flush=True)

def parse_args():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform',choices=['web','desktop'],default='web')
    parser.add_argument('--port',type=int,default=8080)
    parser.add_argument('--check',action='store_true',help='read-only registry and dependency check')
    return parser.parse_args()

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
    stopped=threading.Event();revision=[0];child=[None]
    output=target/'web'
    def rebuild():
        if args.platform=='web':
            subprocess.run([sys.executable,str(PROJECT_ROOT/'scripts/build_web.py'),'--out-dir',str(output)],cwd=PROJECT_ROOT,env=env,check=True)
        else:
            if child[0] is not None and child[0].poll() is None:
                child[0].terminate();child[0].wait(timeout=15)
            subprocess.run(['cargo','build','--locked','--features','desktop','--bin','inkson'],cwd=PROJECT_ROOT,env=env,check=True)
            executable=target/'debug'/('inkson.exe' if os.name=='nt' else 'inkson')
            child[0]=subprocess.Popen([str(executable)],cwd=PROJECT_ROOT,env=env)
        revision[0]+=1
        print(f'[inkson-dev] build {revision[0]} ready',flush=True)
    try:rebuild()
    except (OSError,subprocess.SubprocessError) as error:
        print(f'[inkson-dev] {error}',file=sys.stderr);return 1
    watcher=threading.Thread(target=dependency_watch_loop,args=(roots,build_dirs,stopped,rebuild),daemon=True,name='inkson-source-watch')
    watcher.start()
    server=None
    try:
        if args.platform=='web':
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
            print(f'[inkson-dev] http://127.0.0.1:{args.port}',flush=True);server.serve_forever()
        else:
            while not stopped.wait(0.5):
                if child[0] is not None and child[0].poll() is not None:return child[0].returncode
    except KeyboardInterrupt:return 0
    finally:
        stopped.set()
        if server:server.server_close()
        if child[0] is not None and child[0].poll() is None:child[0].terminate();child[0].wait(timeout=15)
        watcher.join(timeout=3)
    return 0
if __name__=='__main__':raise SystemExit(main())
