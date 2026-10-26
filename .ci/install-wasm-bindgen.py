#!/usr/bin/env python3
"""Install the CLI matching the one exact wasm-bindgen version in Cargo.lock."""
import json,os,pathlib,subprocess,sys,tomllib
root=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'scripts'))
from build_web import build_environment,find_bindgen

def main():
 env=build_environment()
 try:executable=find_bindgen(env)
 except SystemExit:
  versions={p['version'] for p in tomllib.loads((root/'Cargo.lock').read_text(encoding='utf-8'))['package'] if p['name']=='wasm-bindgen'}
  if len(versions)!=1:raise SystemExit('Expected one locked wasm-bindgen version')
  version=versions.pop()
  metadata=json.loads(subprocess.check_output(['cargo','metadata','--locked','--no-deps','--format-version','1'],cwd=root,env=env,text=True))
  tools=pathlib.Path(metadata['target_directory']).parent/'tools'
  subprocess.run(['cargo','install','wasm-bindgen-cli','--version',version,'--locked','--root',str(tools)],cwd=root,env=env,check=True,timeout=3600)
  executable=str(tools/'bin'/('wasm-bindgen.exe' if os.name=='nt' else 'wasm-bindgen'))
 if env.get('GITHUB_PATH'):
  with open(env['GITHUB_PATH'],'a',encoding='utf-8') as output:output.write(str(pathlib.Path(executable).parent)+'\n')
 if env.get('GITHUB_ENV'):
  with open(env['GITHUB_ENV'],'a',encoding='utf-8') as output:output.write(f'WASM_BINDGEN={executable}\n')
 print(executable)
if __name__=='__main__':main()
