import {spawn} from 'node:child_process';
import {mkdir} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
const cache=process.platform==='win32'?'D:/BuildCache/inkson-glory':process.env.WSL_DISTRO_NAME?'/mnt/d/BuildCache/inkson-glory':path.join(root,'target');
const target=path.resolve(process.env.INKSON_E2E_CARGO_TARGET_DIR||path.join(cache,'playwright-e2e'));
const env={...process.env,CARGO_TARGET_DIR:target};
if(process.platform==='win32'||process.env.WSL_DISTRO_NAME){
  const temporary=path.join(cache,'tmp');await mkdir(temporary,{recursive:true});
  env.TEMP=env.TMP=env.TMPDIR=temporary;env.PYTHONPYCACHEPREFIX=path.join(cache,'pycache');
  env.CARGO_HOME=process.platform==='win32'?'D:/BuildCache/cargo':'/mnt/d/BuildCache/cargo';
}
const profile=process.env.INKSON_E2E_BUILD_PROFILE||'joint-e2e';
const features=process.env.INKSON_E2E_FEATURES||'web,wasm-localstorage-secrets-test,experimental-applets';
const output=path.join(target,'web');let child;
const stop=()=>{if(child&&!child.killed)child.kill();};
process.on('SIGTERM',()=>{stop();process.exit(0)});process.on('SIGINT',()=>{stop();process.exit(130)});
const buildArgs=[path.join(root,'scripts/build_web.py'),'--features',features,'--out-dir',output,...(profile==='release'?['--release']:['--profile',profile])];
child=spawn(process.env.PYTHON||'python',buildArgs,{cwd:root,env,stdio:'inherit'});
const code=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',resolve)});
if(code!==0)process.exit(code||1);
const args=[path.join(root,'tests/e2e/staticServer.mjs'),output,process.env.INKSON_E2E_PORT||'4727'];
if(process.env.INKSON_E2E_FIXTURES)args.push(process.env.INKSON_E2E_FIXTURES);
child=spawn(process.execPath,args,{cwd:root,env,stdio:'inherit'});
child.once('error',error=>{console.error(error);process.exitCode=1});child.once('exit',code=>{process.exitCode=code||0});
