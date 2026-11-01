#!/usr/bin/env python3
"""Generate independent, review-only UI dependency locks in remote temporary workspaces."""
from __future__ import annotations
import argparse,copy,difflib,hashlib,json,os,re,shutil,subprocess,tempfile,time,tomllib
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit,urlunsplit,parse_qs
UI={"glory":"https://github.com/glory-rs/glory.git","sapid":"https://github.com/sapid-ui/sapid.git"}
FEATURE_RENAMES={"glory/blitz-shell":"glory/apace-shell","glory/blitz-assets":"glory/apace-assets","glory/blitz-accesskit":"glory/apace-accesskit"}
DEADLINE=None

def native(argv,cwd,env=None,timeout=900):
    if DEADLINE is not None:
        assert DEADLINE-time.monotonic()>=timeout,"insufficient full command window; no shortened Cargo invocation"
    return subprocess.check_output(argv,cwd=cwd,env=env,timeout=timeout)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def git(root, *args):
    return native(["git", "--no-optional-locks", "-C", str(root), *args], root, timeout=60)

def latest_expected(name, expected, root):
    assert re.fullmatch("[a-f0-9]{40}", expected)
    rows = git(root, "ls-remote", "--exit-code", UI[name], "refs/heads/main").decode("ascii").splitlines()
    assert rows == [expected + "\trefs/heads/main"], "reviewed UI main moved; do not resolve another API " + json.dumps({"repository": UI[name], "name": name, "expectedSHA": expected, "actualrows": rows}, sort_keys=True)

def tracked_copy(source, target):
    assert not target.exists()
    target.mkdir()
    rows = git(source, "ls-files", "--stage", "-z").split(b"\0")
    for row in rows:
        if not row:
            continue
        header, name = row.split(b"\t", 1)
        mode, _oid, stage = header.split()
        rel = name.decode("utf-8", errors="strict")
        part = PurePosixPath(rel)
        assert mode in {b"100644", b"100755"} and stage == b"0"
        assert rel and not part.is_absolute() and ".." not in part.parts and "\\" not in rel and ":" not in rel
        original = source / rel
        assert original.is_file() and not original.is_symlink() and original.resolve().is_relative_to(source.resolve())
        destination = target / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, destination)
        destination.chmod(0o755 if mode == b"100755" else 0o644)

def canonical_git_url(url):
    value = urlsplit(url)
    assert value.scheme == "https" and value.netloc == "github.com" and not value.query and not value.fragment
    assert not value.username and not value.password
    path = value.path.removesuffix(".git")
    assert re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", path)
    return "https://github.com" + path

def validate_source_contract(contract):
    assert contract["schema"] == "reviewed-UI-engine-Git-source-closure-v1"
    assert set(contract["inputs"]) == {"glory", "sapid", "apace", "takia", "wingy"}
    expected_urls = {**UI, "apace": "https://github.com/glory-rs/apace", "takia": "https://github.com/glory-rs/takia", "wingy": "https://github.com/glory-rs/wingy"}
    seen = set()
    for name, item in contract["inputs"].items():
        assert item["git"] == expected_urls[name] and re.fullmatch("[a-f0-9]{40}", item["commit"])
        assert item["selector"] == ("branch" if name in UI else "rev")
        assert re.fullmatch("[a-f0-9]{64}", item["root_manifest_sha256"])
        assert item["packages"]
        for package, spec in item["packages"].items():
            assert package not in seen, "ambiguous engine package ownership"
            seen.add(package)
            path = PurePosixPath(spec["manifest"])
            assert not path.is_absolute() and ".." not in path.parts and "\\" not in spec["manifest"] and ":" not in spec["manifest"]
            assert path.name == "Cargo.toml" and re.fullmatch("[a-f0-9]{64}", spec["manifest_sha256"])
            assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", spec["version"])
    expected = {UI["sapid"]: {"glory": "glory"}, UI["glory"]: {"apace-dom": "apace", "apace-traits": "apace", "apace-paint": "apace", "apace-shell": "apace", "apace_accesskit": "apace", "wingy": "wingy"}, expected_urls["apace"]: {"takia": "takia", "wingy": "wingy"}}
    assert contract["patches"] == expected, "only reviewed normal/build escaping edges may be patched"
    for source, packages in contract["patches"].items():
        for package, target in packages.items():
            item = contract["inputs"][target]
            assert canonical_git_url(source) != canonical_git_url(item["git"]), "Cargo source patch must change its source"
            assert package in item["packages"]
    return contract

def verify_source_inputs(root, contract):
    result = {}
    for name, item in contract["inputs"].items():
        source = root / ".ui-lock-inputs" / name
        assert git(source, "rev-parse", "HEAD").decode("ascii").strip() == item["commit"]
        assert not git(source, "status", "--porcelain").strip()
        rootraw = (source / "Cargo.toml").read_bytes()
        assert sha(rootraw) == item["root_manifest_sha256"]
        workspace = tomllib.loads(rootraw.decode("utf-8"))
        for package, spec in item["packages"].items():
            path = source / spec["manifest"]
            assert path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(source.resolve())
            raw = path.read_bytes()
            assert sha(raw) == spec["manifest_sha256"], "fixed fork manifest identity changed"
            actual = tomllib.loads(raw.decode("utf-8"))["package"]
            version = actual["version"]
            if isinstance(version, dict):
                assert version == {"workspace": True}
                version = workspace["workspace"]["package"]["version"]
            assert actual["name"] == package and version == spec["version"], "actual fork version does not satisfy reviewed closure"
        result[name] = {"git": item["git"], "commit": item["commit"], "root_manifest_sha256": sha(rootraw)}
    verify_escaping_paths(root, contract)
    return result

def verify_escaping_paths(root, contract):
    covered = {}
    for edge in contract["library_escaping_edges"]:
        source = root / ".ui-lock-inputs" / edge["source"]
        manifest = source / edge["manifest"]
        raw = manifest.read_bytes()
        assert sha(raw) == edge["manifest_sha256"]
        document = tomllib.loads(raw.decode("utf-8"))
        section = edge["section"]
        if section == "dependencies":
            entry = document["dependencies"][edge["alias"]]
        else:
            assert section.startswith("target.") and section.endswith(".dependencies")
            target = section[len("target."):-len(".dependencies")]
            entry = document["target"][target]["dependencies"][edge["alias"]]
        base = manifest.parent
        if entry.get("workspace"):
            workspace = tomllib.loads((source / "Cargo.toml").read_text())
            inherited = workspace["workspace"]["dependencies"][edge["alias"]]
            entry = {**inherited, **{key: value for key, value in entry.items() if key != "workspace"}}
            base = source
        owner = contract["inputs"][edge["source"]]["git"]
        target_owner = contract["patches"][owner][edge["target_name"]]
        target = contract["inputs"][target_owner]["packages"][edge["target_name"]]
        assert edge["target_name"] == entry.get("package", edge["alias"])
        assert entry["version"] == "=" + edge["target_version"] == "=" + target["version"], "actual escaping dependency requires a different fork version"
        path = root / ".ui-lock-inputs" / target_owner / target["manifest"]
        assert (base / entry["path"] / "Cargo.toml").resolve() == path.resolve(), "escaping path target is not the reviewed package"
        covered.setdefault(owner, {})[edge["target_name"]] = target_owner
    assert covered == contract["patches"], "patch source/package set must exactly cover reviewed library edges"

def source_matches(actual, item):
    if not isinstance(actual, str) or not actual.startswith("git+"):
        return False
    try:
        parsed = urlsplit(actual[4:])
        base = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        if canonical_git_url(base) != canonical_git_url(item["git"]):
            return False
        query = parse_qs(parsed.query, strict_parsing=True)
        selector = item["selector"]
        required = "main" if selector == "branch" else item["commit"]
        return query == {selector: [required]} and parsed.fragment == item["commit"]
    except (AssertionError, ValueError):
        return False

def read_toml(path):
    return tomllib.loads(path.read_text(encoding="utf-8"))

def inline(value):
    if isinstance(value,dict):return "{ "+", ".join(key+" = "+inline(item) for key,item in value.items())+" }"
    if isinstance(value,list):return "["+", ".join(inline(item) for item in value)+"]"
    if isinstance(value,bool):return "true" if value else "false"
    assert isinstance(value,(str,int))
    return json.dumps(value,ensure_ascii=False)

def replace_field(text,header,key,value):
    marker="["+header+"]"
    assert text.splitlines().count(marker)==1,"explicit root table missing/duplicated"
    start=next(re.finditer(r"(?m)^"+re.escape(marker)+r"$",text)).end()
    endmatch=re.search(r"(?m)^\[",text[start:]);end=start+endmatch.start() if endmatch else len(text)
    part=text[start:end]
    pattern=r"(?m)^("+re.escape(key)+r"\s*=\s*)[^\n]*(\n|$)"
    part,count=re.subn(pattern,lambda m:m[1]+inline(value)+m[2],part)
    assert count==1,"explicit root field must be one line and unique"
    return text[:start]+part+text[end:]

def canonical_manifest(raw,owner,root_bridge):
    before=tomllib.loads(raw.decode("utf-8"));expected=copy.deepcopy(before);text=raw.decode("utf-8")
    if "glory" in expected.get("workspace",{}).get("dependencies",{}):
        table=expected["workspace"]["dependencies"];header="workspace.dependencies"
    elif "glory" in expected.get("dependencies",{}) and not expected["dependencies"]["glory"].get("workspace"):
        table=expected["dependencies"];header="dependencies"
    else:table={};header=None
    for name in ("glory","sapid"):
        if name not in table:continue
        entry=table[name]
        assert isinstance(entry,dict)
        if "path" in entry:
            assert owner=="arkret-org/codmin","unreviewed path UI strategy"
            continue
        assert canonical_git_url(entry["git"])==canonical_git_url(UI[name]) and entry.get("branch")=="main" and "rev" not in entry
        if "version" in entry:
            assert entry["version"] in ({"0.3.1","0.6.1"} if name=="glory" else {"0.1.0","0.6.1"})
            entry["version"]="0.6.1";text=replace_field(text,header,name,entry)
    if owner=="arkret-org/inkson":
        features=expected["features"]["desktop"]
        assert set(FEATURE_RENAMES)<=set(features) or set(FEATURE_RENAMES.values())<=set(features)
        expected["features"]["desktop"]=[FEATURE_RENAMES.get(x,x) for x in features]
        text=replace_field(text,"features","desktop",expected["features"]["desktop"])
    if owner=="arkret-org/flagon":
        assert table["wasm-bindgen"] in {"=0.2.129","=0.2.130"}
        table["wasm-bindgen"]="=0.2.130";text=replace_field(text,header,"wasm-bindgen",table["wasm-bindgen"])
    bridge=expected.get("patch",{}).get(UI["sapid"],{}).get("glory")
    if bridge is not None:
        assert canonical_git_url(bridge["git"])==canonical_git_url(UI["glory"]) and bridge.get("branch")=="main" and "rev" not in bridge
        if "version" in bridge:
            assert bridge["version"] in {"0.3.1","0.6.1"}
            bridge["version"]="0.6.1";text=replace_field(text,"patch."+json.dumps(UI["sapid"]),"glory",bridge)
    elif root_bridge:
        bridge={"git":UI["glory"],"branch":"main","version":"0.6.1"}
        assert UI["sapid"] not in expected.get("patch",{})
        expected.setdefault("patch",{})[UI["sapid"]]={"glory":bridge}
        text+="\n[patch."+json.dumps(UI["sapid"])+"]\nglory = "+inline(bridge)+"\n"
    assert tomllib.loads(text)==expected,"manifest change exceeded reviewed fields"
    return text.encode("utf-8")

def install_root_source_patches(raw,upstreams):
    before=tomllib.loads(raw.decode("utf-8"));expected=copy.deepcopy(before);text=raw.decode("utf-8")
    for source,packages in upstreams["patches"].items():
        header="patch."+json.dumps(source);existing=expected.setdefault("patch",{}).get(source)
        if existing is None:
            existing={};expected["patch"][source]=existing;text+="\n["+header+"]\n"
        for package,target in packages.items():
            item=upstreams["inputs"][target]
            entry={"git":item["git"],item["selector"]:"main" if item["selector"]=="branch" else item["commit"],"version":"="+item["packages"][package]["version"]}
            if package in existing:
                old=existing[package]
                assert canonical_git_url(old["git"])==canonical_git_url(entry["git"])
                assert old.get("branch")=="main" and target=="glory","unexpected pre-existing engine override"
                entry=copy.deepcopy(old)
                assert entry.get("version") in {None,"0.6.1"}
                text=replace_field(text,header,package,entry)
            else:text+=package+" = "+inline(entry)+"\n"
            existing[package]=entry
    assert tomllib.loads(text)==expected
    return text.encode("utf-8")

def workspace_file(package,stop):
    directory=package.parent
    while directory.is_relative_to(stop):
        file=directory/"Cargo.toml"
        if file.is_file() and "workspace" in read_toml(file):return file
        if directory==stop:break
        directory=directory.parent
    return package

def workspace_members(root):
    document=read_toml(root/"Cargo.toml");result=set()
    if "package" in document:result.add(root/"Cargo.toml")
    excluded=[(root/x).resolve() for x in document.get("workspace",{}).get("exclude",[])]
    for member in document.get("workspace",{}).get("members",[]):
        for directory in root.glob(member):
            path=directory/"Cargo.toml"
            if path.is_file() and not any(directory.resolve()==x or directory.resolve().is_relative_to(x) for x in excluded):result.add(path)
    assert result,"root workspace has no package manifests"
    return result

def dependency_entries(document,include_dev):
    for section in ("dependencies","build-dependencies",*( ("dev-dependencies",) if include_dev else ())):
        for name,value in document.get(section,{}).items():yield name,value
    for target in document.get("target",{}).values():yield from dependency_entries(target,include_dev)

def discover_UI_owners(temporary,target_root,repositories):
    initial=workspace_members(target_root);queue=list(initial);seen=set();owners={}
    while queue:
        package=queue.pop().resolve()
        if package in seen:continue
        seen.add(package)
        assert package.is_relative_to(temporary)
        if package.is_relative_to(temporary/"glory-rs"):continue
        assert package.is_file(),"a required source path is unavailable"
        document=read_toml(package);workspace=workspace_file(package,temporary);wd=read_toml(workspace)
        for alias,value in dependency_entries(document,package in initial):
            if not isinstance(value,dict):continue
            base=package.parent;effective=value
            if value.get("workspace"):
                inherited=wd["workspace"]["dependencies"][alias]
                if not isinstance(inherited,dict):continue
                effective={**inherited,**{k:v for k,v in value.items() if k!="workspace"}};base=workspace.parent
            if alias in {"glory","sapid"} or effective.get("package") in {"glory","sapid"}:
                owner_manifest=workspace if value.get("workspace") else package
                relative=owner_manifest.relative_to(temporary);owner="/".join(relative.parts[:2])
                assert owner in repositories,"UI declaration owner must be an explicit input"
                owners.setdefault(owner_manifest,set()).add(package)
            if "path" in effective:
                dependency=(base/effective["path"]/"Cargo.toml").resolve()
                assert dependency.is_relative_to(temporary),"dependency escaped temporary input layout"
                queue.append(dependency)
    return owners

def refresh_command(lock,profile):
    names={p["name"] for p in tomllib.loads(lock.decode("utf-8"))["package"]}
    ui=names&{"glory","sapid"}
    if profile["update_mode"]=="targeted_existing_UI":
        assert ui=={"glory","sapid"},"targeted package selectors must exist in this root lock"
        command=["cargo","update","-p","glory","-p","sapid"]
        for name in profile["extra_existing_unlocks"]:
            if name in names:command += ["-p",name]
        return command
    assert profile["update_mode"] in {"workspace_new_UI_graph","workspace_path_graph"}
    assert (not ui) if profile["update_mode"]=="workspace_new_UI_graph" else ui=={"glory","sapid"}
    return ["cargo","update","--workspace"]

def owner_for_manifest(path,temporary,originals,upstreams):
    for name,item in upstreams["inputs"].items():
        base=temporary/"glory-rs"/name
        if path.is_relative_to(base):
            relative=path.relative_to(base)
            original=originals/".ui-lock-inputs"/name/relative
            assert path.read_bytes()==original.read_bytes(),"path-source upstream was changed"
            return {"repository":item["git"].removeprefix("https://github.com/").removesuffix(".git"),"commit":item["commit"],"manifest":relative.as_posix(),"manifest_sha256":sha(path.read_bytes())}
    return None

def validate_graph(metadata,profile,temporary,originals,upstreams,target):
    assert Path(metadata["target_directory"]).resolve()==(temporary/"target"/profile["repository"].split("/")[-1]).resolve()
    packages=metadata["packages"];rows=metadata["resolve"]["nodes"];nodes={node["id"]:node for node in rows}
    assert len(nodes)==len(rows) and len({p["id"] for p in packages})==len(packages),"duplicate metadata identity"
    assert set(nodes)<={p["id"] for p in packages}
    selected_UI={};origins={};engine_map={}
    catalog={pkg:(name,item,spec) for name,item in upstreams["inputs"].items() for pkg,spec in item["packages"].items()}
    for package in packages:
        name=package["name"]
        ui_name="glory" if name=="glory" or name.startswith("glory-") else "sapid" if name=="sapid" else None
        owned=upstreams["inputs"][ui_name] if ui_name else catalog.get(name,(None,None,None))[1]
        if owned is None:continue
        assert name not in origins,"a UI/engine package has multiple source identities"
        if package.get("source") is None:
            assert profile["source_mode"]=="path","Git-main consumer unexpectedly selected local UI"
            origin=owner_for_manifest(Path(package["manifest_path"]).resolve(),temporary,originals,upstreams)
            assert origin and origin["commit"]==owned["commit"]
            origins[name]=origin
        else:
            assert profile["source_mode"]=="git" and source_matches(package["source"],owned),"resolved UI/engine Git source differs from reviewed main/fork"
            origins[name]={"source":package["source"]}
        expected="0.6.1" if ui_name else catalog[name][2]["version"]
        assert package["version"]==expected
        if name in {"glory","sapid"}:selected_UI[name]=package
        elif ui_name is None:engine_map[name]={"version":package["version"],**origins[name]}
    assert set(selected_UI)=={"glory","sapid"}
    assert any(p["name"]==profile["UI_package"] for p in packages),"declared actual UI entry package absent"
    features=set(nodes[selected_UI["glory"]["id"]]["features"])
    assert not any(x=="apace" or x.startswith(("apace-","blitz")) for x in features),"web/memory root was forced onto a native renderer"
    minimum=profile["minimum_native_features"] if target=="native" else profile["minimum_wasm_features"]
    assert set(minimum)<=features
    if profile["UI_package"]=="cotest-inkson-client-tests":assert not ({"web","ssr"}&features)
    ids={p["id"]:sha(p["id"].encode()) for p in packages}
    normalized={"schema":"root-target-locked-metadata-v1","target":target,"consumer":profile["repository"],"packages":[{"id_sha256":ids[p["id"]],"name":p["name"],"version":p["version"],"source":p.get("source"),"features":p["features"],"verified_UI_origin":origins.get(p["name"])} for p in packages],"resolve":[{"id_sha256":ids[n["id"]],"features":n["features"],"dependencies":[ids[d] for d in n["dependencies"]]} for n in nodes.values()],"actual_Glory_features":sorted(features),"observed_engine_sources":engine_map,"native_engine_minimum_required":False,"approved":False,"runtime_credit":None}
    return normalized,{Path(p["manifest_path"]).resolve() for p in packages}


def main():
    global DEADLINE
    DEADLINE=time.monotonic()+4500
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-root",type=Path,required=True);parser.add_argument("--consumer",required=True)
    parser.add_argument("--source-config",type=Path,required=True);parser.add_argument("--source-config-sha256",required=True);parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args();config_raw=args.source_config.read_bytes();assert sha(config_raw)==args.source_config_sha256
    config=json.loads(config_raw);assert config["schema"]=="explicit-multi-root-UI-resolution-v1" and args.consumer in config["consumers"]
    profile=config["consumers"][args.consumer];upstreams=validate_source_contract(config["upstreams"]);original=args.workspace_root.resolve(strict=True);output=args.output.resolve();assert not output.exists();output.mkdir(parents=True)
    status={"consumer":profile["repository"],"phase":"initial","candidate_complete":False,"root_approved":False,"allows_publication":False,"merge_ready":False,"runtime_credit":None}
    try:
        sources={};original_bytes={}
        for repository,location in config["workspace_repositories"].items():
            source=original/location;assert not git(source,"status","--porcelain").strip();sources[repository]=git(source,"rev-parse","HEAD").decode().strip();assert re.fullmatch("[a-f0-9]{40}",sources[repository])
            for filename in ("Cargo.toml","Cargo.lock"):
                path=source/filename;original_bytes[(repository,filename)]=sha(path.read_bytes()) if path.is_file() else None
        source_root=original/profile["repository"]
        assert sources[profile["repository"]]==profile["base_commit"] and sha((source_root/"Cargo.toml").read_bytes())==profile["manifest_sha256"] and sha((source_root/"Cargo.lock").read_bytes())==profile["lock_sha256"]
        for name in UI:latest_expected(name,upstreams["inputs"][name]["commit"],source_root)
        verified=verify_source_inputs(original,upstreams)
        with tempfile.TemporaryDirectory(prefix="UI-lock-"+args.consumer+"-",dir=os.environ["RUNNER_TEMP"]) as directory:
            temporary=Path(directory)
            for repository,location in config["workspace_repositories"].items():
                (temporary/repository).parent.mkdir(parents=True,exist_ok=True);tracked_copy(original/location,temporary/repository)
            for name in upstreams["inputs"]:
                (temporary/"glory-rs").mkdir(exist_ok=True);tracked_copy(original/".ui-lock-inputs"/name,temporary/"glory-rs"/name)
            root=temporary/profile["repository"];owners=discover_UI_owners(temporary,root,config["workspace_repositories"]);owners.setdefault(root/"Cargo.toml",set())
            overlays=[]
            for manifest,triggers in owners.items():
                relative=manifest.relative_to(temporary);owner="/".join(relative.parts[:2]);before=manifest.read_bytes()
                bridge=manifest==root/"Cargo.toml" and profile["source_mode"]=="git"
                after=canonical_manifest(before,owner,bridge)
                if bridge:after=install_root_source_patches(after,upstreams)
                if before!=after:manifest.write_bytes(after);overlays.append({"file":relative.as_posix(),"before_sha256":sha(before),"after_sha256":sha(after),"trigger_packages":[p.relative_to(temporary).as_posix() for p in sorted(triggers)]})
            environment=dict(os.environ,CARGO_TARGET_DIR=str(temporary/"target"/args.consumer),CARGO_NET_GIT_FETCH_WITH_CLI="true")
            command=refresh_command((source_root/"Cargo.lock").read_bytes(),profile);status["phase"]="official_root_update";native(command,root,environment)
            graphs={};observed=set()
            for label,target in (("native",config["native_target"]),("wasm",config["wasm_target"])):
                status["phase"]="official_locked_metadata_"+label
                raw=native(["cargo","metadata","--locked","--all-features","--filter-platform",target,"--format-version","1"],root,environment)
                normalized,paths=validate_graph(json.loads(raw),profile,temporary,original,upstreams,label);normalized["raw_metadata_sha256"]=sha(raw);graphs[label]=normalized;observed|=paths
            status["phase"]="official_locked_tree";tree=native(["cargo","tree","--locked","--workspace","--all-features","--prefix","none","--format","{p}"],root,environment)
            for name in UI:latest_expected(name,upstreams["inputs"][name]["commit"],source_root)
            assert verify_source_inputs(original,upstreams)==verified
            for filename in ("Cargo.toml","Cargo.lock"):shutil.copyfile(root/filename,output/filename)
            for label,graph in graphs.items():(output/("metadata-"+label+".json")).write_bytes((json.dumps(graph,indent=2)+"\n").encode())
            needed=[];patch=""
            for overlay in overlays:
                triggers={temporary/p for p in overlay["trigger_packages"]};active=overlay["file"]==(profile["repository"]+"/Cargo.toml") or bool(triggers&observed)
                overlay["actual_metadata_owner_used"]=active
                if not active:continue
                relative=PurePosixPath(overlay["file"]);destination=output/"overlays"/relative;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(temporary/relative,destination);needed.append(overlay["file"])
                old=original/relative;patch+="".join(difflib.unified_diff(old.read_text().splitlines(True),(temporary/relative).read_text().splitlines(True),"a/"+str(relative),"b/"+str(relative)))
            patch+="".join(difflib.unified_diff((source_root/"Cargo.lock").read_text().splitlines(True),(root/"Cargo.lock").read_text().splitlines(True),"a/"+profile["repository"]+"/Cargo.lock","b/"+profile["repository"]+"/Cargo.lock"));(output/"candidate.patch").write_bytes(patch.encode())
            context={"consumer":profile["repository"],"consumer_base_commit":profile["base_commit"],"input_repositories":sources,"upstream_inputs":verified,"source_config_sha256":sha(config_raw),"original_manifest_sha256":profile["manifest_sha256"],"original_lock_sha256":profile["lock_sha256"],"source_mode":profile["source_mode"],"actual_update_command":command,"staged_manifest_overlays":overlays,"needed_manifest_overlays":needed,"raw_locked_tree_sha256":sha(tree),"approved":False,"runtime_credit":None};(output/"input-context.json").write_bytes((json.dumps(context,indent=2)+"\n").encode())
        status["phase"]="verify_original_inputs"
        for (repository,filename),expected in original_bytes.items():
            path=original/repository/filename;assert (sha(path.read_bytes()) if path.is_file() else None)==expected
        assert all(git(original/repository,"rev-parse","HEAD").decode().strip()==commit and not git(original/repository,"status","--porcelain").strip() for repository,commit in sources.items())
        status.update(phase="review_only_root_candidate_complete",candidate_complete=True)
    except (AssertionError,OSError,ValueError,subprocess.SubprocessError) as error:
        status.update(phase="candidate_unavailable_"+status["phase"],exception_type=type(error).__name__);raise
    finally:
        (output/"status.json").write_bytes((json.dumps(status,indent=2)+"\n").encode());records=[{"file":p.relative_to(output).as_posix(),"bytes":p.stat().st_size,"sha256":sha(p.read_bytes())} for p in sorted(output.rglob("*")) if p.is_file()];(output/"manifest.json").write_bytes((json.dumps({"consumer":profile["repository"],"files":records,"approved":False,"runtime_credit":None},indent=2)+"\n").encode())

if __name__=="__main__":main()
