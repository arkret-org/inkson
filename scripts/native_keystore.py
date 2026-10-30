"""Own a disposable, unlocked Linux Secret Service for one native command."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import uuid


class NativeKeystoreLease:
    def __init__(self, output: Path) -> None:
        self.output = output
        self.daemon = self.log = self.temporary = self.private_path = None
        self.environment = os.environ.copy()
        self.proof = {
            "actual_bus_owner_matches_owned_daemon": False,
            "actual_default_collection_ready": False,
            "daemon_cleanup": False,
            "private_state_cleanup": False,
        }

    def call(self, command, **kwargs):
        return subprocess.run(command, env=self.environment, capture_output=True,
                              text=True, timeout=10, **kwargs)

    def owner_matches(self) -> bool:
        if self.daemon.poll() is not None:
            raise RuntimeError("owned Secret Service exited before command completion")
        owner = self.call([
            "gdbus", "call", "--session", "--dest", "org.freedesktop.DBus",
            "--object-path", "/org/freedesktop/DBus", "--method",
            "org.freedesktop.DBus.GetConnectionUnixProcessID", "org.freedesktop.secrets",
        ])
        if owner.returncode != 0:
            return False
        if owner.stdout.strip() != f"(uint32 {self.daemon.pid},)":
            raise RuntimeError("Secret Service bus owner is not the owned daemon")
        return True

    def __enter__(self):
        try:
            self.output.mkdir(parents=True, exist_ok=True)
            self.temporary = tempfile.TemporaryDirectory(prefix="inkson-native-keyring-")
            self.private_path = Path(self.temporary.name)
            self.environment.pop("GNOME_KEYRING_CONTROL", None)
            for key, directory in (("XDG_DATA_HOME", "data"), ("XDG_CONFIG_HOME", "config"),
                                   ("XDG_RUNTIME_DIR", "runtime")):
                path = self.private_path / directory
                path.mkdir(mode=0o700)
                self.environment[key] = str(path)
            self.log = (self.output / "daemon.log").open("wb")
            self.daemon = subprocess.Popen(
                ["gnome-keyring-daemon", "--foreground", "--components=secrets", "--unlock",
                 "--control-directory", str(self.private_path / "control")],
                env=self.environment, stdin=subprocess.PIPE, stdout=self.log,
                stderr=subprocess.STDOUT)
            self.proof["owned_daemon_pid"] = self.daemon.pid
            self.daemon.stdin.write(b"\n")
            self.daemon.stdin.close()
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if self.owner_matches():
                    self.proof["actual_bus_owner_matches_owned_daemon"] = True
                    alias = self.call([
                        "gdbus", "call", "--session", "--dest", "org.freedesktop.secrets",
                        "--object-path", "/org/freedesktop/secrets", "--method",
                        "org.freedesktop.Secret.Service.ReadAlias", "default",
                    ])
                    if alias.returncode == 0 and "collection/" in alias.stdout:
                        self.proof["actual_default_collection_ready"] = True
                        break
                time.sleep(0.25)
            else:
                raise RuntimeError("private default collection did not become ready")
            attributes = ["service", "arkret.inkson-ci-probe", "account", "preflight"]
            self.call(["secret-tool", "store", "--label=inkson-ci-probe", *attributes],
                      input="durable-value", check=True)
            found = self.call(["secret-tool", "lookup", *attributes], check=True)
            if found.stdout.strip() != "durable-value":
                raise RuntimeError("private Secret Service round-trip did not match")
            self.call(["secret-tool", "clear", *attributes], check=True)
            return self
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        try:
            if self.daemon is not None:
                if self.daemon.poll() is None:
                    self.daemon.terminate()
                try:
                    self.daemon.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.daemon.kill()
                    self.daemon.wait(timeout=10)
                self.proof["owned_daemon_exit_code"] = self.daemon.returncode
            self.proof["daemon_cleanup"] = self.daemon is None or self.daemon.poll() is not None
        finally:
            if self.log is not None:
                self.log.close()
            if self.temporary is not None:
                self.temporary.cleanup()
            self.proof["private_state_cleanup"] = (
                self.private_path is None or not self.private_path.exists())

    def __exit__(self, *_):
        self.close()


def main(arguments=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(arguments)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a native command is required")
    output = args.output_dir or (
        Path(__file__).resolve().parents[1] / "artifacts/native-keystore" / uuid.uuid4().hex)
    lease = NativeKeystoreLease(output)
    result = {"command": command, "passed": False}
    exit_code = 1

    def interrupted(signum, _frame):
        raise SystemExit(128 + signum)

    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        with lease:
            completed = subprocess.run(command, env=lease.environment)
            result["command_exit_code"] = completed.returncode
            exit_code = completed.returncode if completed.returncode >= 0 else 128 - completed.returncode
            if exit_code == 0:
                if not lease.owner_matches():
                    raise RuntimeError("owned Secret Service lost its bus name during the command")
                result["final_bus_owner_matches_owned_daemon"] = True
                result["passed"] = True
    except Exception as error:
        result["error"] = str(error)
        print(f"native Secret Service lease failed: {error}", file=sys.stderr)
        exit_code = 1
    finally:
        signal.signal(signal.SIGTERM, previous)
        result.update(lease.proof)
        result["passed"] = (result["passed"] and exit_code == 0
                            and result["daemon_cleanup"] and result["private_state_cleanup"])
        if exit_code == 0 and not result["passed"]:
            exit_code = 1
        output.mkdir(parents=True, exist_ok=True)
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"native Secret Service lease evidence: {output}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
