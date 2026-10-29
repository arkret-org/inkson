"""Resource ownership tests; real Secret Service persistence is exercised by CI."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import native_keystore


class Daemon:
    pid = 4312

    def __init__(self):
        self.stdin = io.BytesIO()
        self.returncode = None
        self.terminated = self.killed = False
        self.stubborn = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        if not self.stubborn:
            self.returncode = -15

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout):
        if self.stubborn and not self.killed:
            raise subprocess.TimeoutExpired("owned-daemon", timeout)
        return self.returncode


class NativeKeystoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="inkson-lease-unit-")
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / "evidence"
        self.daemon = Daemon()
        self.owner = self.daemon.pid
        self.command_code = 0
        self.drop_owner_after_command = False
        self.command_raises = False
        self.commands = []
        self.popen = self.enterContext(patch.object(
            native_keystore.subprocess, "Popen", return_value=self.daemon))
        self.enterContext(patch.object(
            native_keystore.subprocess, "run", side_effect=self.run_command))
        self.enterContext(patch.dict(os.environ, {
            "GNOME_KEYRING_CONTROL": "user-owned-control",
            "XDG_DATA_HOME": "user-owned-data",
            "INKSON_LEASE_TEST_MARKER": "inherited",
        }))

    def run_command(self, command, **kwargs):
        self.commands.append((command, kwargs))
        if command[0] == "gdbus":
            if command[-2].endswith("GetConnectionUnixProcessID"):
                return subprocess.CompletedProcess(command, 0, f"(uint32 {self.owner},)", "")
            return subprocess.CompletedProcess(
                command, 0, "(objectpath '/org/freedesktop/secrets/collection/login',)", "")
        if command[0] == "secret-tool":
            return subprocess.CompletedProcess(
                command, 0, "durable-value" if command[1] == "lookup" else "", "")
        if self.drop_owner_after_command:
            self.owner += 1
        if self.command_raises:
            raise OSError("native command launch failed")
        return subprocess.CompletedProcess(command, self.command_code)

    def invoke(self):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = native_keystore.main([
                "--output-dir", str(self.output), "--", "native-command", "literal argument",
            ])
        return code, json.loads((self.output / "result.json").read_text())

    def test_foreground_owned_daemon_is_private_and_outlives_the_command(self):
        code, result = self.invoke()
        self.assertEqual(code, 0)
        self.assertTrue(result["passed"])
        self.assertTrue(result["final_bus_owner_matches_owned_daemon"])
        command, kwargs = next(item for item in self.commands if item[0][0] == "native-command")
        self.assertEqual(command, ["native-command", "literal argument"])
        environment = kwargs["env"]
        self.assertEqual(environment["INKSON_LEASE_TEST_MARKER"], "inherited")
        self.assertNotIn("GNOME_KEYRING_CONTROL", environment)
        for key in ("XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR"):
            self.assertTrue(Path(environment[key]).parent.name.startswith("inkson-native-keyring-"))
            self.assertFalse(Path(environment[key]).exists())
        self.assertEqual(self.commands[0][0][0], "gdbus")
        self.assertNotEqual(environment["XDG_DATA_HOME"], os.environ["XDG_DATA_HOME"])
        self.assertIn("--foreground", self.popen.call_args.args[0])
        self.assertIn("--control-directory", self.popen.call_args.args[0])
        self.assertTrue(self.daemon.terminated)
        self.assertTrue(result["daemon_cleanup"] and result["private_state_cleanup"])
        self.assertEqual(os.environ["GNOME_KEYRING_CONTROL"], "user-owned-control")
        self.assertEqual(os.environ["XDG_DATA_HOME"], "user-owned-data")

    def test_native_failure_is_not_replaced_by_successful_cleanup(self):
        self.command_code = 101
        code, result = self.invoke()
        self.assertEqual(code, 101)
        self.assertFalse(result["passed"])
        self.assertEqual(result["command_exit_code"], 101)
        self.assertTrue(result["daemon_cleanup"] and result["private_state_cleanup"])

    def test_foreign_bus_owner_is_refused_before_command_dispatch(self):
        self.owner += 1
        code, result = self.invoke()
        self.assertEqual(code, 1)
        self.assertFalse(result["passed"])
        self.assertFalse(any(c[0][0] == "native-command" for c in self.commands))
        self.assertTrue(self.daemon.terminated)
        self.assertIn("not the owned daemon", result["error"])

    def test_early_daemon_exit_cannot_authorize_a_native_command(self):
        self.daemon.returncode = 1
        code, result = self.invoke()
        self.assertEqual(code, 1)
        self.assertFalse(any(c[0][0] == "native-command" for c in self.commands))
        self.assertFalse(result["passed"])
        self.assertTrue(result["private_state_cleanup"])

    def test_owner_replacement_after_preflight_cannot_report_success(self):
        self.drop_owner_after_command = True
        code, result = self.invoke()
        self.assertEqual(code, 1)
        self.assertFalse(result["passed"])
        self.assertEqual(result["command_exit_code"], 0)
        self.assertIn("not the owned daemon", result["error"])

    def test_stubborn_owned_daemon_is_reaped_before_private_state_removal(self):
        self.daemon.stubborn = True
        code, result = self.invoke()
        self.assertEqual(code, 0)
        self.assertTrue(self.daemon.killed)
        self.assertTrue(result["passed"])
        self.assertTrue(result["daemon_cleanup"] and result["private_state_cleanup"])

    def test_spawn_failure_cleans_private_state_and_never_runs_the_command(self):
        self.popen.side_effect = OSError("fixture daemon unavailable")
        code, result = self.invoke()
        self.assertEqual(code, 1)
        self.assertFalse(result["passed"])
        self.assertTrue(result["private_state_cleanup"])
        self.assertEqual(self.commands, [])

    def test_command_launch_exception_still_cleans_the_owned_daemon_and_private_state(self):
        self.command_raises = True
        code, result = self.invoke()
        self.assertEqual(code, 1)
        self.assertFalse(result["passed"])
        self.assertTrue(self.daemon.terminated)
        self.assertTrue(result["daemon_cleanup"] and result["private_state_cleanup"])


if __name__ == "__main__":
    unittest.main()
