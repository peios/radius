#!/usr/bin/env python3
"""Preservation checks for host operations that touch the persistent VM disk."""

import argparse
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location("vm", Path(__file__).parents[2] / "tools/dev-vm/vm.py")
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)


class Preservation(unittest.TestCase):
    def test_stopping_launcher_reaps_its_child(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "child.pid"
            child = f"import os,time; open({str(pid_file)!r},'w').write(str(os.getpid())); time.sleep(60)"
            script = ("import importlib.util; "
                      f"s=importlib.util.spec_from_file_location('vm', {str(Path(vm.__file__).resolve())!r}); "
                      "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
                      f"m.run_vm([{sys.executable!r}, '-c', {child!r}])")
            launcher = subprocess.Popen([sys.executable, "-c", script])
            try:
                deadline = time.monotonic() + 5
                while not pid_file.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(pid_file.exists())
                child_pid = int(pid_file.read_text())
                launcher.terminate()
                self.assertEqual(launcher.wait(timeout=5), 143)
                with self.assertRaises(ProcessLookupError):
                    os.kill(child_pid, 0)
            finally:
                if launcher.poll() is None:
                    launcher.terminate()
                    launcher.wait(timeout=5)

    def test_existing_state_is_never_formatted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "state.img").write_bytes(b"existing machine")
            with self.assertRaises(FileExistsError):
                vm.create_state(argparse.Namespace(vm=root))
            self.assertEqual((root / "state.img").read_bytes(), b"existing machine")

    def test_missing_state_does_not_start_a_vm(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(SystemExit, "required state disk is missing"):
                vm.boot(argparse.Namespace(vm=Path(directory), name="test", initialize=False))

    def test_failed_stage_preserves_existing_sets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sets = root / "share/sets"
            (sets / "current").mkdir(parents=True)
            (sets / "current/SHA256SUMS").write_bytes(b"unchanged")
            source = root / "input"
            source.mkdir()
            with self.assertRaisesRegex(SystemExit, "missing runtime file"):
                vm.stage(argparse.Namespace(vm=root, name="next", source=source))
            self.assertEqual((sets / "current/SHA256SUMS").read_bytes(), b"unchanged")
            self.assertFalse((sets / "next").exists())

    def test_complete_stage_is_immutable_by_name(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "share/sets").mkdir(parents=True)
            source = root / "input"
            for file in vm.FILES:
                path = source / file
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(file.encode())
            args = argparse.Namespace(vm=root, name="test", source=source)
            with contextlib.redirect_stdout(io.StringIO()):
                vm.stage(args)
            first = (root / "share/sets/test/SHA256SUMS").read_bytes()
            (source / vm.FILES[0]).write_bytes(b"replacement")
            with self.assertRaisesRegex(SystemExit, "set already exists"):
                vm.stage(args)
            self.assertEqual((root / "share/sets/test/SHA256SUMS").read_bytes(), first)


if __name__ == "__main__":
    unittest.main()
