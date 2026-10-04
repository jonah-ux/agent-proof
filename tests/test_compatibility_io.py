"""Hostile local-input regressions for the offline compatibility reader."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from agent_proof import compatibility


class CompatibilityIOTests(unittest.TestCase):
    def test_root_directory_refuses_without_descriptor_error(self):
        with tempfile.TemporaryDirectory() as directory:
            result = compatibility._read_artifact(Path(directory), Path("."), 4096)
        self.assertEqual(result, (None, "unsafe_path"))

    def test_directory_symlink_and_traversal_have_unsafe_path_refusals(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "nested").mkdir()
            (root / "owner.json").write_bytes(b"{}")
            (root / "link.json").symlink_to(root / "owner.json")
            (root / "dir-link").symlink_to(root / "nested", target_is_directory=True)
            for relative in (
                "nested",
                "link.json",
                "dir-link/owner.json",
                "../owner.json",
            ):
                with self.subTest(relative=relative):
                    self.assertEqual(
                        compatibility._read_artifact(root, Path(relative), 4096),
                        (None, "unsafe_path"),
                    )

    def test_missing_regular_file_has_a_distinct_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            result = compatibility._read_artifact(
                Path(directory), Path("absent.json"), 4096
            )
        self.assertEqual(result, (None, "artifact_missing"))

    def test_nested_read_releases_each_owned_descriptor(self):
        original_open, original_close = os.open, os.close
        owned = set()

        def tracked_open(*args, **kwargs):
            descriptor = original_open(*args, **kwargs)
            self.assertNotIn(descriptor, owned)
            owned.add(descriptor)
            return descriptor

        def tracked_close(descriptor):
            self.assertIn(descriptor, owned)
            owned.remove(descriptor)
            original_close(descriptor)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one" / "two").mkdir(parents=True)
            (root / "one" / "two" / "owner.json").write_bytes(b"{}")
            with (
                patch.object(compatibility.os, "open", tracked_open),
                patch.object(compatibility.os, "close", tracked_close),
            ):
                result = compatibility._read_artifact(
                    root, Path("one/two/owner.json"), 4096
                )
                self.assertEqual(owned, set())
        self.assertEqual(result, (b"{}", None))

    def test_same_size_rewrite_during_read_is_refused(self):
        original_read = os.read
        rewrote = False
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "owner.json"
            source.write_bytes(b'{"value":1}')

            def rewrite_after_read(descriptor, count):
                nonlocal rewrote
                chunk = original_read(descriptor, count)
                if chunk and not rewrote:
                    rewrote = True
                    source.write_bytes(b'{"value":2}')
                return chunk

            with patch.object(compatibility.os, "read", rewrite_after_read):
                result = compatibility._read_artifact(root, Path("owner.json"), 4096)
        self.assertTrue(rewrote)
        self.assertEqual(result, (None, "artifact_changed_during_read"))

    def test_manifest_same_size_rewrite_during_read_is_refused(self):
        original_read = os.read
        rewrote = False
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "manifest.json"
            source.write_bytes(b'{"value":1}')

            def rewrite_after_read(descriptor, count):
                nonlocal rewrote
                chunk = original_read(descriptor, count)
                if chunk and not rewrote:
                    rewrote = True
                    source.write_bytes(b'{"value":2}')
                return chunk

            with patch.object(compatibility.os, "read", rewrite_after_read):
                with self.assertRaises(
                    compatibility.CompatibilityInputError
                ) as failure:
                    compatibility.load_manifest(source)
        self.assertEqual(failure.exception.code, "manifest_changed_during_read")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes require a POSIX host")
    def test_manifest_named_pipe_refuses_before_the_owned_child_deadline(self):
        child = """
import sys
from pathlib import Path
from agent_proof.compatibility import CompatibilityInputError, load_manifest
try:
    load_manifest(Path(sys.argv[1]) / 'manifest.json')
except CompatibilityInputError as error:
    print(error.code)
"""
        with tempfile.TemporaryDirectory() as directory:
            os.mkfifo(Path(directory) / "manifest.json")
            try:
                result = subprocess.run(
                    [sys.executable, "-c", child, directory],
                    capture_output=True,
                    text=True,
                    timeout=2,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                self.fail("named-pipe manifest blocked instead of refusing")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "unsafe_path")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes require a POSIX host")
    def test_named_pipe_refuses_before_the_owned_child_deadline(self):
        child = (
            "import json,sys; from pathlib import Path; "
            "from agent_proof.compatibility import _read_artifact; "
            'print(json.dumps(_read_artifact(Path(sys.argv[1]), Path("owner.json"), 4096)))'
        )
        with tempfile.TemporaryDirectory() as directory:
            os.mkfifo(Path(directory) / "owner.json")
            try:
                result = subprocess.run(
                    [sys.executable, "-c", child, directory],
                    capture_output=True,
                    text=True,
                    timeout=2,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                self.fail("named-pipe input blocked instead of refusing")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [None, "unsafe_path"])


if __name__ == "__main__":
    unittest.main()
