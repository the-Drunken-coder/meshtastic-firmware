#!/usr/bin/env python3
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
PATCHER_PATH = HERE / "apply_lr2021_patch.py"
spec = importlib.util.spec_from_file_location("apply_lr2021_patch", PATCHER_PATH)
assert spec and spec.loader
patcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patcher)


class ApplyLr2021PatchTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="lr2021-patch-test-"))
        self.radiolib_root = self.temp_dir / "RadioLib"
        source_path = self.radiolib_root / patcher.SOURCE_RELATIVE_PATH
        source_path.parent.mkdir(parents=True)
        self.original_source = (
            b"prefix\n"
            + patcher.OLD_STATUS_BLOCK.encode()
            + b"middle\n"
            + patcher.OLD_LENGTH_BLOCK.encode()
            + patcher.OLD_CLEANUP_BLOCK.encode()
            + b"suffix\n"
        )
        self.patched_source = self.original_source.replace(
            patcher.OLD_STATUS_BLOCK.encode(), patcher.NEW_STATUS_BLOCK.encode(), 1
        ).replace(patcher.OLD_LENGTH_BLOCK.encode(), patcher.NEW_LENGTH_BLOCK.encode(), 1).replace(
            patcher.OLD_CLEANUP_BLOCK.encode(), patcher.NEW_CLEANUP_BLOCK.encode(), 1
        )
        source_path.write_bytes(self.original_source)
        self.hashes = patch.object(
            patcher,
            "ORIGINAL_SHA256",
            patcher.sha256_bytes(self.original_source),
        )
        self.hashes.start()
        self.patched_hash = patch.object(
            patcher,
            "PATCHED_SHA256",
            patcher.sha256_bytes(self.patched_source),
        )
        self.patched_hash.start()
        self.addCleanup(self.hashes.stop)
        self.addCleanup(self.patched_hash.stop)
        (self.radiolib_root / ".piopm").write_text(
            json.dumps(
                {
                    "type": "library",
                    "name": "RadioLib",
                    "version": patcher.RADIOLIB_VERSION,
                    "spec": {"uri": patcher.RADIOLIB_URI},
                }
            )
        )
        (self.radiolib_root / "library.json").write_text(
            json.dumps({"name": "RadioLib", "version": patcher.RADIOLIB_VERSION})
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_original_is_patched_and_second_run_is_idempotent(self):
        self.assertEqual(patcher.ORIGINAL_SHA256, patcher.sha256(self.radiolib_root / patcher.SOURCE_RELATIVE_PATH))
        self.assertEqual("patched", patcher.apply_patch(self.radiolib_root))
        source_path = self.radiolib_root / patcher.SOURCE_RELATIVE_PATH
        patched_source = source_path.read_bytes()
        self.assertEqual(self.patched_source, patched_source)
        self.assertEqual(patcher.PATCHED_SHA256, patcher.sha256(source_path))
        self.assertEqual("already-patched", patcher.apply_patch(self.radiolib_root))
        self.assertEqual(patched_source, source_path.read_bytes())

    def test_unknown_source_hash_fails_without_writing(self):
        source_path = self.radiolib_root / patcher.SOURCE_RELATIVE_PATH
        source_path.write_bytes(source_path.read_bytes() + b"\n")
        before = source_path.read_bytes()
        with self.assertRaises(patcher.PatchError):
            patcher.apply_patch(self.radiolib_root)
        self.assertEqual(before, source_path.read_bytes())

    def test_unexpected_patch_bytes_fail_before_writing(self):
        source_path = self.radiolib_root / patcher.SOURCE_RELATIVE_PATH
        with patch.object(patcher, "PATCHED_SHA256", "unexpected"):
            before = source_path.read_bytes()
            with self.assertRaises(patcher.PatchError):
                patcher.apply_patch(self.radiolib_root)
            self.assertEqual(before, source_path.read_bytes())

    def test_unknown_dependency_pin_fails(self):
        metadata_path = self.radiolib_root / ".piopm"
        metadata = json.loads(metadata_path.read_text())
        metadata["spec"]["uri"] = "https://example.invalid/RadioLib.zip"
        metadata_path.write_text(json.dumps(metadata))
        with self.assertRaises(patcher.PatchError):
            patcher.apply_patch(self.radiolib_root)


if __name__ == "__main__":
    unittest.main()
