#!/usr/bin/env python3

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
PATCHER_PATH = HERE / "apply_lr2021_patch.py"
spec = importlib.util.spec_from_file_location("atomic_apply_lr2021_patch", PATCHER_PATH)
assert spec and spec.loader
patcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patcher)


class ApplyAtomicLr2021PatchTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="lr2021-atomic-patch-test-")
        self.radiolib_root = Path(self.temp_dir.name) / "RadioLib"
        source_dir = self.radiolib_root / patcher.SOURCE_RELATIVE_PATH.parent
        source_dir.mkdir(parents=True)
        self.cpp_path = self.radiolib_root / patcher.SOURCE_RELATIVE_PATH
        self.header_path = self.radiolib_root / patcher.HEADER_RELATIVE_PATH
        dependency = Path(os.environ.get("MESHTASTIC_RADIOLIB_TEST_ROOT", HERE.parent / ".pio/libdeps/native/RadioLib"))
        patcher.verify_dependency_pin(dependency)
        cpp = (dependency / patcher.SOURCE_RELATIVE_PATH).read_bytes()
        header = (dependency / patcher.HEADER_RELATIVE_PATH).read_bytes()
        state = patcher._pair_state(patcher.sha256_bytes(cpp), patcher.sha256_bytes(header))
        if state == "atomic":
            cpp = patcher._apply_unified_patch(cpp, patcher._API_CPP_PATCH, reverse=True)
            header = patcher._apply_unified_patch(header, patcher._API_HEADER_PATCH, reverse=True)
            state = "checked_cpp_original_header"
        if state == "checked_cpp_original_header":
            cpp = patcher._apply_unified_patch(cpp, patcher._CORRECTNESS_PATCH, reverse=True)
        self.original_cpp = cpp
        self.original_header = header
        self.checked_cpp = patcher._apply_unified_patch(cpp, patcher._CORRECTNESS_PATCH)
        self.atomic_cpp = patcher._apply_unified_patch(self.checked_cpp, patcher._API_CPP_PATCH)
        self.atomic_header = patcher._apply_unified_patch(header, patcher._API_HEADER_PATCH)
        self._write_pair(self.original_cpp, self.original_header)
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
        self.temp_dir.cleanup()

    def _write_pair(self, cpp: bytes, header: bytes):
        self.cpp_path.write_bytes(cpp)
        self.header_path.write_bytes(header)

    def _pair_bytes(self):
        return self.cpp_path.read_bytes(), self.header_path.read_bytes()

    def test_installed_pair_round_trips_full_pinned_sources(self):
        self.assertEqual(patcher.ORIGINAL_SHA256, patcher.sha256_bytes(self.original_cpp))
        self.assertEqual(patcher.CHECKED_CPP_SHA256, patcher.sha256_bytes(self.checked_cpp))
        self.assertEqual(patcher.ORIGINAL_HEADER_SHA256, patcher.sha256_bytes(self.original_header))
        self.assertEqual(patcher.PATCHED_SHA256, patcher.sha256_bytes(self.atomic_cpp))
        self.assertEqual(patcher.PATCHED_HEADER_SHA256, patcher.sha256_bytes(self.atomic_header))
        self.assertGreater(len(self.original_cpp), 30000)
        self.assertGreater(len(self.original_header), 20000)

    def test_original_pair_is_patched_and_second_run_is_idempotent(self):
        self.assertEqual("patched", patcher.apply_patch(self.radiolib_root))
        self.assertEqual((self.atomic_cpp, self.atomic_header), self._pair_bytes())
        self.assertEqual("already-patched", patcher.apply_patch(self.radiolib_root))
        self.assertEqual((self.atomic_cpp, self.atomic_header), self._pair_bytes())

    def test_existing_checked_cpp_with_original_header_is_accepted(self):
        self._write_pair(self.checked_cpp, self.original_header)
        self.assertEqual("patched", patcher.apply_patch(self.radiolib_root))
        self.assertEqual((self.atomic_cpp, self.atomic_header), self._pair_bytes())

    def test_mixed_or_unknown_pair_fails_without_writing(self):
        pairs = (
            (self.original_cpp, self.atomic_header),
            (self.checked_cpp, self.atomic_header),
            (self.atomic_cpp, self.original_header),
            (self.original_cpp + b"\n", self.original_header),
            (self.original_cpp, self.original_header + b"\n"),
        )
        for cpp, header in pairs:
            with self.subTest(cpp=patcher.sha256_bytes(cpp), header=patcher.sha256_bytes(header)):
                self._write_pair(cpp, header)
                before = self._pair_bytes()
                with self.assertRaises(patcher.PatchError):
                    patcher.apply_patch(self.radiolib_root)
                self.assertEqual(before, self._pair_bytes())

    def test_missing_header_fails_without_writing(self):
        self.header_path.unlink()
        before = self.cpp_path.read_bytes()
        with self.assertRaises(patcher.PatchError):
            patcher.apply_patch(self.radiolib_root)
        self.assertEqual(before, self.cpp_path.read_bytes())
        self.assertFalse(self.header_path.exists())

    def test_unexpected_generated_cpp_hash_fails_before_either_write(self):
        before = self._pair_bytes()
        with patch.object(patcher, "PATCHED_SHA256", "unexpected-cpp-hash"):
            with self.assertRaises(patcher.PatchError):
                patcher.apply_patch(self.radiolib_root)
        self.assertEqual(before, self._pair_bytes())

    def test_unexpected_generated_header_hash_fails_before_either_write(self):
        before = self._pair_bytes()
        with patch.object(patcher, "PATCHED_HEADER_SHA256", "unexpected-header-hash"):
            with self.assertRaises(patcher.PatchError):
                patcher.apply_patch(self.radiolib_root)
        self.assertEqual(before, self._pair_bytes())

    def test_metadata_pin_mismatch_fails_without_writing(self):
        metadata_path = self.radiolib_root / ".piopm"
        metadata = json.loads(metadata_path.read_text())
        metadata["spec"]["uri"] = "https://example.invalid/RadioLib.zip"
        metadata_path.write_text(json.dumps(metadata))
        before = self._pair_bytes()
        with self.assertRaises(patcher.PatchError):
            patcher.apply_patch(self.radiolib_root)
        self.assertEqual(before, self._pair_bytes())

    def test_bad_manifest_version_fails_without_writing(self):
        manifest_path = self.radiolib_root / "library.json"
        manifest_path.write_text(json.dumps({"name": "RadioLib", "version": "7.7.0"}))
        before = self._pair_bytes()
        with self.assertRaises(patcher.PatchError):
            patcher.apply_patch(self.radiolib_root)
        self.assertEqual(before, self._pair_bytes())


if __name__ == "__main__":
    unittest.main()
