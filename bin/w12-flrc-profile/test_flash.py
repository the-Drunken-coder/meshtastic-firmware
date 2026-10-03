#!/usr/bin/env python3
"""Regression tests for OTA preservation and fail-closed flash evidence."""

import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import flash  # noqa: E402


def ota_entry(sequence: int, state: int, crc: int | None = None) -> bytes:
    entry = bytearray(b"\xff" * 32)
    struct.pack_into("<I", entry, 0, sequence)
    struct.pack_into("<I", entry, flash.OTA_STATE_OFFSET, state)
    struct.pack_into(
        "<I",
        entry,
        flash.OTA_CRC_OFFSET,
        flash.ota_crc(sequence) if crc is None else crc,
    )
    return bytes(entry)


def ota_data(*entries: bytes) -> bytes:
    data = bytearray(b"\xff" * 0x10000)
    for offset, entry in zip(flash.OTA_COPY_OFFSETS, entries, strict=False):
        data[offset : offset + 32] = entry
    return bytes(data)


class OtaMetadataTests(unittest.TestCase):
    def test_known_seq_one_crc_selects_app0(self) -> None:
        self.assertEqual(flash.ota_crc(1), 0x4743989A)
        selected = flash.select_ota_entry(
            ota_data(ota_entry(1, flash.OTA_STATE_UNDEFINED), ota_entry(0, 0))
        )
        self.assertEqual(selected[1:3], (1, flash.OTA_STATE_UNDEFINED))

    def test_corrupt_crc_has_no_valid_entry(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "no valid OTA"):
            flash.select_ota_entry(ota_data(ota_entry(1, flash.OTA_STATE_VALID, 0)))

    def test_unconfirmed_states_are_rejected(self) -> None:
        for state in (0, 1, 5):
            with self.subTest(state=state), self.assertRaisesRegex(
                RuntimeError, "not confirmed"
            ):
                flash.select_ota_entry(ota_data(ota_entry(1, state)))

    def test_bootloader_invalid_states_are_not_valid_entries(self) -> None:
        for state in (3, 4):
            with self.subTest(state=state), self.assertRaisesRegex(
                RuntimeError, "no valid OTA"
            ):
                flash.select_ota_entry(ota_data(ota_entry(1, state)))

    def test_stale_sequence_is_rejected(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "no valid OTA"):
            flash.select_ota_entry(
                ota_data(ota_entry(0xFFFFFFFF, flash.OTA_STATE_UNDEFINED))
            )

    def test_highest_valid_even_sequence_rejects_app1(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "app0"):
            flash.select_ota_entry(
                ota_data(
                    ota_entry(1, flash.OTA_STATE_VALID),
                    ota_entry(2, flash.OTA_STATE_UNDEFINED),
                )
            )

    def test_newer_unconfirmed_entry_cannot_be_ignored(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "not confirmed"):
            flash.select_ota_entry(
                ota_data(
                    ota_entry(1, flash.OTA_STATE_UNDEFINED),
                    ota_entry(2, 0),
                )
            )


class FlashManifestTests(unittest.TestCase):
    def test_write_failure_persists_unverified_manifest(self) -> None:
        binary = b"\xe9" + b"diagnostic"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary_path = root / "profile.bin"
            binary_path.write_bytes(binary)
            output = root / "flash"
            flash_data = bytearray(b"\xff" * 0x1000000)
            for index, (ptype, subtype, offset, size) in enumerate(
                (
                    (1, 2, 0x9000, 0x5000),
                    (1, 0, 0xE000, 0x2000),
                    (0, 16, 0x10000, 0x300000),
                    (0, 17, 0x310000, 0x300000),
                    (1, 130, 0x610000, 0x9E0000),
                    (1, 3, 0xFF0000, 0x10000),
                )
            ):
                struct.pack_into(
                    "<HBBII16sI",
                    flash_data,
                    0x8000 + index * 32,
                    0x50AA,
                    ptype,
                    subtype,
                    offset,
                    size,
                    b"\0" * 16,
                    0,
                )
            flash_data[0xE000 : 0xE000 + 32] = ota_entry(1, flash.OTA_STATE_UNDEFINED)

            def run(command: list[str], check: bool) -> None:
                if "read-flash" in command:
                    Path(command[-1]).write_bytes(flash_data)
                else:
                    raise RuntimeError("simulated write failure")

            argv = [
                "flash.py",
                "--identity",
                "test-identity",
                "--binary",
                str(binary_path),
                "--esptool",
                "esptool",
                "--output",
                str(output),
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(flash.shutil, "which", return_value="/bin/esptool"),
                mock.patch.object(flash.subprocess, "run", side_effect=run),
                self.assertRaisesRegex(RuntimeError, "simulated write failure"),
            ):
                flash.main()

            manifest = json.loads((output / "flash-manifest.json").read_text())
            self.assertEqual(manifest["status"], "failed")
            self.assertEqual(manifest["phase"], "write_started")
            self.assertFalse(manifest["write_verified"])
            self.assertEqual(manifest["ota_selected_sequence"], 1)
            self.assertEqual(manifest["failure"]["type"], "RuntimeError")


if __name__ == "__main__":
    unittest.main()
