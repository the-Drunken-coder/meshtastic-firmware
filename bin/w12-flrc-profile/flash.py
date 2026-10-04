#!/usr/bin/env python3
"""Back up one identity-selected W12, then update its application partition only."""

import argparse
import datetime as dt
import hashlib
import json
import shutil
import struct
import subprocess
import zlib
from pathlib import Path

OTA_COPY_OFFSETS = (0xE000, 0xF000)
OTA_STATE_OFFSET = 24
OTA_CRC_OFFSET = 28
OTA_STATE_VALID = 2
OTA_STATE_UNDEFINED = 0xFFFFFFFF
OTA_STATE_ALLOWED = (OTA_STATE_VALID, OTA_STATE_UNDEFINED)


def ota_crc(sequence: int) -> int:
    # ESP-IDF v5.4 bootloader_common_ota_select_crc seeds esp_rom_crc32_le
    # with UINT32_MAX and covers only the four ota_seq bytes.
    # Source: ESP-IDF v5.4 bootloader_common_loader.c,
    # components/bootloader_support/src.
    return zlib.crc32(struct.pack("<I", sequence), 0xFFFFFFFF)


def ota_entries(data: bytes) -> list[tuple[int, int, int, int]]:
    return [
        (
            offset,
            struct.unpack_from("<I", data, offset)[0],
            struct.unpack_from("<I", data, offset + OTA_STATE_OFFSET)[0],
            struct.unpack_from("<I", data, offset + OTA_CRC_OFFSET)[0],
        )
        for offset in OTA_COPY_OFFSETS
    ]


def select_ota_entry(data: bytes) -> tuple[int, int, int, int]:
    valid = [
        entry
        for entry in ota_entries(data)
        if entry[1] != 0xFFFFFFFF
        and entry[2] not in (3, 4)
        and entry[3] == ota_crc(entry[1])
    ]
    if not valid:
        raise RuntimeError("no valid OTA metadata entry")
    selected = max(valid, key=lambda entry: entry[1])
    if selected[1] == 0 or selected[2] not in OTA_STATE_ALLOWED:
        raise RuntimeError("selected OTA metadata is not confirmed")
    if (selected[1] - 1) % 2 != 0:
        raise RuntimeError("app0 is not the selected OTA slot")
    return selected


def write_manifest(path: Path, manifest: dict) -> None:
    path.write_text(json.dumps(manifest, indent=2) + "\n")


def set_phase(path: Path, manifest: dict, phase: str) -> None:
    manifest["phase"] = phase
    write_manifest(path, manifest)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--identity", required=True, help="USB serial number, e.g. 44:B1:76:AE:19:14"
    )
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument(
        "--esptool",
        default="esptool",
        help="esptool executable, e.g. /opt/homebrew/bin/esptool",
    )
    parser.add_argument(
        "--output", type=Path, required=True, help="new private backup directory"
    )
    args = parser.parse_args()
    binary = args.binary.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    manifest_path = output / "flash-manifest.json"
    manifest = {
        "utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "identity": args.identity,
        "port_filter": f"serial={args.identity}",
        "binary": str(binary),
        "output": str(output),
        "status": "in_progress",
        "phase": "created",
        "write_verified": False,
    }
    write_manifest(manifest_path, manifest)
    backup = output / "before-16mb.bin"
    try:
        esptool = shutil.which(args.esptool)
        if esptool is None:
            raise RuntimeError(f"esptool executable not found: {args.esptool}")
        if binary.stat().st_size > 0x300000 or binary.read_bytes()[:1] != b"\xe9":
            raise RuntimeError("expected an ESP32 application image of at most 3 MiB")
        manifest["esptool"] = esptool
        manifest["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        common = [
            esptool,
            "--chip",
            "esp32s3",
            "--port-filter",
            f"serial={args.identity}",
            "--baud",
            "921600",
        ]
        set_phase(manifest_path, manifest, "backup_started")
        subprocess.run(
            common
            + [
                "--before",
                "default-reset",
                "--after",
                "no-reset",
                "read-flash",
                "0",
                "0x1000000",
                str(backup),
            ],
            check=True,
        )
        backup.chmod(0o600)
        data = backup.read_bytes()
        if len(data) != 0x1000000:
            raise RuntimeError("incomplete flash backup")
        manifest["backup"] = str(backup)
        manifest["backup_sha256"] = hashlib.sha256(data).hexdigest()
        set_phase(manifest_path, manifest, "backup_verified")
        partitions = [
            struct.unpack("<HBBII16sI", data[offset : offset + 32])
            for offset in range(0x8000, 0x80C0, 32)
        ]
        expected = [
            (1, 2, 0x9000, 0x5000),
            (1, 0, 0xE000, 0x2000),
            (0, 16, 0x10000, 0x300000),
            (0, 17, 0x310000, 0x300000),
            (1, 130, 0x610000, 0x9E0000),
            (1, 3, 0xFF0000, 0x10000),
        ]
        if (
            any(row[0] != 0x50AA for row in partitions)
            or [row[1:5] for row in partitions] != expected
        ):
            raise RuntimeError(
                "partition layout differs from the preserved W12 survey layout"
            )
        selected = select_ota_entry(data)
        manifest["ota_selected_sequence"] = selected[1]
        manifest["ota_selected_state"] = selected[2]
        manifest["write_offset"] = 0x10000
        manifest["preserved"] = [
            "bootloader",
            "partition table",
            "NVS",
            "OTA metadata",
            "app1",
            "filesystem",
            "coredump",
        ]
        set_phase(manifest_path, manifest, "metadata_validated")
        set_phase(manifest_path, manifest, "write_started")
        subprocess.run(
            common
            + [
                "--before",
                "default-reset",
                "--after",
                "watchdog-reset",
                "write-flash",
                "--flash-mode",
                "keep",
                "--flash-freq",
                "keep",
                "--flash-size",
                "keep",
                "0x10000",
                str(binary),
            ],
            check=True,
        )
        manifest["status"] = "complete"
        manifest["phase"] = "complete"
        manifest["write_verified"] = True
        write_manifest(manifest_path, manifest)
    except Exception as error:
        manifest["status"] = "failed"
        manifest["write_verified"] = False
        manifest["failure"] = {
            "type": type(error).__name__,
            "message": str(error),
        }
        write_manifest(manifest_path, manifest)
        raise


if __name__ == "__main__":
    main()
