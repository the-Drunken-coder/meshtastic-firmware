#!/usr/bin/env python3
"""Build the idle-on-boot W12 diagnostic with the project's pinned RadioLib."""

import argparse
import hashlib
import json
import shutil
import subprocess
import urllib.request
import zipfile
from pathlib import Path

DRIVER_REVISION = "510e00cfb05bbc3c2b7b524262785454944adb6e"
DRIVER_ARCHIVE_SHA256 = (
    "9c74664d8fec577a97d57674b92addb01ab24ccc84ac9492be50974eacfe5626"
)
FQBN = "esp32:esp32:esp32s3:CDCOnBoot=cdc,USBMode=hwcdc,FlashSize=16M,PartitionScheme=app3M_fat9M_16MB,PSRAM=opi"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arduino-cli", default="arduino-cli")
    parser.add_argument("--config-file", type=Path, required=True)
    parser.add_argument("--ctags-path", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    snapshots = [output / name for name in ("driver", "source", "build")]
    existing = [path for path in snapshots if path.exists()]
    if existing:
        names = ", ".join(str(path) for path in existing)
        raise RuntimeError(f"output contains pre-existing build snapshots: {names}")
    archive = output / "radiolib.zip"
    if not archive.exists():
        urllib.request.urlretrieve(  # nosec B310: the URL is a fixed HTTPS GitHub commit archive.
            f"https://github.com/jgromes/RadioLib/archive/{DRIVER_REVISION}.zip",
            archive,
        )
    if digest(archive) != DRIVER_ARCHIVE_SHA256:
        raise RuntimeError("RadioLib archive checksum does not match the pinned driver")
    driver = output / "driver"
    driver.mkdir()
    with zipfile.ZipFile(archive) as source:
        source.extractall(driver)
    library = output / "driver" / f"RadioLib-{DRIVER_REVISION}"
    sketch = output / "source" / "W12_FLRC_Profile"
    shutil.copytree(Path(__file__).resolve().parent / "W12_FLRC_Profile", sketch)
    command = [
        args.arduino_cli,
        "compile",
        "--config-file",
        str(args.config_file.resolve()),
        "--fqbn",
        FQBN,
        "--library",
        str(library),
        "--build-path",
        str(output / "build"),
    ]
    if args.ctags_path:
        command.extend(
            [
                "--build-property",
                f"runtime.tools.ctags.path={args.ctags_path.resolve()}",
            ]
        )
    command.append(str(sketch))
    subprocess.run(command, check=True)
    binary = output / "build" / "W12_FLRC_Profile.ino.bin"
    manifest = {
        "driver_revision": DRIVER_REVISION,
        "driver_archive_sha256": digest(archive),
        "fqbn": FQBN,
        "compile_command": command,
        "source_sha256": digest(sketch / "W12_FLRC_Profile.ino"),
        "partitions_sha256": digest(sketch / "partitions.csv"),
        "binary_sha256": digest(binary),
        "binary": str(binary),
        "arduino_cli": subprocess.check_output(
            [args.arduino_cli, "version"], text=True
        ).strip(),
    }
    (output / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
