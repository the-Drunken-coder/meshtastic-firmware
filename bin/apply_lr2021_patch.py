#!/usr/bin/env python3
"""Apply the pinned LR2021 readData correctness patch once per dependency tree."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


RADIOLIB_VERSION = "7.7.1"
RADIOLIB_COMMIT = "510e00cfb05bbc3c2b7b524262785454944adb6e"
RADIOLIB_URI = f"https://github.com/jgromes/RadioLib/archive/{RADIOLIB_COMMIT}.zip"
SOURCE_RELATIVE_PATH = Path("src/modules/LR2021/LR2021.cpp")
ORIGINAL_SHA256 = "7662c16d8a2e4d10cd1fee7d5910a85a5a246d79f3c76586195af16a2fbbbfa9"
PATCHED_SHA256 = "12bc9aa547d24b0b311fda8e231bff3e8f1177bf8398160238f9e836f2cae701"

OLD_STATUS_BLOCK = """  // check integrity CRC
  uint32_t irq = getIrqStatus();
"""
NEW_STATUS_BLOCK = """  auto finishRead = [this](int16_t result) {
    const int16_t fifoState = clearRxFifo();
    const int16_t irqState = clearIrqState(RADIOLIB_LR2021_IRQ_ALL);
    if(result != RADIOLIB_ERR_NONE) {
      return(result);
    }
    if(fifoState != RADIOLIB_ERR_NONE) {
      return(fifoState);
    }
    return(irqState);
  };

  // check integrity CRC
  uint8_t stat1 = 0;
  uint8_t stat2 = 0;
  uint32_t irq = 0;
  Module::BitWidth_t statusWidth = this->mod->spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS];
  this->mod->spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS] = Module::BITS_0;
  // With no status prefix, getStatus() returns the status bytes and IRQ flags in one transfer;
  // SPItransferStream routes stat1 through the existing parseStatusCb.
  state = getStatus(&stat1, &stat2, &irq);
  this->mod->spiConfig.widths[RADIOLIB_MODULE_SPI_WIDTH_STATUS] = statusWidth;
  if(state != RADIOLIB_ERR_NONE) {
    return(finishRead(state));
  }

"""
OLD_LENGTH_BLOCK = """  // get packet length
  size_t length = getPacketLength();
"""
NEW_LENGTH_BLOCK = """  // get packet length
  size_t length = this->implicitLen;
  if((modem != RADIOLIB_LR2021_PACKET_TYPE_LORA) ||
     (this->headerType != RADIOLIB_LRXXXX_LORA_HEADER_IMPLICIT)) {
    uint16_t packetLength = 0;
    state = getRxPktLength(&packetLength);
    if(state != RADIOLIB_ERR_NONE) {
      return(finishRead(state));
    }
    length = (size_t)packetLength;
  }
  // Meshtastic passes FLRC's pre-queried expected length here. Reject a shorter
  // radio-reported packet, including zero, while retaining prefix reads when actual > requested.
  // Keep len == 0 and LoRa implicit mode's existing compatibility semantics.
  if((modem == RADIOLIB_LR2021_PACKET_TYPE_FLRC) && (len != 0) && (length < len)) {
    return(finishRead(RADIOLIB_ERR_PACKET_TOO_SHORT));
  }
"""
OLD_CLEANUP_BLOCK = """  // read packet data
  state = readRadioRxFifo(data, length);
  RADIOLIB_ASSERT(state);

  // clear the Rx buffer
  state = clearRxFifo();
  RADIOLIB_ASSERT(state);

  // clear interrupt flags
  state = clearIrqState(RADIOLIB_LR2021_IRQ_ALL);

  // check if CRC failed - this is done after reading data to give user the option to keep them
  RADIOLIB_ASSERT(crcState);

  return(state);
"""
NEW_CLEANUP_BLOCK = """  // read packet data
  state = readRadioRxFifo(data, length);
  if(state != RADIOLIB_ERR_NONE) {
    return(finishRead(state));
  }

  // check if CRC failed - this is done after reading data to give user the option to keep them
  return(finishRead(crcState));
"""


class PatchError(RuntimeError):
    """Raised when the dependency is absent, unpinned, or at an unknown hash."""


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_dependency_pin(radiolib_root: Path) -> None:
    metadata_path = radiolib_root / ".piopm"
    manifest_path = radiolib_root / "library.json"
    try:
        metadata = json.loads(metadata_path.read_text())
        manifest = json.loads(manifest_path.read_text())
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        raise PatchError(f"RadioLib metadata is missing or invalid under {radiolib_root}") from exc

    uri = metadata.get("spec", {}).get("uri")
    version = metadata.get("version")
    manifest_version = manifest.get("version")
    if uri != RADIOLIB_URI or version != RADIOLIB_VERSION or manifest_version != RADIOLIB_VERSION:
        raise PatchError(
            "RadioLib dependency is not the pinned 7.7.1/"
            f"{RADIOLIB_COMMIT} package: uri={uri!r}, version={version!r}, "
            f"manifest_version={manifest_version!r}"
        )


def apply_patch(radiolib_root: Path) -> str:
    """Patch one installed RadioLib tree and return ``patched`` or ``already-patched``."""

    radiolib_root = radiolib_root.resolve()
    verify_dependency_pin(radiolib_root)
    source_path = radiolib_root / SOURCE_RELATIVE_PATH
    if not source_path.is_file():
        raise PatchError(f"Pinned RadioLib source is missing: {source_path}")

    observed_hash = sha256(source_path)
    if observed_hash == PATCHED_SHA256:
        return "already-patched"
    if observed_hash != ORIGINAL_SHA256:
        raise PatchError(
            f"Refusing to patch unknown LR2021.cpp hash {observed_hash}; "
            f"expected {ORIGINAL_SHA256} or {PATCHED_SHA256}"
        )

    source = source_path.read_bytes()
    old_status_block = OLD_STATUS_BLOCK.encode()
    new_status_block = NEW_STATUS_BLOCK.encode()
    old_length_block = OLD_LENGTH_BLOCK.encode()
    new_length_block = NEW_LENGTH_BLOCK.encode()
    old_cleanup_block = OLD_CLEANUP_BLOCK.encode()
    new_cleanup_block = NEW_CLEANUP_BLOCK.encode()
    if (
        source.count(old_status_block) != 1
        or source.count(old_length_block) != 1
        or source.count(old_cleanup_block) != 1
    ):
        raise PatchError("Pinned LR2021.cpp does not contain the expected patch anchors")

    patched = (
        source.replace(old_status_block, new_status_block, 1)
        .replace(old_length_block, new_length_block, 1)
        .replace(old_cleanup_block, new_cleanup_block, 1)
    )
    patched_hash = sha256_bytes(patched)
    if patched_hash != PATCHED_SHA256:
        raise PatchError(f"Patch produced unexpected LR2021.cpp hash {patched_hash}")

    source_path.write_bytes(patched)
    return "patched"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("radiolib_root", type=Path)
    args = parser.parse_args()
    try:
        result = apply_patch(args.radiolib_root)
    except PatchError as exc:
        parser.error(str(exc))
    print(f"RadioLib LR2021 dependency patch: {result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
