#!/usr/bin/env python3
"""Apply the pinned LR2021 correctness and finite-FLRC driver patch as a pair."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
PATCH_DIRECTORY = HERE / "lr2021-patches"
MANIFEST_PATH = PATCH_DIRECTORY / "manifest.json"


class PatchError(RuntimeError):
    """Raised when the dependency, source pair, or patch inputs are not pinned."""


def _load_manifest() -> dict:
    try:
        manifest = json.loads(MANIFEST_PATH.read_text())
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        raise PatchError(f"Atomic LR2021 patch manifest is missing or invalid: {MANIFEST_PATH}") from exc
    try:
        dependency = manifest["dependency"]
        files = manifest["files"]
        states = manifest["states"]
        patches = manifest["patches"]
        if dependency["name"] != "RadioLib":
            raise KeyError("dependency.name")
        for state in ("original", "checked_cpp_original_header", "atomic"):
            states[state]["cpp_sha256"]
            states[state]["header_sha256"]
        files["cpp"]
        files["header"]
        patches["correctness"]
        patches["api_cpp"]
        patches["api_header"]
    except (KeyError, TypeError) as exc:
        raise PatchError(f"Atomic LR2021 patch manifest is incomplete: {MANIFEST_PATH}") from exc
    return manifest


_MANIFEST = _load_manifest()
RADIOLIB_VERSION = _MANIFEST["dependency"]["version"]
RADIOLIB_COMMIT = _MANIFEST["dependency"]["commit"]
RADIOLIB_URI = _MANIFEST["dependency"]["uri"]
SOURCE_RELATIVE_PATH = Path(_MANIFEST["files"]["cpp"])
HEADER_RELATIVE_PATH = Path(_MANIFEST["files"]["header"])
ORIGINAL_SHA256 = _MANIFEST["states"]["original"]["cpp_sha256"]
CHECKED_CPP_SHA256 = _MANIFEST["states"]["checked_cpp_original_header"]["cpp_sha256"]
ORIGINAL_HEADER_SHA256 = _MANIFEST["states"]["original"]["header_sha256"]
PATCHED_SHA256 = _MANIFEST["states"]["atomic"]["cpp_sha256"]
PATCHED_HEADER_SHA256 = _MANIFEST["states"]["atomic"]["header_sha256"]

_CORRECTNESS_PATCH = PATCH_DIRECTORY / _MANIFEST["patches"]["correctness"]
_API_CPP_PATCH = PATCH_DIRECTORY / _MANIFEST["patches"]["api_cpp"]
_API_HEADER_PATCH = PATCH_DIRECTORY / _MANIFEST["patches"]["api_header"]

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


def _pair_state(cpp_hash: str, header_hash: str) -> str:
    if cpp_hash == PATCHED_SHA256 and header_hash == PATCHED_HEADER_SHA256:
        return "atomic"
    if cpp_hash == ORIGINAL_SHA256 and header_hash == ORIGINAL_HEADER_SHA256:
        return "original"
    if cpp_hash == CHECKED_CPP_SHA256 and header_hash == ORIGINAL_HEADER_SHA256:
        return "checked_cpp_original_header"
    raise PatchError(
        "Refusing mixed or unknown LR2021 source pair: "
        f"cpp={cpp_hash}, header={header_hash}"
    )


_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def _patch_hunks(patch_path: Path) -> list[tuple[int, list[str], list[str]]]:
    try:
        lines = patch_path.read_text().splitlines(keepends=True)
    except FileNotFoundError as exc:
        raise PatchError(f"Stored LR2021 patch is missing: {patch_path}") from exc
    hunks: list[tuple[int, list[str], list[str]]] = []
    index = 0
    while index < len(lines) and not lines[index].startswith("@@ "):
        index += 1
    while index < len(lines):
        match = _HUNK_RE.match(lines[index])
        if not match:
            raise PatchError(f"Invalid unified-diff hunk in {patch_path}: {lines[index].rstrip()}")
        old_start = int(match.group(1))
        index += 1
        old_lines: list[str] = []
        new_lines: list[str] = []
        while index < len(lines) and not lines[index].startswith("@@ "):
            line = lines[index]
            if line.startswith("\\ No newline at end of file"):
                index += 1
                continue
            if not line or line[0] not in " +-":
                raise PatchError(f"Invalid unified-diff line in {patch_path}: {line.rstrip()}")
            if line[0] in " -":
                old_lines.append(line[1:])
            if line[0] in " +":
                new_lines.append(line[1:])
            index += 1
        if not old_lines:
            raise PatchError(f"Empty patch hunk in {patch_path}")
        old_count = int(match.group(2) or "1")
        new_count = int(match.group(4) or "1")
        if len(old_lines) != old_count or len(new_lines) != new_count:
            raise PatchError(f"Unified-diff line counts do not match hunk header in {patch_path}")
        hunks.append((old_start, old_lines, new_lines))
    if not hunks:
        raise PatchError(f"Stored LR2021 patch has no hunks: {patch_path}")
    return hunks


def _apply_unified_patch(source: bytes, patch_path: Path, reverse: bool = False) -> bytes:
    text = source.decode("utf-8")
    lines = text.splitlines(keepends=True)
    replacements: list[tuple[int, int, list[str]]] = []
    for old_start, old_lines, new_lines in _patch_hunks(patch_path):
        if reverse:
            old_lines, new_lines = new_lines, old_lines
        matches = [
            index
            for index in range(len(lines) - len(old_lines) + 1)
            if lines[index : index + len(old_lines)] == old_lines
        ]
        if len(matches) != 1:
            raise PatchError(
                f"Patch hunk from {patch_path} matched {len(matches)} times "
                f"(expected one near line {old_start})"
            )
        start = matches[0]
        replacements.append((start, start + len(old_lines), new_lines))
    for start, end, new_lines in reversed(replacements):
        lines[start:end] = new_lines
    return "".join(lines).encode("utf-8")


def _write_pair(source_path: Path, source: bytes, header_path: Path, header: bytes) -> None:
    temporary_paths: list[Path] = []
    replaced: list[tuple[Path, bytes]] = []
    try:
        for destination, data in ((source_path, source), (header_path, header)):
            with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=f".{destination.name}.", delete=False) as temporary:
                temporary.write(data)
                temporary.flush()
                os.fsync(temporary.fileno())
                temporary_paths.append(Path(temporary.name))
        for temporary, destination in zip(temporary_paths, (source_path, header_path)):
            replaced.append((destination, destination.read_bytes()))
            os.replace(temporary, destination)
    except Exception:
        for destination, original in replaced:
            destination.write_bytes(original)
        raise
    finally:
        for temporary in temporary_paths:
            temporary.unlink(missing_ok=True)


def apply_patch(radiolib_root: Path) -> str:
    """Patch the pinned LR2021 source/header pair and return its transition."""

    radiolib_root = radiolib_root.resolve()
    verify_dependency_pin(radiolib_root)
    source_path = radiolib_root / SOURCE_RELATIVE_PATH
    header_path = radiolib_root / HEADER_RELATIVE_PATH
    if not source_path.is_file() or not header_path.is_file():
        raise PatchError(f"Pinned LR2021 source pair is incomplete under {radiolib_root}")

    source = source_path.read_bytes()
    header = header_path.read_bytes()
    state = _pair_state(sha256_bytes(source), sha256_bytes(header))
    if state == "atomic":
        return "already-patched"

    generated_source = source
    if state == "original":
        generated_source = _apply_unified_patch(generated_source, _CORRECTNESS_PATCH)
        if sha256_bytes(generated_source) != CHECKED_CPP_SHA256:
            raise PatchError("Correctness patch produced an unexpected checked LR2021.cpp hash")
    generated_source = _apply_unified_patch(generated_source, _API_CPP_PATCH)
    generated_header = _apply_unified_patch(header, _API_HEADER_PATCH)

    # Both outputs are validated before either destination is replaced.
    if sha256_bytes(generated_source) != PATCHED_SHA256:
        raise PatchError("Finite-FLRC patch produced an unexpected LR2021.cpp hash")
    if sha256_bytes(generated_header) != PATCHED_HEADER_SHA256:
        raise PatchError("Finite-FLRC patch produced an unexpected LR2021.h hash")
    _write_pair(source_path, generated_source, header_path, generated_header)
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
