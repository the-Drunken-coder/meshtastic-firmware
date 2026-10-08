#!/usr/bin/env python3
"""Collect the frozen board-local public-HAL SPI-yield page (op 11, kind 9).

The page is a diagnostic of the optional SPI-yield hook.  It describes the
requested clock and local transfer timing; it says nothing about RF delivery,
guard margin, collision safety, or radio capacity.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


MAGIC = 0x5731
VERSION = 1
KIND = 9
REPORT_BYTES = 80
CONTROL_BYTES = 32
SNAPSHOT_OP = 11
ENABLE_OP = 12
PUBLIC_HAL_SOURCE = 1
PRIVATE_APP_PORTNUM = 256
TRANSPORT_INTERNAL = 0
TRANSPORT_API = 7
MAX_PENDING_TX = 16
UINT32_MAX = 0xFFFFFFFF
UINT64_MAX = 0xFFFFFFFFFFFFFFFF
REQUESTED_CLOCKS_HZ = frozenset({4_000_000, 8_000_000})
FIRMWARE_PROVENANCE_NAME = "firmware-provenance.json"
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
FLASH_VERIFIED_STATUS = "application_bytes_boot_state_diagnostics_cli_verified"

STATUS_PREPARED = 0x01
STATUS_RUNNING = 0x02
STATUS_COMPLETE = 0x04
STATUS_AVAILABLE = 0x08
STATUS_PENDING = 0x10
STATUS_ACTIVE = 0x20
STATUS_MASK = (
    STATUS_PREPARED
    | STATUS_RUNNING
    | STATUS_COMPLETE
    | STATUS_AVAILABLE
    | STATUS_PENDING
    | STATUS_ACTIVE
)


class BenchmarkError(RuntimeError):
    """A protocol, identity, provenance, health, or collector failure."""


@dataclasses.dataclass(frozen=True)
class SpiYieldReport:
    run_id: int
    source: int
    destination: int
    elapsed_ms: int
    status: int
    pending_tx_count: int
    requested_hz: int
    transfer_count: int
    transferred_bytes: int
    transfer_sum_us: int
    transfer_max_us: int
    yield_count: int
    yield_sum_us: int
    yield_max_us: int
    source_kind: int
    overflow: bool
    raw: bytes = dataclasses.field(repr=False, compare=False, default=b"")

    @property
    def prepared(self) -> bool:
        return bool(self.status & STATUS_PREPARED)

    @property
    def running(self) -> bool:
        return bool(self.status & STATUS_RUNNING)

    @property
    def complete(self) -> bool:
        return bool(self.status & STATUS_COMPLETE)

    @property
    def available(self) -> bool:
        return bool(self.status & STATUS_AVAILABLE)

    @property
    def pending(self) -> bool:
        return bool(self.status & STATUS_PENDING)

    @property
    def active(self) -> bool:
        return bool(self.status & STATUS_ACTIVE)

    @property
    def snapshot_terminal(self) -> bool:
        return (
            self.prepared
            and self.complete
            and not self.running
            and not self.active
            and self.pending_tx_count == 0
            and not self.pending
        )


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _u64(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 8], "little")


def _duration_metric(
    data: bytes, count_offset: int, sum_offset: int, max_offset: int, label: str, overflow: bool
) -> tuple[int, int, int]:
    count = _u32(data, count_offset)
    total = _u64(data, sum_offset)
    maximum = _u32(data, max_offset)
    if count == 0:
        if total or maximum:
            raise ValueError(f"kind 9 {label} has values without samples")
        return 0, 0, 0
    if maximum > total:
        raise ValueError(f"kind 9 {label} maximum exceeds sum")
    if total == UINT64_MAX and not overflow:
        raise ValueError(f"kind 9 {label} sum is saturated without overflow")
    if not overflow and total > count * maximum:
        raise ValueError(f"kind 9 {label} sum exceeds sample bounds")
    return count, total, maximum


def decode_report(data: bytes | bytearray | memoryview) -> SpiYieldReport:
    """Decode one exact 80-byte kind-9 page and reject ambiguous state."""

    raw = bytes(data)
    if len(raw) != REPORT_BYTES:
        raise ValueError(f"kind 9 report must be exactly {REPORT_BYTES} bytes")
    if _u16(raw, 0) != MAGIC or raw[2] != VERSION or raw[3] != KIND:
        raise ValueError("invalid kind 9 report header")
    if any(raw[22:24]) or any(raw[70:]):
        raise ValueError("nonzero reserved kind 9 bytes")

    status = raw[20]
    if status & ~STATUS_MASK:
        raise ValueError("unknown kind 9 status bits")
    pending_count = raw[21]
    if pending_count > MAX_PENDING_TX:
        raise ValueError("invalid kind 9 pending TX count")
    prepared = bool(status & STATUS_PREPARED)
    running = bool(status & STATUS_RUNNING)
    complete = bool(status & STATUS_COMPLETE)
    pending = bool(status & STATUS_PENDING)
    active = bool(status & STATUS_ACTIVE)
    if not prepared or not complete or running:
        raise ValueError("kind 9 snapshot is not frozen and complete")
    if pending != bool(pending_count) or active != (running or pending):
        raise ValueError("kind 9 pending or active status does not match count")
    if pending_count:
        raise ValueError("kind 9 snapshot has pending TX")
    if active:
        raise ValueError("kind 9 snapshot is active")

    requested_hz = _u32(raw, 24)
    if requested_hz not in REQUESTED_CLOCKS_HZ:
        raise ValueError("kind 9 requested clock must be 4 MHz or 8 MHz")
    source_kind = raw[68]
    if source_kind != PUBLIC_HAL_SOURCE:
        raise ValueError("unknown kind 9 timing source")
    overflow = raw[69]
    if overflow > 1:
        raise ValueError("invalid kind 9 overflow flag")
    transfer_count, transfer_sum_us, transfer_max_us = _duration_metric(
        raw, 28, 40, 48, "transfer", bool(overflow)
    )
    yield_count, yield_sum_us, yield_max_us = _duration_metric(
        raw, 52, 56, 64, "yield", bool(overflow)
    )
    transferred_bytes = _u64(raw, 32)
    if not (status & STATUS_AVAILABLE) and any(
        (transfer_count, transferred_bytes, transfer_sum_us, transfer_max_us, yield_count, yield_sum_us, yield_max_us, overflow)
    ):
        raise ValueError("unavailable kind 9 page has metrics")
    return SpiYieldReport(
        run_id=_u32(raw, 4),
        source=_u32(raw, 8),
        destination=_u32(raw, 12),
        elapsed_ms=_u32(raw, 16),
        status=status,
        pending_tx_count=pending_count,
        requested_hz=requested_hz,
        transfer_count=transfer_count,
        transferred_bytes=transferred_bytes,
        transfer_sum_us=transfer_sum_us,
        transfer_max_us=transfer_max_us,
        yield_count=yield_count,
        yield_sum_us=yield_sum_us,
        yield_max_us=yield_max_us,
        source_kind=source_kind,
        overflow=bool(overflow),
        raw=raw,
    )


def _int_field(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"kind 9 {label} is not a nonnegative integer")
    if value > maximum:
        raise ValueError(f"kind 9 {label} exceeds its wire width")
    return value


def report_from_mapping(value: Mapping[str, Any]) -> SpiYieldReport:
    """Convert a captured event mapping through the same wire validator."""

    if not isinstance(value, Mapping):
        raise ValueError("kind 9 response is not a mapping")
    aliases = {
        "run_id": ("run_id", "runId"),
        "source": ("source",),
        "destination": ("destination",),
        "elapsed_ms": ("elapsed_ms", "elapsedMs"),
        "status": ("status", "status_bits"),
        "pending_tx_count": ("pending_tx_count",),
        "requested_hz": ("requested_hz", "requestedHz"),
        "transfer_count": ("transfer_count", "transferCount"),
        "transferred_bytes": ("transferred_bytes", "transferredBytes"),
        "transfer_sum_us": ("transfer_sum_us", "transferSumUs"),
        "transfer_max_us": ("transfer_max_us", "transferMaxUs"),
        "yield_count": ("yield_count", "yieldCount"),
        "yield_sum_us": ("yield_sum_us", "yieldSumUs"),
        "yield_max_us": ("yield_max_us", "yieldMaxUs"),
        "source_kind": ("source_kind", "sourceKind"),
        "overflow": ("overflow",),
    }
    values: dict[str, Any] = {}
    for field, keys in aliases.items():
        key = next((candidate for candidate in keys if candidate in value), None)
        if key is None:
            raise ValueError(f"kind 9 response misses {field}")
        values[field] = value[key]
    widths = {
        "run_id": UINT32_MAX,
        "source": UINT32_MAX,
        "destination": UINT32_MAX,
        "elapsed_ms": UINT32_MAX,
        "status": 0xFF,
        "pending_tx_count": 0xFF,
        "requested_hz": UINT32_MAX,
        "transfer_count": UINT32_MAX,
        "transferred_bytes": UINT64_MAX,
        "transfer_sum_us": UINT64_MAX,
        "transfer_max_us": UINT32_MAX,
        "yield_count": UINT32_MAX,
        "yield_sum_us": UINT64_MAX,
        "yield_max_us": UINT32_MAX,
        "source_kind": 0xFF,
    }
    for field in aliases:
        if field != "overflow":
            values[field] = _int_field(values[field], field, widths[field])
    if not isinstance(values["overflow"], (bool, int)) or int(values["overflow"]) not in (0, 1):
        raise ValueError("kind 9 overflow is not boolean")
    raw = bytearray(REPORT_BYTES)
    raw[0:2] = MAGIC.to_bytes(2, "little")
    raw[2:4] = bytes((VERSION, KIND))
    for offset, field in ((4, "run_id"), (8, "source"), (12, "destination"), (16, "elapsed_ms")):
        raw[offset : offset + 4] = values[field].to_bytes(4, "little")
    raw[20] = values["status"]
    raw[21] = values["pending_tx_count"]
    raw[24:28] = values["requested_hz"].to_bytes(4, "little")
    raw[28:32] = values["transfer_count"].to_bytes(4, "little")
    raw[32:40] = values["transferred_bytes"].to_bytes(8, "little")
    raw[40:48] = values["transfer_sum_us"].to_bytes(8, "little")
    raw[48:52] = values["transfer_max_us"].to_bytes(4, "little")
    raw[52:56] = values["yield_count"].to_bytes(4, "little")
    raw[56:64] = values["yield_sum_us"].to_bytes(8, "little")
    raw[64:68] = values["yield_max_us"].to_bytes(4, "little")
    raw[68] = values["source_kind"]
    raw[69] = int(values["overflow"])
    return decode_report(raw)


def _report_dict(report: SpiYieldReport) -> dict[str, Any]:
    value = dataclasses.asdict(report)
    value.pop("raw", None)
    value["overflow"] = bool(value["overflow"])
    value.update(
        {
            "prepared": report.prepared,
            "running": report.running,
            "complete": report.complete,
            "available": report.available,
            "pending": report.pending,
            "active": report.active,
            "snapshot_terminal": report.snapshot_terminal,
        }
    )
    return value


def evaluate_report(report: SpiYieldReport) -> dict[str, Any]:
    """Classify the page without making a physical or RF claim."""

    reasons: list[str] = []
    if not report.snapshot_terminal:
        reasons.append("spi_yield_snapshot_not_frozen")
    if not report.available:
        reasons.append("spi_yield_unavailable")
    if report.overflow:
        reasons.append("spi_yield_overflow")
    if report.available and (report.transfer_count == 0 or report.transferred_bytes == 0):
        reasons.append("spi_yield_no_transfers")
    return {
        "status": "valid" if not reasons else "invalid",
        "measurement_valid": not reasons,
        "failure_reasons": reasons,
        "scope": "board_local_public_hal_spi_yield",
        "physical_claims": {
            "rf_delivery": False,
            "guard_margin": False,
            "collision_safety": False,
            "throughput_acceptance": False,
            "radio_capacity": False,
        },
        "requested_clock_hz": report.requested_hz,
        "hal_timing_available": report.available,
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_json_file(path: Path, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise BenchmarkError(f"{label} is unreadable") from error
    if not isinstance(value, Mapping):
        raise BenchmarkError(f"{label} is not an object")
    return value


def _verify_source_record(
    run_dir: Path,
    source_records: Mapping[str, Any],
    name: str,
) -> Mapping[str, Any]:
    record = source_records.get(name)
    if not isinstance(record, Mapping):
        raise BenchmarkError(f"firmware provenance is missing source record {name}")
    path_value = record.get("path")
    expected_hash = record.get("sha256")
    if not isinstance(path_value, str) or not path_value:
        raise BenchmarkError(f"firmware provenance source record {name} has no path")
    if not isinstance(expected_hash, str) or not _HEX64.fullmatch(expected_hash):
        raise BenchmarkError(f"firmware provenance source record {name} has an invalid hash")
    path = Path(path_value)
    if not path.is_absolute():
        path = run_dir / path
    path = path.resolve()
    if not path.is_file():
        raise BenchmarkError(f"firmware provenance source file is missing: {path}")
    if _sha256_file(path) != expected_hash:
        raise BenchmarkError(f"firmware provenance source hash changed: {name}")
    return _read_json_file(path, f"firmware provenance source {name}")


def _required_spi_clock_provenance(
    run_dir: Path,
    benchmark: Any | None = None,
) -> dict[str, int]:
    """Read the exact per-board clock contract before opening a session."""

    results_path = Path(run_dir) / "results.json"
    existing = _read_json_file(results_path, "existing run results.json")
    intent = existing.get("intent")
    if not isinstance(intent, Mapping) or intent.get("spi_yield_requested") is not True:
        raise BenchmarkError("SPI-yield collection requires intent.spi_yield_requested=true")
    roles = (intent.get("sender"), intent.get("receiver"))
    if any(not isinstance(role, str) or not role for role in roles):
        raise BenchmarkError("existing run has no SPI-yield board roles")

    provenance_path = Path(run_dir) / FIRMWARE_PROVENANCE_NAME
    provenance = _read_json_file(provenance_path, FIRMWARE_PROVENANCE_NAME)
    result_hash = provenance.get("result_sha256")
    if not isinstance(result_hash, str) or not _HEX64.fullmatch(result_hash):
        raise BenchmarkError("firmware provenance has no valid result_sha256")
    if result_hash != _sha256_file(results_path):
        raise BenchmarkError("firmware provenance result_sha256 does not match results.json")

    benchmark = benchmark or _load_radio_gaps()._load_benchmark()
    identities = getattr(benchmark, "BOARD_IDENTITIES", None)
    if not isinstance(identities, Mapping):
        raise BenchmarkError("benchmark identity map is unavailable")
    before = existing.get("configuration_before")
    if not isinstance(before, Mapping):
        raise BenchmarkError("existing run has no configuration_before records")
    existing_provenance = existing.get("provenance")
    image_hashes = (
        existing_provenance.get("image_hashes")
        if isinstance(existing_provenance, Mapping)
        else None
    )
    if not isinstance(image_hashes, Mapping) or not image_hashes:
        raise BenchmarkError("existing run has no primary image hashes")
    for image_path, image_hash in image_hashes.items():
        if not isinstance(image_path, str) or not isinstance(image_hash, str) or not _HEX64.fullmatch(image_hash):
            raise BenchmarkError("existing primary image provenance is malformed")
    image_hashes_by_role = existing_provenance.get("image_hashes_by_role") if isinstance(existing_provenance, Mapping) else None
    if not isinstance(image_hashes_by_role, Mapping):
        raise BenchmarkError("existing run has no role-bound primary image hashes")

    boards = provenance.get("boards")
    if not isinstance(boards, Mapping):
        raise BenchmarkError("firmware-provenance.json has no board records")
    source_records = provenance.get("source_records")
    if not isinstance(source_records, Mapping):
        raise BenchmarkError("firmware-provenance.json has no source records")

    expected: dict[str, int] = {}
    source_revisions: set[str] = set()
    for role in roles:
        board = boards.get(role)
        if not isinstance(board, Mapping):
            raise BenchmarkError(f"firmware-provenance.json has no {role} board record")
        identity = identities.get(role)
        if (
            not isinstance(identity, tuple)
            or len(identity) != 2
            or board.get("usb_identity") != identity[0]
            or board.get("node_num") != identity[1]
        ):
            raise BenchmarkError(f"{role}: firmware provenance board identity does not match BOARD_IDENTITIES")
        before_row = before.get(role)
        if not isinstance(before_row, Mapping):
            raise BenchmarkError(f"existing run has no {role} configuration_before record")
        if before_row.get("usb_identity") != identity[0] or before_row.get("node_num") != identity[1]:
            raise BenchmarkError(f"{role}: firmware provenance identity does not match configuration_before")

        source_revision = board.get("source_revision")
        if not isinstance(source_revision, str) or not _HEX40.fullmatch(source_revision):
            raise BenchmarkError(f"{role}: firmware provenance source_revision is not lowercase 40-hex")
        source_revisions.add(source_revision)
        application_hash = board.get("application_sha256")
        if not isinstance(application_hash, str) or not _HEX64.fullmatch(application_hash):
            raise BenchmarkError(f"{role}: firmware provenance application_sha256 is malformed")
        role_image = image_hashes_by_role.get(role)
        if not isinstance(role_image, Mapping):
            raise BenchmarkError(f"{role}: primary provenance has no role-bound image")
        role_image_path = role_image.get("path")
        role_image_hash = role_image.get("sha256")
        if (
            not isinstance(role_image_path, str)
            or not role_image_path
            or not isinstance(role_image_hash, str)
            or not _HEX64.fullmatch(role_image_hash)
            or role_image_hash != application_hash
            or image_hashes.get(role_image_path) != role_image_hash
        ):
            raise BenchmarkError(f"{role}: firmware application image is not bound to role-bound primary provenance")

        build = _verify_source_record(Path(run_dir), source_records, f"{role}_build")
        flash = _verify_source_record(
            Path(run_dir),
            source_records,
            f"{role}_flash",
        )
        build_files = build.get("files")
        firmware_file = build_files.get("firmware.bin") if isinstance(build_files, Mapping) else None
        build_hash = firmware_file.get("sha256") if isinstance(firmware_file, Mapping) else None
        if build_hash != application_hash or flash.get("application_sha256") != application_hash:
            raise BenchmarkError(f"{role}: source records do not match application_sha256")
        if build.get("application_source_revision") != source_revision or flash.get("application_source_revision") != source_revision:
            raise BenchmarkError(f"{role}: source records do not match source_revision")
        if (
            flash.get("identity") != identity[0]
            or flash.get("app_only") is not True
            or flash.get("status") != FLASH_VERIFIED_STATUS
        ):
            raise BenchmarkError(f"{role}: flash source record identity/application scope is invalid")
        build_flags = build.get("experimental_flags")
        if not isinstance(build_flags, Mapping):
            raise BenchmarkError(f"{role}: build source record has no experimental_flags")
        build_clock = build_flags.get("requested_spi_hz")
        if (
            isinstance(build_clock, bool)
            or not isinstance(build_clock, int)
            or build_clock not in REQUESTED_CLOCKS_HZ
            or build_clock != board.get("requested_spi_hz")
        ):
            raise BenchmarkError(f"{role}: build source record clock disagrees with board record")
        build_hal_timing = build_flags.get("hal_timing")
        if not (
            build_hal_timing is True
            or (
                isinstance(build_hal_timing, int)
                and not isinstance(build_hal_timing, bool)
                and build_hal_timing == 1
            )
        ):
            raise BenchmarkError(f"{role}: build source record does not enable hal_timing")

        requested_hz = board.get("requested_spi_hz")
        if (
            isinstance(requested_hz, bool)
            or not isinstance(requested_hz, int)
            or requested_hz not in REQUESTED_CLOCKS_HZ
        ):
            raise BenchmarkError(f"{role}: firmware provenance has no supported requested_spi_hz")
        if board.get("hal_timing") is not True:
            raise BenchmarkError(f"{role}: firmware provenance does not enable hal_timing")
        expected[role] = requested_hz
    # Canonical HAL runs deliberately require a matched A/B source revision.
    if len(source_revisions) != 1:
        raise BenchmarkError("firmware provenance records mixed source revisions")
    if len(set(expected.values())) != 1:
        raise BenchmarkError("firmware provenance records mixed SPI clocks")

    policy = provenance.get("policy")
    if isinstance(policy, Mapping) and "requested_spi_hz" in policy:
        if policy.get("requested_spi_hz") != next(iter(expected.values())):
            raise BenchmarkError("firmware provenance policy clock disagrees with board records")
    return expected


def _validate_report_clock(role: str, report: SpiYieldReport, expected: Mapping[str, int]) -> None:
    expected_hz = expected.get(role)
    if expected_hz is None:
        raise BenchmarkError(f"{role}: no expected SPI clock provenance")
    if report.requested_hz != expected_hz:
        raise BenchmarkError(
            f"{role}: SPI report clock {report.requested_hz} does not match recorded {expected_hz}"
        )


def _load_radio_gaps() -> Any:
    try:
        import radio_gaps
        return radio_gaps
    except ImportError as error:  # pragma: no cover - import fallback
        path = Path(__file__).with_name("radio_gaps.py")
        spec = importlib.util.spec_from_file_location("radio_gaps", path)
        if spec is None or spec.loader is None:
            raise BenchmarkError("radio_gaps.py cannot be loaded") from error
        module = importlib.util.module_from_spec(spec)
        sys.modules["radio_gaps"] = module
        spec.loader.exec_module(module)
        return module


def _request_snapshot(
    session: Any,
    config: Any,
    timeout: float,
    *,
    prefer_session_method: bool = True,
) -> SpiYieldReport:
    shared = _load_radio_gaps()
    return shared._request_page_snapshot(
        session,
        config,
        timeout,
        operation=SNAPSHOT_OP,
        field_name="spi_yield",
        decoder=decode_report,
        mapping_decoder=report_from_mapping,
        report_dict=_report_dict,
        method_name="snapshot_spi_yield" if prefer_session_method else None,
    )


def _collect_spi_page(
    run_dir: Path,
    output: Path,
    *,
    command_gap: float = 0.20,
    control_timeout: float = 15.0,
    session_factory: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    if Path(run_dir).resolve() == Path(output).resolve():
        raise BenchmarkError("spi-yield output must be a new directory")
    expected_clocks = _required_spi_clock_provenance(run_dir)
    shared = _load_radio_gaps()
    shared_source = Path(getattr(shared, "__file__", "")).resolve()
    protocol = Path(__file__).with_name("spi-yield-protocol.json").resolve()
    firmware_provenance = Path(run_dir) / FIRMWARE_PROVENANCE_NAME
    result = shared._collect_page(
        run_dir,
        output,
        command_gap=command_gap,
        control_timeout=control_timeout,
        session_factory=session_factory,
        operation=SNAPSHOT_OP,
        field_name="spi_yield",
        page_label="spi-yield",
        page_decoder=decode_report,
        page_mapping_decoder=report_from_mapping,
        page_report_dict=_report_dict,
        page_evaluator=evaluate_report,
        session_method="snapshot_spi_yield",
        scope="board_local_public_hal_spi_yield",
        software_budget=(
            "public-HAL SPI transfer/yield timing and background HAL control during the declared window; "
            "not limited to payload-only work"
        ),
        provenance_files=(Path(__file__).resolve(), shared_source, protocol, firmware_provenance),
        physical_claims={
            "rf_delivery": False,
            "guard_margin": False,
            "collision_safety": False,
            "throughput_acceptance": False,
            "radio_capacity": False,
        },
        include_page_metadata=True,
        collector_script=Path(__file__).resolve(),
        page_validator=lambda role, report: _validate_report_clock(role, report, expected_clocks),
        include_executed_sources=True,
    )
    existing_intent: Mapping[str, Any] = {}
    results_path = Path(run_dir) / "results.json"
    if results_path.is_file():
        try:
            parsed = json.loads(results_path.read_text(encoding="utf-8"))
            if isinstance(parsed, Mapping) and isinstance(parsed.get("intent"), Mapping):
                existing_intent = parsed["intent"]
        except (OSError, ValueError):
            existing_intent = {}
    result["intent"].update(
        {
            "spi_yield_requested": bool(existing_intent.get("spi_yield_requested", False)),
            "enable_operation": ENABLE_OP,
            "snapshot_operation": SNAPSHOT_OP,
            "collection_window": (
                "each board's accepted START handler through that board's STOP return and final "
                "owned pending-terminal callback; the receiver includes the armed interval before "
                "the sender START; finishRun abort work before freeze included; final post-terminal "
                "RadioTxHooks.packetReleased, radio packet-pool release, and final RX rearm excluded"
            ),
            "command_gap_seconds": command_gap,
            "control_timeout_seconds": control_timeout,
            "expected_requested_hz_by_role": dict(expected_clocks),
        }
    )
    result["collection_window"] = {
        "scope": "per_board",
        "anchor": "each board's accepted START handler",
        "end": "that board's STOP return and final owned pending-terminal callback",
        "receiver_includes_pre_sender_armed_interval": True,
        "host_sender_wall_anchor": "sender START return (producer wall-clock only)",
        "includes_pending_drain": True,
        "includes_background_hal_control": True,
        "includes_finish_run_abort_before_freeze": True,
        "excludes_final_post_terminal_packet_released": True,
        "excludes_final_radio_packet_pool_release": True,
        "excludes_final_rx_rearm": True,
    }
    shared._load_benchmark()._safe_json_write(Path(output) / "results.json", result)
    return result


collect_spi_yield = _collect_spi_page
decode_report_frame = decode_report


def encode_control_frame(
    run_id: int,
    source: int,
    destination: int,
    count: int,
    size: int,
    duration_ms: int,
    window: int,
    flags: int = 0,
    operation: int = SNAPSHOT_OP,
) -> bytes:
    values = (run_id, source, destination, count, size, duration_ms, window, flags)
    limits = (UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX, 0xFFFF, UINT32_MAX, 0xFFFF, 0xFF)
    if operation not in (SNAPSHOT_OP, ENABLE_OP):
        raise ValueError("kind 9 control operation is unsupported")
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in values):
        raise ValueError("kind 9 control fields must be nonnegative integers")
    if any(value > limit for value, limit in zip(values, limits)):
        raise ValueError("kind 9 control field exceeds its wire width")
    if flags != 0:
        raise ValueError("kind 9 control flags must be zero")
    return (
        MAGIC.to_bytes(2, "little")
        + bytes((VERSION, operation))
        + int(run_id).to_bytes(4, "little")
        + int(source).to_bytes(4, "little")
        + int(destination).to_bytes(4, "little")
        + int(count).to_bytes(4, "little")
        + int(size).to_bytes(2, "little")
        + int(duration_ms).to_bytes(4, "little")
        + int(window).to_bytes(2, "little")
        + bytes((flags, 0, 0, 0))
    )


encode_snapshot_control = encode_control_frame


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True, help="completed benchmark result directory")
    parser.add_argument("--output", type=Path, required=True, help="new protected output directory")
    parser.add_argument("--command-gap", type=float, default=0.20)
    parser.add_argument("--control-timeout", type=float, default=15.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = collect_spi_yield(
            args.run_dir,
            args.output,
            command_gap=args.command_gap,
            control_timeout=args.control_timeout,
        )
    except Exception as error:
        print(f"RESULT error {type(error).__name__}: {error}", flush=True)
        return 1
    print("RESULT", result["status"], flush=True)
    return 0 if result["measurement_valid"] else 1


if __name__ == "__main__":  # pragma: no cover - hardware entry point
    raise SystemExit(main())
