#!/usr/bin/env python3
"""Collect the board-local W12 owner-radio timing page (op 10, kind 8).

The page describes software callback timing around the local radio owner.  It
does not measure RF delivery, guard margin, throughput, or collision safety.
This module keeps the wire decoder usable without a connected Meshtastic
client; the client is imported only when the collector opens a board.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hashlib
import importlib.metadata
import importlib.util
import json
import math
import os
import platform
import re
import sys
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


MAGIC = 0x5731
VERSION = 1
KIND = 8
REPORT_BYTES = 112
CONTROL_BYTES = 32
SNAPSHOT_OP = 10
OWNER_NOTIFY_SOURCE = 1
PRIVATE_APP_PORTNUM = 256
TRANSPORT_INTERNAL = 0
TRANSPORT_API = 7
MAX_PENDING_TX = 16
MAX_RADIO_GAP_US = 10 * 60 * 1000 * 1000
UINT32_MAX = 0xFFFFFFFF
UINT64_MAX = 0xFFFFFFFFFFFFFFFF

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

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


class BenchmarkError(RuntimeError):
    """A protocol, identity, provenance, health, or collector failure."""


@dataclasses.dataclass(frozen=True)
class RadioGapMetric:
    count: int
    min_us: int
    max_us: int
    sum_us: int


@dataclasses.dataclass(frozen=True)
class RadioGapsReport:
    run_id: int
    source: int
    destination: int
    elapsed_ms: int
    status: int
    pending_tx_count: int
    owner_rx_notify_to_rearm_us: RadioGapMetric
    owner_tx_notify_to_start_transmit_call_us: RadioGapMetric
    rx_notifications: int
    rx_valid_done: int
    rx_invalid: int
    rx_arm_failures: int
    tx_valid_done: int
    tx_invalid_irq: int
    tx_start_failures: int
    tx_unpaired: int
    interval_rejected: int
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
    def as_of_incomplete(self) -> bool:
        return self.active

    @property
    def snapshot_terminal(self) -> bool:
        return self.prepared and self.complete and not self.running and not self.pending


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _u64(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 8], "little")


def _metric(data: bytes, offset: int, label: str, overflow: bool) -> RadioGapMetric:
    count = _u32(data, offset)
    minimum = _u32(data, offset + 4)
    maximum = _u32(data, offset + 8)
    total = _u64(data, offset + 12)
    if count == 0:
        if minimum or maximum or total:
            raise ValueError(f"kind 8 {label} has values without samples")
        return RadioGapMetric(0, 0, 0, 0)
    if minimum > MAX_RADIO_GAP_US or maximum > MAX_RADIO_GAP_US:
        raise ValueError(f"kind 8 {label} sample exceeds finite interval bound")
    if minimum > maximum or total < maximum:
        raise ValueError(f"kind 8 {label} metric bounds are inconsistent")
    # The firmware saturates the total at UINT64_MAX.  A saturated aggregate
    # is only meaningful when the page reports an overflow.
    if total == UINT64_MAX and not overflow:
        raise ValueError(f"kind 8 {label} total is saturated without overflow")
    if total < count * minimum:
        raise ValueError(f"kind 8 {label} total is below sample bounds")
    if not overflow and total > count * maximum:
        raise ValueError(f"kind 8 {label} total exceeds sample bounds")
    return RadioGapMetric(count, minimum, maximum, total)


def decode_report(data: bytes | bytearray | memoryview) -> RadioGapsReport:
    """Decode and validate one complete kind-8 report."""

    raw = bytes(data)
    if len(raw) != REPORT_BYTES:
        raise ValueError(f"kind 8 report must be exactly {REPORT_BYTES} bytes")
    if _u16(raw, 0) != MAGIC or raw[2] != VERSION or raw[3] != KIND:
        raise ValueError("invalid kind 8 report header")
    if any(raw[22:24]) or any(raw[102:]):
        raise ValueError("nonzero reserved kind 8 bytes")

    status = raw[20]
    if status & ~STATUS_MASK:
        raise ValueError("unknown kind 8 status bits")
    pending_count = raw[21]
    if pending_count > MAX_PENDING_TX:
        raise ValueError("invalid kind 8 pending TX count")
    prepared = bool(status & STATUS_PREPARED)
    running = bool(status & STATUS_RUNNING)
    complete = bool(status & STATUS_COMPLETE)
    pending = bool(status & STATUS_PENDING)
    active = bool(status & STATUS_ACTIVE)
    if not prepared or running == complete:
        raise ValueError("inconsistent kind 8 run state")
    if pending != bool(pending_count):
        raise ValueError("kind 8 pending status does not match count")
    if active != (running or pending):
        raise ValueError("kind 8 active status does not match state")

    overflow = raw[101]
    if overflow > 1:
        raise ValueError("invalid kind 8 overflow flag")
    first = _metric(raw, 24, "RX", bool(overflow))
    second = _metric(raw, 44, "TX", bool(overflow))

    counters = tuple(_u32(raw, offset) for offset in range(64, 100, 4))
    if raw[100] != OWNER_NOTIFY_SOURCE:
        raise ValueError("unknown kind 8 timing source")
    if not (status & STATUS_AVAILABLE):
        if first != RadioGapMetric(0, 0, 0, 0) or second != RadioGapMetric(0, 0, 0, 0):
            raise ValueError("unavailable kind 8 page has metric values")
        if any(counters) or overflow:
            raise ValueError("unavailable kind 8 page has counters")

    # RX notifications count callbacks.  A callback with valid RX completions
    # and an arm failure is both valid_done and invalid in the firmware, so an
    # equality check would reject the real source semantics.  These bounds are
    # the conservative relationships that remain true without losing overlap.
    rx_notifications, rx_valid_done, rx_invalid, rx_arm_failures = counters[:4]
    if not overflow:
        if rx_invalid > rx_notifications:
            raise ValueError("kind 8 RX invalid count exceeds notifications")
        if rx_notifications > rx_valid_done + rx_invalid:
            raise ValueError("kind 8 RX notifications cannot be reconciled")
        if rx_valid_done == 0 and rx_notifications != rx_invalid:
            raise ValueError("kind 8 RX zero-valid notifications are inconsistent")
        if rx_arm_failures and rx_invalid == 0:
            raise ValueError("kind 8 RX arm failures require an invalid callback")

    return RadioGapsReport(
        run_id=_u32(raw, 4),
        source=_u32(raw, 8),
        destination=_u32(raw, 12),
        elapsed_ms=_u32(raw, 16),
        status=status,
        pending_tx_count=pending_count,
        owner_rx_notify_to_rearm_us=first,
        owner_tx_notify_to_start_transmit_call_us=second,
        rx_notifications=rx_notifications,
        rx_valid_done=rx_valid_done,
        rx_invalid=rx_invalid,
        rx_arm_failures=rx_arm_failures,
        tx_valid_done=counters[4],
        tx_invalid_irq=counters[5],
        tx_start_failures=counters[6],
        tx_unpaired=counters[7],
        interval_rejected=counters[8],
        source_kind=raw[100],
        overflow=bool(overflow),
        raw=raw,
    )


def _mapping_metric(value: Any, name: str) -> RadioGapMetric:
    if isinstance(value, RadioGapMetric):
        return value
    if not isinstance(value, Mapping):
        raise ValueError(f"kind 8 {name} metric is not a mapping")
    aliases = {
        "count": ("count",),
        "min_us": ("min_us", "min"),
        "max_us": ("max_us", "max"),
        "sum_us": ("sum_us", "sum"),
    }
    values: dict[str, int] = {}
    for field, keys in aliases.items():
        key = next((candidate for candidate in keys if candidate in value), None)
        if key is None or isinstance(value[key], bool) or not isinstance(value[key], int):
            raise ValueError(f"kind 8 {name} metric misses {field}")
        values[field] = value[key]
    return RadioGapMetric(**values)


def report_from_mapping(value: Mapping[str, Any]) -> RadioGapsReport:
    """Convert a parsed capture event to the same strict report type."""

    if not isinstance(value, Mapping):
        raise ValueError("kind 8 response is not a mapping")
    aliases = {
        "run_id": ("run_id",),
        "source": ("source",),
        "destination": ("destination",),
        "elapsed_ms": ("elapsed_ms",),
        "status": ("status_bits", "status"),
        "pending_tx_count": ("pending_tx_count",),
        "rx_notifications": ("rx_notifications",),
        "rx_valid_done": ("rx_valid_done",),
        "rx_invalid": ("rx_invalid",),
        "rx_arm_failures": ("rx_arm_failures",),
        "tx_valid_done": ("tx_valid_done",),
        "tx_invalid_irq": ("tx_invalid_irq",),
        "tx_start_failures": ("tx_start_failures",),
        "tx_unpaired": ("tx_unpaired",),
        "interval_rejected": ("interval_rejected",),
        "source_kind": ("source_kind",),
        "overflow": ("overflow",),
    }
    scalar: dict[str, Any] = {}
    for field, keys in aliases.items():
        key = next((candidate for candidate in keys if candidate in value), None)
        if key is None:
            if field == "source_kind":
                continue
            raise ValueError(f"kind 8 response misses {field}")
        scalar[field] = value[key]
    def metric_from_flat(prefix: str, name: str) -> RadioGapMetric | None:
        fields = {field: value.get(f"{prefix}_{field}") for field in ("count", "min_us", "max_us", "sum_us")}
        if any(item is None for item in fields.values()):
            return None
        return _mapping_metric(fields, name)

    rx_metric = value.get("owner_rx_notify_to_rearm_us")
    tx_metric = value.get("owner_tx_notify_to_start_transmit_call_us")
    if rx_metric is None:
        rx_metric = metric_from_flat("owner_rx_notify_to_rearm_us", "RX")
    if rx_metric is None:
        rx_metric = metric_from_flat("rx", "RX")
    if tx_metric is None:
        tx_metric = metric_from_flat("owner_tx_notify_to_start_transmit_call_us", "TX")
    if tx_metric is None:
        tx_metric = metric_from_flat("tx", "TX")
    if rx_metric is None or tx_metric is None:
        raise ValueError("kind 8 response misses timing metrics")
    scalar["owner_rx_notify_to_rearm_us"] = _mapping_metric(rx_metric, "RX")
    scalar["owner_tx_notify_to_start_transmit_call_us"] = _mapping_metric(tx_metric, "TX")
    scalar.setdefault("source_kind", OWNER_NOTIFY_SOURCE)
    for field in (
        "run_id",
        "source",
        "destination",
        "elapsed_ms",
        "status",
        "pending_tx_count",
        "rx_notifications",
        "rx_valid_done",
        "rx_invalid",
        "rx_arm_failures",
        "tx_valid_done",
        "tx_invalid_irq",
        "tx_start_failures",
        "tx_unpaired",
        "interval_rejected",
        "source_kind",
    ):
        if isinstance(scalar[field], bool) or not isinstance(scalar[field], int):
            raise ValueError(f"kind 8 {field} is not an integer")
    if not isinstance(scalar["overflow"], (bool, int)):
        raise ValueError("kind 8 overflow is not boolean")
    raw = bytearray(REPORT_BYTES)
    raw[0:2] = MAGIC.to_bytes(2, "little")
    raw[2] = VERSION
    raw[3] = KIND
    for offset, field in ((4, "run_id"), (8, "source"), (12, "destination"), (16, "elapsed_ms")):
        raw[offset : offset + 4] = int(scalar[field]).to_bytes(4, "little", signed=False)
    raw[20] = int(scalar["status"])
    raw[21] = int(scalar["pending_tx_count"])
    for offset, metric in ((24, scalar["owner_rx_notify_to_rearm_us"]), (44, scalar["owner_tx_notify_to_start_transmit_call_us"])):
        raw[offset : offset + 4] = metric.count.to_bytes(4, "little", signed=False)
        raw[offset + 4 : offset + 8] = metric.min_us.to_bytes(4, "little", signed=False)
        raw[offset + 8 : offset + 12] = metric.max_us.to_bytes(4, "little", signed=False)
        raw[offset + 12 : offset + 20] = metric.sum_us.to_bytes(8, "little", signed=False)
    for offset, field in zip(
        range(64, 100, 4),
        ("rx_notifications", "rx_valid_done", "rx_invalid", "rx_arm_failures", "tx_valid_done", "tx_invalid_irq", "tx_start_failures", "tx_unpaired", "interval_rejected"),
    ):
        raw[offset : offset + 4] = int(scalar[field]).to_bytes(4, "little", signed=False)
    raw[100] = int(scalar["source_kind"])
    raw[101] = int(bool(scalar["overflow"]))
    return decode_report(raw)


def encode_snapshot_control(
    run_id: int,
    source: int,
    destination: int,
    count: int,
    size: int,
    duration_ms: int,
    window: int,
    flags: int = 0,
) -> bytes:
    """Encode a self-authorized op-10 control for the matching run."""

    values = (run_id, source, destination, count, size, duration_ms, window, flags)
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in values):
        raise ValueError("kind 8 control fields must be nonnegative integers")
    if flags != 0:
        raise ValueError("kind 8 control flags must be zero")
    if any(value > limit for value, limit in zip(values, (UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX, 0xFFFF, UINT32_MAX, 0xFFFF, 0xFF))):
        raise ValueError("kind 8 control field exceeds its wire width")
    return (
        MAGIC.to_bytes(2, "little")
        + bytes((VERSION, SNAPSHOT_OP))
        + int(run_id).to_bytes(4, "little")
        + int(source).to_bytes(4, "little")
        + int(destination).to_bytes(4, "little")
        + int(count).to_bytes(4, "little")
        + int(size).to_bytes(2, "little")
        + int(duration_ms).to_bytes(4, "little")
        + int(window).to_bytes(2, "little")
        + bytes((flags, 0, 0, 0))
    )


def evaluate_report(report: RadioGapsReport) -> dict[str, Any]:
    """Classify software timing evidence without making a physical claim."""

    reasons: list[str] = []
    if (
        report.owner_rx_notify_to_rearm_us.count == 0
        and report.owner_tx_notify_to_start_transmit_call_us.count == 0
    ):
        reasons.append("radio_gaps_no_observations")
    if not report.available:
        reasons.append("radio_gaps_unavailable")
    if not report.complete or report.running:
        reasons.append("radio_gaps_incomplete")
    if report.pending_tx_count or report.pending:
        reasons.append("radio_gaps_pending_tx")
    if report.overflow:
        reasons.append("radio_gaps_overflow")
    if report.interval_rejected:
        reasons.append("radio_gaps_interval_rejected")
    return {
        "status": "valid" if not reasons else "invalid",
        "measurement_valid": not reasons,
        "failure_reasons": reasons,
        "scope": "board_local_owner_radio_timing",
        "software_budget": {
            "rx": "owner_rx_notify_to_rearm_us",
            "tx": "owner_tx_notify_to_start_transmit_call_us",
        },
        "physical_claims": {
            "rf_delivery": False,
            "guard_margin": False,
            "collision_safety": False,
            "throughput_acceptance": False,
        },
    }


def _load_benchmark() -> Any:
    try:
        import benchmark_probe
        return benchmark_probe
    except ImportError as error:  # pragma: no cover - only a missing local module
        path = Path(__file__).with_name("benchmark_probe.py")
        if not path.is_file():
            raise BenchmarkError("benchmark_probe.py is required for hardware collection") from error
        spec = importlib.util.spec_from_file_location("benchmark_probe", path)
        if spec is None or spec.loader is None:
            raise BenchmarkError("benchmark_probe.py cannot be loaded") from error
        module = importlib.util.module_from_spec(spec)
        sys.modules["benchmark_probe"] = module
        spec.loader.exec_module(module)
        return module


def _load_health_helpers() -> tuple[Callable[..., Any], Callable[..., Any], Callable[..., Any]]:
    try:
        import reliable_pilot
    except ImportError:
        path = Path(__file__).with_name("reliable_pilot.py")
        spec = importlib.util.spec_from_file_location("reliable_pilot", path)
        if spec is None or spec.loader is None:
            raise BenchmarkError("reliable_pilot.py cannot be loaded")
        reliable_pilot = importlib.util.module_from_spec(spec)
        sys.modules["reliable_pilot"] = reliable_pilot
        spec.loader.exec_module(reliable_pilot)
    return (
        reliable_pilot._prepare_capture_health,
        reliable_pilot._session_capture_health,
        reliable_pilot._close_sessions_and_collect_health,
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _module_provenance(module: Any, distribution: str | None = None) -> dict[str, Any]:
    module_path = getattr(module, "__file__", None)
    if not isinstance(module_path, str) or not module_path:
        raise BenchmarkError(f"runtime module {getattr(module, '__name__', '?')} has no file")
    path = Path(module_path).resolve()
    if not path.is_file():
        raise BenchmarkError(f"runtime module file is missing: {path}")
    version = getattr(module, "__version__", None)
    if distribution is not None:
        with contextlib.suppress(importlib.metadata.PackageNotFoundError):
            version = importlib.metadata.version(distribution)
    return {"path": str(path), "version": version, "sha256": _sha256_file(path)}


def _runtime_provenance() -> dict[str, Any]:
    """Record the client and generated protobuf runtime used to open boards."""

    try:
        import google.protobuf
        import meshtastic
        import serial
        from meshtastic import mesh_interface, serial_interface, stream_interface
        from meshtastic.protobuf import mesh_pb2, portnums_pb2
    except ImportError as error:  # pragma: no cover - exercised by hardware setup
        raise BenchmarkError(
            "the pinned Meshtastic client, generated protobufs, and pyserial are required"
        ) from error
    descriptor = getattr(getattr(mesh_pb2, "DESCRIPTOR", None), "serialized_pb", None)
    if not isinstance(descriptor, bytes):
        raise BenchmarkError("generated mesh protobuf descriptor is unavailable")
    return {
        "python_executable": sys.executable,
        "python_executable_resolved": str(Path(sys.executable).resolve()),
        "python_version": platform.python_version(),
        "pythonpath": os.environ.get("PYTHONPATH", ""),
        "meshtastic": _module_provenance(meshtastic, "meshtastic"),
        "control_modules": {
            "mesh_interface": _module_provenance(mesh_interface),
            "serial_interface": _module_provenance(serial_interface),
            "stream_interface": _module_provenance(stream_interface),
            "portnums_pb2": _module_provenance(portnums_pb2),
        },
        "protobuf": {
            "runtime": _module_provenance(google.protobuf, "protobuf"),
            "generated_mesh_module": _module_provenance(mesh_pb2),
            "generated_mesh_descriptor_sha256": _sha256_bytes(descriptor),
        },
        "pyserial": _module_provenance(serial, "pyserial"),
    }


def _config_from_result(run: Mapping[str, Any], benchmark: Any) -> Any:
    fields = ("run_id", "source", "destination", "count", "size", "duration_ms", "window", "flags")
    if any(field not in run for field in fields):
        raise BenchmarkError("existing run has an incomplete benchmark config")
    try:
        return benchmark.RunConfig(**{field: int(run[field]) for field in fields})
    except (TypeError, ValueError) as error:
        raise BenchmarkError("existing run benchmark config is malformed") from error


_PRIMARY_REPORT_FIELDS = (
    "run_id",
    "source",
    "destination",
    "count",
    "size",
    "duration_ms",
    "window",
    "flags",
    "prepared",
    "running",
    "complete",
    "enqueued",
    "send_failures",
    "tx_started",
    "tx_succeeded",
    "tx_failures",
    "tx_dropped",
    "tx_cancelled",
    "received",
    "missing",
    "duplicates",
    "corrupt",
    "out_of_range",
    "elapsed_ms",
    "goodput_bps",
)


def _primary_report(value: Any, label: str, benchmark: Any) -> Any:
    if not isinstance(value, Mapping):
        raise BenchmarkError(f"existing benchmark {label} report is missing")
    missing = [field for field in _PRIMARY_REPORT_FIELDS if field not in value]
    if missing:
        raise BenchmarkError(
            f"existing benchmark {label} report is incomplete: {', '.join(missing)}"
        )
    try:
        return benchmark.report_from_mapping(value)
    except Exception as error:
        raise BenchmarkError(f"existing benchmark {label} report is malformed") from error


def _finite_result_number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise BenchmarkError(f"existing benchmark {label} is not finite")
    return float(value)


def _validate_primary_reports(
    result: Mapping[str, Any], intent: Mapping[str, Any], config: Any, benchmark: Any
) -> None:
    primary = result.get("report")
    if not isinstance(primary, Mapping):
        raise BenchmarkError("existing benchmark primary report is missing")
    if primary.get("status") != "measurement_valid" or primary.get("measurement_valid") is not True:
        raise BenchmarkError("existing benchmark primary report is not marked valid")
    if primary.get("failure_reasons") != []:
        raise BenchmarkError("existing benchmark primary report has failure reasons")

    fixed_wall = _finite_result_number(intent.get("fixed_wall_seconds"), "fixed wall window")
    if fixed_wall != 60.0:
        raise BenchmarkError("existing benchmark fixed wall window is not 60 seconds")
    drain_seconds = _finite_result_number(intent.get("drain_seconds"), "drain window")
    if drain_seconds < 0:
        raise BenchmarkError("existing benchmark drain window is negative")
    run_anchor = primary.get("run")
    if not isinstance(run_anchor, Mapping) or any(run_anchor.get(field) != getattr(config, field) for field in (
        "run_id", "source", "destination", "count", "size", "duration_ms", "window", "flags"
    )):
        raise BenchmarkError("existing benchmark primary report run anchor does not match config")
    time_window = primary.get("time_window")
    if not isinstance(time_window, Mapping):
        raise BenchmarkError("existing benchmark primary report has no time window")
    if _finite_result_number(time_window.get("fixed_wall_seconds"), "primary fixed wall window") != 60.0:
        raise BenchmarkError("existing benchmark primary report fixed wall window is not 60 seconds")
    if _finite_result_number(time_window.get("drain_seconds_required"), "primary drain window") != drain_seconds:
        raise BenchmarkError("existing benchmark primary report drain window does not match intent")
    observed_wall = _finite_result_number(time_window.get("observed_wall_seconds"), "observed wall window")
    observed_drain = _finite_result_number(time_window.get("observed_drain_seconds"), "observed drain window")

    persisted = result.get("firmware_reports")
    if not isinstance(persisted, Mapping):
        raise BenchmarkError("existing benchmark lacks primary firmware reports")
    reports: dict[str, Any] = {}
    for role in ("sender", "receiver"):
        persisted_report = _primary_report(persisted.get(role), f"{role} firmware", benchmark)
        primary_report = _primary_report(primary.get(role), f"{role} primary", benchmark)
        if persisted_report != primary_report:
            raise BenchmarkError(f"existing benchmark {role} primary report differs from firmware report")
        reports[role] = persisted_report

    reevaluated = benchmark.evaluate_reports(
        config,
        reports["sender"],
        reports["receiver"],
        wall_seconds=60.0,
        drain_seconds=drain_seconds,
        observed_wall_seconds=observed_wall,
        observed_drain_seconds=observed_drain,
    )
    if reevaluated.get("status") != "measurement_valid" or reevaluated.get("measurement_valid") is not True:
        reasons = ", ".join(str(reason) for reason in reevaluated.get("failure_reasons", ()))
        raise BenchmarkError(f"existing benchmark reports are not valid: {reasons}")
    persisted_capture = primary.get("capture_validity")
    capture_fields = (
        "sender_report_present",
        "receiver_report_present",
        "sender_snapshot_valid",
        "receiver_snapshot_valid",
        "physical_tx_terminal_complete",
        "aggregate_receiver_bitmap_authoritative",
    )
    if not isinstance(persisted_capture, Mapping) or any(
        persisted_capture.get(field) is not True for field in capture_fields
    ):
        raise BenchmarkError("existing benchmark primary capture validity is incomplete")
    reevaluated_capture = reevaluated.get("capture_validity")
    if not isinstance(reevaluated_capture, Mapping) or any(
        reevaluated_capture.get(field) is not True for field in capture_fields
    ):
        raise BenchmarkError("existing benchmark reports are not terminal and capture-valid")


def _resolve_provenance_path(run_dir: Path, name: str) -> Path:
    path = Path(name)
    candidates = (path, run_dir / path)
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise BenchmarkError(f"provenance file is missing: {name}")


def _validate_existing_run(run_dir: Path, result: Mapping[str, Any], benchmark: Any) -> tuple[Any, dict[str, str], dict[str, str]]:
    intent = result.get("intent")
    run = intent.get("run") if isinstance(intent, Mapping) else None
    if not isinstance(run, Mapping):
        raise BenchmarkError("existing benchmark has no run config")
    config = _config_from_result(run, benchmark)
    try:
        benchmark.validate_config(config)
    except Exception as error:
        raise BenchmarkError("existing benchmark config fails the primary validator") from error
    if not isinstance(intent, Mapping):
        raise BenchmarkError("existing benchmark intent is malformed")
    _validate_primary_reports(result, intent, config, benchmark)
    report = result.get("report")
    if result.get("status") != "measurement_valid":
        raise BenchmarkError("existing benchmark result is not measurement_valid")
    if result.get("configuration_preserved") is not True:
        raise BenchmarkError("existing benchmark did not preserve configuration")
    firmware_reports = result.get("firmware_reports")
    if not isinstance(firmware_reports, Mapping):
        raise BenchmarkError("existing benchmark lacks nested firmware reports")
    for label in ("sender", "receiver"):
        nested = firmware_reports.get(label)
        if not isinstance(nested, Mapping):
            raise BenchmarkError(f"existing benchmark lacks nested {label} report")
        for field, expected in (
            ("run_id", config.run_id),
            ("source", config.source),
            ("destination", config.destination),
            ("elapsed_ms", config.duration_ms),
        ):
            if nested.get(field) != expected:
                raise BenchmarkError(f"existing nested {label} report {field} does not match run config")
    for result_section in (report, result.get("firmware_reports")):
        if isinstance(result_section, Mapping):
            sections = result_section.values() if result_section is not report else (result_section,)
            for section in sections:
                if not isinstance(section, Mapping):
                    continue
                for field, expected in (
                    ("run_id", config.run_id),
                    ("source", config.source),
                    ("destination", config.destination),
                ):
                    if field in section and section[field] != expected:
                        raise BenchmarkError(f"existing benchmark {field} does not match run config")
    roles = {
        "sender": intent.get("sender") if isinstance(intent, Mapping) else None,
        "receiver": intent.get("receiver") if isinstance(intent, Mapping) else None,
    }
    if roles["sender"] not in benchmark.BOARD_IDENTITIES or roles["receiver"] not in benchmark.BOARD_IDENTITIES:
        raise BenchmarkError("existing benchmark has unknown board roles")
    if benchmark.BOARD_IDENTITIES[roles["sender"]][1] != config.source or benchmark.BOARD_IDENTITIES[roles["receiver"]][1] != config.destination:
        raise BenchmarkError("existing run source/destination do not match role identities")
    before = result.get("configuration_before")
    after = result.get("configuration_after")
    if not isinstance(before, Mapping) or not isinstance(after, Mapping):
        raise BenchmarkError("existing benchmark lacks persisted config fingerprints")
    expected: dict[str, str] = {}
    for role in (roles["sender"], roles["receiver"]):
        before_row = before.get(role)
        after_row = after.get(role)
        if not isinstance(before_row, Mapping) or not isinstance(after_row, Mapping):
            raise BenchmarkError(f"existing benchmark lacks {role} config fingerprint")
        if before_row.get("usb_identity") != benchmark.BOARD_IDENTITIES[role][0] or after_row.get("usb_identity") != benchmark.BOARD_IDENTITIES[role][0]:
            raise BenchmarkError(f"existing benchmark has wrong {role} USB identity")
        fields = ("local_config_sha256", "module_config_sha256", "channels_sha256", "lora_sha256", "private_key_sha256", "public_key_sha256")
        if any(before_row.get(field) != after_row.get(field) for field in fields):
            raise BenchmarkError(f"existing benchmark {role} config changed")
        expected[role] = json.dumps({field: before_row.get(field) for field in fields}, sort_keys=True)

    provenance = result.get("provenance")
    image_hashes = provenance.get("image_hashes") if isinstance(provenance, Mapping) else None
    if not isinstance(image_hashes, Mapping) or not image_hashes:
        raise BenchmarkError("existing benchmark has no application flash/file hashes")
    verified: dict[str, str] = {}
    for name, expected_hash in image_hashes.items():
        if not isinstance(name, str) or not isinstance(expected_hash, str) or not _HEX64.fullmatch(expected_hash):
            raise BenchmarkError("existing provenance contains an invalid file hash")
        path = _resolve_provenance_path(run_dir, name)
        actual = benchmark.sha256_file(path)
        if actual.lower() != expected_hash.lower():
            raise BenchmarkError(f"provenance hash changed: {name}")
        verified[str(path)] = actual
    return config, expected, verified


def _capture_events(session: Any) -> list[dict[str, Any]]:
    capture = getattr(session, "capture", None)
    snapshot = getattr(capture, "snapshot", None)
    if not callable(snapshot):
        return []
    events = snapshot()
    if not isinstance(events, list):
        raise BenchmarkError("capture event snapshot is malformed")
    if any(not isinstance(event, Mapping) for event in events):
        raise BenchmarkError("capture event snapshot contains a malformed event")
    return [dict(event) for event in events]


def _protocol_event_failures(events: Sequence[Mapping[str, Any]]) -> list[str]:
    failures = []
    for event in events:
        if event.get("kind") == "protocol_error":
            failures.append(str(event.get("message", "protocol error")))
    return failures


def _persist_capture(session: Any) -> None:
    capture = getattr(session, "capture", None)
    persist = getattr(capture, "persist", None)
    if not callable(persist):
        raise BenchmarkError("capture has no persistence seam")
    try:
        persisted = persist()
    except Exception as error:
        raise BenchmarkError(f"capture persistence failed: {error}") from error
    if persisted is False:
        raise BenchmarkError("capture persistence failed")


def _config_fingerprint(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        field: row.get(field)
        for field in (
            "local_config_sha256",
            "module_config_sha256",
            "channels_sha256",
            "lora_sha256",
            "private_key_sha256",
            "public_key_sha256",
        )
    }


def _report_from_response(response: Any) -> RadioGapsReport:
    if isinstance(response, RadioGapsReport):
        return decode_report(response.raw) if response.raw else response
    if isinstance(response, (bytes, bytearray, memoryview)):
        return decode_report(response)
    if isinstance(response, Mapping):
        return report_from_mapping(response)
    raise BenchmarkError("kind 8 response has no decodable payload")


def _report_dict(report: RadioGapsReport) -> dict[str, Any]:
    value = dataclasses.asdict(report)
    value.pop("raw", None)
    value["overflow"] = bool(value["overflow"])
    return value


def _install_raw_response_capture(session: Any) -> None:
    """Add a kind-8 event seam when the shared benchmark reader predates op 10."""

    interface = getattr(session, "interface", None)
    capture = getattr(session, "capture", None)
    original = getattr(interface, "_handleFromRadio", None)
    if capture is None or not callable(original) or getattr(interface, "_radio_gaps_capture", False):
        return
    try:
        from meshtastic.protobuf import mesh_pb2, portnums_pb2
    except ImportError:
        return
    private_app = int(portnums_pb2.PRIVATE_APP)

    def handle(data: bytes) -> Any:
        incoming = mesh_pb2.FromRadio()
        try:
            incoming.ParseFromString(data)
            if incoming.HasField("packet"):
                packet = incoming.packet
                if packet.HasField("decoded") and int(packet.decoded.portnum) == private_app:
                    payload = bytes(packet.decoded.payload)
                    with contextlib.suppress(ValueError):
                        report = decode_report(payload)
                        capture.record(
                            "packet",
                            packet_id=int(packet.id),
                            to=int(packet.to),
                            **{"from": int(getattr(packet, "from"))},
                            portnum=int(packet.decoded.portnum),
                            request_id=int(packet.decoded.request_id),
                            want_ack=bool(packet.want_ack),
                            pki_encrypted=bool(packet.pki_encrypted),
                            via_mqtt=bool(packet.via_mqtt),
                            transport=int(packet.transport_mechanism),
                            payload_size=len(payload),
                            radio_gaps=_report_dict(report),
                        )
        except Exception:
            # The shared reader remains authoritative for malformed protobufs.
            # This optional seam must never hide or replace its health signal.
            pass
        return original(data)

    interface._handleFromRadio = handle
    interface._radio_gaps_capture = True


def _radio_gaps_event_matches(
    session: Any,
    event: Mapping[str, Any],
    packet_id: int,
    config: Any,
    deadline: float,
) -> bool:
    matcher = getattr(session, "_response_event_matches", None)
    if not callable(matcher):
        return False
    try:
        matched = matcher(event, packet_id, "radio_gaps", config, deadline)
    except Exception:
        return False
    if matched is not True:
        return False
    portnum = event.get("portnum")
    transport = event.get("transport")
    if (
        isinstance(portnum, bool)
        or not isinstance(portnum, int)
        or isinstance(transport, bool)
        or not isinstance(transport, int)
    ):
        return False
    return (
        portnum == PRIVATE_APP_PORTNUM
        and transport in {TRANSPORT_INTERNAL, TRANSPORT_API}
        and event.get("want_ack") is False
        and event.get("pki_encrypted") is False
        and event.get("via_mqtt") is False
    )


def _request_snapshot(session: Any, config: Any, timeout: float) -> RadioGapsReport:
    method = getattr(session, "snapshot_radio_gaps", None)
    if callable(method):
        return _report_from_response(method(config, timeout))
    control = getattr(session, "control", None)
    capture = getattr(session, "capture", None)
    matcher = getattr(session, "_response_event_matches", None)
    if not callable(control) or capture is None or not callable(matcher):
        raise BenchmarkError("BoardSession has no kind-8 snapshot seam")
    _install_raw_response_capture(session)
    packet_id = control(SNAPSHOT_OP, config, want_response=True)
    sent_at = getattr(session, "_last_control", {}).get(packet_id)
    if not isinstance(sent_at, (int, float)) or not math.isfinite(sent_at):
        raise BenchmarkError("kind 8 control has no finite send timestamp")
    deadline = sent_at + timeout
    event = capture.wait_for(
        lambda item: _radio_gaps_event_matches(session, item, packet_id, config, deadline),
        max(0.0, deadline - time.monotonic()),
    )
    if event is None:
        raise BenchmarkError("kind 8 snapshot response timed out")
    response = event.get("radio_gaps")
    if response is None:
        response = event.get("radio_gap")
    if response is None:
        response = event.get("payload")
    return _report_from_response(response)


def collect_radio_gaps(
    run_dir: Path,
    output: Path,
    *,
    command_gap: float = 0.20,
    control_timeout: float = 15.0,
    session_factory: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Read both board-local kind-8 pages from an existing completed run."""

    if command_gap < 0 or not math.isfinite(command_gap) or control_timeout <= 0 or not math.isfinite(control_timeout):
        raise BenchmarkError("timing options must be finite and nonnegative")
    run_dir = Path(run_dir)
    output = Path(output)
    if run_dir.resolve() == output.resolve():
        raise BenchmarkError("radio-gaps output must be a new directory")
    result_path = run_dir / "results.json"
    if not result_path.is_file():
        raise BenchmarkError("existing run has no results.json")
    try:
        existing = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise BenchmarkError("existing run results.json is unreadable") from error
    if not isinstance(existing, Mapping):
        raise BenchmarkError("existing run results.json is not an object")

    benchmark = _load_benchmark()
    config, expected_configs, verified_files = _validate_existing_run(run_dir, existing, benchmark)
    runtime_provenance = _runtime_provenance()
    prepare_capture_health, session_capture_health, close_sessions_and_collect_health = _load_health_helpers()
    factory = session_factory or benchmark.BoardSession
    intent = existing["intent"]
    roles = (intent["sender"], intent["receiver"])
    try:
        output.mkdir(parents=True, exist_ok=False, mode=0o700)
    except FileExistsError as error:
        raise BenchmarkError("radio-gaps output must be a new directory") from error
    os.chmod(output, 0o700)
    captured: dict[str, Any] = {}
    failures: list[str] = []
    integrity_failures: list[str] = []

    for role in roles:
        session = None
        row: dict[str, Any] = {"role": role, "status": "invalid"}
        try:
            session = factory(role, output, command_gap)
            prepare_capture_health(session)
            initial_health, initial_health_failures = session_capture_health({role: session})
            row["health_before_close"] = initial_health.get(role, {})
            row["health_preclose"] = row["health_before_close"]
            if initial_health_failures:
                details = ", ".join(initial_health_failures.get(role, ()))
                raise BenchmarkError(f"{role}: capture health before snapshot: {details}")
            expected_node = config.source if role == intent["sender"] else config.destination
            if getattr(session, "identity", None) != benchmark.BOARD_IDENTITIES[role][0] or int(getattr(session, "node_num", 0)) != expected_node:
                raise BenchmarkError(f"{role}: live identity does not match existing run")
            row["identity"] = {
                "usb_identity": session.identity,
                "node_num": session.node_num,
                "expected_node_num": expected_node,
            }
            persisted = existing["configuration_before"][role]
            snapshot_config = getattr(session, "snapshot_config", None)
            if not callable(snapshot_config):
                raise BenchmarkError(f"{role}: BoardSession has no config snapshot seam")
            fresh = snapshot_config(output, "radio-gaps")
            if not isinstance(fresh, Mapping) or _config_fingerprint(fresh) != json.loads(expected_configs[role]):
                raise BenchmarkError(f"{role}: live config fingerprint differs from existing run")
            if fresh.get("usb_identity") != persisted.get("usb_identity"):
                raise BenchmarkError(f"{role}: live USB identity differs from existing run")
            row["configuration"] = dict(fresh)
            row["capture_events_before"] = _capture_events(session)
            protocol_failures = _protocol_event_failures(row["capture_events_before"])
            if protocol_failures:
                raise BenchmarkError(f"{role}: capture protocol error: {', '.join(protocol_failures)}")
            report = _request_snapshot(session, config, control_timeout)
            if (report.run_id, report.source, report.destination) != (config.run_id, config.source, config.destination):
                raise BenchmarkError(f"{role}: kind 8 identity mismatch")
            if report.elapsed_ms != config.duration_ms:
                raise BenchmarkError(f"{role}: kind 8 elapsed_ms does not match run duration")
            row["report"] = _report_dict(report)
            row["evaluation"] = evaluate_report(report)
            row["measurement_valid"] = row["evaluation"]["measurement_valid"]
            row["status"] = row["evaluation"]["status"]
            _persist_capture(session)
        except Exception as error:
            row["error"] = str(error)
            failures.append(f"{role}: {error}")
            integrity_failures.append(f"{role}: {error}")
        finally:
            if session is not None:
                try:
                    row["capture_events_preclose"] = _capture_events(session)
                    protocol_failures = _protocol_event_failures(row["capture_events_preclose"])
                    if protocol_failures:
                        raise BenchmarkError(f"capture protocol error: {', '.join(protocol_failures)}")
                except Exception as error:
                    row["capture_events_preclose_error"] = str(error)
                    failures.append(f"{role}: pre-close capture persistence: {error}")
                    integrity_failures.append(f"{role}: pre-close capture persistence: {error}")
                try:
                    preclose, preclose_failures = session_capture_health({role: session})
                    row["health_preclose"] = preclose.get(role, row.get("health_preclose", {}))
                    if preclose_failures:
                        details = ", ".join(preclose_failures.get(role, ()))
                        failures.append(f"{role}: pre-close capture health: {details}")
                        integrity_failures.append(f"{role}: pre-close capture health: {details}")
                except Exception as error:
                    row["health_preclose_error"] = str(error)
                    failures.append(f"{role}: pre-close health sampling: {error}")
                    integrity_failures.append(f"{role}: pre-close health sampling: {error}")
                close_results: dict[str, bool] = {}
                close_errors: dict[str, str] = {}
                merged_health: dict[str, dict[str, Any]] = {}
                merged_health_failures: dict[str, list[str]] = {}
                try:
                    close_sessions_and_collect_health(
                        {role: session},
                        close_results,
                        merged_health,
                        merged_health_failures,
                        close_errors,
                    )
                except Exception as error:
                    close_errors[role] = str(error)
                row["close_result"] = close_results.get(role, False)
                row["close_errors"] = dict(close_errors)
                row["health_postclose"] = merged_health.get(role, {})
                if close_errors or not close_results.get(role, False):
                    detail = close_errors.get(role, "session close timed out")
                    failures.append(f"{role}: {detail}")
                    integrity_failures.append(f"{role}: {detail}")
                if merged_health_failures.get(role):
                    details = ", ".join(merged_health_failures[role])
                    failures.append(f"{role}: post-close capture health: {details}")
                    integrity_failures.append(f"{role}: post-close capture health: {details}")
                try:
                    postclose, postclose_failures = session_capture_health({role: session})
                    row["health_postclose_observation"] = postclose.get(role, {})
                    if postclose_failures.get(role):
                        details = ", ".join(postclose_failures[role])
                        failures.append(f"{role}: post-close capture health: {details}")
                        integrity_failures.append(f"{role}: post-close capture health: {details}")
                except Exception as error:
                    row["health_postclose_error"] = str(error)
                    failures.append(f"{role}: post-close health sampling: {error}")
                    integrity_failures.append(f"{role}: post-close health sampling: {error}")
                stream = getattr(getattr(session, "interface", None), "stream", None)
                if stream is not None:
                    try:
                        is_open = getattr(stream, "is_open", None)
                        if callable(is_open):
                            is_open = is_open()
                        closed = getattr(stream, "closed", None)
                        if is_open is True or closed is False:
                            raise BenchmarkError("serial stream remains open after close")
                    except Exception as error:
                        row["stream_close_error"] = str(error)
                        failures.append(f"{role}: stream close: {error}")
                        integrity_failures.append(f"{role}: stream close: {error}")
                try:
                    row["capture_events_postclose"] = _capture_events(session)
                    protocol_failures = _protocol_event_failures(row["capture_events_postclose"])
                    if protocol_failures:
                        raise BenchmarkError(f"capture protocol error: {', '.join(protocol_failures)}")
                except Exception as error:
                    row["capture_events_postclose_error"] = str(error)
                    failures.append(f"{role}: post-close capture events: {error}")
                    integrity_failures.append(f"{role}: post-close capture events: {error}")
                try:
                    _persist_capture(session)
                except Exception as error:
                    row["capture_persistence_error"] = str(error)
                    failures.append(f"{role}: capture persistence: {error}")
                    integrity_failures.append(f"{role}: capture persistence: {error}")
        captured[role] = row

    for role, row in captured.items():
        evaluation = row.get("evaluation")
        if not isinstance(evaluation, Mapping) or evaluation.get("measurement_valid") is not True:
            if isinstance(evaluation, Mapping):
                failures.extend(f"{role}: {reason}" for reason in evaluation.get("failure_reasons", []))
            elif "error" not in row:
                failures.append(f"{role}: missing evaluation")

    if integrity_failures:
        for row in captured.values():
            row["status"] = "invalid"
            row["measurement_valid"] = False
            row["invalidated_by_integrity_failures"] = list(integrity_failures)
            evaluation = row.get("evaluation")
            if isinstance(evaluation, dict):
                evaluation["status"] = "invalid"
                evaluation["measurement_valid"] = False
                reasons = evaluation.setdefault("failure_reasons", [])
                if "collector_integrity_failure" not in reasons:
                    reasons.append("collector_integrity_failure")
            else:
                row["evaluation"] = {
                    "status": "invalid",
                    "measurement_valid": False,
                    "failure_reasons": ["collector_integrity_failure"],
                    "scope": "board_local_owner_radio_timing",
                    "physical_claims": {"rf_delivery": False, "guard_margin": False, "collision_safety": False, "throughput_acceptance": False},
                }

    output_result: dict[str, Any] = {
        "status": "measurement_valid" if not failures else "measurement_invalid",
        "measurement_valid": not failures,
        "scope": "board_local_owner_radio_timing",
        "software_budget": "owner callback timing only",
        "physical_claims": {"rf_delivery": False, "guard_margin": False, "collision_safety": False, "throughput_acceptance": False},
        "existing_run": str(run_dir.resolve()),
        "existing_run_results_sha256": benchmark.sha256_file(result_path),
        "provenance": {
            "application_files_verified_before_open": verified_files,
            "runtime": runtime_provenance,
            "collector_script": {
                "path": str(Path(__file__).resolve()),
                "sha256": _sha256_file(Path(__file__).resolve()),
            },
        },
        "intent": {"control_address": "local_self_only", "operation": SNAPSHOT_OP, "persistent_configuration_writes": False, "rf_control": False},
        "boards": captured,
        "capture_events": {role: row.get("capture_events_postclose", []) for role, row in captured.items()},
        "capture_health": {
            role: {"preclose": row.get("health_preclose", {}), "postclose": row.get("health_postclose", {})}
            for role, row in captured.items()
        },
        "failure_reasons": failures,
        "started_utc": benchmark._utc_now(),
    }
    benchmark._safe_json_write(output / "results.json", output_result)
    return output_result


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
        result = collect_radio_gaps(args.run_dir, args.output, command_gap=args.command_gap, control_timeout=args.control_timeout)
    except Exception as error:
        print(f"RESULT error {type(error).__name__}: {error}", flush=True)
        return 1
    print("RESULT", result["status"], flush=True)
    return 0 if result["measurement_valid"] else 1


if __name__ == "__main__":  # pragma: no cover - hardware entry point
    raise SystemExit(main())


# Protocol-helper aliases used by small host harnesses.
decode_report_frame = decode_report
encode_control_frame = encode_snapshot_control
