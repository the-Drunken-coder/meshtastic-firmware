#!/usr/bin/env python3
"""Run the diagnostic W12 owner-loop benchmark through the local radio API.

The benchmark has two deliberately separate interfaces.  The firmware owns the
producer, RF packet sequence, and receiver bitmap.  This file owns the local
control packets, serial capture, immutable run intent, and fail-closed report.
No command in this module addresses the peer over RF: every control packet is a
PRIVATE_APP packet addressed to the board that supplied the USB connection.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import dataclasses
import datetime as _dt
import hashlib
import json
import os
import platform
import secrets
import sys
import termios
import threading
import time
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

MAGIC = 0x5731
VERSION = 1
CONTROL_BYTES = 32
DATA_HEADER_BYTES = 24
REPORT_BYTES = 86
DEFAULT_SIZE = 219
MAX_SIZE = 219
MAX_COUNT = 8192
MIN_COUNT = 1000
MAX_DURATION_MS = 10 * 60 * 1000
MAX_WINDOW = 16
DEFAULT_WALL_SECONDS = 60.0
DEFAULT_DRAIN_SECONDS = 10.0
DEFAULT_COMMAND_GAP_SECONDS = 0.20
DEFAULT_CONTROL_TIMEOUT_SECONDS = 15.0
DEFAULT_COMPLETION_TIMEOUT_SECONDS = 60.0
CONTROL_RESET = 1
CONTROL_START = 2
CONTROL_STOP = 3
CONTROL_SNAPSHOT = 4
DATA_KIND = 2
REPORT_KIND = 3
FLAG_NONE = 0

BOARD_IDENTITIES: dict[str, tuple[str, int]] = {
    "base": ("44:B1:76:AE:19:14", 2686237816),
    "walker": ("44:B1:76:AE:20:18", 1273374798),
}


class BenchmarkError(RuntimeError):
    """A protocol, identity, timing, or report-integrity failure."""


@dataclasses.dataclass(frozen=True)
class RunConfig:
    run_id: int
    source: int
    destination: int
    count: int
    size: int = DEFAULT_SIZE
    duration_ms: int = int(DEFAULT_WALL_SECONDS * 1000)
    window: int = MAX_WINDOW
    flags: int = FLAG_NONE


@dataclasses.dataclass(frozen=True)
class DataIdentity:
    run_id: int
    source: int
    destination: int
    sequence: int
    size: int
    flags: int


@dataclasses.dataclass(frozen=True)
class FirmwareReport:
    config: RunConfig
    prepared: bool
    running: bool
    complete: bool
    enqueued: int
    send_failures: int
    tx_started: int
    tx_succeeded: int
    tx_failures: int
    tx_dropped: int
    tx_cancelled: int
    received: int
    missing: int
    duplicates: int
    corrupt: int
    out_of_range: int
    elapsed_ms: int
    goodput_bps: int
    raw: bytes = dataclasses.field(repr=False, compare=False, default=b"")


@dataclasses.dataclass(frozen=True)
class CompletionResult:
    report: FirmwareReport | None
    polls: int
    completed_at: float
    timed_out: bool
    timeout_reason: str | None
    stop_sent: bool
    final_snapshot: bool
    stop_error: str | None = None


def _u16(value: int) -> bytes:
    return int(value).to_bytes(2, "little", signed=False)


def _u32(value: int) -> bytes:
    return int(value).to_bytes(4, "little", signed=False)


def _read16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


def _read32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def validate_config(config: RunConfig) -> None:
    values = (config.run_id, config.source, config.destination)
    if any(
        not isinstance(value, int) or value <= 0 or value > 0xFFFFFFFF
        for value in values
    ):
        raise BenchmarkError("run_id and node numbers must be nonzero uint32 values")
    if config.source == config.destination:
        raise BenchmarkError("source and destination must be different")
    if not MIN_COUNT <= config.count <= MAX_COUNT:
        raise BenchmarkError(f"count must be in {MIN_COUNT}..{MAX_COUNT}")
    if config.size != DEFAULT_SIZE:
        raise BenchmarkError(
            f"size must be exactly {DEFAULT_SIZE} for the acceptance run"
        )
    if config.duration_ms != int(DEFAULT_WALL_SECONDS * 1000):
        raise BenchmarkError("duration_ms must be exactly 60000 for the acceptance run")
    if not 1 <= config.window <= MAX_WINDOW:
        raise BenchmarkError(f"window must be in 1..{MAX_WINDOW}")
    if config.flags != FLAG_NONE:
        raise BenchmarkError("the initial firmware contract only accepts flags=0")


def encode_control(config: RunConfig, operation: int) -> bytes:
    """Encode the firmware's exact 32-byte local control frame."""

    validate_config(config)
    if operation not in (CONTROL_RESET, CONTROL_START, CONTROL_STOP, CONTROL_SNAPSHOT):
        raise BenchmarkError(f"unsupported control operation {operation}")
    payload = bytearray(CONTROL_BYTES)
    payload[0:2] = _u16(MAGIC)
    payload[2] = VERSION
    payload[3] = operation
    payload[4:8] = _u32(config.run_id)
    payload[8:12] = _u32(config.source)
    payload[12:16] = _u32(config.destination)
    payload[16:20] = _u32(config.count)
    payload[20:22] = _u16(config.size)
    payload[22:26] = _u32(config.duration_ms)
    payload[26:28] = _u16(config.window)
    payload[28] = config.flags
    return bytes(payload)


def decode_control(payload: bytes) -> tuple[int, RunConfig]:
    if len(payload) != CONTROL_BYTES:
        raise BenchmarkError(f"control payload must be exactly {CONTROL_BYTES} bytes")
    if _read16(payload, 0) != MAGIC or payload[2] != VERSION or any(payload[29:32]):
        raise BenchmarkError("invalid control magic, version, or reserved bytes")
    operation = payload[3]
    config = RunConfig(
        run_id=_read32(payload, 4),
        source=_read32(payload, 8),
        destination=_read32(payload, 12),
        count=_read32(payload, 16),
        size=_read16(payload, 20),
        duration_ms=_read32(payload, 22),
        window=_read16(payload, 26),
        flags=payload[28],
    )
    if operation not in (CONTROL_RESET, CONTROL_START, CONTROL_STOP, CONTROL_SNAPSHOT):
        raise BenchmarkError("invalid control operation")
    validate_config(config)
    return operation, config


def decode_data(payload: bytes) -> tuple[DataIdentity, bytes]:
    """Decode a data frame and retain the complete frame for pattern checks."""

    if not DATA_HEADER_BYTES <= len(payload) <= MAX_SIZE:
        raise BenchmarkError("data frame length is outside the firmware limit")
    if _read16(payload, 0) != MAGIC or payload[2] != VERSION or payload[3] != DATA_KIND:
        raise BenchmarkError("invalid data magic, version, or kind")
    if payload[23] != 0:
        raise BenchmarkError("data reserved byte is not zero")
    identity = DataIdentity(
        run_id=_read32(payload, 4),
        source=_read32(payload, 8),
        destination=_read32(payload, 12),
        sequence=_read32(payload, 16),
        size=_read16(payload, 20),
        flags=payload[22],
    )
    if identity.size != len(payload):
        raise BenchmarkError("data size field does not match frame length")
    return identity, payload


def encode_report(report: FirmwareReport | Mapping[str, Any]) -> bytes:
    """Encode a report for tests and fixture generation."""

    if isinstance(report, Mapping):
        report = report_from_mapping(report)
    payload = bytearray(REPORT_BYTES)
    payload[0:2] = _u16(MAGIC)
    payload[2] = VERSION
    payload[3] = REPORT_KIND
    config = report.config
    payload[4:8] = _u32(config.run_id)
    payload[8:12] = _u32(config.source)
    payload[12:16] = _u32(config.destination)
    payload[16:20] = _u32(config.count)
    payload[20:22] = _u16(config.size)
    payload[22:26] = _u32(config.duration_ms)
    payload[26:28] = _u16(config.window)
    payload[28] = config.flags
    payload[29] = (
        int(report.prepared) | (int(report.running) << 1) | (int(report.complete) << 2)
    )
    fields = (
        report.enqueued,
        report.send_failures,
        report.tx_started,
        report.tx_succeeded,
        report.tx_failures,
        report.tx_dropped,
        report.tx_cancelled,
        report.received,
        report.missing,
        report.duplicates,
        report.corrupt,
        report.out_of_range,
        report.elapsed_ms,
        report.goodput_bps,
    )
    offset = 30
    for value in fields:
        payload[offset : offset + 4] = _u32(value)
        offset += 4
    return bytes(payload)


def decode_report(payload: bytes) -> FirmwareReport:
    if len(payload) != REPORT_BYTES:
        raise BenchmarkError(f"report payload must be exactly {REPORT_BYTES} bytes")
    if (
        _read16(payload, 0) != MAGIC
        or payload[2] != VERSION
        or payload[3] != REPORT_KIND
    ):
        raise BenchmarkError("invalid report magic, version, or kind")
    config = RunConfig(
        run_id=_read32(payload, 4),
        source=_read32(payload, 8),
        destination=_read32(payload, 12),
        count=_read32(payload, 16),
        size=_read16(payload, 20),
        duration_ms=_read32(payload, 22),
        window=_read16(payload, 26),
        flags=payload[28],
    )
    status = payload[29]
    if status & ~0x07:
        raise BenchmarkError("report contains unknown status bits")
    values = []
    for offset in range(30, REPORT_BYTES, 4):
        values.append(_read32(payload, offset))
    return FirmwareReport(
        config=config,
        prepared=bool(status & 1),
        running=bool(status & 2),
        complete=bool(status & 4),
        enqueued=values[0],
        send_failures=values[1],
        tx_started=values[2],
        tx_succeeded=values[3],
        tx_failures=values[4],
        tx_dropped=values[5],
        tx_cancelled=values[6],
        received=values[7],
        missing=values[8],
        duplicates=values[9],
        corrupt=values[10],
        out_of_range=values[11],
        elapsed_ms=values[12],
        goodput_bps=values[13],
        raw=bytes(payload),
    )


def report_from_mapping(value: Mapping[str, Any]) -> FirmwareReport:
    """Accept firmware-style camelCase and Python-style snake_case fixtures."""

    def get(name: str, alternate: str | None = None, default: Any = None) -> Any:
        if name in value:
            return value[name]
        if alternate is not None and alternate in value:
            return value[alternate]
        return default

    config_value = value.get("config", value)
    if not isinstance(config_value, Mapping):
        raise BenchmarkError("report config is missing")
    config = RunConfig(
        run_id=int(config_value.get("run_id", config_value.get("runId", 0))),
        source=int(config_value.get("source", 0)),
        destination=int(config_value.get("destination", 0)),
        count=int(config_value.get("count", 0)),
        size=int(config_value.get("size", 0)),
        duration_ms=int(
            config_value.get("duration_ms", config_value.get("durationMs", 0))
        ),
        window=int(config_value.get("window", 0)),
        flags=int(config_value.get("flags", 0)),
    )
    return FirmwareReport(
        config=config,
        prepared=bool(get("prepared", default=False)),
        running=bool(get("running", default=False)),
        complete=bool(get("complete", default=False)),
        enqueued=int(get("enqueued", default=0)),
        send_failures=int(get("send_failures", "sendFailures", 0)),
        tx_started=int(get("tx_started", "txStarted", 0)),
        tx_succeeded=int(get("tx_succeeded", "txSucceeded", 0)),
        tx_failures=int(get("tx_failures", "txFailures", 0)),
        tx_dropped=int(get("tx_dropped", "txDropped", 0)),
        tx_cancelled=int(get("tx_cancelled", "txCancelled", 0)),
        received=int(get("received", default=0)),
        missing=int(get("missing", default=0)),
        duplicates=int(get("duplicates", default=0)),
        corrupt=int(get("corrupt", default=0)),
        out_of_range=int(get("out_of_range", "outOfRange", 0)),
        elapsed_ms=int(get("elapsed_ms", "elapsedMs", 0)),
        goodput_bps=int(get("goodput_bps", "goodputBps", 0)),
    )


def _report_dict(report: FirmwareReport | None) -> dict[str, Any] | None:
    if report is None:
        return None
    return {
        "run_id": report.config.run_id,
        "source": report.config.source,
        "destination": report.config.destination,
        "count": report.config.count,
        "size": report.config.size,
        "duration_ms": report.config.duration_ms,
        "window": report.config.window,
        "flags": report.config.flags,
        "prepared": report.prepared,
        "running": report.running,
        "complete": report.complete,
        "enqueued": report.enqueued,
        "send_failures": report.send_failures,
        "tx_started": report.tx_started,
        "tx_succeeded": report.tx_succeeded,
        "tx_failures": report.tx_failures,
        "tx_dropped": report.tx_dropped,
        "tx_cancelled": report.tx_cancelled,
        "received": report.received,
        "missing": report.missing,
        "duplicates": report.duplicates,
        "corrupt": report.corrupt,
        "out_of_range": report.out_of_range,
        "elapsed_ms": report.elapsed_ms,
        "goodput_bps": report.goodput_bps,
    }


def fixed_wall_goodput_bytes_per_second(
    received: int, size: int, wall_seconds: float
) -> float:
    if wall_seconds <= 0:
        raise BenchmarkError("wall_seconds must be positive")
    if received < 0 or size <= 0:
        raise BenchmarkError("received and size must be nonnegative/positive")
    return (received * size) / wall_seconds


def _same_config(left: RunConfig, right: RunConfig) -> bool:
    return left == right


def evaluate_reports(
    expected: RunConfig,
    sender: FirmwareReport | Mapping[str, Any] | None,
    receiver: FirmwareReport | Mapping[str, Any] | None,
    *,
    wall_seconds: float = DEFAULT_WALL_SECONDS,
    drain_seconds: float = DEFAULT_DRAIN_SECONDS,
    observed_wall_seconds: float | None = None,
    observed_drain_seconds: float | None = None,
    auth_ack_count: int | None = None,
    auth_ack_supported: bool = False,
    peer_bitmap: Mapping[str, Any] | None = None,
    extra_failure_reasons: Iterable[str] = (),
) -> dict[str, Any]:
    """Produce a fail-closed report from aggregate firmware snapshots.

    A measurement is valid only when both endpoints identify the same run, the
    sender admitted at least the minimum trusted count, both snapshots are
    complete, and the fixed wall and drain windows were actually observed.
    The configured count is a producer cap and is reported separately.
    Goodput always uses the configured wall duration, so a short success span
    cannot inflate it. Both the 219-byte envelope and 195-byte pattern payload
    rates are exposed; the ratio is diagnostic because endpoint windows differ.
    """

    validate_config(expected)
    if isinstance(sender, Mapping):
        sender = report_from_mapping(sender)
    if isinstance(receiver, Mapping):
        receiver = report_from_mapping(receiver)
    reasons: list[str] = []
    if wall_seconds <= 0:
        reasons.append("invalid_wall_window")
    elif abs(wall_seconds - DEFAULT_WALL_SECONDS) > 1e-6:
        reasons.append("fixed_wall_not_60_seconds")
    if drain_seconds < 0:
        reasons.append("invalid_drain_window")
    if sender is None:
        reasons.append("missing_sender_stats")
    if receiver is None:
        reasons.append("missing_receiver_stats")
    if sender is not None and not _same_config(sender.config, expected):
        reasons.append("sender_identity_mismatch")
    if receiver is not None and not _same_config(receiver.config, expected):
        reasons.append("receiver_identity_mismatch")
    if sender is not None and not sender.prepared:
        reasons.append("sender_not_prepared")
    if receiver is not None and not receiver.prepared:
        reasons.append("receiver_not_prepared")
    if sender is not None and not sender.complete:
        reasons.append("sender_incomplete")
    if receiver is not None and not receiver.complete:
        reasons.append("receiver_incomplete")
    if sender is not None and sender.running:
        reasons.append("sender_still_running")
    if receiver is not None and receiver.running:
        reasons.append("receiver_still_running")
    cap_reached = False
    terminal_count = None
    if sender is not None:
        cap_reached = sender.enqueued >= expected.count
        terminal_count = (
            sender.tx_succeeded
            + sender.tx_failures
            + sender.tx_dropped
            + sender.tx_cancelled
        )
        if sender.enqueued < MIN_COUNT or sender.enqueued > expected.count:
            reasons.append("sender_count_mismatch")
        if sender.send_failures:
            reasons.append("sender_send_failures")
        if sender.tx_started != sender.enqueued:
            reasons.append("sender_tx_started_mismatch")
        if terminal_count != sender.tx_started:
            reasons.append("sender_physical_terminal_incomplete")
        if sender.tx_succeeded < MIN_COUNT:
            reasons.append("sender_physical_results_below_minimum")
        if sender.tx_failures or sender.tx_dropped or sender.tx_cancelled:
            reasons.append("sender_physical_terminal_failure")
    if receiver is not None:
        if terminal_count is not None and receiver.received > terminal_count:
            reasons.append("receiver_exceeds_physical_sender")
        if (
            terminal_count is not None
            and receiver.received + max(terminal_count - receiver.received, 0)
            < MIN_COUNT
        ):
            reasons.append("receiver_denominator_incomplete")
        if receiver.received > expected.count:
            reasons.append("receiver_count_exceeds_expected")
        if receiver.received == 0:
            reasons.append("receiver_zero_results")
        if (
            receiver.complete
            and not receiver.running
            and receiver.received == 0
            and receiver.elapsed_ms == 0
        ):
            reasons.append("no_first_authenticated_frame_in_finite_window")
    if observed_wall_seconds is None or observed_wall_seconds + 1e-6 < wall_seconds:
        reasons.append("wall_window_timeout")
    if observed_drain_seconds is None or observed_drain_seconds + 1e-6 < drain_seconds:
        reasons.append("drain_window_timeout")
    if sender is not None and sender.elapsed_ms <= 0:
        reasons.append("sender_zero_elapsed")
    if receiver is not None and receiver.elapsed_ms <= 0:
        reasons.append("receiver_zero_elapsed")
    if sender is not None and sender.elapsed_ms != expected.duration_ms:
        reasons.append("sender_elapsed_out_of_window")
    if receiver is not None and receiver.elapsed_ms != expected.duration_ms:
        reasons.append("receiver_elapsed_out_of_window")
    reasons.extend(extra_failure_reasons)

    sender_snapshot_valid = (
        sender is not None
        and _same_config(sender.config, expected)
        and sender.prepared
        and sender.complete
        and not sender.running
        and sender.elapsed_ms == expected.duration_ms
    )
    receiver_snapshot_valid = (
        receiver is not None
        and _same_config(receiver.config, expected)
        and receiver.prepared
        and receiver.complete
        and not receiver.running
        and receiver.elapsed_ms == expected.duration_ms
    )
    sender_counters_valid = (
        sender_snapshot_valid
        and sender.enqueued >= MIN_COUNT
        and sender.enqueued <= expected.count
        and sender.send_failures == 0
        and sender.tx_started == sender.enqueued
        and terminal_count == sender.tx_started
        and sender.tx_succeeded >= MIN_COUNT
        and sender.tx_failures == 0
        and sender.tx_dropped == 0
        and sender.tx_cancelled == 0
    )
    receiver_counters_valid = (
        receiver_snapshot_valid
        and receiver.received > 0
        and receiver.received <= expected.count
        and terminal_count is not None
        and receiver.received <= terminal_count
    )
    physical_tx_terminal_complete = sender_counters_valid
    aggregate_receiver_bitmap_authoritative = (
        sender_counters_valid and receiver_counters_valid
    )

    received = receiver.received if receiver is not None else 0
    physical_sent = sender.tx_succeeded if sender is not None else None
    missing = max(physical_sent - received, 0) if physical_sent is not None else None
    diagnostic_authenticated_rx_over_tx_done = (
        received / physical_sent
        if physical_sent is not None and physical_sent > 0
        else None
    )
    goodput = (
        fixed_wall_goodput_bytes_per_second(received, expected.size, wall_seconds)
        if wall_seconds > 0
        else None
    )
    pattern_bytes = expected.size - DATA_HEADER_BYTES
    pattern_goodput = (
        fixed_wall_goodput_bytes_per_second(received, pattern_bytes, wall_seconds)
        if wall_seconds > 0 and pattern_bytes > 0
        else None
    )
    result: dict[str, Any] = {
        "status": "measurement_valid" if not reasons else "measurement_invalid",
        "measurement_valid": not reasons,
        "failure_reasons": list(dict.fromkeys(reasons)),
        "run": dataclasses.asdict(expected),
        "sender": _report_dict(sender),
        "receiver": _report_dict(receiver),
        "counts": {
            "expected": expected.count,
            "sent": sender.enqueued if sender is not None else None,
            "physical_sent": sender.tx_succeeded if sender is not None else None,
            "physical_terminal_total": terminal_count,
            "physical_terminal": {
                "tx_started": sender.tx_started if sender is not None else None,
                "tx_succeeded": sender.tx_succeeded if sender is not None else None,
                "tx_failures": sender.tx_failures if sender is not None else None,
                "tx_dropped": sender.tx_dropped if sender is not None else None,
                "tx_cancelled": sender.tx_cancelled if sender is not None else None,
            },
            "exact_unique": receiver.received if receiver is not None else None,
            "duplicate": receiver.duplicates if receiver is not None else None,
            "corrupt": receiver.corrupt if receiver is not None else None,
            "out_of_range": receiver.out_of_range if receiver is not None else None,
            # The firmware's missing field is config.count - received. The
            # host metric is a cross-endpoint count gap. It is not an exact
            # RF-missing count or a packet error rate because the receiver
            # window starts on its first authenticated RF frame.
            "tx_receipt_count_gap": missing,
            "firmware_missing": receiver.missing if receiver is not None else None,
        },
        "admission": {
            "configured_cap": expected.count,
            "admitted": sender.enqueued if sender is not None else None,
            "producer_cap_reached": cap_reached,
            "minimum_trusted_admitted": MIN_COUNT,
            "physical_tx_succeeded": physical_sent,
            "physical_terminal_total": terminal_count,
        },
        "diagnostic_authenticated_rx_over_tx_done": diagnostic_authenticated_rx_over_tx_done,
        # Compatibility alias retained for existing result consumers. It is a
        # diagnostic ratio across independent endpoint windows, not transport
        # acceptance, delivery success, or PER.
        "delivery_fraction": diagnostic_authenticated_rx_over_tx_done,
        "delivery_fraction_semantics": "diagnostic_authenticated_rx_over_tx_done across independent sender and receiver windows",
        "capture_validity": {
            "sender_report_present": sender is not None,
            "receiver_report_present": receiver is not None,
            "sender_snapshot_valid": sender_snapshot_valid,
            "receiver_snapshot_valid": receiver_snapshot_valid,
            "physical_tx_terminal_complete": physical_tx_terminal_complete,
            "aggregate_receiver_bitmap_authoritative": aggregate_receiver_bitmap_authoritative,
            "host_sequence_capture_authoritative": False,
            "host_sequence_capture_note": "Benchmark DATA is intentionally suppressed from phone forwarding; aggregate firmware counters are authoritative.",
        },
        "sequence": {
            "first": 0,
            "last": expected.count - 1,
            "count": expected.count,
            "run_id": expected.run_id,
        },
        "peer_bitmap": dict(peer_bitmap or {}),
        "firmware_auth_ack": {
            "supported": bool(auth_ack_supported),
            "count": auth_ack_count,
        },
        "transport_acceptance": "not_evaluated_no_ack",
        "time_window": {
            "fixed_wall_seconds": wall_seconds,
            "observed_wall_seconds": observed_wall_seconds,
            "observed_drain_seconds": observed_drain_seconds,
            "drain_seconds_required": drain_seconds,
            "sender_anchor": "sender_START_return",
            "receiver_anchor": "first_authenticated_rf_data",
            "boundary_note": "TX/receipt count gap spans independent sender and receiver windows; it is not exact RF missing or PER.",
        },
        "fixed_wall_goodput_Bps": goodput,
        "fixed_wall_goodput_bps": goodput * 8 if goodput is not None else None,
        "fixed_wall_goodput_envelope_Bps": goodput,
        "fixed_wall_goodput_envelope_bps": goodput * 8 if goodput is not None else None,
        "fixed_wall_goodput_pattern_Bps": pattern_goodput,
        "fixed_wall_goodput_pattern_bps": (
            pattern_goodput * 8 if pattern_goodput is not None else None
        ),
        "goodput_envelope_bytes": expected.size,
        "goodput_payload_bytes": expected.size,
        "goodput_pattern_bytes": pattern_bytes,
    }
    return result


# Short aliases make the pure protocol helpers convenient for external checks.
encode_control_frame = encode_control
decode_control_frame = decode_control
decode_report_frame = decode_report
evaluate_report = evaluate_reports


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_json_write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    encoded = (
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(fd)
        raise


def _safe_bytes_write(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(value)
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(fd)
        raise


def _utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _portnum_private_app() -> int:
    try:
        from meshtastic.protobuf import portnums_pb2

        return int(portnums_pb2.PRIVATE_APP)
    except ImportError:
        return 256


def _load_meshtastic() -> tuple[Any, Any, Any, Any, Any]:
    try:
        import serial
        from meshtastic.protobuf import mesh_pb2, portnums_pb2
        from meshtastic.serial_interface import SerialInterface
        from meshtastic.stream_interface import StreamInterface
    except ImportError as error:  # pragma: no cover - hardware-only path
        raise BenchmarkError(
            "the pinned Meshtastic client and pyserial are required"
        ) from error
    return serial, mesh_pb2, portnums_pb2, (SerialInterface, StreamInterface)


def clear_hupcl(connection: Any) -> None:
    attrs = termios.tcgetattr(connection.fileno())
    attrs[2] &= ~termios.HUPCL
    termios.tcsetattr(connection.fileno(), termios.TCSAFLUSH, attrs)


class _EventCapture:
    def __init__(self, role: str, output: Path, checkpoint: Any = None) -> None:
        self.role = role
        self.output = output
        self.checkpoint = checkpoint
        self.condition = threading.Condition()
        self.events: list[dict[str, Any]] = []

    def record(self, kind: str, **values: Any) -> dict[str, Any]:
        event = {
            "utc": _utc_now(),
            "monotonic": time.monotonic(),
            "role": self.role,
            "kind": kind,
            **values,
        }
        with self.condition:
            self.events.append(event)
            self.condition.notify_all()
        if self.checkpoint is not None and kind.startswith("control_"):
            self.checkpoint(f"event_{kind}")
        return event

    def snapshot(self) -> list[dict[str, Any]]:
        with self.condition:
            return list(self.events)

    def persist(self) -> None:
        _safe_json_write(
            self.output / self.role / "capture-events.json", self.snapshot()
        )

    def wait_for(self, predicate: Any, timeout: float) -> dict[str, Any] | None:
        deadline = time.monotonic() + timeout
        with self.condition:
            while True:
                for event in self.events:
                    if predicate(event):
                        return event
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self.condition.wait(min(remaining, 0.25))


def _make_capture_serial_classes() -> tuple[Any, Any, Any, Any]:
    serial, mesh_pb2, portnums_pb2, interfaces = _load_meshtastic()
    serial_interface, stream_interface = interfaces

    class PreserveControlSerial(serial.Serial):
        def _update_dtr_state(self) -> None:
            return

        def _update_rts_state(self) -> None:
            return

    class CapturingSerial(serial_interface):
        def __init__(self, *args: Any, capture: _EventCapture, **kwargs: Any) -> None:
            self.capture = capture
            self._command_lock = threading.Lock()
            super().__init__(*args, **kwargs)

        def connect(self) -> None:
            if self.devPath is None:
                raise BenchmarkError(f"{self.capture.role}: no serial path")
            # Clear HUPCL before opening the port as well as after opening it.
            # The pyserial subclass suppresses its DTR/RTS updates entirely.
            with open(self.devPath, encoding="utf8") as descriptor:
                clear_hupcl(descriptor)
            self.stream = PreserveControlSerial(
                self.devPath, 115200, exclusive=True, timeout=0.5, write_timeout=3
            )
            clear_hupcl(self.stream)
            stream_interface.connect(self)

        def _is_local_w12_control(self, to_radio: Any) -> bool:
            if not to_radio.HasField("packet"):
                return False
            packet = to_radio.packet
            local_node = getattr(self, "node_num", None)
            if local_node is None and getattr(self, "myInfo", None) is not None:
                local_node = getattr(self.myInfo, "my_node_num", None)
            try:
                if local_node is None or int(local_node) <= 0:
                    return False
                if (
                    int(packet.to) != int(local_node)
                    or int(getattr(packet, "from")) != 0
                ):
                    return False
                if bool(packet.want_ack) or bool(packet.pki_encrypted):
                    return False
                if not packet.HasField("decoded"):
                    return False
                if int(packet.decoded.portnum) != _portnum_private_app():
                    return False
                decode_control(bytes(packet.decoded.payload))
            except (BenchmarkError, TypeError, ValueError):
                return False
            return True

        def _sendToRadio(self, to_radio: Any) -> None:
            # Local controls and protocol frames must not wait on the SDK's
            # cached RF queue; every other MeshPacket retains that behavior.
            if self.noProto:
                super()._sendToRadio(to_radio)
                return
            if not to_radio.HasField("packet") or self._is_local_w12_control(to_radio):
                self._sendToRadioImpl(to_radio)
                return
            super()._sendToRadio(to_radio)

        def _writeBytes(self, data: bytes) -> None:
            if self.stream:
                with self.serial_write_lock:
                    written = self.stream.write(data)
                    self.stream.flush()
                    if written != len(data):
                        raise BenchmarkError(
                            f"{self.capture.role}: incomplete USB write"
                        )

        def _handleFromRadio(self, data: bytes) -> None:
            incoming = mesh_pb2.FromRadio()
            try:
                incoming.ParseFromString(data)
            except Exception:
                self.capture.record(
                    "protocol_error", message="invalid FromRadio protobuf"
                )
                raise
            if incoming.HasField("packet"):
                packet = incoming.packet
                payload = (
                    bytes(packet.decoded.payload) if packet.HasField("decoded") else b""
                )
                portnum = (
                    int(packet.decoded.portnum) if packet.HasField("decoded") else None
                )
                event: dict[str, Any] = {
                    "packet_id": int(packet.id),
                    "to": int(packet.to),
                    "from": int(getattr(packet, "from")),
                    "portnum": portnum,
                    "payload_size": len(payload),
                    "payload_sha256": sha256_bytes(payload),
                    "request_id": (
                        int(packet.decoded.request_id)
                        if packet.HasField("decoded")
                        else 0
                    ),
                }
                if portnum == int(portnums_pb2.PRIVATE_APP):
                    try:
                        event["report"] = _report_dict(decode_report(payload))
                    except BenchmarkError:
                        try:
                            identity, _ = decode_data(payload)
                            event["data_identity"] = dataclasses.asdict(identity)
                        except BenchmarkError:
                            pass
                self.capture.record("packet", **event)
            elif incoming.HasField("queueStatus"):
                self.capture.record(
                    "queue_status",
                    mesh_packet_id=int(incoming.queueStatus.mesh_packet_id),
                    free=int(incoming.queueStatus.free),
                    res=int(incoming.queueStatus.res),
                )
            super()._handleFromRadio(data)

    return PreserveControlSerial, CapturingSerial, mesh_pb2, portnums_pb2


class BoardSession:
    """Identity-pinned USB session with concurrent reader and serialized commands."""

    def __init__(
        self,
        role: str,
        output: Path,
        command_gap: float = DEFAULT_COMMAND_GAP_SECONDS,
        checkpoint: Any = None,
    ) -> None:
        PreserveControlSerial, CapturingSerial, _mesh_pb2, _portnums = (
            _make_capture_serial_classes()
        )
        del PreserveControlSerial, _mesh_pb2, _portnums
        try:
            from serial.tools import list_ports
        except ImportError as error:  # pragma: no cover - hardware-only path
            raise BenchmarkError("pyserial is required") from error
        if role not in BOARD_IDENTITIES:
            raise BenchmarkError(f"unknown board role {role}")
        serial_identity, expected_node = BOARD_IDENTITIES[role]
        ports = [
            port
            for port in list_ports.comports()
            if port.serial_number == serial_identity
        ]
        if len(ports) != 1:
            raise BenchmarkError(
                f"{role}: expected one USB identity, found {len(ports)}"
            )
        self.role = role
        self.identity = serial_identity
        self.expected_node = expected_node
        self.dev_path = ports[0].device
        self.capture = _EventCapture(role, output, checkpoint)
        self.command_gap = command_gap
        self.last_command = 0.0
        self._last_control: dict[int, float] = {}
        self._interface = CapturingSerial(
            self.dev_path, connectNow=False, timeout=30, capture=self.capture
        )
        self._interface.board = role
        self._interface.serial_write_lock = threading.Lock()
        self._interface.connect()
        self._interface.waitForConfig()
        actual = int(self._interface.myInfo.my_node_num)
        if actual != expected_node:
            self.close()
            raise BenchmarkError(
                f"{role}: node identity mismatch ({actual} != {expected_node})"
            )
        self.node_num = actual

    @property
    def interface(self) -> Any:
        return self._interface

    def _pace(self) -> None:
        remaining = self.last_command + self.command_gap - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)

    def control(
        self, operation: int, config: RunConfig, *, want_response: bool = False
    ) -> int:
        payload = encode_control(config, operation)
        with self._interface._command_lock:
            self._pace()
            sent_at = time.monotonic()
            self.capture.record(
                "control_attempt",
                operation=operation,
                run_id=config.run_id,
                source=config.source,
                destination=config.destination,
                count=config.count,
                size=config.size,
                payload_sha256=sha256_bytes(payload),
                local_destination=self.node_num,
            )
            packet = self._interface.sendData(
                payload,
                destinationId=self.node_num,
                portNum=_portnum_private_app(),
                wantAck=False,
                wantResponse=want_response,
                pkiEncrypted=False,
            )
            if int(packet.to) != self.node_num or int(getattr(packet, "from")) != 0:
                raise BenchmarkError(f"{self.role}: control escaped local self address")
            self.last_command = sent_at
            self._last_control[int(packet.id)] = sent_at
            self.capture.record(
                "control_intent",
                operation=operation,
                packet_id=int(packet.id),
                run_id=config.run_id,
                source=config.source,
                destination=config.destination,
                count=config.count,
                size=config.size,
                payload_sha256=sha256_bytes(payload),
                local_destination=self.node_num,
            )
            return int(packet.id)

    def snapshot(self, config: RunConfig, timeout: float) -> FirmwareReport:
        packet_id = self.control(CONTROL_SNAPSHOT, config, want_response=True)
        event = self.capture.wait_for(
            lambda item: item["kind"] == "packet"
            and item.get("request_id") == packet_id
            and item.get("report") is not None,
            timeout,
        )
        if event is None:
            raise BenchmarkError(f"{self.role}: snapshot response timed out")
        return report_from_mapping(event["report"])

    def snapshot_config(self, output: Path, label: str) -> dict[str, Any]:
        node = self._interface.localNode
        local = node.localConfig.SerializeToString()
        module = node.moduleConfig.SerializeToString()
        channels = b"".join(channel.SerializeToString() for channel in node.channels)
        base = output / self.role
        _safe_bytes_write(base / f"{label}-local-config.pb", local)
        _safe_bytes_write(base / f"{label}-module-config.pb", module)
        _safe_bytes_write(base / f"{label}-channels.pb", channels)
        lora = getattr(node.localConfig, "lora", None)
        return {
            "role": self.role,
            "usb_identity": self.identity,
            "port": self.dev_path,
            "node_num": self.node_num,
            "local_config_sha256": sha256_bytes(local),
            "module_config_sha256": sha256_bytes(module),
            "channels_sha256": sha256_bytes(channels),
            "local_config_bytes": len(local),
            "module_config_bytes": len(module),
            "channel_count": len(node.channels),
            "region": int(getattr(lora, "region", 0)) if lora is not None else None,
            "lora_sha256": (
                sha256_bytes(lora.SerializeToString()) if lora is not None else None
            ),
            "private_key_sha256": sha256_bytes(
                bytes(getattr(node.localConfig.security, "private_key", b""))
            ),
            "public_key_sha256": sha256_bytes(
                bytes(getattr(node.localConfig.security, "public_key", b""))
            ),
        }

    def close(self, timeout: float = 5.0) -> bool:
        """Stop the reader and close USB without entering the SDK queue drain."""

        interface = self._interface
        heartbeat = getattr(interface, "heartbeatTimer", None)
        if heartbeat is not None:
            with contextlib.suppress(Exception):
                heartbeat.cancel()
        with contextlib.suppress(Exception):
            interface._wantExit = True
        reader = getattr(interface, "_rxThread", None)
        if (
            reader is not None
            and reader is not threading.current_thread()
            and reader.is_alive()
        ):
            with contextlib.suppress(Exception):
                reader.join(max(0.0, timeout))
        alive = bool(reader is not None and reader.is_alive())
        if alive:
            # The SDK reader owns normal stream shutdown. If a driver ignores
            # _wantExit past the bounded join, force the port closed as a
            # last-resort failure path and report it as unusable to the caller.
            stream = getattr(interface, "stream", None)
            if stream is not None:
                with contextlib.suppress(Exception):
                    stream.close()
            with contextlib.suppress(Exception):
                reader.join(min(max(0.0, timeout), 0.5))
            alive = reader.is_alive()
        else:
            # A reader that already exited has closed the stream itself. Only
            # an unstarted or absent reader leaves the host responsible for it.
            stream = getattr(interface, "stream", None)
            if stream is not None:
                with contextlib.suppress(Exception):
                    stream.close()
                with contextlib.suppress(Exception):
                    interface.stream = None
        with contextlib.suppress(Exception):
            self.capture.persist()
        return not alive


def _configuration_preserved(
    before: Mapping[str, Mapping[str, Any]],
    after: Mapping[str, Mapping[str, Any]],
) -> bool:
    fields = (
        "local_config_sha256",
        "module_config_sha256",
        "channels_sha256",
        "local_config_bytes",
        "module_config_bytes",
        "channel_count",
        "region",
        "lora_sha256",
        "private_key_sha256",
        "public_key_sha256",
    )
    return set(before) == set(after) and all(
        all(before[role].get(field) == after[role].get(field) for field in fields)
        for role in before
    )


def _fresh_config_snapshots(
    output: Path,
    roles: Iterable[str],
    command_gap: float,
    session_factory: Any = BoardSession,
) -> dict[str, dict[str, Any]]:
    """Read each board's config through a new identity-pinned session."""

    snapshots: dict[str, dict[str, Any]] = {}
    for role in roles:
        session = session_factory(role, output, command_gap)
        try:
            snapshots[role] = session.snapshot_config(output, "after")
        finally:
            if session.close() is False:
                raise BenchmarkError(
                    f"{role}: fresh config session close timed out; port remains occupied"
                )
    return snapshots


def _snapshot_until_complete(
    session: BoardSession,
    config: RunConfig,
    *,
    timeout: float,
    poll_interval: float,
) -> CompletionResult:
    """Poll status, then stop and snapshot once when the finite poll expires."""

    deadline = time.monotonic() + timeout
    polls = 0
    last_report: FirmwareReport | None = None
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            report = session.snapshot(
                config, min(session.command_gap + timeout, remaining)
            )
        except BenchmarkError:
            break
        polls += 1
        last_report = report
        if report.complete and not report.running:
            return CompletionResult(
                report=report,
                polls=polls,
                completed_at=time.monotonic(),
                timed_out=False,
                timeout_reason=None,
                stop_sent=False,
                final_snapshot=False,
            )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(poll_interval, remaining))

    stop_sent = False
    stop_error: str | None = None
    try:
        session.control(CONTROL_STOP, config)
        stop_sent = True
    except BenchmarkError as error:
        stop_error = str(error)

    final_snapshot = False
    try:
        final_report = session.snapshot(config, max(session.command_gap, 1.0))
        polls += 1
        last_report = final_report
        final_snapshot = True
    except BenchmarkError:
        pass

    timeout_reason = (
        "no_first_authenticated_frame_in_finite_window"
        if last_report is not None
        and last_report.received == 0
        and last_report.elapsed_ms == 0
        else "receiver_completion_timeout"
    )
    return CompletionResult(
        report=last_report,
        polls=polls,
        completed_at=time.monotonic(),
        timed_out=True,
        timeout_reason=timeout_reason,
        stop_sent=stop_sent,
        final_snapshot=final_snapshot,
        stop_error=stop_error,
    )


def _peer_bitmap(
    sessions: Mapping[str, BoardSession], sender: str, receiver: str
) -> dict[str, Any]:
    sender_session = sessions[sender]
    receiver_session = sessions[receiver]
    sender_peers = getattr(sender_session.interface, "nodesByNum", {})
    receiver_peers = getattr(receiver_session.interface, "nodesByNum", {})
    sender_peer = _peer_entry(sender_peers, receiver_session.node_num)
    receiver_peer = _peer_entry(receiver_peers, sender_session.node_num)
    sender_peer_key = _public_key_bytes(sender_peer)
    receiver_peer_key = _public_key_bytes(receiver_peer)
    sender_local_key = _local_public_key_bytes(sender_session)
    receiver_local_key = _local_public_key_bytes(receiver_session)
    if sender_local_key is None:
        raise BenchmarkError(f"{sender}_local_public_key_missing_or_invalid")
    if receiver_local_key is None:
        raise BenchmarkError(f"{receiver}_local_public_key_missing_or_invalid")
    if sender_peer_key is None:
        raise BenchmarkError(f"{sender}_peer_public_key_missing_or_invalid")
    if receiver_peer_key is None:
        raise BenchmarkError(f"{receiver}_peer_public_key_missing_or_invalid")
    if sender_peer_key != receiver_local_key:
        raise BenchmarkError(f"{sender}_peer_public_key_mismatch")
    if receiver_peer_key != sender_local_key:
        raise BenchmarkError(f"{receiver}_peer_public_key_mismatch")
    return {
        "mask": 3,
        "sender_knows_receiver": True,
        "receiver_knows_sender": True,
        "sender_node": sender_session.node_num,
        "receiver_node": receiver_session.node_num,
        "sender_peer_public_key_sha256": sha256_bytes(sender_peer_key),
        "receiver_peer_public_key_sha256": sha256_bytes(receiver_peer_key),
        "sender_local_public_key_sha256": sha256_bytes(sender_local_key),
        "receiver_local_public_key_sha256": sha256_bytes(receiver_local_key),
    }


def _peer_entry(peers: Any, node_num: int) -> Any:
    if not isinstance(peers, Mapping):
        return None
    return peers.get(node_num, peers.get(str(node_num)))


def _public_key_bytes(entry: Any) -> bytes | None:
    if not isinstance(entry, Mapping):
        return None
    user = entry.get("user")
    if not isinstance(user, Mapping):
        return None
    value = user.get("publicKey", user.get("public_key"))
    return _decode_public_key(value)


def _local_public_key_bytes(session: BoardSession) -> bytes | None:
    node = getattr(session.interface, "localNode", None)
    config = getattr(node, "localConfig", None)
    security = getattr(config, "security", None)
    return _decode_public_key(getattr(security, "public_key", None))


def _decode_public_key(value: Any) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            encoded = value.strip().encode("ascii")
        except UnicodeEncodeError:
            return None
    elif isinstance(value, (bytes, bytearray, memoryview)):
        encoded = bytes(value)
        if len(encoded) == 32:
            return encoded
    else:
        return None
    if not encoded:
        return None
    padded = encoded + b"=" * (-len(encoded) % 4)
    try:
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        return None
    return decoded if len(decoded) == 32 else None


def _sequence_capture_summary(
    events: Iterable[Mapping[str, Any]], expected: RunConfig
) -> dict[str, Any]:
    sequences: set[int] = set()
    run_ids: set[int] = set()
    invalid = 0
    for event in events:
        identity = event.get("data_identity")
        if not isinstance(identity, Mapping):
            continue
        run_ids.add(int(identity.get("run_id", 0)))
        sequence = int(identity.get("sequence", -1))
        if (
            int(identity.get("run_id", 0)) != expected.run_id
            or int(identity.get("source", 0)) != expected.source
            or int(identity.get("destination", 0)) != expected.destination
            or int(identity.get("size", 0)) != expected.size
            or int(identity.get("flags", 0)) != expected.flags
            or sequence < 0
            or sequence >= expected.count
        ):
            invalid += 1
            continue
        sequences.add(sequence)
    bitmap = bytearray((expected.count + 7) // 8)
    for sequence in sequences:
        bitmap[sequence // 8] |= 1 << (sequence % 8)
    return {
        "run_ids": sorted(run_ids),
        "unique_sequences": len(sequences),
        "invalid_frames": invalid,
        "sequence_bitmap_sha256": sha256_bytes(bytes(bitmap)),
        "sequence_bitmap_hex": bytes(bitmap).hex(),
    }


def _script_digest() -> str:
    try:
        return sha256_file(Path(__file__).resolve())
    except OSError:
        return "unavailable"


def run_hardware(args: argparse.Namespace) -> dict[str, Any]:
    os.umask(0o077)
    if not args.image:
        raise BenchmarkError(
            "at least one --image is required for a verifiable hardware run"
        )
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output, 0o700)
    run_id = (
        args.run_id if args.run_id is not None else secrets.randbelow(0xFFFFFFFF) + 1
    )
    sender_role = args.sender
    receiver_role = "walker" if sender_role == "base" else "base"
    sender_node = BOARD_IDENTITIES[sender_role][1]
    receiver_node = BOARD_IDENTITIES[receiver_role][1]
    config = RunConfig(
        run_id=run_id,
        source=sender_node,
        destination=receiver_node,
        count=args.count,
        size=args.size,
        duration_ms=int(args.wall_seconds * 1000),
        window=args.window,
        flags=FLAG_NONE,
    )
    validate_config(config)
    provenance: dict[str, Any] = {
        "started_utc": _utc_now(),
        "script_sha256": _script_digest(),
        "python": sys.executable,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "argv": list(sys.argv),
        "knob_state": {
            key: str(value) if isinstance(value, Path) else value
            for key, value in vars(args).items()
        },
        "image_hashes": {},
    }
    for image in args.image:
        path = Path(image)
        provenance["image_hashes"][str(path)] = sha256_file(path)
    protocol_path = Path(__file__).with_name("benchmark-protocol.json")
    file_digests = {str(Path(__file__).resolve()): _script_digest()}
    if protocol_path.exists():
        file_digests[str(protocol_path.resolve())] = sha256_file(protocol_path)
    result: dict[str, Any] = {
        "status": "error",
        "intent": {
            "control_port": "PRIVATE_APP",
            "control_address": "local_self_only",
            "rf_control": False,
            "persistent_configuration_writes": False,
            "run": dataclasses.asdict(config),
            "sender": sender_role,
            "receiver": receiver_role,
            "fixed_wall_seconds": args.wall_seconds,
            "drain_seconds": args.drain_seconds,
            "window_anchors": {
                "sender": "sender_START_return",
                "receiver": "first_authenticated_rf_data",
            },
        },
        "provenance": provenance,
        "file_digests": file_digests,
    }
    sessions: dict[str, BoardSession] = {}
    capture_events: dict[str, list[dict[str, Any]]] = {}
    reports_captured = False

    def checkpoint(stage: str) -> None:
        result["phase"] = stage
        result["last_checkpoint_utc"] = _utc_now()
        for role, session in sessions.items():
            capture_events[role] = session.capture.snapshot()
        result["capture_events"] = {
            role: list(events) for role, events in capture_events.items()
        }
        result["sequence_capture"] = {
            role: _sequence_capture_summary(session.capture.snapshot(), config)
            for role, session in sessions.items()
        }
        for session in sessions.values():
            session.capture.persist()
        # Fresh preservation sessions have no benchmark controls but use the
        # same role directories. Restore the captured run events after each
        # checkpoint so a reconnect cannot overwrite the evidence with [].
        for role, events in capture_events.items():
            _safe_json_write(output / role / "capture-events.json", events)
        _safe_json_write(output / "results.json", result)

    def invalidate_report(reason: str) -> None:
        report = result.get("report")
        if not isinstance(report, dict):
            return
        reasons = report.setdefault("failure_reasons", [])
        if reason not in reasons:
            reasons.append(reason)
        report["status"] = "measurement_invalid"
        report["measurement_valid"] = False
        result["status"] = "measurement_invalid"

    def wait_with_checkpoints(duration: float, stage: str) -> None:
        deadline = time.monotonic() + duration
        next_checkpoint = time.monotonic()
        while True:
            now = time.monotonic()
            if now >= deadline:
                break
            if now >= next_checkpoint:
                checkpoint(stage)
                next_checkpoint = now + 1.0
            time.sleep(min(0.25, max(0.01, deadline - now)))
        checkpoint(f"{stage}_complete")

    checkpoint("intent_initialized")
    try:
        # Opening both readers before the run prevents a receiver-side burst from
        # being hidden behind sender setup. Commands remain locked per port.
        checkpoint(f"opening_{sender_role}")
        sessions[sender_role] = BoardSession(
            sender_role, output, args.command_gap, checkpoint
        )
        checkpoint(f"{sender_role}_connected")
        checkpoint(f"opening_{receiver_role}")
        sessions[receiver_role] = BoardSession(
            receiver_role, output, args.command_gap, checkpoint
        )
        checkpoint(f"{receiver_role}_connected")
        before = {
            role: session.snapshot_config(output, "before")
            for role, session in sessions.items()
        }
        result["configuration_before"] = before
        checkpoint("configuration_before_saved")
        peer_bitmap = _peer_bitmap(sessions, sender_role, receiver_role)
        result["peer_bitmap"] = peer_bitmap
        checkpoint("peer_keys_verified")
        # The receiver must be armed before the producer is released.
        checkpoint("receiver_reset_attempt")
        sessions[receiver_role].control(CONTROL_RESET, config)
        checkpoint("receiver_reset_sent")
        checkpoint("receiver_start_attempt")
        sessions[receiver_role].control(CONTROL_START, config)
        checkpoint("receiver_start_sent")
        time.sleep(args.command_gap)
        checkpoint("sender_reset_attempt")
        sessions[sender_role].control(CONTROL_RESET, config)
        checkpoint("sender_reset_sent")
        checkpoint("sender_start_attempt")
        sessions[sender_role].control(CONTROL_START, config)
        # The fixed host wall starts when the sender START command has been
        # accepted by the local client. The firmware report remains the
        # authoritative duration check and must equal config.duration_ms.
        start = time.monotonic()
        result["burst_started_monotonic"] = start
        wait_with_checkpoints(args.wall_seconds, "burst_running")
        wall_end = time.monotonic()
        wait_with_checkpoints(args.drain_seconds, "drain_running")
        drain_end = time.monotonic()
        sender_report = sessions[sender_role].snapshot(config, args.control_timeout)
        completion = _snapshot_until_complete(
            sessions[receiver_role],
            config,
            timeout=args.completion_timeout,
            poll_interval=max(args.command_gap, 1.0),
        )
        receiver_report = completion.report
        result["receiver_completion_poll"] = {
            "polls": completion.polls,
            "additional_wait_seconds": completion.completed_at - drain_end,
            "bounded_timeout_seconds": args.completion_timeout,
            "poll_interval_seconds": max(args.command_gap, 1.0),
            "timed_out": completion.timed_out,
            "timeout_reason": completion.timeout_reason,
            "stop_sent": completion.stop_sent,
            "final_snapshot": completion.final_snapshot,
            "stop_error": completion.stop_error,
        }
        result["firmware_reports"] = {
            "sender": _report_dict(sender_report),
            "receiver": _report_dict(receiver_report),
        }
        result["report"] = evaluate_reports(
            config,
            sender_report,
            receiver_report,
            wall_seconds=args.wall_seconds,
            drain_seconds=args.drain_seconds,
            observed_wall_seconds=wall_end - start,
            observed_drain_seconds=drain_end - wall_end,
            peer_bitmap=peer_bitmap,
            extra_failure_reasons=(
                (completion.timeout_reason,)
                if completion.timeout_reason is not None
                else ()
            ),
        )
        result["status"] = result["report"]["status"]
        reports_captured = True
        # DATA forwarding is intentionally suppressed by the firmware, so
        # retain the original reader events before closing these sessions.
        checkpoint("reports_captured_before_close")
        close_errors = []
        for role, session in list(sessions.items()):
            try:
                if not session.close():
                    close_errors.append(role)
            except Exception:
                close_errors.append(role)
        sessions.clear()
        if close_errors:
            result["close_errors"] = close_errors
            result["configuration_after"] = {}
            result["configuration_preserved"] = False
            invalidate_report("session_close_timeout")
            checkpoint("sessions_close_timeout")
        else:
            checkpoint("sessions_closed")

        if not close_errors:
            # Reconnect each board by USB identity and read a fresh device state.
            # This prevents the cached protobuf objects used during the run from
            # making a persisted configuration change appear preserved.
            checkpoint("opening_fresh_config_sessions")
            after = _fresh_config_snapshots(
                output,
                (sender_role, receiver_role),
                args.command_gap,
            )
            result["configuration_after"] = after
            result["configuration_preserved"] = _configuration_preserved(before, after)
            if not result["configuration_preserved"]:
                invalidate_report("configuration_changed")
            checkpoint("configuration_after_saved")
    finally:
        if reports_captured and "configuration_preserved" not in result:
            invalidate_report("run_interrupted_after_reports")
        with contextlib.suppress(Exception):
            checkpoint("finally_before_close")
        close_errors = []
        for role, session in list(sessions.items()):
            try:
                if not session.close():
                    close_errors.append(role)
            except Exception:
                close_errors.append(role)
        sessions.clear()
        if close_errors:
            result["close_errors"] = close_errors
            invalidate_report("session_close_timeout")
        with contextlib.suppress(Exception):
            checkpoint("finally_after_close")
        result["finished_utc"] = _utc_now()
        _safe_json_write(output / "results.json", result)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, default=Path(".scratch/w12-throughput-20261007")
    )
    parser.add_argument("--sender", choices=tuple(BOARD_IDENTITIES), default="base")
    parser.add_argument("--count", type=int, default=MAX_COUNT)
    parser.add_argument("--size", type=int, default=DEFAULT_SIZE)
    parser.add_argument("--window", type=int, default=MAX_WINDOW)
    parser.add_argument("--wall-seconds", type=float, default=DEFAULT_WALL_SECONDS)
    parser.add_argument("--drain-seconds", type=float, default=DEFAULT_DRAIN_SECONDS)
    parser.add_argument(
        "--command-gap", type=float, default=DEFAULT_COMMAND_GAP_SECONDS
    )
    parser.add_argument(
        "--control-timeout", type=float, default=DEFAULT_CONTROL_TIMEOUT_SECONDS
    )
    parser.add_argument(
        "--completion-timeout", type=float, default=DEFAULT_COMPLETION_TIMEOUT_SECONDS
    )
    parser.add_argument("--run-id", type=int, default=None)
    parser.add_argument(
        "--image",
        action="append",
        default=[],
        help="firmware image to hash into provenance",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if (
            args.wall_seconds <= 0
            or args.drain_seconds < 0
            or args.command_gap < 0
            or args.control_timeout <= 0
            or args.completion_timeout <= 0
        ):
            raise BenchmarkError("timing knobs must be positive (drain may be zero)")
        result = run_hardware(args)
    except Exception as error:
        print(f"RESULT error {type(error).__name__}: {error}", flush=True)
        return 1
    print("RESULT", result.get("status", "error"), flush=True)
    return 0 if result.get("status") == "measurement_valid" else 1


if __name__ == "__main__":  # pragma: no cover - hardware entry point
    raise SystemExit(main())
