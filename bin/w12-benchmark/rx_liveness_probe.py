#!/usr/bin/env python3
"""Run the bounded W12 RX-liveness diagnostic probe.

This probe is deliberately separate from the throughput acceptance harness. It
asks each board for one local kind-6 snapshot per second, records the existing
LR2021 diagnostic seam, and can request one guarded receiver rearm. It makes no
delivery, PER, capacity, or throughput claim.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import dataclasses
import datetime as _dt
import hashlib
import importlib.util
import math
import os
import platform
import secrets
import sys
import threading
import time
from collections.abc import Mapping as MappingABC
from pathlib import Path
from typing import Any, Mapping, Sequence


def _load_benchmark_module() -> Any:
    path = Path(__file__).with_name("benchmark_probe.py")
    spec = importlib.util.spec_from_file_location("w12_frozen_benchmark", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load frozen benchmark helper {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


benchmark = _load_benchmark_module()


def _load_pre_send_module() -> Any:
    path = Path(__file__).with_name("pre_send_attribution.py")
    spec = importlib.util.spec_from_file_location("w12_pre_send_attribution", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load pre-send attribution helper {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


pre_send = _load_pre_send_module()

MAGIC = benchmark.MAGIC
VERSION = benchmark.VERSION
CONTROL_BYTES = benchmark.CONTROL_BYTES
REPORT_BYTES = 80
KIND = 6
CONTROL_SNAPSHOT = benchmark.CONTROL_SNAPSHOT
CONTROL_START = benchmark.CONTROL_START
CONTROL_STOP = benchmark.CONTROL_STOP
CONTROL_RESET = benchmark.CONTROL_RESET
CONTROL_SNAPSHOT_DIAGNOSTICS = benchmark.CONTROL_SNAPSHOT_DIAGNOSTICS
CONTROL_SNAPSHOT_RX_LIVENESS = 7
CONTROL_REARM_RX_LIVENESS = 8
CONTROL_SNAPSHOT_PRE_SEND = pre_send.SNAPSHOT_OP
PRE_SEND_KIND = pre_send.KIND
DEFAULT_WALL_SECONDS = 60.0
DEFAULT_SAMPLE_INTERVAL_SECONDS = 1.0
DEFAULT_REARM_AT_SECONDS = 20.0
DEFAULT_STAGNANT_SECONDS = 3.0
DEFAULT_COMMAND_GAP_SECONDS = benchmark.DEFAULT_COMMAND_GAP_SECONDS
DEFAULT_CONTROL_TIMEOUT_SECONDS = benchmark.DEFAULT_CONTROL_TIMEOUT_SECONDS
DEFAULT_CLOSE_TIMEOUT_SECONDS = benchmark.DEFAULT_CLOSE_TIMEOUT_SECONDS
DEFAULT_WINDOW = 8
SUPPORTED_WINDOWS = (8, 16)
SOURCE_PROGRESS_SAMPLE_DELAY_SECONDS = 1.0
MIN_RX_COUNTER_SAMPLES = 2
MIN_RX_COUNTER_SPAN_SECONDS = 3.0
RECEIVER_COMPLETION_TIMEOUT_SECONDS = DEFAULT_WALL_SECONDS + 10.0
REARM_RECEIVER_STATS_DELAY_SECONDS = 1.0
REARM_EVIDENCE_MARGIN_MS = 2000
INT16_MIN = -32768
HEADER_STATUS_MASK = 0x37
SAMPLE_STATUS_MASK = 0x3F
UINT16_MAX = 0xFFFF
UINT32_MAX = 0xFFFFFFFF


class LivenessError(benchmark.BenchmarkError):
    """A fail-closed diagnostic-probe lifecycle or protocol error."""


@dataclasses.dataclass(frozen=True)
class RxLivenessReport:
    run_id: int
    source: int
    destination: int
    elapsed_ms: int
    status: int
    pending_tx_count: int
    snapshot_sequence: int
    snapshot_time_ms: int
    sample_status: int
    sample_source: int
    rearm_count: int
    rearm_result: int
    rearm_before_state: int
    rearm_after_state: int
    rearm_last_time_ms: int
    rearm_last_duration_us: int
    raw_irq_flags: int
    raw_status: int
    irq_read_result: int
    chip_rx_packets: int
    chip_crc_errors: int
    chip_len_errors: int
    chip_stats_result: int
    rssi_dbm: int
    rssi_read_result: int
    software_state: int
    raw: bytes = dataclasses.field(repr=False, compare=False, default=b"")

    @property
    def prepared(self) -> bool:
        return bool(self.status & 0x01)

    @property
    def running(self) -> bool:
        return bool(self.status & 0x02)

    @property
    def complete(self) -> bool:
        return bool(self.status & 0x04)

    @property
    def pending_tx(self) -> bool:
        return bool(self.status & 0x10)

    @property
    def as_of_incomplete(self) -> bool:
        return bool(self.status & 0x20)

    @property
    def operation_rearm_performed(self) -> bool:
        return bool(self.sample_status & 0x08)

    @property
    def operation_rearm_software_armed(self) -> bool:
        return bool(self.sample_status & 0x10)

    @property
    def sample_source_valid(self) -> bool:
        return bool(self.sample_status & 0x20)

    @property
    def chip_stats_read_ok(self) -> bool:
        return bool(self.sample_status & 0x02)


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _i16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little", signed=True)


def decode_rx_liveness_report(payload: bytes) -> RxLivenessReport:
    """Decode the exact 80-byte kind-6 report without inventing values."""

    if not isinstance(payload, (bytes, bytearray)) or len(payload) != REPORT_BYTES:
        raise LivenessError(f"RX liveness payload must be exactly {REPORT_BYTES} bytes")
    payload = bytes(payload)
    if (
        _u16(payload, 0) != MAGIC
        or payload[2] != VERSION
        or payload[3] != KIND
    ):
        raise LivenessError("invalid RX liveness magic, version, or kind")
    if payload[22:24] != b"\x00\x00":
        raise LivenessError("RX liveness header reserved bytes are not zero")
    if payload[41:44] != b"\x00\x00\x00" or payload[76:80] != b"\x00\x00\x00\x00":
        raise LivenessError("RX liveness reserved bytes are not zero")

    status = payload[20]
    pending_tx_count = payload[21]
    if status & ~HEADER_STATUS_MASK:
        raise LivenessError("RX liveness header contains unknown status bits")
    prepared = bool(status & 0x01)
    running = bool(status & 0x02)
    complete = bool(status & 0x04)
    if not prepared:
        raise LivenessError("RX liveness report is not prepared")
    if running and complete:
        raise LivenessError("RX liveness report cannot be running and complete")
    if bool(status & 0x10) != bool(pending_tx_count):
        raise LivenessError("RX liveness pending status does not match count")
    if bool(status & 0x20) != (running or bool(pending_tx_count)):
        raise LivenessError("RX liveness as-of status does not match state")

    sample_status = payload[32]
    if sample_status & ~SAMPLE_STATUS_MASK:
        raise LivenessError("RX liveness sample contains unknown status bits")
    sample_source = payload[33]
    if sample_source not in (0, 1):
        raise LivenessError("RX liveness sample source is invalid")
    if bool(sample_status & 0x20) != bool(sample_source):
        raise LivenessError("RX liveness source-valid status does not match source")

    rearm_count = _u32(payload, 34)
    rearm_result = payload[38]
    if rearm_result not in (0, 1, 2):
        raise LivenessError("RX liveness rearm result is invalid")
    if rearm_count == 0 and rearm_result != 0:
        raise LivenessError("RX liveness rearm result has no historical count")
    if rearm_count != 0 and rearm_result == 0:
        raise LivenessError("RX liveness historical count has no result")
    operation_rearm = bool(sample_status & 0x08)
    operation_armed = bool(sample_status & 0x10)
    if operation_armed and not operation_rearm:
        raise LivenessError("RX liveness armed flag lacks operation rearm flag")
    if operation_rearm and rearm_result == 0:
        raise LivenessError("RX liveness operation rearm has no result")
    if operation_armed != (operation_rearm and rearm_result == 1):
        raise LivenessError("RX liveness rearm software state is inconsistent")

    rearm_before_state = payload[39]
    rearm_after_state = payload[40]
    if rearm_before_state & ~0x1F or rearm_after_state & ~0x1F:
        raise LivenessError("RX liveness rearm software state has unknown bits")
    irq_read_result = _i16(payload, 58)
    chip_stats_result = _i16(payload, 66)
    rssi_dbm = _i16(payload, 68)
    rssi_read_result = _i16(payload, 70)
    for bit, value, label in (
        (0x01, irq_read_result, "IRQ"),
        (0x02, chip_stats_result, "chip stats"),
        (0x04, rssi_read_result, "RSSI"),
    ):
        if bool(sample_status & bit) != (value == 0):
            raise LivenessError(f"RX liveness {label} availability does not match result")
    if sample_source == 0:
        if any(
            value != INT16_MIN
            for value in (irq_read_result, chip_stats_result, rssi_dbm, rssi_read_result)
        ):
            raise LivenessError("RX liveness unavailable source lacks sentinel results")
    elif (rssi_read_result == 0) != (rssi_dbm != INT16_MIN):
        raise LivenessError("RX liveness RSSI sentinel does not match result")
    return RxLivenessReport(
        run_id=_u32(payload, 4),
        source=_u32(payload, 8),
        destination=_u32(payload, 12),
        elapsed_ms=_u32(payload, 16),
        status=status,
        pending_tx_count=pending_tx_count,
        snapshot_sequence=_u32(payload, 24),
        snapshot_time_ms=_u32(payload, 28),
        sample_status=sample_status,
        sample_source=sample_source,
        rearm_count=rearm_count,
        rearm_result=rearm_result,
        rearm_before_state=rearm_before_state,
        rearm_after_state=rearm_after_state,
        rearm_last_time_ms=_u32(payload, 44),
        rearm_last_duration_us=_u32(payload, 48),
        raw_irq_flags=_u32(payload, 52),
        raw_status=_u16(payload, 56),
        irq_read_result=irq_read_result,
        chip_rx_packets=_u16(payload, 60),
        chip_crc_errors=_u16(payload, 62),
        chip_len_errors=_u16(payload, 64),
        chip_stats_result=chip_stats_result,
        rssi_dbm=rssi_dbm,
        rssi_read_result=rssi_read_result,
        software_state=_u32(payload, 72),
        raw=payload,
    )


def rx_liveness_report_dict(report: RxLivenessReport) -> dict[str, Any]:
    """Serialize a report while distinguishing operation and historical state."""

    unavailable = lambda value: None if value == INT16_MIN else value
    return {
        "scope": "board_local_rx_liveness_diagnostic",
        "run_id": report.run_id,
        "source": report.source,
        "destination": report.destination,
        "elapsed_ms": report.elapsed_ms,
        "status_bits": report.status,
        "prepared": report.prepared,
        "running": report.running,
        "complete": report.complete,
        "pending_tx_count": report.pending_tx_count,
        "as_of_incomplete": report.as_of_incomplete,
        "snapshot_sequence": report.snapshot_sequence,
        "snapshot_time_ms": report.snapshot_time_ms,
        "sample_status_bits": report.sample_status,
        "sample_source": report.sample_source,
        "sample_source_valid": report.sample_source_valid,
        "operation_rearm_performed": report.operation_rearm_performed,
        "operation_rearm_software_armed": report.operation_rearm_software_armed,
        "historical_rearm_count": report.rearm_count,
        "historical_rearm_result": report.rearm_result,
        "rearm_before_state": report.rearm_before_state,
        "rearm_after_state": report.rearm_after_state,
        "rearm_last_time_ms": report.rearm_last_time_ms,
        "rearm_last_duration_us": report.rearm_last_duration_us,
        "raw_irq_flags": report.raw_irq_flags,
        "raw_status": report.raw_status,
        "irq_read_result": unavailable(report.irq_read_result),
        "irq_read_result_unavailable": report.irq_read_result == INT16_MIN,
        "chip_rx_packets": report.chip_rx_packets,
        "chip_crc_errors": report.chip_crc_errors,
        "chip_len_errors": report.chip_len_errors,
        "chip_stats_result": unavailable(report.chip_stats_result),
        "chip_stats_result_unavailable": report.chip_stats_result == INT16_MIN,
        "rssi_dbm": unavailable(report.rssi_dbm),
        "rssi_read_result": unavailable(report.rssi_read_result),
        "rssi_read_result_unavailable": report.rssi_read_result == INT16_MIN,
        "software_state": report.software_state,
        "software_state_note": "software state is not a physical RX assertion",
        "rf_delivery_authoritative": False,
        "per_authoritative": False,
        "capacity_claim": "not_evaluated",
    }


def encode_liveness_control(config: Any, operation: int) -> bytes:
    """Build op7/op8 from the frozen 32-byte control template."""

    if operation not in (CONTROL_SNAPSHOT_RX_LIVENESS, CONTROL_REARM_RX_LIVENESS):
        raise LivenessError(f"unsupported RX liveness operation {operation}")
    payload = bytearray(benchmark.encode_control(config, CONTROL_SNAPSHOT))
    payload[3] = operation
    return bytes(payload)


def encode_pre_send_control(config: Any) -> bytes:
    """Build the exact local op9 control for this prepared run."""

    payload = pre_send.encode_snapshot_control(
        config.run_id,
        config.source,
        config.destination,
        config.count,
        config.size,
        config.duration_ms,
        config.window,
        config.flags,
    )
    if len(payload) != pre_send.CONTROL_BYTES or payload[3] != CONTROL_SNAPSHOT_PRE_SEND:
        raise LivenessError("pre_send_control_invalid: op9 control layout mismatch")
    fields = (
        int.from_bytes(payload[4:8], "little"),
        int.from_bytes(payload[8:12], "little"),
        int.from_bytes(payload[12:16], "little"),
        int.from_bytes(payload[16:20], "little"),
        int.from_bytes(payload[20:22], "little"),
        int.from_bytes(payload[22:26], "little"),
        int.from_bytes(payload[26:28], "little"),
        payload[28],
    )
    expected = (
        config.run_id,
        config.source,
        config.destination,
        config.count,
        config.size,
        config.duration_ms,
        config.window,
        config.flags,
    )
    if payload[:2] != MAGIC.to_bytes(2, "little") or payload[2] != VERSION or fields != expected:
        raise LivenessError("pre_send_control_identity_mismatch: config fields do not match")
    if payload[29:] != b"\x00\x00\x00":
        raise LivenessError("pre_send_control_invalid: reserved control bytes are not zero")
    return payload


def pre_send_report_dict(report: Any) -> dict[str, Any]:
    value = dataclasses.asdict(report)
    value.pop("raw", None)
    value.update(
        {
            "scope": "board_local_pre_send_attribution_diagnostic",
            "rf_delivery_authoritative": False,
            "per_authoritative": False,
            "capacity_claim": "not_evaluated",
        }
    )
    return value


def validate_pre_send_report(report: Any, config: Any, label: str) -> Any:
    if not all(
        getattr(report, field) == getattr(config, field)
        for field in ("run_id", "source", "destination")
    ):
        raise LivenessError(
            f"{label}_identity_mismatch: run/source/destination mismatch"
        )
    if (
        not isinstance(report.elapsed_ms, int)
        or isinstance(report.elapsed_ms, bool)
        or not 0 <= report.elapsed_ms <= config.duration_ms
    ):
        raise LivenessError(f"{label}_time_invalid: elapsed is outside the run")
    return report


def pre_send_record(
    report: Any, role: str, request_id: int, sent_monotonic: float
) -> dict[str, Any]:
    return {
        "role": role,
        "report_kind": PRE_SEND_KIND,
        "request_id": request_id,
        "sent_monotonic": sent_monotonic,
        "host_monotonic": time.monotonic(),
        "report": pre_send_report_dict(report),
    }


def optional_source_pre_send(
    session: LivenessSession,
    config: Any,
    timeout: float,
    role: str,
    requested: bool,
    state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Request source op9 only when explicitly enabled; propagate failures."""

    if state is None:
        state = {
            "requested": requested,
            "support_expected": requested,
            "status": "pending" if requested else "not_requested",
        }
    if not requested:
        return state
    try:
        session.check_health()
        report, sent_monotonic, request_id = session.request_pre_send(config, timeout)
        report = validate_pre_send_report(report, config, "pre_send_source")
    except BaseException as error:
        state.update({"status": "failed", "error": str(error)})
        raise
    state.update(
        {
            "status": "captured",
            "record": pre_send_record(report, role, request_id, sent_monotonic),
        }
    )
    return state


def decode_liveness_control(payload: bytes) -> tuple[int, Any]:
    if len(payload) != CONTROL_BYTES:
        raise LivenessError(f"RX liveness control must be exactly {CONTROL_BYTES} bytes")
    operation = payload[3]
    if operation not in (CONTROL_SNAPSHOT_RX_LIVENESS, CONTROL_REARM_RX_LIVENESS):
        raise LivenessError("invalid RX liveness control operation")
    template = bytearray(payload)
    template[3] = CONTROL_SNAPSHOT
    decoded_operation, config = benchmark.decode_control(bytes(template))
    if decoded_operation != CONTROL_SNAPSHOT:
        raise LivenessError("RX liveness control template mismatch")
    return operation, config


def _same_identity(report: RxLivenessReport, config: Any) -> bool:
    return all(
        getattr(report, field) == getattr(config, field)
        for field in ("run_id", "source", "destination")
    )


def _same_config_mapping(value: Mapping[str, Any], config: Any) -> bool:
    return all(
        value.get(field) == getattr(config, field)
        for field in (
            "run_id",
            "source",
            "destination",
            "count",
            "size",
            "duration_ms",
            "window",
            "flags",
        )
    )


def counter_delta(previous: int | None, current: int) -> dict[str, Any]:
    """Compute only monotonic deltas; decreases remain reset/wrap unknown."""

    if previous is None:
        return {"valid": True, "delta": current, "kind": "initial"}
    if current >= previous:
        return {"valid": True, "delta": current - previous, "kind": "monotonic"}
    return {
        "valid": False,
        "delta": None,
        "kind": "unknown_reset_or_wrap",
        "previous": previous,
        "current": current,
    }


def analyze_samples(samples: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Validate finite probe attribution without claiming RF delivery."""

    reasons: list[str] = []
    deltas: list[dict[str, Any]] = []
    previous_sequence: int | None = None
    previous_counters: dict[str, int | None] = {
        "chip_rx_packets": None,
        "chip_crc_errors": None,
        "chip_len_errors": None,
    }
    previous_monotonic: float | None = None
    for sample in samples:
        sequence = sample.get("snapshot_sequence")
        monotonic = sample.get("host_monotonic")
        if not isinstance(sequence, int) or sequence <= 0:
            reasons.append("invalid_snapshot_sequence")
        if previous_sequence is not None and isinstance(sequence, int) and sequence <= previous_sequence:
            reasons.append("snapshot_sequence_not_monotonic")
        previous_sequence = sequence if isinstance(sequence, int) else previous_sequence
        if not isinstance(monotonic, (int, float)):
            reasons.append("missing_host_timestamp")
        elif previous_monotonic is not None and monotonic < previous_monotonic:
            reasons.append("host_timestamp_not_monotonic")
        elif isinstance(monotonic, (int, float)):
            previous_monotonic = float(monotonic)
        if sample.get("sample_source_valid") and sample.get("chip_stats_result") == 0:
            for counter in previous_counters:
                current = sample.get(counter)
                if not isinstance(current, int) or not 0 <= current <= UINT16_MAX:
                    reasons.append(f"invalid_{counter}")
                    continue
                delta = counter_delta(previous_counters[counter], current)
                if not delta["valid"]:
                    reasons.append(f"{counter}_reset_or_wrap_unknown")
                deltas.append(
                    {
                        "counter": counter,
                        **delta,
                        "host_monotonic": monotonic,
                        "snapshot_sequence": sequence,
                    }
                )
                previous_counters[counter] = current
    if not samples:
        reasons.append("no_liveness_samples")
    if not any(sample.get("sample_source_valid") for sample in samples):
        reasons.append("sample_source_unavailable")
    return {
        "diagnostic_valid": not reasons,
        "status": "diagnostic_valid" if not reasons else "diagnostic_invalid",
        "failure_reasons": list(dict.fromkeys(reasons)),
        "counter_deltas": deltas,
        "rf_delivery_authoritative": False,
        "per_authoritative": False,
        "capacity_claim": "not_evaluated",
        "interpretation": "radio liveness perturbation diagnostic only; no delivery or capacity claim",
    }


def evaluate_receiver_counter_guard(
    samples: Sequence[Mapping[str, Any]],
    *,
    minimum_samples: int = MIN_RX_COUNTER_SAMPLES,
    minimum_span_seconds: float = MIN_RX_COUNTER_SPAN_SECONDS,
) -> dict[str, Any]:
    """Require a continuous, successful three-counter history before rearm."""

    counters = ("chip_rx_packets", "chip_crc_errors", "chip_len_errors")
    valid_samples: list[tuple[float, dict[str, int]]] = []
    unavailable_after_valid = False
    counter_decrease = False
    latest_read_success = False
    previous: dict[str, int] | None = None
    last_progress: float | None = None
    for sample in samples:
        host_monotonic = sample.get("host_monotonic")
        values = {counter: sample.get(counter) for counter in counters}
        readable = (
            isinstance(host_monotonic, (int, float))
            and sample.get("sample_source_valid") is True
            and sample.get("chip_stats_result") == 0
            and all(isinstance(value, int) and 0 <= value <= UINT16_MAX for value in values.values())
        )
        latest_read_success = readable
        if not readable:
            if valid_samples:
                unavailable_after_valid = True
            continue
        typed_values = {counter: int(values[counter]) for counter in counters}
        if previous is not None:
            if any(typed_values[counter] < previous[counter] for counter in counters):
                counter_decrease = True
            if typed_values["chip_rx_packets"] > previous["chip_rx_packets"]:
                last_progress = float(host_monotonic)
        else:
            last_progress = float(host_monotonic)
        previous = typed_values
        valid_samples.append((float(host_monotonic), typed_values))
    span_seconds = (
        valid_samples[-1][0] - valid_samples[0][0] if len(valid_samples) >= 2 else 0.0
    )
    eligible = (
        len(valid_samples) >= minimum_samples
        and span_seconds >= minimum_span_seconds
        and latest_read_success
        and not unavailable_after_valid
        and not counter_decrease
    )
    if counter_decrease:
        reason = "counter_reset_or_wrap_unknown"
    elif unavailable_after_valid:
        reason = "intervening_unavailable_sample"
    elif not latest_read_success:
        reason = "latest_sample_unavailable"
    elif len(valid_samples) < minimum_samples:
        reason = "insufficient_valid_samples"
    elif span_seconds < minimum_span_seconds:
        reason = "insufficient_counter_span"
    else:
        reason = "continuous_counter_history"
    return {
        "eligible": eligible,
        "reason": reason,
        "valid_counter_samples": len(valid_samples),
        "counter_span_seconds": span_seconds,
        "latest_read_success": latest_read_success,
        "intervening_unavailable_sample": unavailable_after_valid,
        "counter_decrease": counter_decrease,
        "last_progress_monotonic": last_progress,
    }


def receiver_window_observation(
    report: RxLivenessReport | None, duration_ms: int
) -> dict[str, Any]:
    """Describe the receiver's first-authenticated-frame anchored window."""

    if report is None:
        return {
            "anchor": "first_authenticated_rf_frame",
            "status": "no_snapshot",
            "first_authenticated_rf_frame_observed": False,
            "elapsed_ms": None,
            "running": None,
            "complete": None,
        }
    first_authenticated = report.elapsed_ms > 0
    if not first_authenticated:
        status = "inconclusive_no_first_authenticated_frame"
    elif report.complete and not report.running and report.elapsed_ms == duration_ms:
        status = "complete"
    elif report.complete and not report.running:
        status = "complete_partial_window"
    elif report.running:
        status = "running"
    else:
        status = "terminal_without_complete"
    return {
        "anchor": "first_authenticated_rf_frame",
        "status": status,
        "first_authenticated_rf_frame_observed": first_authenticated,
        "elapsed_ms": report.elapsed_ms,
        "running": report.running,
        "complete": report.complete,
        "duration_ms_expected": duration_ms,
        "pending_tx_count": report.pending_tx_count,
        "snapshot_sequence": report.snapshot_sequence,
    }


def inspect_sdk_queue(queue: Any) -> dict[str, Any]:
    """Separate real ToRadio queue entries from SDK false ACK markers."""

    if queue is None:
        return {
            "known": False,
            "queue_entries": None,
            "queued_packets": None,
            "pending_packets": None,
            "ack_markers": None,
            "unknown_entries": 1,
            "unknown_details": ["queue_is_missing"],
        }
    if not isinstance(queue, MappingABC):
        return {
            "known": False,
            "queue_entries": None,
            "queued_packets": None,
            "pending_packets": None,
            "ack_markers": None,
            "unknown_entries": 1,
            "unknown_details": ["queue_is_not_mapping"],
        }
    queued_packets = 0
    ack_markers = 0
    unknown_details: list[str] = []
    try:
        entries = list(queue.items())
    except Exception as error:
        return {
            "known": False,
            "queue_entries": None,
            "queued_packets": None,
            "pending_packets": None,
            "ack_markers": None,
            "unknown_entries": 1,
            "unknown_details": [f"queue_read_failed:{type(error).__name__}"],
        }
    try:
        mesh_pb2, _ = _load_meshtastic_types()
        to_radio_type = mesh_pb2.ToRadio
    except Exception as error:
        return {
            "known": False,
            "queue_entries": len(entries),
            "queued_packets": None,
            "pending_packets": None,
            "ack_markers": None,
            "unknown_entries": len(entries),
            "unknown_details": [f"protobuf_type_unavailable:{type(error).__name__}"],
        }
    for entry in entries:
        try:
            key, value = entry
        except Exception as error:
            unknown_details.append(f"{entry!r}:{type(error).__name__}")
            continue
        if (
            not isinstance(key, int)
            or isinstance(key, bool)
            or not 0 < key <= 0xFFFFFFFF
        ):
            unknown_details.append(f"{key!r}:ValueError")
            continue
        if value is False:
            ack_markers += 1
            continue
        try:
            if not isinstance(value, to_radio_type):
                raise ValueError("entry is not a protobuf ToRadio message")
            if not value.HasField("packet"):
                raise ValueError("entry has no packet field")
            packet_id = value.packet.id
            if (
                not isinstance(packet_id, int)
                or isinstance(packet_id, bool)
                or not 0 < packet_id <= 0xFFFFFFFF
                or packet_id != key
            ):
                raise ValueError("entry packet ID does not match queue key")
        except Exception as error:
            unknown_details.append(f"{key!r}:{type(error).__name__}")
            continue
        queued_packets += 1
    return {
        "known": not unknown_details,
        "queue_entries": len(entries),
        "queued_packets": queued_packets,
        "pending_packets": queued_packets,
        "ack_markers": ack_markers,
        "unknown_entries": len(unknown_details),
        "unknown_details": unknown_details,
    }


def rearm_candidate(
    elapsed_seconds: float,
    now: float,
    last_progress: float,
    attempted: bool,
    rearm_at_seconds: float,
    stagnant_seconds: float,
) -> dict[str, Any]:
    """Return the one-shot timing decision without asserting radio state."""

    if attempted:
        return {"eligible": False, "reason": "already_attempted"}
    if elapsed_seconds < rearm_at_seconds:
        return {"eligible": False, "reason": "before_rearm_time"}
    if now - last_progress < stagnant_seconds:
        return {"eligible": False, "reason": "progress_not_stagnant"}
    return {"eligible": True, "reason": "stagnant_after_threshold"}


def evaluate_source_tx_progress(
    before: Mapping[str, Any], after: Mapping[str, Any]
) -> dict[str, Any]:
    """Authorize rearm only when bounded kind-3 snapshots show sent progress."""

    result: dict[str, Any] = {
        "valid": True,
        "eligible": False,
        "reason": "no_tx_succeeded_progress",
        "tx_started_delta": None,
        "tx_succeeded_delta": None,
    }
    for field in ("tx_started", "tx_succeeded"):
        previous = before.get(field)
        current = after.get(field)
        if (
            not isinstance(previous, int)
            or not isinstance(current, int)
            or previous < 0
            or current < 0
        ):
            result["valid"] = False
            result["reason"] = f"missing_or_invalid_{field}"
            continue
        if current < previous:
            result["valid"] = False
            result["reason"] = f"{field}_counter_reset_or_wrap_unknown"
            result[f"{field}_delta"] = None
            continue
        result[f"{field}_delta"] = current - previous
    succeeded_delta = result["tx_succeeded_delta"]
    if result["valid"] and isinstance(succeeded_delta, int) and succeeded_delta > 0:
        result["eligible"] = True
        result["reason"] = "tx_succeeded_progress"
    return result


@dataclasses.dataclass
class _ReaderHealth:
    error: dict[str, str] | None = None
    closing: bool = False
    lock: threading.Lock = dataclasses.field(default_factory=threading.Lock)

    def fail(self, reason: str, detail: str) -> None:
        with self.lock:
            if self.error is None:
                self.error = {"reason": reason, "detail": detail}

    def snapshot(self) -> dict[str, str] | None:
        with self.lock:
            return None if self.error is None else dict(self.error)


def _load_meshtastic_types() -> tuple[Any, Any]:
    try:
        from meshtastic.protobuf import mesh_pb2, portnums_pb2
    except ImportError as error:  # pragma: no cover - hardware-only path
        raise LivenessError("pinned Meshtastic protobufs are required") from error
    return mesh_pb2, portnums_pb2


class LivenessSession:
    """Wrap a frozen BoardSession with only the narrow op7/op8 seam."""

    def __init__(
        self,
        role: str,
        output: Path,
        command_gap: float,
        checkpoint: Any = None,
    ) -> None:
        self.base = benchmark.BoardSession(role, output, command_gap, checkpoint)
        self.role = role
        self.node_num = self.base.node_num
        self.capture = self.base.capture
        self.interface = self.base.interface
        self.health = _ReaderHealth()
        self._mesh_pb2, self._portnums_pb2 = _load_meshtastic_types()
        self._original_handle = self.interface._handleFromRadio
        self.interface._handleFromRadio = self._handle_from_radio

    def _handle_from_radio(self, data: bytes) -> None:
        try:
            incoming = self._mesh_pb2.FromRadio()
            incoming.ParseFromString(data)
            if incoming.HasField("packet"):
                packet = incoming.packet
                if packet.HasField("decoded") and int(packet.decoded.portnum) == int(
                    self._portnums_pb2.PRIVATE_APP
                ):
                    payload = bytes(packet.decoded.payload)
                    if len(payload) >= 4 and payload[3] == KIND:
                        try:
                            report = decode_rx_liveness_report(payload)
                        except LivenessError as error:
                            self.health.fail("parser_error", str(error))
                            self.capture.record(
                                "liveness_protocol_error",
                                error=str(error),
                                raw_payload_hex=payload.hex(),
                            )
                            raise
                        self.capture.record(
                            "liveness_packet",
                            packet_id=int(packet.id),
                            request_id=int(packet.decoded.request_id),
                            to=int(packet.to),
                            from_node=int(getattr(packet, "from")),
                            payload_size=len(payload),
                            raw_payload_hex=payload.hex(),
                            report=rx_liveness_report_dict(report),
                        )
                    elif len(payload) >= 4 and payload[3] == PRE_SEND_KIND:
                        try:
                            report = pre_send.decode_report(payload)
                        except ValueError as error:
                            self.health.fail("parser_error", str(error))
                            self.capture.record(
                                "pre_send_protocol_error",
                                error=str(error),
                                raw_payload_hex=payload.hex(),
                            )
                            raise LivenessError(str(error)) from error
                        self.capture.record(
                            "pre_send_packet",
                            packet_id=int(packet.id),
                            request_id=int(packet.decoded.request_id),
                            to=int(packet.to),
                            from_node=int(getattr(packet, "from")),
                            payload_size=len(payload),
                            raw_payload_hex=payload.hex(),
                            report=pre_send_report_dict(report),
                        )
            self._original_handle(data)
        except BaseException as error:
            if self.health.snapshot() is None:
                self.health.fail("reader_error", str(error))
            raise

    def check_health(self) -> None:
        failure = self.health.snapshot()
        if failure is not None:
            raise LivenessError(f"{failure['reason']}: {failure['detail']}")
        if self.health.closing:
            return
        reader = getattr(self.interface, "_rxThread", None)
        if reader is not None and not reader.is_alive():
            self.health.fail("reader_exit", "serial reader stopped unexpectedly")
            raise LivenessError("reader_exit: serial reader stopped unexpectedly")
        if getattr(self.interface, "_wantExit", False):
            self.health.fail("serial_disconnected", "serial interface requested exit")
            raise LivenessError("serial_disconnected: serial interface requested exit")
        if reader is not None and getattr(self.interface, "stream", None) is None:
            self.health.fail("serial_disconnected", "serial stream disappeared")
            raise LivenessError("serial_disconnected: serial stream disappeared")

    def _response_matches(
        self,
        event: Mapping[str, Any],
        request_id: int,
        config: Any,
        sent_monotonic: float,
    ) -> bool:
        return (
            event.get("kind") == "liveness_packet"
            and event.get("request_id") == request_id
            and float(event.get("monotonic", -1)) >= sent_monotonic
        )

    def _wait_response(
        self,
        request_id: int,
        config: Any,
        sent_monotonic: float,
        timeout: float,
    ) -> RxLivenessReport:
        deadline = time.monotonic() + timeout
        while True:
            self.check_health()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LivenessError("response_timeout: kind-6 response did not arrive")
            event = self.capture.wait_for(
                lambda item: self._response_matches(
                    item, request_id, config, sent_monotonic
                ),
                min(remaining, 0.25),
            )
            if event is None:
                continue
            if event.get("to") != self.node_num or event.get("from_node") != self.node_num:
                raise LivenessError("response_identity_mismatch: local from/to mismatch")
            report = decode_rx_liveness_report(bytes.fromhex(event["raw_payload_hex"]))
            if not _same_identity(report, config):
                raise LivenessError("response_identity_mismatch: run/source/destination mismatch")
            return report

    def _wait_pre_send_response(
        self,
        request_id: int,
        config: Any,
        sent_monotonic: float,
        timeout: float,
    ) -> Any:
        deadline = time.monotonic() + timeout

        def matches(event: Mapping[str, Any]) -> bool:
            if event.get("kind") != "pre_send_packet":
                return False
            if event.get("request_id") != request_id:
                return False
            try:
                return float(event.get("monotonic", -1)) >= sent_monotonic
            except (TypeError, ValueError):
                return False

        while True:
            self.check_health()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LivenessError("response_timeout: kind-7 response did not arrive")
            event = self.capture.wait_for(matches, min(remaining, 0.25))
            if event is None:
                continue
            if event.get("to") != self.node_num or event.get("from_node") != self.node_num:
                raise LivenessError("response_identity_mismatch: local from/to mismatch")
            try:
                report = pre_send.decode_report(bytes.fromhex(event["raw_payload_hex"]))
            except (KeyError, ValueError, TypeError) as error:
                self.health.fail("parser_error", str(error))
                raise LivenessError(f"parser_error: {error}") from error
            return validate_pre_send_report(report, config, "pre_send_response")

    def request(
        self, config: Any, operation: int, timeout: float
    ) -> tuple[RxLivenessReport, float, int]:
        request_id, sent_monotonic = send_liveness_control(self, config, operation)
        report = self._wait_response(request_id, config, sent_monotonic, timeout)
        return report, sent_monotonic, request_id

    def request_pre_send(
        self, config: Any, timeout: float
    ) -> tuple[Any, float, int]:
        request_id, sent_monotonic = send_pre_send_control(self, config)
        report = self._wait_pre_send_response(
            request_id, config, sent_monotonic, timeout
        )
        return report, sent_monotonic, request_id

    def base_control(self, operation: int, config: Any) -> int:
        """Run an existing control while folding serial failures into health."""

        self.check_health()
        try:
            return self.base.control(operation, config)
        except BaseException as error:
            self.health.fail("control_write_error", str(error))
            raise LivenessError(f"control_write_error: {error}") from error

    def host_rearm_guard(self) -> dict[str, Any]:
        missing = object()
        queue_status = getattr(self.interface, "queueStatus", None)
        queue_free = (
            missing if queue_status is None else getattr(queue_status, "free", missing)
        )
        queue = getattr(self.interface, "queue", None)
        queue_state = inspect_sdk_queue(queue)
        free_valid = (
            isinstance(queue_free, int)
            and not isinstance(queue_free, bool)
            and queue_free > 0
        )
        eligible = (
            queue_state["known"]
            and queue_state["queued_packets"] == 0
            and free_valid
        )
        return {
            "eligible": eligible,
            "queue_free_cached": None if queue_free is missing else queue_free,
            "queue_entries": queue_state["queue_entries"],
            "queued_packets": queue_state["queued_packets"],
            "pending_packets": queue_state["pending_packets"],
            "ack_markers": queue_state["ack_markers"],
            "unknown_queue_entries": queue_state["unknown_entries"],
            "unknown_queue_details": queue_state["unknown_details"],
            "queue_state_known": queue_state["known"] and free_valid,
            "queue_free_invalid": not free_valid,
            "firmware_guard_authoritative": True,
            "note": "firmware checks active TX, radio TX queue, receiver window, and one-shot budget",
        }

    def close(self, timeout: float = DEFAULT_CLOSE_TIMEOUT_SECONDS) -> bool:
        self.health.closing = True
        return bool(self.base.close(timeout=timeout))


def send_liveness_control(
    session: LivenessSession, config: Any, operation: int
) -> tuple[int, float]:
    """Send op7/op8 directly through the validated local USB path."""

    payload = encode_liveness_control(config, operation)
    session.check_health()
    interface = session.interface
    if getattr(interface, "noProto", False):
        raise LivenessError("control_unavailable: interface protocol is disabled")
    if not callable(getattr(interface, "_sendToRadioImpl", None)):
        raise LivenessError("control_unavailable: direct serial sender is missing")
    packet_id_factory = getattr(interface, "_generatePacketId", None)
    packet_id = (
        int(packet_id_factory())
        if callable(packet_id_factory)
        else secrets.randbelow(0xFFFFFFFF) + 1
    )
    to_radio = session._mesh_pb2.ToRadio()
    mesh_packet = to_radio.packet
    mesh_packet.id = packet_id
    mesh_packet.to = session.node_num
    setattr(mesh_packet, "from", 0)
    mesh_packet.want_ack = False
    mesh_packet.pki_encrypted = False
    mesh_packet.hop_limit = 0
    mesh_packet.decoded.portnum = int(session._portnums_pb2.PRIVATE_APP)
    mesh_packet.decoded.payload = payload
    mesh_packet.decoded.want_response = True
    if (
        int(mesh_packet.to) != session.node_num
        or int(getattr(mesh_packet, "from")) != 0
        or bool(mesh_packet.want_ack)
        or bool(mesh_packet.pki_encrypted)
        or int(mesh_packet.decoded.portnum) != int(session._portnums_pb2.PRIVATE_APP)
        or bytes(mesh_packet.decoded.payload) != payload
    ):
        raise LivenessError("control_identity_mismatch: local control packet validation failed")

    lock = getattr(interface, "_command_lock", None)
    if lock is None:
        raise LivenessError("control_unavailable: command lock is missing")
    with lock:
        session.base._pace()
        sent_monotonic = time.monotonic()
        session.capture.record(
            "liveness_control_attempt",
            operation=operation,
            packet_id=packet_id,
            run_id=config.run_id,
            source=config.source,
            destination=config.destination,
            payload_sha256=benchmark.sha256_bytes(payload),
            local_destination=session.node_num,
        )
        try:
            interface._sendToRadioImpl(to_radio)
        except BaseException as error:
            session.health.fail("control_write_error", str(error))
            raise LivenessError(f"control_write_error: {error}") from error
        interface.last_command = sent_monotonic
        session.capture.record(
            "liveness_control_intent",
            operation=operation,
            packet_id=packet_id,
            run_id=config.run_id,
            source=config.source,
            destination=config.destination,
            payload_sha256=benchmark.sha256_bytes(payload),
            local_destination=session.node_num,
        )
    return packet_id, sent_monotonic


def send_pre_send_control(session: LivenessSession, config: Any) -> tuple[int, float]:
    """Send only the validated local op9 control through the direct serial seam."""

    payload = encode_pre_send_control(config)
    session.check_health()
    interface = session.interface
    if getattr(interface, "noProto", False):
        raise LivenessError("control_unavailable: interface protocol is disabled")
    if not callable(getattr(interface, "_sendToRadioImpl", None)):
        raise LivenessError("control_unavailable: direct serial sender is missing")
    packet_id_factory = getattr(interface, "_generatePacketId", None)
    packet_id = (
        int(packet_id_factory())
        if callable(packet_id_factory)
        else secrets.randbelow(0xFFFFFFFF) + 1
    )
    to_radio = session._mesh_pb2.ToRadio()
    mesh_packet = to_radio.packet
    mesh_packet.id = packet_id
    mesh_packet.to = session.node_num
    setattr(mesh_packet, "from", 0)
    mesh_packet.want_ack = False
    mesh_packet.pki_encrypted = False
    mesh_packet.hop_limit = 0
    mesh_packet.decoded.portnum = int(session._portnums_pb2.PRIVATE_APP)
    mesh_packet.decoded.payload = payload
    mesh_packet.decoded.want_response = True
    if (
        int(mesh_packet.to) != session.node_num
        or int(getattr(mesh_packet, "from")) != 0
        or bool(mesh_packet.want_ack)
        or bool(mesh_packet.pki_encrypted)
        or int(mesh_packet.decoded.portnum) != int(session._portnums_pb2.PRIVATE_APP)
        or bytes(mesh_packet.decoded.payload) != payload
        or payload[3] != CONTROL_SNAPSHOT_PRE_SEND
    ):
        raise LivenessError("control_identity_mismatch: local op9 packet validation failed")

    lock = getattr(interface, "_command_lock", None)
    if lock is None:
        raise LivenessError("control_unavailable: command lock is missing")
    with lock:
        session.base._pace()
        sent_monotonic = time.monotonic()
        session.capture.record(
            "pre_send_control_attempt",
            operation=CONTROL_SNAPSHOT_PRE_SEND,
            packet_id=packet_id,
            run_id=config.run_id,
            source=config.source,
            destination=config.destination,
            payload_sha256=benchmark.sha256_bytes(payload),
            local_destination=session.node_num,
        )
        try:
            interface._sendToRadioImpl(to_radio)
        except BaseException as error:
            session.health.fail("control_write_error", str(error))
            raise LivenessError(f"control_write_error: {error}") from error
        interface.last_command = sent_monotonic
        session.capture.record(
            "pre_send_control_intent",
            operation=CONTROL_SNAPSHOT_PRE_SEND,
            packet_id=packet_id,
            run_id=config.run_id,
            source=config.source,
            destination=config.destination,
            payload_sha256=benchmark.sha256_bytes(payload),
            local_destination=session.node_num,
        )
    return packet_id, sent_monotonic


def _script_digest() -> str:
    try:
        return benchmark.sha256_file(Path(__file__).resolve())
    except OSError:
        return "unavailable"


def _utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_write(path: Path, value: Any) -> None:
    benchmark._safe_json_write(path, value)


def _sample_dict(report: RxLivenessReport, host_monotonic: float, request_id: int, operation: int) -> dict[str, Any]:
    value = rx_liveness_report_dict(report)
    value.update(
        {
            "operation": operation,
            "request_id": request_id,
            "host_monotonic": host_monotonic,
        }
    )
    return value


def _identity_check(value: Mapping[str, Any], config: Any, label: str) -> None:
    if not _same_config_mapping(value, config):
        raise LivenessError(f"{label}_identity_mismatch: run/source/destination mismatch")


def validate_rearm_kind3_report(
    value: Mapping[str, Any], config: Any, label: str
) -> dict[str, Any]:
    """Validate a local kind-3 report used to bound the rearm experiment."""

    _identity_check(value, config, label)
    if value.get("prepared") is not True:
        raise LivenessError(f"{label}_incomplete: report is not prepared")
    if value.get("running") is not True or value.get("complete") is not False:
        raise LivenessError(f"{label}_incomplete: report is not a running window")
    elapsed_ms = value.get("elapsed_ms")
    if (
        not isinstance(elapsed_ms, int)
        or isinstance(elapsed_ms, bool)
        or not 0 < elapsed_ms < config.duration_ms
    ):
        raise LivenessError(f"{label}_time_invalid: elapsed window is outside the run")
    counters = (
        "received",
        "duplicates",
        "corrupt",
        "out_of_range",
        "enqueued",
        "send_failures",
        "tx_started",
        "tx_succeeded",
        "tx_failures",
        "tx_dropped",
        "tx_cancelled",
    )
    for field in counters:
        value_field = value.get(field)
        if (
            not isinstance(value_field, int)
            or isinstance(value_field, bool)
            or not 0 <= value_field <= UINT32_MAX
        ):
            raise LivenessError(f"{label}_counter_invalid: {field} is invalid")
    if value["received"] > config.count:
        raise LivenessError(f"{label}_counter_invalid: received exceeds configured count")
    return dict(value)


def authenticated_unique_progress(
    before: Mapping[str, Any], after: Mapping[str, Any], config: Any
) -> dict[str, Any]:
    """Return exact kind-3 authenticated-unique progress without RF claims."""

    before_report = validate_rearm_kind3_report(before, config, "receiver_before")
    after_report = validate_rearm_kind3_report(after, config, "receiver_after")
    if after_report["elapsed_ms"] < before_report["elapsed_ms"]:
        raise LivenessError("receiver_after_time_invalid: elapsed time decreased")
    before_received = before_report["received"]
    after_received = after_report["received"]
    if after_received < before_received:
        raise LivenessError("receiver_after_counter_invalid: received decreased")
    return {
        "authenticated_unique_count_before": before_received,
        "authenticated_unique_count_after": after_received,
        "authenticated_unique_count_delta": after_received - before_received,
        "elapsed_ms_before": before_report["elapsed_ms"],
        "elapsed_ms_after": after_report["elapsed_ms"],
        "interpretation": "authenticated unique benchmark receipts from an independent local window; not packet-level TX/RX matching or PER",
    }


def freeze_rearm_decision(
    receiver_counter_guard: Mapping[str, Any],
    host_guard: Mapping[str, Any],
    receiver_window: Mapping[str, Any],
    source_progress: Mapping[str, Any],
    source_snapshots: Sequence[Mapping[str, Any]],
    decision_host_monotonic: float,
) -> dict[str, Any]:
    """Copy all decision-time evidence so later samples cannot overwrite it."""

    return copy.deepcopy(
        {
            "decision_host_monotonic": decision_host_monotonic,
            "receiver_counter_guard": receiver_counter_guard,
            "host_guard": host_guard,
            "receiver_window": receiver_window,
            "source_progress": source_progress,
            "source_snapshots": list(source_snapshots),
        }
    )


def rearm_evidence_margin(
    elapsed_ms: Any,
    duration_ms: Any,
    margin_ms: int = REARM_EVIDENCE_MARGIN_MS,
) -> dict[str, Any]:
    """Require bounded post-op8 evidence time before sending op8."""

    valid = (
        isinstance(elapsed_ms, int)
        and not isinstance(elapsed_ms, bool)
        and isinstance(duration_ms, int)
        and not isinstance(duration_ms, bool)
        and isinstance(margin_ms, int)
        and not isinstance(margin_ms, bool)
        and margin_ms > 0
    )
    if not valid:
        return {
            "eligible": False,
            "reason": "invalid_evidence_margin_inputs",
            "remaining_ms": None,
            "margin_ms": margin_ms,
        }
    remaining_ms = duration_ms - elapsed_ms
    return {
        "eligible": remaining_ms >= margin_ms,
        "reason": "sufficient_evidence_margin"
        if remaining_ms >= margin_ms
        else "rearm_evidence_window_margin",
        "remaining_ms": remaining_ms,
        "margin_ms": margin_ms,
    }


def rearm_evidence_margin_with_host_elapsed(
    device_elapsed_ms: Any,
    duration_ms: Any,
    request_started_host_monotonic: Any,
    now_host_monotonic: Any,
    margin_ms: int = REARM_EVIDENCE_MARGIN_MS,
) -> dict[str, Any]:
    """Charge pre-op8 host time against the device window conservatively."""

    result = rearm_evidence_margin(device_elapsed_ms, duration_ms, margin_ms)
    host_values_valid = all(
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        for value in (request_started_host_monotonic, now_host_monotonic)
    )
    device_values_valid = (
        isinstance(device_elapsed_ms, int)
        and not isinstance(device_elapsed_ms, bool)
        and isinstance(duration_ms, int)
        and not isinstance(duration_ms, bool)
    )
    if not host_values_valid or not device_values_valid:
        result.update(
            {
                "eligible": False,
                "reason": "invalid_evidence_timing_inputs",
                "device_elapsed_ms": device_elapsed_ms,
                "host_elapsed_ms": None,
                "conservative_elapsed_ms": None,
                "host_elapsed_upper_bound": True,
            }
        )
        return result
    host_elapsed_seconds = float(now_host_monotonic) - float(
        request_started_host_monotonic
    )
    if host_elapsed_seconds < 0:
        result.update(
            {
                "eligible": False,
                "reason": "invalid_evidence_timing_inputs",
                "device_elapsed_ms": device_elapsed_ms,
                "host_elapsed_ms": None,
                "conservative_elapsed_ms": None,
                "host_elapsed_upper_bound": True,
            }
        )
        return result
    host_elapsed_ms = math.ceil(host_elapsed_seconds * 1000)
    conservative_elapsed_ms = device_elapsed_ms + host_elapsed_ms
    result = rearm_evidence_margin(
        conservative_elapsed_ms, duration_ms, margin_ms
    )
    result.update(
        {
            "device_elapsed_ms": device_elapsed_ms,
            "host_elapsed_ms": host_elapsed_ms,
            "conservative_elapsed_ms": conservative_elapsed_ms,
            "host_elapsed_upper_bound": True,
        }
    )
    return result


def evaluate_source_progress_across_rearm(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    config: Any,
    *,
    start_host_monotonic: float,
    end_host_monotonic: float,
) -> dict[str, Any]:
    """Describe the source interval spanning the pre-op8 tail and post-op8 period."""

    before_report = validate_rearm_kind3_report(before, config, "source_before_rearm")
    after_report = validate_rearm_kind3_report(after, config, "source_after_rearm")
    if end_host_monotonic <= start_host_monotonic:
        raise LivenessError("source_progress_across_rearm_time_invalid: host time did not advance")
    if after_report["elapsed_ms"] <= before_report["elapsed_ms"]:
        raise LivenessError("source_progress_across_rearm_time_invalid: elapsed time did not advance")
    progress = evaluate_source_tx_progress(before_report, after_report)
    progress.update(
        {
            "interval_start": "source_kind3_after_baseline_before_receiver_pre_op8",
            "interval_end": "source_kind3_after_receiver_post_op8",
            "interval_start_sample": "after_tx_progress_check",
            "interval_end_sample": "after_rearm",
            "interval_start_host_monotonic": start_host_monotonic,
            "interval_end_host_monotonic": end_host_monotonic,
            "interval_start_elapsed_ms": before_report["elapsed_ms"],
            "interval_end_elapsed_ms": after_report["elapsed_ms"],
            "receiver_pre_op8_tail_included": True,
            "interval_note": "includes receiver pre-op8 kind-3 snapshot/control tail and post-op8 interval; does not isolate post-op8 TX",
        }
    )
    return progress


def fresh_config_snapshots_checked(
    output: Path,
    roles: Sequence[str],
    command_gap: float,
    captured_events: Mapping[str, Sequence[Mapping[str, Any]]],
    session_factory: Any = benchmark.BoardSession,
) -> dict[str, Any]:
    """Reconnect each role sequentially and reject an already-dead reader."""

    snapshots: dict[str, Any] = {}
    for role in roles:
        session = session_factory(role, output, command_gap)
        try:
            snapshots[role] = session.snapshot_config(output, "after")
            reader = getattr(session.interface, "_rxThread", None)
            if reader is not None and not reader.is_alive():
                raise LivenessError(f"{role}: fresh config reader exited before close")
        finally:
            closed = session.close()
            if closed is False:
                raise LivenessError(f"{role}: fresh config close failed; port reuse prohibited")
        events = captured_events.get(role)
        if events is not None:
            benchmark._safe_json_write(output / role / "capture-events.json", list(events))
    return snapshots


def run_probe(args: argparse.Namespace) -> dict[str, Any]:
    """Run the diagnostic probe with bounded controls and preserved evidence."""

    os.umask(0o077)
    if not args.image:
        raise LivenessError("at least one --image is required before opening hardware")
    if args.wall_seconds != DEFAULT_WALL_SECONDS:
        raise LivenessError("RX liveness wall window must be exactly 60 seconds")
    if args.window not in SUPPORTED_WINDOWS:
        raise LivenessError(f"RX liveness window must be one of {SUPPORTED_WINDOWS}")
    if args.sample_interval <= 0 or args.rearm_stagnant_seconds <= 0:
        raise LivenessError("sample and stagnation intervals must be positive")

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output, 0o700)
    script_path = Path(__file__).resolve()
    script_digest = _script_digest()
    if script_digest == "unavailable":
        raise LivenessError("probe script digest is unavailable")
    helper_path = Path(benchmark.__file__).resolve()
    try:
        helper_digest = benchmark.sha256_file(helper_path)
    except OSError as error:
        raise LivenessError("frozen benchmark helper digest is unavailable") from error
    pre_send_helper_path = Path(pre_send.__file__).resolve()
    try:
        pre_send_helper_digest = benchmark.sha256_file(pre_send_helper_path)
    except OSError as error:
        raise LivenessError("frozen pre-send helper digest is unavailable") from error
    protocol_path = Path(__file__).with_name("rx-liveness-protocol.json")
    if not protocol_path.is_file():
        raise LivenessError("RX liveness protocol file is required before opening hardware")
    try:
        protocol_digest = benchmark.sha256_file(protocol_path)
    except OSError as error:
        raise LivenessError("RX liveness protocol digest is unavailable") from error
    pre_send_protocol_path = Path(__file__).with_name(
        "pre-send-attribution-protocol.json"
    )
    if not pre_send_protocol_path.is_file():
        raise LivenessError(
            "pre-send attribution protocol file is required before opening hardware"
        )
    try:
        pre_send_protocol_digest = benchmark.sha256_file(pre_send_protocol_path)
    except OSError as error:
        raise LivenessError("pre-send attribution protocol digest is unavailable") from error
    for image in args.image:
        if not Path(image).is_file():
            raise LivenessError(f"firmware image is not a regular file: {image}")
    sender_role = args.sender
    receiver_role = "walker" if sender_role == "base" else "base"
    run_id = args.run_id or secrets.randbelow(0xFFFFFFFF) + 1
    config = benchmark.RunConfig(
        run_id=run_id,
        source=benchmark.BOARD_IDENTITIES[sender_role][1],
        destination=benchmark.BOARD_IDENTITIES[receiver_role][1],
        count=args.count,
        size=benchmark.DEFAULT_SIZE,
        duration_ms=int(DEFAULT_WALL_SECONDS * 1000),
        window=args.window,
        flags=0,
    )
    benchmark.validate_config(config)
    provenance = {
        "started_utc": _utc_now(),
        "script_sha256": script_digest,
        "benchmark_helper_sha256": helper_digest,
        "pre_send_helper_sha256": pre_send_helper_digest,
        "protocol_sha256": protocol_digest,
        "pre_send_protocol_sha256": pre_send_protocol_digest,
        "python": sys.executable,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "argv": list(sys.argv),
        "knob_state": {
            key: str(value) if isinstance(value, Path) else value
            for key, value in vars(args).items()
        },
        "image_hashes": {
            str(Path(image)): benchmark.sha256_file(Path(image)) for image in args.image
        },
    }
    file_digests = {
        str(script_path): script_digest,
        str(helper_path): helper_digest,
        str(pre_send_helper_path): pre_send_helper_digest,
        str(protocol_path.resolve()): protocol_digest,
        str(pre_send_protocol_path.resolve()): pre_send_protocol_digest,
    }
    result: dict[str, Any] = {
        "status": "diagnostic_pending",
        "probe": "rx_liveness_diagnostic",
        "capacity_acceptance": "not_evaluated",
        "rf_delivery_authoritative": False,
        "per_authoritative": False,
        "intent": {
            "control_port": "PRIVATE_APP",
            "control_address": "local_self_only",
            "rf_control": False,
            "persistent_configuration_writes": False,
            "run": dataclasses.asdict(config),
            "sender": sender_role,
            "receiver": receiver_role,
            "fixed_wall_seconds": DEFAULT_WALL_SECONDS,
            "window": args.window,
            "sender_window_anchor": "sender_start",
            "receiver_window_anchor": "first_authenticated_rf_frame",
            "receiver_completion_timeout_seconds": RECEIVER_COMPLETION_TIMEOUT_SECONDS,
            "sample_interval_seconds": args.sample_interval,
            "rearm_at_seconds": args.rearm_at_seconds,
            "stagnant_seconds": args.rearm_stagnant_seconds,
            "rearm_evidence_margin_ms": REARM_EVIDENCE_MARGIN_MS,
            "pre_send_attribution": {
                "operation": CONTROL_SNAPSHOT_PRE_SEND,
                "kind": PRE_SEND_KIND,
                "report_bytes": pre_send.REPORT_BYTES,
                "scope": "diagnostic_only",
                "receiver_snapshot": {
                    "requested": True,
                    "support_expected": True,
                },
                "source_snapshot": {
                    "requested": bool(args.source_pre_send),
                    "support_expected": bool(args.source_pre_send),
                },
            },
        },
        "provenance": provenance,
        "file_digests": file_digests,
        "samples": [],
        "source_snapshots": [],
        "rearm": {
            "attempted": False,
            "performed": False,
            "pre_send_source": {
                "requested": bool(args.source_pre_send),
                "support_expected": bool(args.source_pre_send),
                "status": "pending" if args.source_pre_send else "not_requested",
            },
        },
        "sender_window": {
            "anchor": "sender_start",
            "duration_ms": config.duration_ms,
            "status": "pending",
        },
        "receiver_window": receiver_window_observation(None, config.duration_ms),
        "failure_reasons": [],
    }
    sessions: dict[str, LivenessSession] = {}
    before: dict[str, Any] = {}
    run_started = False
    closed_ok = False
    captured_events: dict[str, list[dict[str, Any]]] = {}

    def add_failure(reason: str) -> None:
        if reason not in result["failure_reasons"]:
            result["failure_reasons"].append(reason)

    def checkpoint(stage: str) -> None:
        result["phase"] = stage
        result["last_checkpoint_utc"] = _utc_now()
        result["capture_events"] = {
            role: session.capture.snapshot() for role, session in sessions.items()
        }
        captured_events.clear()
        captured_events.update(
            {
                role: list(events)
                for role, events in result["capture_events"].items()
            }
        )
        for session in sessions.values():
            session.capture.persist()
        _safe_write(output / "results.json", result)

    try:
        checkpoint("intent_initialized")
        sessions[sender_role] = LivenessSession(sender_role, output, args.command_gap, checkpoint)
        sessions[receiver_role] = LivenessSession(receiver_role, output, args.command_gap, checkpoint)
        for role, session in sessions.items():
            session.check_health()
            before[role] = session.base.snapshot_config(output, "before")
        result["configuration_before"] = before
        result["peer_bitmap"] = benchmark._peer_bitmap(sessions, sender_role, receiver_role)
        checkpoint("configuration_before_saved")

        receiver = sessions[receiver_role]
        sender = sessions[sender_role]
        receiver.base_control(CONTROL_RESET, config)
        receiver.base_control(CONTROL_START, config)
        checkpoint("receiver_started")
        time.sleep(args.command_gap)
        sender.base_control(CONTROL_RESET, config)
        sender.base_control(CONTROL_START, config)
        start = time.monotonic()
        result["sender_start_monotonic"] = start
        result["sender_window"].update(
            {
                "status": "running",
                "started_monotonic": start,
                "anchor_note": "fixed sender wall window; independent of receiver first-auth anchor",
            }
        )
        run_started = True
        checkpoint("sender_started")

        last_sample: RxLivenessReport | None = None
        last_progress = start
        rearm_attempted = False
        next_sample = start
        deadline = start + DEFAULT_WALL_SECONDS
        while time.monotonic() < deadline:
            receiver.check_health()
            sender.check_health()
            now = time.monotonic()
            if now < next_sample:
                time.sleep(min(next_sample - now, 0.05))
                continue
            report, sent_at, request_id = receiver.request(
                config, CONTROL_SNAPSHOT_RX_LIVENESS, args.control_timeout
            )
            sample = _sample_dict(
                report, time.monotonic(), request_id, CONTROL_SNAPSHOT_RX_LIVENESS
            )
            result["samples"].append(sample)
            last_sample = report
            result["receiver_window"] = receiver_window_observation(
                report, config.duration_ms
            )
            receiver_counter_guard = evaluate_receiver_counter_guard(result["samples"])
            result["rearm"]["receiver_counter_guard"] = receiver_counter_guard
            if receiver_counter_guard["last_progress_monotonic"] is not None:
                last_progress = receiver_counter_guard["last_progress_monotonic"]

            elapsed = time.monotonic() - start
            rearm_decision = rearm_candidate(
                elapsed,
                time.monotonic(),
                last_progress,
                rearm_attempted,
                args.rearm_at_seconds,
                args.rearm_stagnant_seconds,
            )
            if rearm_decision["eligible"]:
                guard = receiver.host_rearm_guard()
                result["rearm"]["host_guard"] = guard
                evidence_margin = rearm_evidence_margin(
                    report.elapsed_ms, config.duration_ms
                )
                result["rearm"]["evidence_window_margin"] = evidence_margin
                if not receiver_counter_guard["eligible"]:
                    result["rearm"]["skipped_reason"] = "receiver_counter_guard_not_ready"
                elif not report.elapsed_ms > 0:
                    result["rearm"]["skipped_reason"] = "receiver_window_not_started"
                elif not evidence_margin["eligible"]:
                    result["rearm"]["skipped_reason"] = "rearm_evidence_window_margin"
                elif guard["eligible"]:
                    sender.check_health()
                    source_before_report = sender.base.snapshot(
                        config, args.control_timeout
                    )
                    source_before = benchmark._report_dict(source_before_report)
                    if source_before is None:
                        raise LivenessError("source_diagnostic_before: empty kind-3 report")
                    _identity_check(source_before, config, "source_diagnostic_before")
                    source_before_record = {
                        **dict(source_before),
                        "report_kind": benchmark.REPORT_KIND,
                        "sample": "before_tx_progress_check",
                        "host_monotonic": time.monotonic(),
                    }
                    result["source_snapshots"].append(source_before_record)
                    checkpoint("source_progress_baseline_captured")
                    time.sleep(SOURCE_PROGRESS_SAMPLE_DELAY_SECONDS)
                    sender.check_health()
                    source_after_report = sender.base.snapshot(
                        config, args.control_timeout
                    )
                    source_after = benchmark._report_dict(source_after_report)
                    if source_after is None:
                        raise LivenessError("source_diagnostic_after: empty kind-3 report")
                    _identity_check(source_after, config, "source_diagnostic_after")
                    source_after_record = {
                        **dict(source_after),
                        "report_kind": benchmark.REPORT_KIND,
                        "sample": "after_tx_progress_check",
                        "host_monotonic": time.monotonic(),
                    }
                    result["source_snapshots"].append(source_after_record)
                    checkpoint("source_progress_sampled")
                    source_progress = evaluate_source_tx_progress(
                        source_before, source_after
                    )
                    result["rearm"]["source_tx_progress"] = source_progress
                    if source_progress["eligible"]:
                        decision_context = freeze_rearm_decision(
                            receiver_counter_guard,
                            guard,
                            result["receiver_window"],
                            source_progress,
                            [source_before_record, source_after_record],
                            time.monotonic(),
                        )
                        decision_context["pre_send_source"] = copy.deepcopy(
                            result["rearm"]["pre_send_source"]
                        )
                        result["rearm"]["decision"] = copy.deepcopy(
                            decision_context
                        )
                        checkpoint("rearm_decision_context_saved")
                        pre_send_receiver_report, pre_send_receiver_sent, pre_send_receiver_request = receiver.request_pre_send(
                            config, args.control_timeout
                        )
                        pre_send_receiver_report = validate_pre_send_report(
                            pre_send_receiver_report, config, "pre_send_receiver"
                        )
                        pre_send_receiver_record = pre_send_record(
                            pre_send_receiver_report,
                            receiver_role,
                            pre_send_receiver_request,
                            pre_send_receiver_sent,
                        )
                        result["rearm"]["pre_send_receiver"] = (
                            pre_send_receiver_record
                        )
                        try:
                            result["rearm"]["pre_send_source"] = optional_source_pre_send(
                                sender,
                                config,
                                args.control_timeout,
                                sender_role,
                                args.source_pre_send,
                                result["rearm"]["pre_send_source"],
                            )
                        except BaseException:
                            decision_context["pre_send_source"] = copy.deepcopy(
                                result["rearm"]["pre_send_source"]
                            )
                            result["rearm"]["decision"] = copy.deepcopy(
                                decision_context
                            )
                            raise
                        decision_context["pre_send_receiver"] = copy.deepcopy(
                            pre_send_receiver_record
                        )
                        decision_context["pre_send_source"] = copy.deepcopy(
                            result["rearm"]["pre_send_source"]
                        )
                        pre_op8_guard = receiver.host_rearm_guard()
                        result["rearm"]["pre_op8_host_guard"] = pre_op8_guard
                        decision_context["pre_op8_host_guard"] = copy.deepcopy(
                            pre_op8_guard
                        )
                        result["rearm"]["decision"] = copy.deepcopy(
                            decision_context
                        )
                        checkpoint("pre_send_attribution_captured")
                        if not pre_op8_guard["eligible"]:
                            result["rearm"]["skipped_reason"] = (
                                "host_queue_guard_not_ready"
                            )
                            next_sample = max(
                                next_sample + args.sample_interval,
                                time.monotonic() + args.sample_interval,
                            )
                            continue
                        receiver_before_request_started = time.monotonic()
                        receiver_before_report = receiver.base.snapshot(
                            config, args.control_timeout
                        )
                        receiver_before = benchmark._report_dict(
                            receiver_before_report
                        )
                        if receiver_before is None:
                            raise LivenessError(
                                "receiver_before: empty kind-3 report"
                            )
                        receiver_before = validate_rearm_kind3_report(
                            receiver_before, config, "receiver_before"
                        )
                        receiver_before_record = {
                            **receiver_before,
                            "report_kind": benchmark.REPORT_KIND,
                            "host_monotonic": time.monotonic(),
                        }
                        result["rearm"]["receiver_kind3_before"] = (
                            receiver_before_record
                        )
                        decision_context["receiver_kind3_before"] = copy.deepcopy(
                            receiver_before_record
                        )
                        result["rearm"]["decision"] = copy.deepcopy(
                            decision_context
                        )
                        checkpoint("rearm_receiver_before_captured")
                        pre_op8_evidence_margin = rearm_evidence_margin_with_host_elapsed(
                            receiver_before["elapsed_ms"],
                            config.duration_ms,
                            receiver_before_request_started,
                            time.monotonic(),
                        )
                        result["rearm"]["pre_op8_evidence_window_margin"] = (
                            pre_op8_evidence_margin
                        )
                        decision_context["pre_op8_evidence_window_margin"] = copy.deepcopy(
                            pre_op8_evidence_margin
                        )
                        final_pre_op8_guard = receiver.host_rearm_guard()
                        result["rearm"]["final_pre_op8_host_guard"] = (
                            final_pre_op8_guard
                        )
                        decision_context["final_pre_op8_host_guard"] = copy.deepcopy(
                            final_pre_op8_guard
                        )
                        result["rearm"]["decision"] = copy.deepcopy(
                            decision_context
                        )
                        if not final_pre_op8_guard["eligible"]:
                            result["rearm"]["skipped_reason"] = (
                                "host_queue_guard_not_ready"
                            )
                            checkpoint("rearm_final_host_guard_skipped")
                            next_sample = max(
                                next_sample + args.sample_interval,
                                time.monotonic() + args.sample_interval,
                            )
                            continue
                        if not pre_op8_evidence_margin["eligible"]:
                            result["rearm"]["skipped_reason"] = (
                                "rearm_evidence_window_margin"
                            )
                            checkpoint("rearm_pre_op8_evidence_margin_skipped")
                            next_sample = max(
                                next_sample + args.sample_interval,
                                time.monotonic() + args.sample_interval,
                            )
                            continue
                        rearm_attempted = True
                        result["rearm"]["attempted"] = True
                        rearm_report, rearm_sent_monotonic, rearm_request_id = receiver.request(
                            config, CONTROL_REARM_RX_LIVENESS, args.control_timeout
                        )
                        rearm_sample = _sample_dict(
                            rearm_report,
                            time.monotonic(),
                            rearm_request_id,
                            CONTROL_REARM_RX_LIVENESS,
                        )
                        result["samples"].append(rearm_sample)
                        result["rearm"].update(
                            {
                                "performed": rearm_report.operation_rearm_performed,
                                "software_armed": rearm_report.operation_rearm_software_armed,
                                "sample_sequence": rearm_report.snapshot_sequence,
                                "sent_monotonic": rearm_sent_monotonic,
                            }
                        )
                        if not rearm_report.operation_rearm_performed:
                            add_failure("rearm_response_not_performed")
                        time.sleep(REARM_RECEIVER_STATS_DELAY_SECONDS)
                        receiver_after_report = receiver.base.snapshot(
                            config, args.control_timeout
                        )
                        receiver_after = benchmark._report_dict(
                            receiver_after_report
                        )
                        if receiver_after is None:
                            raise LivenessError(
                                "receiver_after: empty kind-3 report"
                            )
                        receiver_after = validate_rearm_kind3_report(
                            receiver_after, config, "receiver_after"
                        )
                        receiver_after_record = {
                            **receiver_after,
                            "report_kind": benchmark.REPORT_KIND,
                            "host_monotonic": time.monotonic(),
                        }
                        result["rearm"]["receiver_kind3_after"] = (
                            receiver_after_record
                        )
                        result["rearm"]["receiver_authenticated_unique_progress"] = (
                            authenticated_unique_progress(
                                receiver_before, receiver_after, config
                            )
                        )
                        source_after_rearm_report = sender.base.snapshot(
                            config, args.control_timeout
                        )
                        source_after_rearm = benchmark._report_dict(
                            source_after_rearm_report
                        )
                        if source_after_rearm is None:
                            raise LivenessError(
                                "source_after_rearm: empty kind-3 report"
                            )
                        source_after_rearm = validate_rearm_kind3_report(
                            source_after_rearm, config, "source_after_rearm"
                        )
                        source_after_rearm_record = {
                            **source_after_rearm,
                            "report_kind": benchmark.REPORT_KIND,
                            "sample": "after_rearm",
                            "host_monotonic": time.monotonic(),
                        }
                        result["source_snapshots"].append(source_after_rearm_record)
                        source_progress_across_rearm = evaluate_source_progress_across_rearm(
                            source_after,
                            source_after_rearm,
                            config,
                            start_host_monotonic=source_after_record["host_monotonic"],
                            end_host_monotonic=source_after_rearm_record[
                                "host_monotonic"
                            ],
                        )
                        result["rearm"]["source_progress_across_rearm"] = (
                            source_progress_across_rearm
                        )
                        if not source_progress_across_rearm["valid"]:
                            add_failure("source_post_rearm_counter_invalid")
                        decision_context["receiver_kind3_after"] = copy.deepcopy(
                            receiver_after_record
                        )
                        decision_context["op8"] = {
                            "sent_monotonic": rearm_sent_monotonic,
                            "request_id": rearm_request_id,
                            "performed": rearm_report.operation_rearm_performed,
                            "software_armed": rearm_report.operation_rearm_software_armed,
                            "sample_sequence": rearm_report.snapshot_sequence,
                        }
                        decision_context["receiver_authenticated_unique_progress"] = copy.deepcopy(
                            result["rearm"][
                                "receiver_authenticated_unique_progress"
                            ]
                        )
                        decision_context["source_after_rearm"] = copy.deepcopy(
                            source_after_rearm_record
                        )
                        decision_context["source_progress_across_rearm"] = copy.deepcopy(
                            source_progress_across_rearm
                        )
                        result["rearm"]["decision"] = copy.deepcopy(
                            decision_context
                        )
                        checkpoint("rearm_evidence_captured")
                else:
                    result["rearm"]["skipped_reason"] = "host_queue_guard_not_ready"
            next_sample = max(
                next_sample + args.sample_interval,
                time.monotonic() + args.sample_interval,
            )

        result["elapsed_host_seconds"] = time.monotonic() - start
        result["sender_window"].update(
            {
                "status": "fixed_wall_complete",
                "elapsed_host_seconds": result["elapsed_host_seconds"],
            }
        )
        if last_sample is not None and last_sample.elapsed_ms > 0:
            post_source_started = time.monotonic()
            receiver_completion_deadline = (
                post_source_started + RECEIVER_COMPLETION_TIMEOUT_SECONDS
            )
            post_source_polls = 0
            while last_sample.running and not last_sample.complete:
                remaining = receiver_completion_deadline - time.monotonic()
                if remaining <= 0:
                    add_failure("receiver_completion_timeout")
                    break
                receiver.check_health()
                time.sleep(min(args.sample_interval, remaining))
                report, _, request_id = receiver.request(
                    config, CONTROL_SNAPSHOT_RX_LIVENESS, args.control_timeout
                )
                sample = _sample_dict(
                    report, time.monotonic(), request_id, CONTROL_SNAPSHOT_RX_LIVENESS
                )
                result["samples"].append(sample)
                last_sample = report
                post_source_polls += 1
                result["receiver_window"] = receiver_window_observation(
                    report, config.duration_ms
                )
            result["receiver_window"]["post_source_polls"] = post_source_polls
            result["receiver_window"]["post_source_wait_seconds"] = (
                time.monotonic() - post_source_started
            )
        else:
            result["receiver_window"] = receiver_window_observation(
                last_sample, config.duration_ms
            )
            result["receiver_window"]["post_source_polls"] = 0
            result["receiver_window"]["post_source_wait_seconds"] = 0.0
            add_failure("receiver_window_inconclusive_no_first_authenticated_frame")
        receiver_window_status = result["receiver_window"]["status"]
        if receiver_window_status == "complete_partial_window":
            add_failure("receiver_window_elapsed_out_of_window")
        elif receiver_window_status == "terminal_without_complete":
            add_failure("receiver_window_terminal_without_complete")
        result["analysis"] = analyze_samples(result["samples"])
        result["failure_reasons"].extend(
            reason
            for reason in result["analysis"]["failure_reasons"]
            if reason not in result["failure_reasons"]
        )
        result["status"] = (
            "diagnostic_valid"
            if not result["failure_reasons"]
            else "diagnostic_invalid"
        )
        checkpoint("samples_captured_before_close")
    except BaseException as error:
        if isinstance(error, LivenessError):
            add_failure(str(error).split(":", 1)[0])
        else:
            add_failure("probe_exception")
        result["error"] = str(error)
        result["status"] = "diagnostic_invalid"
    finally:
        if run_started:
            for role in (receiver_role, sender_role):
                session = sessions.get(role)
                if session is None:
                    continue
                try:
                    session.base_control(CONTROL_STOP, config)
                except BaseException as error:
                    add_failure(f"{role}_stop_failed")
                    result.setdefault("stop_errors", {})[role] = str(error)
        try:
            checkpoint("finally_before_close")
        except BaseException as error:
            add_failure("capture_persist_error")
            result["capture_persist_error"] = str(error)
        for role, session in sessions.items():
            try:
                session.check_health()
            except LivenessError as error:
                add_failure(f"{role}_{str(error).split(':', 1)[0]}")
        close_failures: list[str] = []
        for role, session in list(sessions.items()):
            try:
                if not session.close():
                    close_failures.append(role)
            except BaseException as error:
                close_failures.append(role)
                result.setdefault("close_errors", {})[role] = str(error)
            failure = session.health.snapshot()
            if failure is not None:
                add_failure(f"{role}_{failure['reason']}")
        if close_failures:
            add_failure("session_close_timeout")
        else:
            closed_ok = True
        sessions.clear()
        if closed_ok and before:
            try:
                after = fresh_config_snapshots_checked(
                    output,
                    (sender_role, receiver_role),
                    args.command_gap,
                    captured_events,
                )
                result["configuration_after"] = after
                result["configuration_preserved"] = benchmark._configuration_preserved(before, after)
                if not result["configuration_preserved"]:
                    add_failure("configuration_changed")
            except BaseException as error:
                result["configuration_after"] = {}
                result["configuration_preserved"] = False
                result["fresh_config_error"] = str(error)
                add_failure("fresh_config_failed")
        elif before:
            result["configuration_after"] = {}
            result["configuration_preserved"] = False
        result["status"] = "diagnostic_valid" if not result["failure_reasons"] else "diagnostic_invalid"
        result["finished_utc"] = _utc_now()
        _safe_write(output / "results.json", result)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(".scratch/w12-throughput-20261007/rx-liveness-run"))
    parser.add_argument("--sender", choices=tuple(benchmark.BOARD_IDENTITIES), default="base")
    parser.add_argument("--count", type=int, default=benchmark.MAX_COUNT)
    parser.add_argument("--window", type=int, choices=SUPPORTED_WINDOWS, default=DEFAULT_WINDOW)
    parser.add_argument("--wall-seconds", type=float, default=DEFAULT_WALL_SECONDS)
    parser.add_argument("--sample-interval", type=float, default=DEFAULT_SAMPLE_INTERVAL_SECONDS)
    parser.add_argument("--rearm-at-seconds", type=float, default=DEFAULT_REARM_AT_SECONDS)
    parser.add_argument("--rearm-stagnant-seconds", type=float, default=DEFAULT_STAGNANT_SECONDS)
    parser.add_argument(
        "--source-pre-send",
        action="store_true",
        help="request one source op9 snapshot; unsupported sources fail closed",
    )
    parser.add_argument("--command-gap", type=float, default=DEFAULT_COMMAND_GAP_SECONDS)
    parser.add_argument("--control-timeout", type=float, default=DEFAULT_CONTROL_TIMEOUT_SECONDS)
    parser.add_argument("--run-id", type=int, default=None)
    parser.add_argument("--image", action="append", default=[])
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        result = run_probe(build_parser().parse_args(argv))
    except LivenessError as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 1
    print("RESULT", result.get("status", "diagnostic_invalid"), flush=True)
    return 0 if result.get("status") == "diagnostic_valid" else 1


if __name__ == "__main__":
    raise SystemExit(main())
