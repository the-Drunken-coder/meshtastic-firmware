"""Strict decoder for the local W12 pre-send attribution page (op 9, kind 7).

Busy reason counters record one primary reason per deferral. Firmware gives
BUSY_TX precedence when TX and RX are both busy, so the reason counters are
intentionally exclusive rather than an independent busy-bit matrix.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


MAGIC = 0x5731
VERSION = 1
KIND = 7
REPORT_BYTES = 233
CONTROL_BYTES = 32
SNAPSHOT_OP = 9
INT16_MIN = -32768
_HEADER = struct.Struct("<HBBIIII")


@dataclass(frozen=True)
class PreSendAttribution:
    run_id: int
    source: int
    destination: int
    elapsed_ms: int
    status: int
    pending_tx_count: int
    busy_tx_deferrals: int
    busy_rx_active_deferrals: int
    busy_rx_irq_read_failure_deferrals: int
    tx_timer_accepted: int
    tx_timer_dispatches: int
    tx_timer_late_count: int
    tx_timer_late_sum_ms: int
    tx_timer_late_max_ms: int
    tx_timer_overwritten: int
    tx_timer_stale: int
    tx_timer_cancelled: int
    tx_timer_irq_displaced: int
    tx_timer_active: bool
    rx_sample_valid: bool
    rx_sample_status: int
    rx_dio_level: int
    rx_busy_level: int
    rx_active_receive_start_ms: int
    rx_sampled_at_ms: int
    rx_raw_irq_flags: int
    rx_raw_status: int
    rx_fifo_level: int
    rx_fifo_flags: int
    tx_fifo_flags: int
    rx_chip_errors: int
    rx_irq_read_result: int
    rx_fifo_flags_result: int
    rx_fifo_level_result: int
    rx_errors_result: int
    rx_software_state: int
    tx_timer_due_at_ms: int


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _i16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<h", data, offset)[0]


def decode_report(data: bytes | bytearray | memoryview) -> PreSendAttribution:
    raw = bytes(data)
    if len(raw) != REPORT_BYTES:
        raise ValueError(f"kind 7 report must be exactly {REPORT_BYTES} bytes")
    magic, version, kind, run_id, source, destination, elapsed_ms = _HEADER.unpack_from(raw)
    if magic != MAGIC or version != VERSION or kind != KIND:
        raise ValueError("invalid kind 7 report header")
    if raw[22:24] != b"\0\0" or raw[77] != 0 or any(raw[114:]):
        raise ValueError("nonzero reserved or unused kind 7 bytes")
    status = raw[20]
    if status & ~0x37:
        raise ValueError("unknown kind 7 status bits")
    prepared = bool(status & 0x01)
    running = bool(status & 0x02)
    complete = bool(status & 0x04)
    pending = raw[21]
    if not prepared or not (running or complete) or (running and complete):
        raise ValueError("inconsistent kind 7 run state")
    if pending > 16:
        raise ValueError("invalid kind 7 pending TX count")
    if bool(status & 0x10) != bool(pending):
        raise ValueError("kind 7 pending status does not match count")
    if bool(status & 0x20) != (running or bool(pending)):
        raise ValueError("kind 7 as-of status does not match state")
    timer_accepted = _u32(raw, 36)
    timer_dispatches = _u32(raw, 40)
    timer_late_count = _u32(raw, 44)
    timer_late_sum = _u32(raw, 48)
    timer_late_max = _u32(raw, 52)
    if timer_dispatches > timer_accepted or timer_late_count > timer_dispatches:
        raise ValueError("kind 7 timer lifecycle counters are inconsistent")
    if (timer_late_count == 0 and (timer_late_sum or timer_late_max)) or (
        timer_late_count and (timer_late_sum < timer_late_max or timer_late_max == 0)
    ):
        raise ValueError("kind 7 timer lateness counters are inconsistent")
    if raw[72] > 1 or raw[73] > 1 or raw[74] & ~0x1F or raw[75] > 1 or raw[76] > 1:
        raise ValueError("invalid kind 7 boolean or sample status")
    if bool(raw[73]) != bool(raw[74] & 0x10):
        raise ValueError("kind 7 sample validity does not match status")
    if not raw[73] and raw[74] & 0x0F:
        raise ValueError("kind 7 unavailable sample has availability bits")
    result_offsets = ((98, 0x01), (100, 0x02), (102, 0x04), (104, 0x08))
    for offset, success_bit in result_offsets:
        result = _i16(raw, offset)
        if result == INT16_MIN:
            if raw[73]:
                raise ValueError("kind 7 valid sample has unavailable result")
        else:
            if not raw[73] or (result == 0) != bool(raw[74] & success_bit):
                raise ValueError("kind 7 result does not match success status")
    timer_active = bool(raw[72])
    timer_due = _u32(raw, 110)
    if (not timer_active and timer_due != 0) or (timer_active and timer_due == 0):
        raise ValueError("kind 7 timer due sentinel is inconsistent")
    software_state = _u32(raw, 106)
    if software_state & ~0x1F:
        raise ValueError("unknown kind 7 software-state bits")
    return PreSendAttribution(
        run_id=run_id,
        source=source,
        destination=destination,
        elapsed_ms=elapsed_ms,
        status=status,
        pending_tx_count=raw[21],
        busy_tx_deferrals=_u32(raw, 24),
        busy_rx_active_deferrals=_u32(raw, 28),
        busy_rx_irq_read_failure_deferrals=_u32(raw, 32),
        tx_timer_accepted=_u32(raw, 36),
        tx_timer_dispatches=_u32(raw, 40),
        tx_timer_late_count=_u32(raw, 44),
        tx_timer_late_sum_ms=_u32(raw, 48),
        tx_timer_late_max_ms=_u32(raw, 52),
        tx_timer_overwritten=_u32(raw, 56),
        tx_timer_stale=_u32(raw, 60),
        tx_timer_cancelled=_u32(raw, 64),
        tx_timer_irq_displaced=_u32(raw, 68),
        tx_timer_active=bool(raw[72]),
        rx_sample_valid=bool(raw[73]),
        rx_sample_status=raw[74],
        rx_dio_level=raw[75],
        rx_busy_level=raw[76],
        rx_active_receive_start_ms=_u32(raw, 78),
        rx_sampled_at_ms=_u32(raw, 82),
        rx_raw_irq_flags=_u32(raw, 86),
        rx_raw_status=_u16(raw, 90),
        rx_fifo_level=_u16(raw, 92),
        rx_fifo_flags=raw[94],
        tx_fifo_flags=raw[95],
        rx_chip_errors=_u16(raw, 96),
        rx_irq_read_result=_i16(raw, 98),
        rx_fifo_flags_result=_i16(raw, 100),
        rx_fifo_level_result=_i16(raw, 102),
        rx_errors_result=_i16(raw, 104),
        rx_software_state=_u32(raw, 106),
        tx_timer_due_at_ms=_u32(raw, 110),
    )


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
    """Encode a self-authorized op9 control for the matching prepared run."""

    return struct.pack(
        "<HBBIII I H I H B 3x",
        MAGIC,
        VERSION,
        SNAPSHOT_OP,
        run_id,
        source,
        destination,
        count,
        size,
        duration_ms,
        window,
        flags,
    )
