#!/usr/bin/env python3
"""Exercise a fixed W12 FLRC profile and turn the wire records into evidence.

The firmware owns radio configuration and payload validation.  This program owns
serial lifetime, phase sequencing, persistence, and analysis.  It deliberately
uses a stable USB identity instead of a remembered tty path.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import math
import os
import signal
import subprocess
import sys
import termios
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable
from zoneinfo import ZoneInfo

try:
    import serial
    from serial.tools import list_ports
except ImportError:  # Analysis helpers remain importable without pyserial.
    serial = None
    list_ports = None


IDENTITIES = {
    "base": "44:B1:76:AE:19:14",
    "walker": "44:B1:76:AE:20:18",
}
EXPECTED_BUILD = "w12-flrc-profile-v2"
DEFAULT_LENGTHS = (12, 16, 32, 64, 128, 240, 255)
DEFAULT_DELAYS_US = (2000, 1000, 500, 250, 100, 0)
MAX_FRAME_LENGTH = 255
AC_REQUIRED_AFTER_SECONDS = 3600
EVENT_POLL_TIMEOUT = 0.05
MAX_SERIAL_LINE = 1024 * 1024
STOP_MARGIN_SECONDS = 30
COMMAND_GUARD_SECONDS = 0.1

stop_requested = False


def stop_signal(_signum: int, _frame: Any) -> None:
    global stop_requested
    stop_requested = True


def utc_stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def write_json(path: Path, value: Any) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
    )
    temporary.replace(path)


def parse_int_list(
    value: str, *, name: str, minimum: int = 0, maximum: int | None = None
) -> tuple[int, ...]:
    try:
        values = tuple(int(part.strip()) for part in value.split(",") if part.strip())
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            f"{name} must be comma-separated integers"
        ) from error
    if not values:
        raise argparse.ArgumentTypeError(f"{name} must contain at least one value")
    if any(item < minimum for item in values):
        raise argparse.ArgumentTypeError(f"{name} values must be >= {minimum}")
    if maximum is not None and any(item > maximum for item in values):
        raise argparse.ArgumentTypeError(f"{name} values must be <= {maximum}")
    return values


def seconds_until_next_seven_am(now: dt.datetime | None = None) -> int:
    eastern = ZoneInfo("America/New_York")
    current = now.astimezone(eastern) if now is not None else dt.datetime.now(eastern)
    target = current.replace(hour=7, minute=0, second=0, microsecond=0)
    if current >= target:
        target += dt.timedelta(days=1)
    return max(1, math.ceil((target - current).total_seconds()))


def read_power_state() -> str:
    try:
        result = subprocess.run(
            ["/usr/bin/pmset", "-g", "batt"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.SubprocessError) as error:
        raise RuntimeError("cannot verify AC power with pmset") from error
    return result.stdout.strip()


def require_ac() -> str:
    power = read_power_state()
    if "AC Power" not in power:
        raise RuntimeError("AC power is required for runs longer than one hour")
    return power


def start_power_guard() -> subprocess.Popen[bytes] | None:
    executable = "/usr/bin/caffeinate"
    if not Path(executable).exists():
        return None
    return subprocess.Popen(
        [executable, "-i", "-s", "-w", str(os.getpid())],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


if serial is not None:

    class PreserveControlSerial(serial.Serial):
        """Open pyserial without touching ESP32-S3 reset modem lines."""

        def _update_dtr_state(self) -> None:
            return

        def _update_rts_state(self) -> None:
            return

else:

    class PreserveControlSerial:  # pragma: no cover - only an import fallback.
        pass


def clear_hupcl(connection: Any) -> None:
    attributes = termios.tcgetattr(connection.fileno())
    attributes[2] &= ~termios.HUPCL
    termios.tcsetattr(connection.fileno(), termios.TCSANOW, attributes)


def discover_port(role: str) -> Any:
    if list_ports is None:
        raise RuntimeError("pyserial is required to access W12 hardware")
    matches = [
        port for port in list_ports.comports() if port.serial_number == IDENTITIES[role]
    ]
    if len(matches) != 1:
        raise RuntimeError(
            f"{role}: expected exactly one USB device with serial {IDENTITIES[role]}, "
            f"found {len(matches)}"
        )
    return matches[0]


@dataclass
class SerialEvent:
    role: str
    monotonic: float
    utc: str
    record: dict[str, Any]


class BoardSession:
    """One persistent, identity-pinned line-JSON serial session."""

    def __init__(self, role: str, output: Path) -> None:
        if serial is None:
            raise RuntimeError("pyserial is required to access W12 hardware")
        port = discover_port(role)
        self.role = role
        self.identity = {
            "role": role,
            "serial": port.serial_number,
            "port": port.device,
            "location": port.location,
        }
        self.output = output
        self.raw_file = (output / f"{role}-serial.raw").open("ab", buffering=0)
        self.jsonl_file = (output / f"{role}-serial.jsonl").open("a", buffering=1)
        self.pending = bytearray()
        self.queue: collections.deque[SerialEvent] = collections.deque()
        self.events: list[SerialEvent] = []
        self.protocol_errors: list[str] = []
        self.reboot_events: list[str] = []
        self.reboot_detection_armed = False
        self.command_number = 0
        self.last_command_monotonic: float | None = None
        self.connection = PreserveControlSerial(
            port=None,
            baudrate=115200,
            timeout=EVENT_POLL_TIMEOUT,
            write_timeout=3,
            exclusive=True,
        )
        self.connection.port = port.device
        try:
            self.connection.open()
            clear_hupcl(self.connection)
        except Exception:
            self.raw_file.close()
            self.jsonl_file.close()
            raise

    def _write_log(self, payload: dict[str, Any]) -> None:
        self.jsonl_file.write(
            json.dumps(payload, sort_keys=True, allow_nan=False) + "\n"
        )

    def _record_line(self, line: bytes) -> None:
        monotonic = time.monotonic()
        text = line.decode("utf-8", errors="replace").rstrip("\r")
        wrapper: dict[str, Any] = {
            "direction": "rx",
            "monotonic": monotonic,
            "role": self.role,
            "utc": utc_stamp(),
            "line": text,
        }
        if self.reboot_detection_armed and any(
            marker in text for marker in ("ESP-ROM", "rst:", "W12_FIELD_SURVEY")
        ):
            message = f"unexpected reboot banner: {text}"
            self.reboot_events.append(message)
            wrapper["reboot_detected"] = message
            self._write_log(wrapper)
            raise RuntimeError(f"{self.role}: {message}")
        try:
            value = json.loads(text)
        except json.JSONDecodeError as error:
            message = f"invalid JSON: {error.msg}"
            wrapper["parse_error"] = message
            self.protocol_errors.append(message)
            self._write_log(wrapper)
            return
        if not isinstance(value, dict) or not isinstance(value.get("event"), str):
            message = "record is not an event object"
            wrapper["parse_error"] = message
            self.protocol_errors.append(message)
            self._write_log(wrapper)
            return
        if self.reboot_detection_armed and (
            value.get("event") == "boot"
            or any(marker in text for marker in ("ESP-ROM", "rst:", "W12_FIELD_SURVEY"))
        ):
            message = f"unexpected reboot record: {text}"
            self.reboot_events.append(message)
            wrapper["reboot_detected"] = message
            wrapper["record"] = value
            self._write_log(wrapper)
            raise RuntimeError(f"{self.role}: {message}")
        event = SerialEvent(self.role, monotonic, wrapper["utc"], value)
        self.events.append(event)
        self.queue.append(event)
        wrapper["record"] = value
        self._write_log(wrapper)

    def poll(self) -> None:
        waiting = self.connection.in_waiting
        chunk = self.connection.read(min(waiting, 4096) if waiting else 1)
        if not chunk:
            return
        self.raw_file.write(chunk)
        self.pending.extend(chunk)
        while b"\n" in self.pending:
            line, _, remainder = self.pending.partition(b"\n")
            self.pending = bytearray(remainder)
            if len(line) > MAX_SERIAL_LINE:
                raise RuntimeError(
                    f"{self.role}: serial line exceeds {MAX_SERIAL_LINE} bytes"
                )
            self._record_line(bytes(line))
        if len(self.pending) > MAX_SERIAL_LINE:
            raise RuntimeError(
                f"{self.role}: unterminated serial line exceeds {MAX_SERIAL_LINE} bytes"
            )

    def _wait_command_guard(self) -> None:
        if self.last_command_monotonic is not None:
            remaining = (
                self.last_command_monotonic + COMMAND_GUARD_SECONDS - time.monotonic()
            )
            if remaining > 0:
                time.sleep(remaining)

    def send(self, command: str, *, guard: bool = True) -> float:
        self.command_number += 1
        if guard:
            self._wait_command_guard()
        sent_at = time.monotonic()
        self._write_log(
            {
                "command": command,
                "command_number": self.command_number,
                "direction": "tx",
                "monotonic": sent_at,
                "role": self.role,
                "utc": utc_stamp(),
            }
        )
        self.connection.write((command + "\n").encode("ascii"))
        self.connection.flush()
        self.last_command_monotonic = sent_at
        return sent_at

    def _discard_events(self, event_name: str) -> None:
        remaining = len(self.queue)
        for _ in range(remaining):
            item = self.queue.popleft()
            if item.record.get("event") != event_name:
                self.queue.append(item)

    def _take_event(
        self,
        event_name: str,
        predicate: Callable[[dict[str, Any]], bool] | None = None,
    ) -> SerialEvent | None:
        match: SerialEvent | None = None
        remaining = len(self.queue)
        for _ in range(remaining):
            item = self.queue.popleft()
            if (
                match is None
                and item.record.get("event") == event_name
                and (predicate is None or predicate(item.record))
            ):
                match = item
            else:
                self.queue.append(item)
        return match

    def wait_event(
        self,
        event_name: str,
        timeout: float,
        predicate: Callable[[dict[str, Any]], bool] | None = None,
        not_before: float | None = None,
    ) -> SerialEvent:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            found = self._take_event(event_name, predicate)
            if (
                found is not None
                and not_before is not None
                and found.monotonic < not_before
            ):
                found = None
            if found is not None:
                return found
            self.poll()
            time.sleep(0.001)
        raise TimeoutError(f"{self.role}: no {event_name} reply within {timeout:.1f}s")

    def command(self, text: str, event_name: str, timeout: float = 10) -> SerialEvent:
        self._wait_command_guard()
        self.poll()
        self._discard_events(event_name)
        sent_at = self.send(text, guard=False)
        return self.wait_event(event_name, timeout, not_before=sent_at)

    def set_crc(self, byte_count: int, timeout: float = 10) -> dict[str, Any]:
        if byte_count not in (2, 4):
            raise ValueError("CRC must be 2 or 4 bytes")
        record = self.command(f"CRC {byte_count}", "crc", timeout).record
        if as_int(record.get("bytes")) != byte_count or not status_ok(
            record.get("status")
        ):
            raise RuntimeError(f"{self.role}: CRC {byte_count} rejected: {record}")
        return record

    def stats(self, timeout: float = 10) -> dict[str, Any]:
        return self.command("STATS", "stats", timeout).record

    def receive(self) -> dict[str, Any]:
        record = self.command("RX", "rx_ready", 10).record
        if not status_ok(record.get("status")):
            raise RuntimeError(f"{self.role}: receive setup failed: {record}")
        return record

    def stop(self, timeout: float = 10) -> SerialEvent:
        event = self.command("STOP", "stopped", timeout)
        record = event.record
        if as_int(record.get("status")) != 0 or not as_bool(record.get("quiescent")):
            raise RuntimeError(
                f"{self.role}: STOP did not confirm quiescence: {record}"
            )
        return event

    def close(self) -> None:
        try:
            self.connection.close()
        finally:
            self.raw_file.close()
            self.jsonl_file.close()


def as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def as_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def as_bool(value: Any) -> bool:
    if isinstance(value, str):
        return value.lower() in {"1", "true", "yes", "on"}
    return bool(value)


def status_ok(value: Any) -> bool:
    return as_int(value) == 0


def percentile(values: Iterable[float], fraction: float) -> float | None:
    ordered = sorted(values)
    if not ordered:
        return None
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * weight


def metric_stats(values: Iterable[float]) -> dict[str, float | int | None]:
    clean = [value for value in values if math.isfinite(value) and value >= 0]
    return {
        "count": len(clean),
        "p50": percentile(clean, 0.50),
        "p95": percentile(clean, 0.95),
        "p99": percentile(clean, 0.99),
        "max": max(clean) if clean else None,
    }


def event_records(output: Path) -> list[SerialEvent]:
    records: list[SerialEvent] = []
    for role in IDENTITIES:
        path = output / f"{role}-serial.jsonl"
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            try:
                wrapper = json.loads(line)
            except json.JSONDecodeError:
                continue
            record = wrapper.get("record")
            if wrapper.get("direction") == "rx" and isinstance(record, dict):
                records.append(
                    SerialEvent(
                        role=str(wrapper.get("role", role)),
                        monotonic=float(wrapper.get("monotonic", 0)),
                        utc=str(wrapper.get("utc", "")),
                        record=record,
                    )
                )
    return records


def phase_records(output: Path) -> list[dict[str, Any]]:
    path = output / "phases.jsonl"
    if not path.exists():
        return []
    latest: dict[int, dict[str, Any]] = {}
    for line in path.read_text().splitlines():
        try:
            value = json.loads(line)
            phase_id = int(value["phase_id"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            continue
        latest[phase_id] = value
    return [latest[key] for key in sorted(latest)]


def info_records(output: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for event in event_records(output):
        if event.record.get("event") == "info":
            result.setdefault(event.role, event.record.copy())
    return result


def run_completion(
    expected_attempts: int,
    observed_attempts: int,
    run_end: dict[str, Any] | None,
) -> dict[str, Any]:
    if run_end is None:
        return {
            "complete": False,
            "requested_attempts": None,
            "observed_attempts": observed_attempts,
            "run_end_attempts": None,
            "stopped": None,
            "complete_flag": None,
        }
    requested = as_int(run_end.get("requested_count"))
    if requested is None:
        requested = expected_attempts
    end_attempts = as_int(run_end.get("attempts"))
    stopped = as_bool(run_end.get("stopped")) if "stopped" in run_end else False
    complete_flag = as_bool(run_end.get("complete")) if "complete" in run_end else None
    complete = (
        requested == expected_attempts
        and observed_attempts == expected_attempts
        and end_attempts == expected_attempts
        and not stopped
        and complete_flag is not False
    )
    return {
        "complete": complete,
        "requested_attempts": requested,
        "observed_attempts": observed_attempts,
        "run_end_attempts": end_attempts,
        "stopped": stopped,
        "complete_flag": complete_flag,
    }


def summarize_phase(
    phase: dict[str, Any],
    records: list[SerialEvent],
) -> dict[str, Any]:
    sender = str(phase["sender"])
    receiver = str(phase["receiver"])
    expected_length = int(phase["length"])
    sender_run = as_int(phase.get("sender_run"))
    start = float(phase.get("started_monotonic", 0))
    end = float(phase.get("ended_monotonic", float("inf")))
    in_phase = [item for item in records if start <= item.monotonic <= end]
    attempts = [
        item.record
        for item in in_phase
        if item.role == sender
        and item.record.get("event") == "attempt"
        and as_int(item.record.get("length")) == expected_length
        and (sender_run is None or as_int(item.record.get("run")) == sender_run)
    ]
    if sender_run is None and attempts:
        sender_run = as_int(attempts[0].get("run"))
    raw_received = [
        item.record
        for item in in_phase
        if item.role == receiver and item.record.get("event") == "rx"
    ]
    receiver_info = phase.get("pre_phase_info", {}).get(receiver, {})
    expected_receiver_run = (
        as_int(receiver_info.get("run")) if isinstance(receiver_info, dict) else None
    )
    receiver_local_run_unvalidated = 0
    receiver_wrong_local_run = 0
    if expected_receiver_run is None:
        all_received = raw_received
        receiver_local_run_validation = "unvalidated_missing_pre_phase_info"
        receiver_local_run_unvalidated = len(raw_received)
    else:
        all_received = []
        for record in raw_received:
            local_run = as_int(record.get("run"))
            if local_run is None:
                all_received.append(record)
                receiver_local_run_unvalidated += 1
            elif local_run == expected_receiver_run:
                all_received.append(record)
            else:
                receiver_wrong_local_run += 1
        receiver_local_run_validation = (
            "validated"
            if receiver_local_run_unvalidated == 0
            else "legacy_missing_record_run"
        )
    received = [
        record
        for record in all_received
        if as_int(record.get("length")) == expected_length
        and (sender_run is None or as_int(record.get("peer_run")) == sender_run)
    ]
    # CRC/header errors may not preserve the sender run or sequence. Keep all
    # receiver events for diagnostics, while only joining unambiguous records.
    received_by_key: dict[
        tuple[int | None, int | None, int | None], list[dict[str, Any]]
    ] = collections.defaultdict(list)
    for record in received:
        key = (
            as_int(record.get("peer_run")),
            as_int(record.get("seq")),
            as_int(record.get("length")),
        )
        received_by_key[key].append(record)

    matches: list[tuple[dict[str, Any], dict[str, Any] | None]] = []
    for attempt in attempts:
        key = (
            as_int(attempt.get("run")),
            as_int(attempt.get("seq")),
            as_int(attempt.get("length")),
        )
        matches.append((attempt, received_by_key.get(key, [None])[0]))
    matched = []
    tx_errors: collections.Counter[str] = collections.Counter()
    receiver_errors: collections.Counter[str] = collections.Counter()
    byte_errors = 0
    missing_echo = 0
    local_tx_completed = [
        attempt
        for attempt in attempts
        if status_ok(attempt.get("tx_status")) and as_bool(attempt.get("tx_done"))
    ]
    local_rx_errors = collections.Counter(
        str(attempt.get("rx_status"))
        for attempt in local_tx_completed
        if not status_ok(attempt.get("rx_status"))
    )
    local_rx_setup_errors = collections.Counter(
        str(attempt.get("rx_arm_status"))
        for attempt in local_tx_completed
        if "rx_arm_status" in attempt
        and (
            "rx_arm_attempted" not in attempt
            or as_bool(attempt.get("rx_arm_attempted"))
        )
        and not status_ok(attempt.get("rx_arm_status"))
    )
    local_rx_setup_unknown = sum(
        "rx_arm_status" not in attempt for attempt in local_tx_completed
    )
    rx_timeout_count = sum(
        as_int(attempt.get("rx_status")) == -6 for attempt in local_tx_completed
    )
    no_echo_local_tx = [
        attempt for attempt in local_tx_completed if not as_bool(attempt.get("echo"))
    ]
    rx_arm_successes = [
        attempt
        for attempt in local_tx_completed
        if "rx_arm_status" in attempt
        and (
            "rx_arm_attempted" not in attempt
            or as_bool(attempt.get("rx_arm_attempted"))
        )
        and status_ok(attempt.get("rx_arm_status"))
    ]
    no_echo_rx_armed = [
        attempt
        for attempt in no_echo_local_tx
        if "rx_arm_status" in attempt
        and (
            "rx_arm_attempted" not in attempt
            or as_bool(attempt.get("rx_arm_attempted"))
        )
        and status_ok(attempt.get("rx_arm_status"))
    ]
    no_echo_status_zero = [
        attempt for attempt in no_echo_local_tx if status_ok(attempt.get("rx_status"))
    ]
    for attempt, received_record in matches:
        if not status_ok(attempt.get("tx_status")) or not as_bool(
            attempt.get("tx_done")
        ):
            tx_errors[str(attempt.get("tx_status"))] += 1
        if received_record is None:
            continue
        if not status_ok(received_record.get("status")):
            receiver_errors[str(received_record.get("status"))] += 1
        if status_ok(received_record.get("status")) and not as_bool(
            received_record.get("payload_valid")
        ):
            byte_errors += 1
        if (
            not as_bool(attempt.get("echo"))
            and status_ok(attempt.get("tx_status"))
            and as_bool(attempt.get("tx_done"))
        ):
            missing_echo += 1
        if (
            status_ok(attempt.get("tx_status"))
            and as_bool(attempt.get("tx_done"))
            and status_ok(received_record.get("status"))
            and as_bool(received_record.get("payload_valid"))
            and as_bool(attempt.get("echo"))
            and status_ok(received_record.get("echo_status"))
        ):
            matched.append((attempt, received_record))

    metric_start_call = [
        value
        for attempt, _received_record in matched
        if (value := as_number(attempt.get("start_call_us"))) is not None
    ]
    metric_completion = [
        value
        for attempt, _received_record in matched
        if (value := as_number(attempt.get("tx_done_us"))) is not None
    ]
    metric_finish_call = [
        value
        for attempt, _received_record in matched
        if (value := as_number(attempt.get("finish_tx_us"))) is not None
    ]
    metric_stage = [
        value
        for attempt, _received_record in matched
        if (value := as_number(attempt.get("stage_tx_us"))) is not None
    ]
    metric_launch_call = [
        value
        for attempt, _received_record in matched
        if (value := as_number(attempt.get("launch_call_us"))) is not None
    ]
    metric_launch_to_done = [
        value
        for attempt, _received_record in matched
        if (value := as_number(attempt.get("launch_to_tx_done_us"))) is not None
    ]
    metric_rx_ready_after_done = [
        value
        for attempt, _received_record in matched
        if (value := as_number(attempt.get("rx_ready_after_tx_done_us"))) is not None
    ]
    metric_arm = [
        value
        for attempt, _received_record in matched
        if (value := as_number(attempt.get("rx_arm_us"))) is not None
    ]
    metric_rtt = [
        value
        for attempt, _received_record in matched
        if (value := as_number(attempt.get("rtt_us"))) is not None
    ]
    metric_toa = [
        value
        for attempt, _received_record in matched
        if (value := as_number(attempt.get("driver_toa_us"))) is not None
    ]
    matched_receiver_poll = [
        (attempt, received_record)
        for attempt, received_record in matched
        if str(received_record.get("irq_source", "")).lower() == "poll"
    ]
    matched_receiver_irq = [
        (attempt, received_record)
        for attempt, received_record in matched
        if str(received_record.get("irq_source", "")).lower() != "poll"
    ]
    receiver_irq_source_counts = collections.Counter(
        str(received_record.get("irq_source", "unknown")).lower()
        for _attempt, received_record in matched
    )
    metric_read = [
        value
        for _attempt, received_record in matched_receiver_irq
        if (value := as_number(received_record.get("read_us"))) is not None
    ]
    metric_echo_start = [
        value
        for _attempt, received_record in matched_receiver_irq
        if (value := as_number(received_record.get("echo_start_us"))) is not None
    ]
    metric_echo_done = [
        value
        for _attempt, received_record in matched_receiver_irq
        if (value := as_number(received_record.get("echo_done_us"))) is not None
    ]
    metric_rx_rearm = [
        value
        for _attempt, received_record in matched_receiver_irq
        if (value := as_number(received_record.get("rx_rearm_us"))) is not None
    ]
    metric_poll_read = [
        value
        for _attempt, received_record in matched_receiver_poll
        if (value := as_number(received_record.get("read_us"))) is not None
    ]
    metric_poll_echo_start = [
        value
        for _attempt, received_record in matched_receiver_poll
        if (value := as_number(received_record.get("echo_start_us"))) is not None
    ]
    metric_poll_echo_done = [
        value
        for _attempt, received_record in matched_receiver_poll
        if (value := as_number(received_record.get("echo_done_us"))) is not None
    ]
    metric_poll_rx_rearm = [
        value
        for _attempt, received_record in matched_receiver_poll
        if (value := as_number(received_record.get("rx_rearm_us"))) is not None
    ]
    local_metric_start_call = [
        value
        for attempt in local_tx_completed
        if (value := as_number(attempt.get("start_call_us"))) is not None
    ]
    local_metric_completion = [
        value
        for attempt in local_tx_completed
        if (value := as_number(attempt.get("tx_done_us"))) is not None
    ]
    local_metric_finish_call = [
        value
        for attempt in local_tx_completed
        if (value := as_number(attempt.get("finish_tx_us"))) is not None
    ]
    local_metric_stage = [
        value
        for attempt in local_tx_completed
        if (value := as_number(attempt.get("stage_tx_us"))) is not None
    ]
    local_metric_launch_call = [
        value
        for attempt in local_tx_completed
        if (value := as_number(attempt.get("launch_call_us"))) is not None
    ]
    local_metric_launch_to_done = [
        value
        for attempt in local_tx_completed
        if (value := as_number(attempt.get("launch_to_tx_done_us"))) is not None
    ]
    local_metric_rx_ready_after_done = [
        value
        for attempt in local_tx_completed
        if (value := as_number(attempt.get("rx_ready_after_tx_done_us"))) is not None
    ]
    local_metric_arm = [
        value
        for attempt in local_tx_completed
        if (value := as_number(attempt.get("rx_arm_us"))) is not None
    ]
    local_metric_toa = [
        value
        for attempt in local_tx_completed
        if (value := as_number(attempt.get("driver_toa_us"))) is not None
    ]
    duplicate_rx = sum(max(0, len(values) - 1) for values in received_by_key.values())
    matched_keys = {
        (
            as_int(attempt.get("run")),
            as_int(attempt.get("seq")),
            as_int(attempt.get("length")),
        )
        for attempt, _received_record in matches
    }
    matched_receiver_records = sum(
        min(len(values), 1)
        for key, values in received_by_key.items()
        if key in matched_keys
    )
    unmatched_rx = len(all_received) - matched_receiver_records
    receiver_status_errors = [
        record for record in all_received if not status_ok(record.get("status"))
    ]
    receiver_payload_errors = [
        record
        for record in all_received
        if status_ok(record.get("status")) and not as_bool(record.get("payload_valid"))
    ]
    receiver_echo_errors = collections.Counter(
        str(record.get("echo_status"))
        for record in all_received
        if not status_ok(record.get("echo_status"))
    )
    receiver_rearm_errors = collections.Counter(
        str(record.get("rearm_status"))
        for record in all_received
        if not status_ok(record.get("rearm_status"))
    )
    receiver_error_observations = {
        "all_rx_records": len(all_received),
        "status_error_records": len(receiver_status_errors),
        "status_by_status": dict(
            collections.Counter(
                str(record.get("status")) for record in receiver_status_errors
            )
        ),
        "status_by_irq": dict(
            collections.Counter(
                str(record.get("irq")) for record in receiver_status_errors
            )
        ),
        "status_by_length": dict(
            collections.Counter(
                str(record.get("length")) for record in receiver_status_errors
            )
        ),
        "unjoined_status_error_records": (
            sum(
                (as_int(record.get("peer_run")) != sender_run)
                for record in receiver_status_errors
            )
            if sender_run is not None
            else len(receiver_status_errors)
        ),
        "payload_validation_error_records": len(receiver_payload_errors),
        "echo_status_errors_by_status": dict(receiver_echo_errors),
        "rearm_status_errors_by_status": dict(receiver_rearm_errors),
    }
    run_end = next(
        (
            item.record
            for item in in_phase
            if item.role == sender
            and item.record.get("event") == "run_end"
            and (sender_run is None or as_int(item.record.get("run")) == sender_run)
        ),
        None,
    )
    completion = run_completion(int(phase["count"]), len(attempts), run_end)
    return {
        "phase_id": phase["phase_id"],
        "phase_state": phase.get("state", "unknown"),
        "kind": phase.get("kind", "measurement"),
        "sender": sender,
        "receiver": receiver,
        "length": expected_length,
        "delay_us": int(phase["delay_us"]),
        "sender_run": sender_run,
        "expected_attempts": int(phase["count"]),
        "attempts": len(attempts),
        "tx_completed": len(local_tx_completed),
        "matched_successes": len(matched),
        "receiver_records_raw": len(raw_received),
        "receiver_records": len(all_received),
        "receiver_records_joined": len(received),
        "receiver_local_run_validation": receiver_local_run_validation,
        "receiver_local_run_expected": expected_receiver_run,
        "receiver_local_run_unvalidated_records": receiver_local_run_unvalidated,
        "receiver_wrong_local_run_records": receiver_wrong_local_run,
        "unmatched_attempts": sum(
            received_record is None for _attempt, received_record in matches
        ),
        "unmatched_receiver_records": unmatched_rx,
        "duplicate_receiver_records": duplicate_rx,
        "tx_errors_by_status": dict(tx_errors),
        "receiver_errors_by_status": dict(receiver_errors),
        "local_rx_setup_errors_by_status": dict(local_rx_setup_errors),
        "local_rx_setup_unknown": local_rx_setup_unknown,
        "local_rx_errors_by_status": dict(local_rx_errors),
        "rx_timeout_count": rx_timeout_count,
        "receiver_error_observations": receiver_error_observations,
        "receiver_error_counts": receiver_error_observations,
        "byte_validation_errors": byte_errors,
        "byte_validation_errors_all": len(receiver_payload_errors),
        "missing_echoes": missing_echo,
        "no_ack_rates": {
            "all_local_tx_completed_descriptive": {
                "description": "Descriptive ratio across every locally completed TX, including attempts with RX setup errors or timeouts.",
                "no_echo": len(no_echo_local_tx),
                "denominator": len(local_tx_completed),
                "rate": (
                    len(no_echo_local_tx) / len(local_tx_completed)
                    if local_tx_completed
                    else None
                ),
            },
            "rx_arm_observed": {
                "no_echo": len(no_echo_rx_armed),
                "denominator": len(rx_arm_successes),
                "rate": (
                    len(no_echo_rx_armed) / len(rx_arm_successes)
                    if rx_arm_successes
                    else None
                ),
            },
            "rx_status_zero": {
                "no_echo": len(no_echo_status_zero),
                "denominator": sum(
                    status_ok(attempt.get("rx_status"))
                    for attempt in local_tx_completed
                ),
                "rate": (
                    len(no_echo_status_zero)
                    / sum(
                        status_ok(attempt.get("rx_status"))
                        for attempt in local_tx_completed
                    )
                    if any(
                        status_ok(attempt.get("rx_status"))
                        for attempt in local_tx_completed
                    )
                    else None
                ),
            },
        },
        "run_end": run_end,
        "run_completion": completion,
        "run_complete": completion["complete"],
        "metrics_matched_success_only": {
            "software_completion_us": metric_stats(metric_completion),
            "start_transmit_call_us": metric_stats(metric_start_call),
            "finish_transmit_call_us": metric_stats(metric_finish_call),
            "stage_tx_us": metric_stats(metric_stage),
            "launch_call_us": metric_stats(metric_launch_call),
            "launch_to_tx_done_us": metric_stats(metric_launch_to_done),
            "rx_ready_after_tx_done_us": metric_stats(metric_rx_ready_after_done),
            "rx_arm_us": metric_stats(metric_arm),
            "rtt_us": metric_stats(metric_rtt),
            "driver_toa_us": metric_stats(metric_toa),
            "read_us": metric_stats(metric_read),
            "echo_start_us": metric_stats(metric_echo_start),
            "echo_done_us": metric_stats(metric_echo_done),
            "rx_rearm_us": metric_stats(metric_rx_rearm),
        },
        "metrics_receiver_irq_poll_excluded": {
            "read_us": metric_stats(metric_poll_read),
            "echo_start_us": metric_stats(metric_poll_echo_start),
            "echo_done_us": metric_stats(metric_poll_echo_done),
            "rx_rearm_us": metric_stats(metric_poll_rx_rearm),
        },
        "receiver_irq_source_counts": dict(receiver_irq_source_counts),
        "receiver_irq_poll_excluded_records": len(matched_receiver_poll),
        "metrics_local_tx_completed": {
            "software_completion_us": metric_stats(local_metric_completion),
            "start_transmit_call_us": metric_stats(local_metric_start_call),
            "finish_transmit_call_us": metric_stats(local_metric_finish_call),
            "stage_tx_us": metric_stats(local_metric_stage),
            "launch_call_us": metric_stats(local_metric_launch_call),
            "launch_to_tx_done_us": metric_stats(local_metric_launch_to_done),
            "rx_ready_after_tx_done_us": metric_stats(local_metric_rx_ready_after_done),
            "rx_arm_us": metric_stats(local_metric_arm),
            "driver_toa_us": metric_stats(local_metric_toa),
        },
        "limitations": [
            "Software completion and firmware-clock RTT are measured by the device; USB only transports the logs, and neither is RF airtime.",
            "A missing receiver record is unobserved by this host and does not identify the RF failure mechanism.",
            "Receiver IRQ timing percentiles exclude records marked irq_source=poll; those records are reported separately.",
        ],
    }


def summarize(output: Path) -> dict[str, Any]:
    records = event_records(output)
    phases = phase_records(output)
    results = [
        summarize_phase(phase, records)
        for phase in phases
        if phase.get("state") in {"complete", "incomplete"}
    ]
    protocol_errors: dict[str, int] = collections.Counter()
    for role in IDENTITIES:
        path = output / f"{role}-serial.jsonl"
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if value.get("parse_error"):
                protocol_errors[role] += 1

    def aggregate_totals(items: list[dict[str, Any]]) -> dict[str, int]:
        return {
            "phases": len(items),
            "complete_phases": sum(item["run_complete"] for item in items),
            "incomplete_phases": sum(not item["run_complete"] for item in items),
            "attempts": sum(item["attempts"] for item in items),
            "tx_completed": sum(item["tx_completed"] for item in items),
            "matched_successes": sum(item["matched_successes"] for item in items),
            "tx_errors": sum(
                sum(item["tx_errors_by_status"].values()) for item in items
            ),
            "receiver_error_records": sum(
                item["receiver_error_observations"]["status_error_records"]
                for item in items
            ),
            "byte_validation_errors": sum(
                item["byte_validation_errors"] for item in items
            ),
        }

    normal_results = [
        item for item in results if item["kind"] != "crc_negative_control"
    ]
    crc_results = [item for item in results if item["kind"] == "crc_negative_control"]
    totals = aggregate_totals(results)
    summary = {
        "utc": utc_stamp(),
        "build": next(iter(info_records(output).values()), {}).get(
            "build", EXPECTED_BUILD
        ),
        "board_info": info_records(output),
        "phases": results,
        "totals": totals,
        "normal_measurement_totals": aggregate_totals(normal_results),
        "crc_negative_control_totals": aggregate_totals(crc_results),
        "protocol_errors_by_role": dict(protocol_errors),
        "limitations": [
            "This measures one fixed FLRC profile at a time. It is not a range test or a complete mesh capacity test.",
            "Only matched TX, receiver payload-valid, and echo-success records contribute to timing percentiles.",
            "Software completion, receive-arm, driver ToA, and firmware-clock RTT are not direct RF-airtime measurements; USB only transports logs.",
            "Unmatched records are reported as unobserved by the peer, with no claim about the RF cause.",
            "The test does not measure amplified RF output; that requires RF test equipment.",
            "normal_measurement_totals excludes the deliberate CRC negative-control phases; those are in crc_negative_control_totals.",
        ],
    }
    write_json(output / "summary.json", summary)
    return summary


class Runner:
    def __init__(
        self,
        output: Path,
        *,
        duration_seconds: int,
        count: int,
        gap_ms: int,
        lengths: tuple[int, ...],
        delays_us: tuple[int, ...],
    ) -> None:
        self.output = output
        self.duration_seconds = duration_seconds
        self.count = count
        self.gap_ms = gap_ms
        self.lengths = lengths
        self.delays_us = delays_us
        self.sessions: dict[str, BoardSession] = {}
        self.phases: list[dict[str, Any]] = []
        self.state: dict[str, Any] = {
            "state": "preflight",
            "host_script_sha256": hashlib.sha256(
                Path(__file__).read_bytes()
            ).hexdigest(),
            "build": EXPECTED_BUILD,
            "requested_duration_seconds": duration_seconds,
            "count": count,
            "gap_ms": gap_ms,
            "lengths": list(lengths),
            "delays_us": list(delays_us),
            "destructive_commands_sent": [],
            "started_utc": utc_stamp(),
        }
        self.started_monotonic: float | None = None
        self.power_guard: subprocess.Popen[bytes] | None = None

    def save_state(self) -> None:
        self.state["updated_utc"] = utc_stamp()
        self.state["completed_phases"] = len(self.phases)
        write_json(self.output / "state.json", self.state)

    def log_phase(self, phase: dict[str, Any]) -> None:
        with (self.output / "phases.jsonl").open("a") as file:
            file.write(json.dumps(phase, sort_keys=True, allow_nan=False) + "\n")
        self.phases.append(phase)

    def open_and_identify(self) -> None:
        for role in IDENTITIES:
            session = BoardSession(role, self.output)
            self.sessions[role] = session
            try:
                session.stop()
                info = session.command("INFO", "info", 10).record
                if info.get("build") != EXPECTED_BUILD:
                    raise RuntimeError(
                        f"{role}: expected build {EXPECTED_BUILD}, got {info.get('build')!r}"
                    )
                if not as_bool(info.get("ready")):
                    raise RuntimeError(f"{role}: firmware is not ready: {info}")
                if not isinstance(info.get("run"), (int, float, str)):
                    raise RuntimeError(f"{role}: INFO has no run identity")
                if str(info.get("board_id", "")).upper() != IDENTITIES[role].upper():
                    raise RuntimeError(
                        f"{role}: INFO board_id {info.get('board_id')!r} does not match USB identity "
                        f"{IDENTITIES[role]}"
                    )
                session._discard_events("boot")
                session.reboot_detection_armed = True
                session.set_crc(4)
                recovery = bool(self.state.get("error_recovery", False))
                reply = session.command(
                    f"RECOVERY {int(recovery)}",
                    "recovery",
                ).record
                if as_bool(reply.get("enabled")) != recovery:
                    raise RuntimeError(f"{role}: recovery setting rejected: {reply}")
                info = session.command("INFO", "info", 10).record
                self.state.setdefault("boards", {})[role] = {
                    "identity": session.identity,
                    "info": info,
                }
                self.save_state()
            except Exception:
                session.close()
                self.sessions.pop(role, None)
                raise

    def verify_board_info(self, role: str) -> dict[str, Any]:
        info = self.sessions[role].command("INFO", "info", 10).record
        expected = self.state["boards"][role]["info"]
        if str(info.get("board_id", "")).upper() != IDENTITIES[role].upper():
            raise RuntimeError(f"{role}: board identity changed: {info}")
        if as_int(info.get("run")) != as_int(expected.get("run")):
            raise RuntimeError(
                f"{role}: run identity changed from {expected.get('run')} to {info.get('run')}"
            )
        if not as_bool(info.get("ready")):
            raise RuntimeError(f"{role}: firmware is not ready: {info}")
        return info

    def pump(self) -> None:
        for session in self.sessions.values():
            session.poll()

    def stop_all(self) -> list[str]:
        errors = []
        for role in ("base", "walker"):
            session = self.sessions.get(role)
            if session is None:
                continue
            try:
                session.stop(timeout=10)
            except Exception as error:
                errors.append(f"{role} STOP: {error}")
        return errors

    def run_phase(
        self,
        *,
        phase_id: int,
        sender: str,
        receiver: str,
        length: int,
        delay_us: int,
        global_deadline: float,
    ) -> dict[str, Any]:
        sender_session = self.sessions[sender]
        receiver_session = self.sessions[receiver]
        if stop_requested:
            raise InterruptedError("stop requested before phase")
        phase: dict[str, Any] = {
            "phase_id": phase_id,
            "state": "running",
            "sender": sender,
            "receiver": receiver,
            "length": length,
            "delay_us": delay_us,
            "count": self.count,
            "gap_ms": self.gap_ms,
            "started_utc": utc_stamp(),
            "started_monotonic": time.monotonic(),
        }
        sender_session.stop()
        receiver_session.stop()
        phase["pre_phase_info"] = {
            role: self.verify_board_info(role) for role in (sender, receiver)
        }
        receiver_session.command(f"DELAY {delay_us}", "delay", 10)
        phase["before_stats"] = {
            role: self.sessions[role].command("STATS", "stats").record
            for role in (sender, receiver)
        }
        phase["receive_setup"] = receiver_session.receive()
        time.sleep(COMMAND_GUARD_SECONDS)
        run_start = sender_session.command(
            f"RUN {length} {self.count} {self.gap_ms}", "run_start", 10
        ).record
        phase["sender_run"] = as_int(run_start.get("run"))
        phase["run_start"] = run_start
        phase["run_deadline_monotonic"] = min(
            global_deadline,
            time.monotonic()
            + max(
                30.0,
                self.count * (0.15 + self.gap_ms / 1000) + 30,
            ),
        )
        run_end = None
        while time.monotonic() < phase["run_deadline_monotonic"] and not stop_requested:
            self.pump()
            found = sender_session._take_event(
                "run_end",
                lambda record: phase["sender_run"] is None
                or as_int(record.get("run")) == phase["sender_run"],
            )
            if found is not None:
                run_end = found.record
                break
            time.sleep(0.001)
        phase["run_end_seen"] = run_end is not None
        phase["run_end"] = run_end
        if run_end is None and time.monotonic() >= global_deadline:
            phase["stop_at_global_deadline"] = True
        settle = max(0.5, delay_us / 1_000_000 + 0.5)
        settle_deadline = min(global_deadline, time.monotonic() + settle)
        while time.monotonic() < settle_deadline and not stop_requested:
            self.pump()
            time.sleep(0.001)
        if run_end is None:
            sender_session.stop()
            ended = sender_session._take_event("run_end")
            if ended is not None:
                run_end = ended.record
        phase["after_stats"] = {
            role: self.sessions[role].command("STATS", "stats").record
            for role in (sender, receiver)
        }
        receiver_session.stop()
        sender_session.stop()
        phase["ended_monotonic"] = time.monotonic()
        phase["ended_utc"] = utc_stamp()
        observed_attempts = sum(
            event.role == sender
            and event.record.get("event") == "attempt"
            and as_int(event.record.get("run")) == phase["sender_run"]
            for event in sender_session.events
            if phase["started_monotonic"] <= event.monotonic <= phase["ended_monotonic"]
        )
        phase["run_completion"] = run_completion(self.count, observed_attempts, run_end)
        phase["state"] = (
            "complete" if phase["run_completion"]["complete"] else "incomplete"
        )
        self.log_phase(phase)
        self.save_state()
        return phase

    def run_crc_negative_control(self, global_deadline: float, phase_id: int) -> None:
        """Run a deliberately mismatched CRC phase, then restore CRC4."""
        sender = "base"
        receiver = "walker"
        length = min(32, max(self.lengths))
        sender_session = self.sessions[sender]
        receiver_session = self.sessions[receiver]
        phase: dict[str, Any] = {
            "phase_id": phase_id,
            "state": "running",
            "kind": "crc_negative_control",
            "sender": sender,
            "receiver": receiver,
            "length": length,
            "delay_us": 0,
            "count": min(self.count, 20),
            "gap_ms": self.gap_ms,
            "started_utc": utc_stamp(),
            "started_monotonic": time.monotonic(),
        }
        try:
            sender_session.stop()
            receiver_session.stop()
            phase["pre_phase_info"] = {
                role: self.verify_board_info(role) for role in (sender, receiver)
            }
            phase["before_stats"] = {
                role: self.sessions[role].stats() for role in (sender, receiver)
            }
            sender_session.set_crc(2)
            receiver_session.set_crc(4)
            phase["receive_setup"] = receiver_session.receive()
            time.sleep(COMMAND_GUARD_SECONDS)
            run_start = sender_session.command(
                f"RUN {length} {phase['count']} {self.gap_ms}", "run_start", 10
            ).record
            phase["sender_run"] = as_int(run_start.get("run"))
            phase["run_start"] = run_start
            phase_deadline = min(
                global_deadline,
                time.monotonic() + max(30.0, phase["count"] * self.gap_ms / 1000 + 10),
            )
            run_end = None
            while time.monotonic() < phase_deadline and not stop_requested:
                self.pump()
                found = sender_session._take_event(
                    "run_end",
                    lambda record: phase["sender_run"] is None
                    or as_int(record.get("run")) == phase["sender_run"],
                )
                if found is not None:
                    run_end = found.record
                    break
                time.sleep(0.001)
            phase["run_end"] = run_end
            phase["run_end_seen"] = run_end is not None
            if run_end is None:
                sender_session.stop()
                ended = sender_session._take_event("run_end")
                if ended is not None:
                    run_end = ended.record
            phase["run_end"] = run_end
            phase["run_end_seen"] = run_end is not None
            phase["after_stats"] = {
                role: self.sessions[role].stats() for role in (sender, receiver)
            }
            receiver_session.stop()
            sender_session.stop()
            phase["ended_monotonic"] = time.monotonic()
            phase["ended_utc"] = utc_stamp()
            observed_attempts = sum(
                event.role == sender
                and event.record.get("event") == "attempt"
                and as_int(event.record.get("run")) == phase["sender_run"]
                for event in sender_session.events
                if phase["started_monotonic"]
                <= event.monotonic
                <= phase["ended_monotonic"]
            )
            phase["run_completion"] = run_completion(
                phase["count"], observed_attempts, run_end
            )
            phase["state"] = (
                "complete" if phase["run_completion"]["complete"] else "incomplete"
            )
        except Exception as error:
            phase["state"] = "failed"
            phase["error"] = f"{type(error).__name__}: {error}"
            phase["ended_monotonic"] = time.monotonic()
            phase["ended_utc"] = utc_stamp()
            raise
        finally:
            try:
                sender_session.set_crc(4)
                receiver_session.set_crc(4)
            finally:
                self.log_phase(phase)
                self.save_state()

    def run(self) -> dict[str, Any]:
        self.output.mkdir(parents=True, exist_ok=False)
        os.umask(0o077)
        self.save_state()
        summary: dict[str, Any] = {}
        try:
            if self.duration_seconds > AC_REQUIRED_AFTER_SECONDS:
                self.state["power"] = require_ac()
            self.power_guard = start_power_guard()
            self.open_and_identify()
            self.started_monotonic = time.monotonic()
            deadline = (
                self.started_monotonic + self.duration_seconds - STOP_MARGIN_SECONDS
            )
            self.state["state"] = "running"
            self.state["test_started_utc"] = utc_stamp()
            self.state["stop_deadline_utc"] = (
                (
                    dt.datetime.now(dt.timezone.utc)
                    + dt.timedelta(seconds=self.duration_seconds - STOP_MARGIN_SECONDS)
                )
                .isoformat()
                .replace("+00:00", "Z")
            )
            self.save_state()
            phase_id = 0
            matrix_complete = True
            if self.state.get("crc_negative_control"):
                self.run_crc_negative_control(deadline, phase_id)
                phase_id += 1
                if self.phases[-1]["state"] != "complete":
                    matrix_complete = False
            if not matrix_complete:
                deadline = time.monotonic()
            for delay_us in self.delays_us:
                for length in self.lengths:
                    for sender, receiver in (("base", "walker"), ("walker", "base")):
                        if stop_requested or time.monotonic() >= deadline:
                            matrix_complete = False
                            break
                        if self.duration_seconds > AC_REQUIRED_AFTER_SECONDS:
                            self.state["power"] = read_power_state()
                            if "AC Power" not in self.state["power"]:
                                raise RuntimeError(
                                    "AC power disconnected during measurement"
                                )
                        try:
                            phase = self.run_phase(
                                phase_id=phase_id,
                                sender=sender,
                                receiver=receiver,
                                length=length,
                                delay_us=delay_us,
                                global_deadline=deadline,
                            )
                        except Exception as error:
                            failed = {
                                "phase_id": phase_id,
                                "state": "failed",
                                "sender": sender,
                                "receiver": receiver,
                                "length": length,
                                "delay_us": delay_us,
                                "count": self.count,
                                "gap_ms": self.gap_ms,
                                "started_monotonic": time.monotonic(),
                                "ended_monotonic": time.monotonic(),
                                "error": f"{type(error).__name__}: {error}",
                            }
                            self.log_phase(failed)
                            self.save_state()
                            raise
                        phase_id += 1
                        if phase["state"] != "complete":
                            matrix_complete = False
                            break
                    if stop_requested or time.monotonic() >= deadline:
                        matrix_complete = False
                        break
                    if not matrix_complete:
                        break
                if stop_requested or time.monotonic() >= deadline:
                    matrix_complete = False
                    break
                if not matrix_complete:
                    break
            if self.phases and self.phases[-1]["state"] == "incomplete":
                self.state["stop_reason"] = "phase_incomplete"
            elif stop_requested:
                self.state["stop_reason"] = "operator_signal"
            elif matrix_complete:
                self.state["stop_reason"] = "matrix_complete"
            else:
                self.state["stop_reason"] = "duration_deadline"
            self.state["matrix_complete"] = matrix_complete
        except Exception as error:
            self.state["stop_reason"] = f"{type(error).__name__}: {error}"
        finally:
            self.state["state"] = "stopping"
            self.save_state()
            self.state["cleanup_errors"] = self.stop_all()
            for role, session in self.sessions.items():
                try:
                    session.close()
                except Exception as error:
                    self.state["cleanup_errors"].append(f"{role} close: {error}")
            self.state["reboot_events"] = {
                role: session.reboot_events
                for role, session in self.sessions.items()
                if session.reboot_events
            }
            self.state["finished_utc"] = utc_stamp()
            try:
                summary = summarize(self.output)
            except Exception as error:
                self.state["summary_error"] = f"{type(error).__name__}: {error}"
                summary = {}
            self.state["state"] = (
                "finished"
                if self.state.get("stop_reason") == "matrix_complete"
                and not self.state["cleanup_errors"]
                and not self.state.get("summary_error")
                else "stopped_early"
            )
            self.state["summary"] = {
                "path": str(self.output / "summary.json"),
                "matched_successes": summary.get("totals", {}).get("matched_successes"),
            }
            self.save_state()
            if self.power_guard is not None:
                self.power_guard.terminate()
                try:
                    self.power_guard.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.power_guard.kill()
        return summary


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", "--output-dir", dest="output", type=Path, required=True
    )
    parser.add_argument(
        "--analyze-only",
        action="store_true",
        help="regenerate summary.json from an existing output directory without opening serial ports",
    )
    parser.add_argument(
        "--duration-seconds",
        "--seconds",
        dest="duration_seconds",
        type=int,
        default=None,
        help="measurement budget; default is until the next 07:00 America/New_York",
    )
    parser.add_argument("--count", type=int, default=200)
    parser.add_argument("--gap-ms", type=int, default=20)
    parser.add_argument(
        "--error-recovery",
        action="store_true",
        help="route terminal RX error IRQs and poll missed events",
    )
    parser.add_argument(
        "--crc-negative-control",
        action="store_true",
        help="run one CRC2 sender to CRC4 receiver rejection phase, then restore CRC4",
    )
    parser.add_argument(
        "--lengths",
        type=lambda value: parse_int_list(
            value, name="lengths", minimum=12, maximum=MAX_FRAME_LENGTH
        ),
        default=DEFAULT_LENGTHS,
    )
    parser.add_argument(
        "--delays",
        type=lambda value: parse_int_list(
            value, name="delays", minimum=0, maximum=50_000
        ),
        default=DEFAULT_DELAYS_US,
    )
    args = parser.parse_args(argv)
    if args.duration_seconds is None and not args.analyze_only:
        args.duration_seconds = seconds_until_next_seven_am()
    if not args.analyze_only and args.duration_seconds <= STOP_MARGIN_SECONDS:
        parser.error(f"duration must exceed the {STOP_MARGIN_SECONDS}s cleanup margin")
    if args.count <= 0 or args.count > 100_000:
        parser.error("count must be between 1 and 100000")
    if args.gap_ms < 0 or args.gap_ms > 1000:
        parser.error("gap must be between 0 and 1000 ms")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_arguments(argv)
    if args.analyze_only:
        try:
            summary = summarize(args.output.resolve())
        except Exception as error:
            print(f"analysis failed: {type(error).__name__}: {error}", file=sys.stderr)
            return 1
        print(json.dumps(summary, indent=2, sort_keys=True), flush=True)
        return 0
    signal.signal(signal.SIGINT, stop_signal)
    signal.signal(signal.SIGTERM, stop_signal)
    runner = Runner(
        args.output.resolve(),
        duration_seconds=args.duration_seconds,
        count=args.count,
        gap_ms=args.gap_ms,
        lengths=tuple(args.lengths),
        delays_us=tuple(args.delays),
    )
    runner.state["crc_negative_control"] = args.crc_negative_control
    runner.state["error_recovery"] = args.error_recovery
    try:
        summary = runner.run()
    except Exception as error:
        print(f"measurement failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True), flush=True)
    return 0 if runner.state.get("state") == "finished" else 1


if __name__ == "__main__":
    raise SystemExit(main())
