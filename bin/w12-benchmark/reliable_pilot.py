#!/usr/bin/env python3
"""Bounded host-fed reliable PRIVATE_APP pilot for the W12 radios.

This is deliberately separate from the firmware owner-loop benchmark.  It
feeds small, deterministic PKI packets through the ordinary Python
``sendData`` path, while keeping the producer deadline, drain deadline, and
proof-qualified ACK accounting on the host.  The pilot never changes device
configuration and never prints key bytes.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hashlib
import importlib
import json
import math
import secrets
import struct
import sys
import time
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


def _workspace_root(path: Path) -> Path:
    for candidate in (path.parent, *path.parents):
        if (candidate / "firmware" / "bin" / "w12-benchmark" / "benchmark_probe.py").is_file():
            return candidate
    raise ImportError("unable to locate the Meshtastic workspace root")


ROOT = _workspace_root(Path(__file__).resolve())
BENCHMARK_DIR = ROOT / "firmware" / "bin" / "w12-benchmark"
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))
benchmark = importlib.import_module("benchmark_probe")


NODES: Mapping[str, tuple[str, int]] = benchmark.BOARD_IDENTITIES
PAYLOAD_SIZE = 200
PAYLOAD_HEADER_SIZE = 24
PAYLOAD_MAGIC = 0x5732
PAYLOAD_VERSION = 1
PAYLOAD_KIND = 2
MAX_PILOT_COUNT = 32
DEFAULT_COUNT = 16
DEFAULT_WALL_SECONDS = 15.0
DEFAULT_DRAIN_SECONDS = 10.0
DEFAULT_COMMAND_GAP_SECONDS = 0.20
DEFAULT_SUBMISSION_GAP_SECONDS = 0.0
REQUESTED_HOP_LIMIT = 1
MAX_WALL_SECONDS = 300.0
MAX_DRAIN_SECONDS = 120.0
MAX_COMMAND_GAP_SECONDS = 10.0
MAX_SUBMISSION_GAP_SECONDS = 1.0
ACK_PROOF_VALID = 1
PRIVATE_APP = 256
ROUTING_APP = 5
TRANSPORT_INTERNAL = 0
TRANSPORT_LORA = 1

ROUTING_ERRORS: Mapping[int, str] = {
    0: "NONE",
    1: "NO_ROUTE",
    2: "GOT_NAK",
    3: "TIMEOUT",
    4: "NO_INTERFACE",
    5: "MAX_RETRANSMIT",
    6: "NO_CHANNEL",
    7: "TOO_LARGE",
    8: "NO_RESPONSE",
    9: "DUTY_CYCLE_LIMIT",
    32: "BAD_REQUEST",
    33: "NOT_AUTHORIZED",
    34: "PKI_FAILED",
    35: "PKI_UNKNOWN_PUBKEY",
    36: "ADMIN_BAD_SESSION_KEY",
    37: "ADMIN_PUBLIC_KEY_UNAUTHORIZED",
    38: "RATE_LIMIT_EXCEEDED",
    39: "PKI_SEND_FAIL_PUBLIC_KEY",
}


class PilotError(RuntimeError):
    """A fail-closed pilot setup, protocol, or lifecycle error."""


class _QueueFull(PilotError):
    """The board queue was full at the immediate admission boundary."""


class SessionOpenError(PilotError):
    """Opening stopped after retaining sessions that the caller must close."""

    def __init__(self, message: str, sessions: Mapping[str, Any]) -> None:
        super().__init__(message)
        self.sessions = dict(sessions)


class CaptureHealthError(PilotError):
    """The raw reader or protocol capture cannot support a valid run."""

    def __init__(self, failures: Mapping[str, Sequence[str]]) -> None:
        self.failures = {role: list(errors) for role, errors in failures.items()}
        super().__init__(f"capture_health_failed:{self.failures}")


@dataclasses.dataclass(frozen=True)
class Direction:
    source_role: str
    destination_role: str

    @property
    def source(self) -> int:
        return NODES[self.source_role][1]

    @property
    def destination(self) -> int:
        return NODES[self.destination_role][1]

    @property
    def label(self) -> str:
        return f"{self.source_role}-to-{self.destination_role}"


@dataclasses.dataclass(frozen=True)
class PendingFrame:
    source: int
    destination: int
    packet_id: int
    sequence: int
    payload_sha256: str
    admitted_at: float

    @property
    def key(self) -> tuple[int, int]:
        return self.source, self.packet_id


@dataclasses.dataclass
class DirectionState:
    direction: Direction
    count: int
    window: int
    next_sequence: int = 0
    submissions: int = 0
    submission_failures: int = 0
    queue_full: int = 0
    duplicate_submission_keys: int = 0
    submitted_frames: dict[tuple[int, int], PendingFrame] = dataclasses.field(
        default_factory=dict
    )
    pending: dict[tuple[int, int], PendingFrame] = dataclasses.field(
        default_factory=dict
    )
    outcomes: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    receipts: dict[tuple[int, int], dict[str, Any]] = dataclasses.field(
        default_factory=dict
    )
    duplicate_receipts: int = 0
    corrupt_receipts: int = 0
    foreign_receipts: int = 0
    firmware_accepted: set[tuple[int, int]] = dataclasses.field(default_factory=set)
    firmware_rejected: dict[tuple[int, int], dict[str, Any]] = dataclasses.field(
        default_factory=dict
    )
    firmware_queue_observations: dict[
        tuple[int, int], list[dict[str, Any]]
    ] = dataclasses.field(default_factory=dict)
    firmware_late_queue_observations: list[dict[str, Any]] = dataclasses.field(
        default_factory=list
    )
    firmware_queue_conflicts: int = 0
    sent_at: float | None = None
    producer_end: float | None = None
    drain_end: float | None = None
    last_submission_at: float | None = None
    seen_queue_events: set[tuple[Any, ...]] = dataclasses.field(default_factory=set)
    seen_receipt_events: set[tuple[Any, ...]] = dataclasses.field(default_factory=set)
    seen_reply_events: set[tuple[Any, ...]] = dataclasses.field(default_factory=set)


def _u32(value: int) -> bytes:
    return int(value).to_bytes(4, "little", signed=False)


def _pattern(header: bytes, size: int) -> bytes:
    output = bytearray()
    offset = 0
    while len(output) < size:
        output.extend(hashlib.sha256(header + _u32(offset)).digest())
        offset += 1
    return bytes(output[:size])


def make_payload(run_id: int, source: int, destination: int, sequence: int) -> bytes:
    """Build the exact 200-byte pilot payload."""

    if not 0 <= sequence <= 0xFFFFFFFF:
        raise PilotError("sequence is outside uint32")
    header = struct.pack(
        "<HBBIIIIHBB",
        PAYLOAD_MAGIC,
        PAYLOAD_VERSION,
        PAYLOAD_KIND,
        run_id,
        source,
        destination,
        sequence,
        PAYLOAD_SIZE,
        0,
        0,
    )
    return header + _pattern(header, PAYLOAD_SIZE - PAYLOAD_HEADER_SIZE)


def decode_payload(payload: bytes) -> tuple[int, int, int, int]:
    """Validate a pilot payload and return run, source, destination, sequence."""

    if len(payload) != PAYLOAD_SIZE:
        raise PilotError("pilot payload has the wrong size")
    fields = struct.unpack("<HBBIIIIHBB", payload[:PAYLOAD_HEADER_SIZE])
    magic, version, kind, run_id, source, destination, sequence, size, flags, reserved = fields
    if (magic, version, kind, size, flags, reserved) != (
        PAYLOAD_MAGIC,
        PAYLOAD_VERSION,
        PAYLOAD_KIND,
        PAYLOAD_SIZE,
        0,
        0,
    ):
        raise PilotError("pilot payload header is invalid")
    expected = make_payload(run_id, source, destination, sequence)
    if payload != expected:
        raise PilotError("pilot payload pattern is invalid")
    return run_id, source, destination, sequence


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _image_provenance(images: Sequence[str | Path]) -> dict[str, dict[str, Any]]:
    if not images:
        raise PilotError("at least one --image is required for a verifiable run")
    provenance: dict[str, dict[str, Any]] = {}
    for image in images:
        path = Path(image).expanduser().resolve()
        if not path.is_file():
            raise PilotError(f"firmware image does not exist: {path}")
        try:
            provenance[str(path)] = {
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
        except OSError as error:
            raise PilotError(f"cannot hash firmware image {path}: {error}") from error
    return provenance


def _script_digest() -> str:
    return sha256_file(Path(__file__).resolve())


def _json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"sha256": sha256_bytes(value), "bytes": len(value)}
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def _public_key_hash(value: Any) -> str | None:
    key = benchmark._decode_public_key(value)
    return sha256_bytes(key) if key is not None else None


def _memory_config_fingerprint(session: Any) -> dict[str, Any]:
    """Return hash-only config state without writing protobuf/key bytes."""

    node = session.interface.localNode
    local = node.localConfig.SerializeToString()
    module = node.moduleConfig.SerializeToString()
    channels = b"".join(channel.SerializeToString() for channel in node.channels)
    local_key = benchmark._local_public_key_bytes(session)
    return {
        "role": session.role,
        "usb_identity": session.identity,
        "node_num": session.node_num,
        "local_config_sha256": sha256_bytes(local),
        "module_config_sha256": sha256_bytes(module),
        "channels_sha256": sha256_bytes(channels),
        "local_public_key_sha256": sha256_bytes(local_key) if local_key else None,
        "local_config_bytes": len(local),
        "module_config_bytes": len(module),
        "channel_bytes": len(channels),
    }


def ensure_peers(
    sessions: Mapping[str, Any], source_role: str, destination_role: str
) -> dict[str, Any]:
    """Require matching peer keys using the existing benchmark helper."""

    try:
        result = benchmark._peer_bitmap(sessions, source_role, destination_role)
    except Exception as error:
        raise PilotError(f"peer_key_check_failed:{error}") from error
    if not result.get("sender_knows_receiver") or not result.get(
        "receiver_knows_sender"
    ):
        raise PilotError("peer_key_check_incomplete")
    return _json_safe(result)


def _routing_details(payload: bytes) -> tuple[int | None, str | None]:
    """Decode a Routing ACK/NAK without depending on SDK response handlers."""

    try:
        mesh_pb2 = importlib.import_module("meshtastic.protobuf.mesh_pb2")
        routing = mesh_pb2.Routing()
        routing.ParseFromString(payload)
        variant = routing.WhichOneof("variant")
        if variant != "error_reason":
            return None, variant
        error = int(routing.error_reason)
        return error, ROUTING_ERRORS.get(error, f"UNKNOWN_{error}")
    except Exception:
        return None, None


def _capture_health(session: Any) -> dict[str, Any]:
    health = getattr(session, "_pilot_capture_health", None)
    if health is None:
        health = {
            "protocol_errors": [],
            "write_errors": [],
            "reader_alive": None,
            "reader_exited": False,
            "disconnected": False,
        }
        session._pilot_capture_health = health
    return health


def _mark_capture_health(session: Any, field: str, detail: str) -> None:
    health = _capture_health(session)
    values = health.setdefault(field, [])
    if detail not in values:
        values.append(detail)


def _packet_id_from_write(data: bytes, mesh_pb2: Any) -> int | None:
    candidates = (data[4:], data) if len(data) >= 4 else (data,)
    for candidate in candidates:
        try:
            to_radio = mesh_pb2.ToRadio()
            to_radio.ParseFromString(candidate)
            if to_radio.HasField("packet"):
                return int(to_radio.packet.id)
        except Exception:
            continue
    return None


def _install_host_write_capture(session: Any, mesh_pb2: Any) -> None:
    interface = session.interface
    if getattr(interface, "_pilot_write_capture_installed", False):
        return
    original_write = interface._writeBytes
    stream = getattr(interface, "stream", None)

    def observed_write(data: bytes) -> Any:
        metadata: dict[str, Any] = {
            "packet_id": _packet_id_from_write(data, mesh_pb2),
            "serialized_frame_len": len(data),
            "return_len": None,
            "write_started_monotonic": time.monotonic(),
            "write_completed_monotonic": None,
            "complete": False,
            "frame_sha256": sha256_bytes(data),
        }
        original_stream_write = getattr(stream, "write", None)
        wrapped = False
        if callable(original_stream_write):
            def write_callback(chunk: bytes) -> Any:
                result = original_stream_write(chunk)
                if isinstance(result, int):
                    metadata["return_len"] = result
                return result

            stream.write = write_callback
            wrapped = True
        try:
            result = original_write(data)
            metadata["complete"] = True
            return result
        except BaseException as error:
            _mark_capture_health(session, "write_errors", str(error))
            raise
        finally:
            if wrapped:
                stream.write = original_stream_write
            metadata["write_completed_monotonic"] = time.monotonic()
            session.capture.record("pilot_host_write", **metadata)

    interface._writeBytes = observed_write
    interface._pilot_write_capture_installed = True


def _capture_health_snapshot(session: Any) -> dict[str, Any]:
    health = _capture_health(session)
    interface = getattr(session, "interface", None)
    if interface is not None:
        exiting = bool(getattr(interface, "_wantExit", False))
        reader = getattr(interface, "_rxThread", None)
        if reader is not None:
            alive = bool(reader.is_alive())
            health["reader_alive"] = alive
            if not alive and not exiting:
                health["reader_exited"] = True
        failure = getattr(interface, "failure", None)
        if failure is not None and not exiting:
            health["disconnected"] = True
            health["disconnect_detail"] = str(failure)
        connected = getattr(interface, "isConnected", None)
        if (
            connected is not None
            and hasattr(connected, "is_set")
            and not connected.is_set()
            and not exiting
        ):
            health["disconnected"] = True
    return _json_safe(dict(health))


def _session_capture_health(
    sessions: Mapping[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, list[str]]]:
    snapshots: dict[str, dict[str, Any]] = {}
    failures: dict[str, list[str]] = {}
    for role, session in sessions.items():
        snapshot = _capture_health_snapshot(session)
        snapshots[role] = snapshot
        errors: list[str] = []
        errors.extend(str(item) for item in snapshot.get("protocol_errors", []))
        errors.extend(str(item) for item in snapshot.get("write_errors", []))
        if snapshot.get("reader_exited"):
            errors.append("reader_exited")
        if snapshot.get("disconnected"):
            errors.append(str(snapshot.get("disconnect_detail", "disconnected")))
        if errors:
            failures[role] = sorted(set(errors))
    return snapshots, failures


def _merge_capture_health_observations(
    health_snapshots: dict[str, dict[str, Any]],
    health_failures: dict[str, list[str]],
    snapshots: Mapping[str, Mapping[str, Any]],
    failures: Mapping[str, Sequence[str]],
) -> None:
    """Retain sticky failures while preserving the latest liveness values."""

    for role, snapshot in snapshots.items():
        merged_snapshot = health_snapshots.setdefault(role, {})
        for field, value in snapshot.items():
            if isinstance(value, list):
                existing = merged_snapshot.get(field, [])
                merged = list(existing) if isinstance(existing, list) else []
                for item in value:
                    if item not in merged:
                        merged.append(item)
                merged_snapshot[field] = merged
            elif field in {"reader_exited", "disconnected"}:
                merged_snapshot[field] = bool(merged_snapshot.get(field, False) or value)
            elif value is not None or field not in merged_snapshot:
                merged_snapshot[field] = value
    for role, role_failures in failures.items():
        merged_failures = list(health_failures.get(role, []))
        for failure in role_failures:
            if failure not in merged_failures:
                merged_failures.append(failure)
        health_failures[role] = sorted(merged_failures)


def _close_sessions_and_collect_health(
    sessions: Mapping[str, Any],
    close_results: dict[str, bool],
    health_snapshots: dict[str, dict[str, Any]],
    health_failures: dict[str, list[str]],
    close_errors: dict[str, str] | None = None,
) -> None:
    """Sample immediately before and after each close, retaining both views."""

    for role, session in sessions.items():
        before_snapshots, before_failures = _session_capture_health({role: session})
        _merge_capture_health_observations(
            health_snapshots,
            health_failures,
            before_snapshots,
            before_failures,
        )
        try:
            close_results[role] = bool(session.close())
        except Exception as error:
            close_results[role] = False
            if close_errors is not None:
                close_errors[role] = str(error)
        closed_snapshots, closed_failures = _session_capture_health({role: session})
        _merge_capture_health_observations(
            health_snapshots,
            health_failures,
            closed_snapshots,
            closed_failures,
        )


def _install_raw_capture(session: Any) -> None:
    """Capture parsed raw FromRadio packets before the SDK consumes them."""

    mesh_pb2 = importlib.import_module("meshtastic.protobuf.mesh_pb2")
    portnums_pb2 = importlib.import_module("meshtastic.protobuf.portnums_pb2")
    interface = session.interface
    _capture_health(session)
    original = interface._handleFromRadio

    def capture_before_sdk(data: bytes) -> None:
        try:
            incoming = mesh_pb2.FromRadio()
            incoming.ParseFromString(data)
            if incoming.HasField("packet"):
                packet = incoming.packet
                decoded = packet.decoded if packet.HasField("decoded") else None
                payload = bytes(decoded.payload) if decoded is not None else b""
                portnum = int(decoded.portnum) if decoded is not None else None
                routing_error, routing_name = (
                    _routing_details(payload)
                    if portnum == int(portnums_pb2.ROUTING_APP)
                    else (None, None)
                )
                session.capture.record(
                    "pilot_raw_packet",
                    raw_sha256=sha256_bytes(data),
                    packet_id=int(packet.id),
                    from_node=int(getattr(packet, "from")),
                    to=int(packet.to),
                    portnum=portnum,
                    payload_size=len(payload),
                    payload_sha256=sha256_bytes(payload),
                    request_id=(int(decoded.request_id) if decoded is not None else 0),
                    want_ack=bool(packet.want_ack),
                    pki_encrypted=bool(packet.pki_encrypted),
                    hop_limit=int(packet.hop_limit),
                    via_mqtt=bool(packet.via_mqtt),
                    transport=int(packet.transport_mechanism),
                    ack_proof_status=int(packet.ack_proof_status),
                    routing_error=routing_error,
                    routing_error_name=routing_name,
                )
            elif incoming.HasField("queueStatus"):
                queue_status = incoming.queueStatus
                # The SDK intentionally leaves rejected entries in its retry
                # map. This pilot never resends a rejected frame, so remove
                # that exact host entry before the SDK sees the status.
                _drop_rejected_host_entry(interface, queue_status)
                session.capture.record(
                    "pilot_raw_queue_status",
                    free=int(queue_status.free),
                    maxlen=int(queue_status.maxlen),
                    res=int(queue_status.res),
                    mesh_packet_id=int(queue_status.mesh_packet_id),
                )
        except BaseException as error:
            _mark_capture_health(session, "protocol_errors", str(error))
            session.capture.record("protocol_error", message=str(error))
            raise
        try:
            original(data)
        except BaseException as error:
            _mark_capture_health(session, "protocol_errors", str(error))
            raise

    interface._handleFromRadio = capture_before_sdk
    _install_host_write_capture(session, mesh_pb2)


def _prepare_capture_health(session: Any) -> None:
    """Install the pilot capture boundary when a session exposes the SDK hooks."""

    _capture_health(session)
    interface = getattr(session, "interface", None)
    if interface is None or not callable(getattr(interface, "_handleFromRadio", None)):
        return
    try:
        _install_raw_capture(session)
    except Exception as error:
        _mark_capture_health(session, "protocol_errors", f"capture_setup: {error}")


def _queue_free(interface: Any) -> int | None:
    status = getattr(interface, "queueStatus", None)
    if status is None:
        return None
    return int(getattr(status, "free", 0))


def _drop_rejected_host_entry(interface: Any, queue_status: Any) -> None:
    if isinstance(queue_status, Mapping):
        result = int(queue_status.get("res", 0))
        packet_id = int(queue_status.get("mesh_packet_id", 0))
    else:
        result = int(getattr(queue_status, "res", 0))
        packet_id = int(getattr(queue_status, "mesh_packet_id", 0))
    if result != 0:
        interface.queue.pop(packet_id, None)


def _send_to_radio_immediate(interface: Any, to_radio: Any) -> None:
    """Send one packet after a live queue check without SDK's unbounded wait."""

    if not to_radio.HasField("packet"):
        interface._sendToRadioImpl(to_radio)
        return
    free = _queue_free(interface)
    if free is None:
        raise _QueueFull("queue_status_unavailable")
    if free <= 0:
        raise _QueueFull("queue_status_full")
    packet_id = int(to_radio.packet.id)
    interface.queue[packet_id] = to_radio
    interface._queueClaim()
    try:
        interface._sendToRadioImpl(to_radio)
    except BaseException:
        interface.queue.pop(packet_id, None)
        raise


def send_data_if_admitted(
    session: Any,
    payload: bytes,
    destination: int,
) -> Any | None:
    """Use PRIVATE_APP sendData with a bounded, nonblocking queue admission."""

    interface = session.interface
    with interface._command_lock:
        if _queue_free(interface) is None:
            raise _QueueFull("queue_status_unavailable")
        if _queue_free(interface) <= 0:
            raise _QueueFull("queue_status_full")
        original_send = interface._sendToRadio

        def bounded_send(to_radio: Any) -> None:
            _send_to_radio_immediate(interface, to_radio)

        interface._sendToRadio = bounded_send
        try:
            packet = interface.sendData(
                payload,
                destinationId=destination,
                portNum=PRIVATE_APP,
                wantAck=True,
                wantResponse=False,
                pkiEncrypted=True,
                hopLimit=REQUESTED_HOP_LIMIT,
            )
        finally:
            interface._sendToRadio = original_send
    if (
        int(packet.to) != destination
        or bool(packet.want_ack) is not True
        or bool(packet.pki_encrypted) is not True
        or int(packet.hop_limit) != REQUESTED_HOP_LIMIT
        or not packet.HasField("decoded")
        or int(packet.decoded.portnum) != PRIVATE_APP
        or bytes(packet.decoded.payload) != payload
    ):
        raise PilotError("SDK sendData changed the reliable pilot packet")
    return packet


def register_submission(
    state: DirectionState, packet: Any, payload: bytes, submitted_at: float
) -> PendingFrame:
    """Retain one immutable host submission identity for later observations."""

    frame = PendingFrame(
        state.direction.source,
        state.direction.destination,
        int(packet.id),
        state.next_sequence,
        sha256_bytes(payload),
        submitted_at,
    )
    if frame.key in state.submitted_frames:
        state.duplicate_submission_keys += 1
        raise PilotError(f"reused_submission_key:{frame.key[0]}:{frame.key[1]}")
    state.submitted_frames[frame.key] = frame
    state.pending[frame.key] = frame
    state.next_sequence += 1
    state.submissions += 1
    return frame


def _event_is_data(event: Mapping[str, Any], direction: Direction) -> bool:
    return (
        event.get("role") == direction.destination_role
        and event.get("portnum") == PRIVATE_APP
        and event.get("from_node") == direction.source
        and event.get("to") == direction.destination
        and event.get("transport") == TRANSPORT_LORA
        and event.get("pki_encrypted") is True
        and event.get("via_mqtt") is False
    )


def _event_is_reply(event: Mapping[str, Any], direction: Direction) -> bool:
    return (
        event.get("role") == direction.source_role
        and event.get("portnum") == ROUTING_APP
        and event.get("to") == direction.source
        and event.get("request_id", 0) != 0
        and event.get("transport") in {TRANSPORT_INTERNAL, TRANSPORT_LORA}
        and event.get("via_mqtt") is False
    )


def _event_key(event: Mapping[str, Any]) -> tuple[Any, ...]:
    """Identify one raw packet event without retaining its payload bytes."""

    return (
        event.get("role"),
        event.get("kind"),
        int(event.get("packet_id", 0)),
        int(event.get("from_node", 0)),
        int(event.get("to", 0)),
        int(event.get("request_id", 0)),
        float(event.get("monotonic", 0.0)),
        str(event.get("payload_sha256", "")),
        int(event.get("routing_error", -1))
        if event.get("routing_error") is not None
        else -1,
        int(event.get("ack_proof_status", 0)),
    )


def _queue_event_key(event: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        event.get("role"),
        event.get("kind"),
        int(event.get("mesh_packet_id", 0)),
        int(event.get("res", 0)),
        float(event.get("monotonic", 0.0)),
    )


def _timestamp_in_run_window(
    state: DirectionState,
    timestamp: float,
    frame: PendingFrame | None = None,
) -> bool:
    start = state.sent_at
    if frame is not None and (start is None or frame.admitted_at > start):
        start = frame.admitted_at
    if start is None or timestamp < start:
        return False
    end = state.drain_end if state.drain_end is not None else state.producer_end
    return end is None or timestamp <= end


TERMINAL_OUTCOMES = {
    "ack_proof_valid",
    "local_nak",
    "local_queue_rejected",
    "remote_nak_authenticated",
}


def _record_queue_status(
    state: DirectionState, events: Iterable[Mapping[str, Any]]
) -> None:
    for event in events:
        if (
            event.get("kind") != "pilot_raw_queue_status"
            or event.get("role") != state.direction.source_role
        ):
            continue
        event_key = _queue_event_key(event)
        if event_key in state.seen_queue_events:
            continue
        state.seen_queue_events.add(event_key)
        packet_key = (state.direction.source, int(event.get("mesh_packet_id", 0)))
        frame = state.submitted_frames.get(packet_key)
        if frame is None:
            continue
        observation = {
            "monotonic": float(event.get("monotonic", 0.0)),
            "mesh_packet_id": packet_key[1],
            "res": int(event.get("res", 0)),
            "free": int(event.get("free", 0)),
            "maxlen": int(event.get("maxlen", 0)),
        }
        state.firmware_queue_observations.setdefault(packet_key, []).append(
            observation
        )
        bounded = _timestamp_in_run_window(
            state, observation["monotonic"], frame
        )
        if not bounded:
            state.firmware_late_queue_observations.append(
                {**observation, "key": list(packet_key), "bounded": False}
            )
            continue
        if observation["res"] == 0:
            if packet_key in state.firmware_rejected:
                state.firmware_queue_conflicts += 1
            state.firmware_accepted.add(packet_key)
            continue
        if packet_key in state.firmware_accepted:
            state.firmware_queue_conflicts += 1
        state.firmware_rejected[packet_key] = observation
        if packet_key not in state.pending:
            continue
        state.pending.pop(packet_key, None)
        state.outcomes.append(
            {
                "key": list(packet_key),
                "sequence": frame.sequence,
                "status": "local_queue_rejected",
                "detail": f"QUEUE_RES_{observation['res']}",
                "timestamp": observation["monotonic"],
                "bounded": _timestamp_in_run_window(
                    state, observation["monotonic"], frame
                ),
                "packet_id": packet_key[1],
                "from_node": state.direction.source,
                "request_id": packet_key[1],
                "ack_proof_status": 0,
            }
        )


def _record_receipts(
    state: DirectionState, events: Iterable[Mapping[str, Any]]
) -> None:
    for event in events:
        if (
            event.get("portnum") != PRIVATE_APP
            or event.get("transport") != TRANSPORT_LORA
            or event.get("via_mqtt") is not False
        ):
            continue
        event_key = _event_key(event)
        if event_key in state.seen_receipt_events:
            continue
        state.seen_receipt_events.add(event_key)
        if not _event_is_data(event, state.direction):
            same_destination = event.get("to") == state.direction.destination
            same_source = event.get("from_node") == state.direction.source
            if same_destination or same_source:
                state.foreign_receipts += 1
            continue
        packet_key = (state.direction.source, int(event.get("packet_id", 0)))
        frame = state.submitted_frames.get(packet_key)
        if frame is None:
            state.corrupt_receipts += 1
            continue
        payload_hash = str(event.get("payload_sha256", ""))
        exact_flags = (
            event.get("want_ack") is True
            and event.get("hop_limit") == REQUESTED_HOP_LIMIT
            and event.get("pki_encrypted") is True
        )
        if not exact_flags or payload_hash != frame.payload_sha256:
            state.corrupt_receipts += 1
            continue
        if packet_key in state.receipts:
            state.duplicate_receipts += 1
            continue
        state.receipts[packet_key] = {
            "sequence": frame.sequence,
            "admitted_at": frame.admitted_at,
            "monotonic": float(event.get("monotonic", 0.0)),
            "packet_id": packet_key[1],
            "from_node": int(event.get("from_node", 0)),
            "to": int(event.get("to", 0)),
            "payload_sha256": payload_hash,
        }


def _record_replies(
    state: DirectionState,
    events: Iterable[Mapping[str, Any]],
    drain_end: float | None = None,
) -> None:
    completed = {
        tuple(outcome["key"])
        for outcome in state.outcomes
        if outcome.get("key") is not None
        and outcome.get("status")
        in TERMINAL_OUTCOMES
        and tuple(outcome["key"]) not in state.pending
    }
    for event in events:
        if not _event_is_reply(event, state.direction):
            continue
        event_key = _event_key(event)
        if event_key in state.seen_reply_events:
            continue
        state.seen_reply_events.add(event_key)
        key = (state.direction.source, int(event.get("request_id", 0)))
        timestamp = float(event.get("monotonic", 0.0))
        if key not in state.submitted_frames:
            state.outcomes.append(
                {
                    "key": list(key),
                    "status": "late_or_unknown_reply",
                    "timestamp": timestamp,
                    "packet_id": int(event.get("packet_id", 0)),
                }
            )
            continue
        if key in completed or key not in state.pending:
            state.outcomes.append(
                {
                    "key": list(key),
                    "status": "duplicate_reply",
                    "timestamp": timestamp,
                    "packet_id": int(event.get("packet_id", 0)),
                }
            )
            continue
        frame = state.submitted_frames.get(key)
        if frame is None:
            continue
        error = event.get("routing_error")
        proof = int(event.get("ack_proof_status", 0))
        sender_matches = int(event.get("from_node", 0)) == state.direction.destination
        local_terminal_nak = (
            int(error or 0) != 0
            and event.get("role") == state.direction.source_role
            and event.get("transport") == TRANSPORT_INTERNAL
            and event.get("via_mqtt") is False
            and event.get("to") == state.direction.source
            and int(event.get("from_node", 0)) in {0, state.direction.source}
        )
        bounded = _timestamp_in_run_window(state, timestamp, frame)
        if error is None:
            status = "untyped_reply"
            detail = "routing_variant_missing"
        elif int(error) != 0 and local_terminal_nak:
            status = "local_nak"
            detail = ROUTING_ERRORS.get(int(error), f"UNKNOWN_{int(error)}")
        elif (
            int(error) != 0
            and sender_matches
            and event.get("transport") == TRANSPORT_LORA
            and event.get("via_mqtt") is False
            and proof == ACK_PROOF_VALID
        ):
            status = "remote_nak_authenticated"
            detail = ROUTING_ERRORS.get(int(error), f"UNKNOWN_{int(error)}")
        elif int(error) != 0:
            status = "remote_nak"
            detail = ROUTING_ERRORS.get(int(error), f"UNKNOWN_{int(error)}")
        elif event.get("transport") != TRANSPORT_LORA:
            status = "local_ack_untrusted"
            detail = "local_transport_ack"
        elif sender_matches and proof == ACK_PROOF_VALID:
            status = "ack_proof_valid"
            detail = "ACK_PROOF_VALID"
        elif not sender_matches:
            status = "ack_foreign"
            detail = "unexpected_sender"
        else:
            status = "ack_unproven"
            detail = {
                0: "ACK_PROOF_ABSENT",
                2: "ACK_PROOF_INVALID",
                3: "ACK_PROOF_NO_KEY",
            }.get(proof, f"ACK_PROOF_{proof}")
        outcome = {
            "key": list(key),
            "sequence": frame.sequence,
            "status": status,
            "detail": detail,
            "timestamp": timestamp,
            "bounded": bounded,
            "packet_id": int(event.get("packet_id", 0)),
            "from_node": int(event.get("from_node", 0)),
            "request_id": int(event.get("request_id", 0)),
            "ack_proof_status": proof,
        }
        state.outcomes.append(outcome)
        if status in TERMINAL_OUTCOMES and bounded:
            state.pending.pop(key, None)
            completed.add(key)
        elif status == "local_nak" and not bounded:
            # A local failure outside the finite run window is only an
            # observation; the in-window state remains unresolved.
            pass


def _update_live_states(
    states: Iterable[DirectionState], sessions: Mapping[str, Any]
) -> None:
    """Advance the sliding window from raw events already received by USB."""

    events: list[Mapping[str, Any]] = []
    for session in sessions.values():
        events.extend(session.capture.snapshot())
    for state in states:
        _record_queue_status(state, events)
        _record_receipts(state, events)
        _record_replies(state, events)


def _percentile(values: Sequence[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(0, min(len(ordered) - 1, math.ceil(percentile * len(ordered)) - 1))
    return ordered[rank]


def _ack_latency_summary(
    state: DirectionState, valid: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    latencies: list[float] = []
    for outcome in valid:
        key = tuple(outcome.get("key", ()))
        frame = state.submitted_frames.get(key)
        if frame is None:
            continue
        latency = float(outcome["timestamp"]) - frame.admitted_at
        if math.isfinite(latency) and latency >= 0:
            latencies.append(latency)
    if not latencies:
        return {
            "count": 0,
            "min": None,
            "median": None,
            "p95": None,
            "max": None,
        }
    ordered = sorted(latencies)
    midpoint = len(ordered) // 2
    median = (
        ordered[midpoint]
        if len(ordered) % 2
        else (ordered[midpoint - 1] + ordered[midpoint]) / 2
    )
    return {
        "count": len(ordered),
        "min": ordered[0],
        "median": median,
        "p95": _percentile(ordered, 0.95),
        "max": ordered[-1],
    }


def _receipt_latency_summary(
    state: DirectionState, receipts: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    latencies: list[float] = []
    for receipt in receipts:
        key = (state.direction.source, int(receipt["packet_id"]))
        frame = state.submitted_frames.get(key)
        if frame is None:
            continue
        latency = float(receipt["monotonic"]) - frame.admitted_at
        if math.isfinite(latency) and latency >= 0:
            latencies.append(latency)
    if not latencies:
        return {
            "count": 0,
            "min": None,
            "median": None,
            "p95": None,
            "max": None,
        }
    ordered = sorted(latencies)
    midpoint = len(ordered) // 2
    median = (
        ordered[midpoint]
        if len(ordered) % 2
        else (ordered[midpoint - 1] + ordered[midpoint]) / 2
    )
    return {
        "count": len(ordered),
        "min": ordered[0],
        "median": median,
        "p95": _percentile(ordered, 0.95),
        "max": ordered[-1],
    }


def _goodput_interval(payload_bytes: int, seconds: float | None) -> dict[str, Any]:
    rate = None
    if seconds is not None and math.isfinite(seconds) and seconds > 0:
        rate = payload_bytes / seconds
    return {
        "confirmed_payload_bytes": payload_bytes,
        "seconds": seconds,
        "bytes_per_second": rate,
        "bits_per_second": rate * 8 if rate is not None else None,
    }


def _host_goodput_summary(
    state: DirectionState, valid: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    confirmed_keys = {tuple(outcome["key"]) for outcome in valid}
    payload_bytes = len(confirmed_keys) * PAYLOAD_SIZE
    observation_seconds = None
    if state.sent_at is not None and state.drain_end is not None:
        candidate = state.drain_end - state.sent_at
        if math.isfinite(candidate) and candidate >= 0:
            observation_seconds = candidate
    producer_seconds = None
    drain_seconds = None
    if state.sent_at is not None and state.producer_end is not None:
        candidate = state.producer_end - state.sent_at
        if math.isfinite(candidate) and candidate >= 0:
            producer_seconds = candidate
    if state.producer_end is not None and state.drain_end is not None:
        candidate = state.drain_end - state.producer_end
        if math.isfinite(candidate) and candidate >= 0:
            drain_seconds = candidate
    first_submit = min(
        (frame.admitted_at for frame in state.submitted_frames.values()),
        default=None,
    )
    last_confirmation = max(
        (float(outcome["timestamp"]) for outcome in valid), default=None
    )
    confirmation_seconds = None
    if first_submit is not None and last_confirmation is not None:
        candidate = last_confirmation - first_submit
        if math.isfinite(candidate) and candidate >= 0:
            confirmation_seconds = candidate
    return {
        "scope": "host-fed proof confirmations; this is not an RF capacity claim",
        "declared_producer_drain": {
            **_goodput_interval(payload_bytes, observation_seconds),
            "producer_seconds": producer_seconds,
            "drain_seconds": drain_seconds,
        },
        "first_submit_to_last_confirmation": {
            **_goodput_interval(payload_bytes, confirmation_seconds),
            "first_submit_monotonic": first_submit,
            "last_confirmation_monotonic": last_confirmation,
        },
    }


def evaluate_direction(
    state: DirectionState,
    events: Iterable[Mapping[str, Any]],
    *,
    wall_end: float,
    drain_end: float,
) -> dict[str, Any]:
    """Produce a fail-closed bounded result from raw events."""

    events = list(events)
    state.drain_end = drain_end
    _record_queue_status(state, events)
    _record_receipts(state, events)
    _record_replies(state, events, drain_end)
    for outcome in state.outcomes:
        if "timestamp" in outcome:
            timestamp = float(outcome["timestamp"])
            frame = state.submitted_frames.get(tuple(outcome.get("key", ())))
            outcome["bounded"] = _timestamp_in_run_window(state, timestamp, frame) and timestamp <= drain_end
    bounded_receipts = [
        receipt
        for receipt in state.receipts.values()
        if _timestamp_in_run_window(
            state,
            float(receipt["monotonic"]),
            state.submitted_frames.get(
                (state.direction.source, int(receipt["packet_id"]))
            ),
        )
        and float(receipt["monotonic"]) <= drain_end
    ]
    valid = [
        outcome
        for outcome in state.outcomes
        if outcome.get("status") == "ack_proof_valid" and outcome.get("bounded")
    ]
    ack_latency = _ack_latency_summary(state, valid)
    receipt_latency = _receipt_latency_summary(state, bounded_receipts)
    host_goodput = _host_goodput_summary(state, valid)
    valid_keys = {tuple(outcome["key"]) for outcome in valid}
    submitted_keys = set(state.submitted_frames)
    accepted_keys = set(state.firmware_accepted)
    rejected_keys = set(state.firmware_rejected)
    unobserved_keys = submitted_keys - accepted_keys - rejected_keys
    bounded_receipt_keys = {
        (state.direction.source, int(receipt["packet_id"]))
        for receipt in bounded_receipts
    }
    local_nak = [
        outcome
        for outcome in state.outcomes
        if outcome.get("status") == "local_nak"
    ]
    remote_nak = [
        outcome
        for outcome in state.outcomes
        if outcome.get("status") == "remote_nak"
    ]
    authenticated_remote_nak = [
        outcome
        for outcome in state.outcomes
        if outcome.get("status") == "remote_nak_authenticated"
    ]
    unresolved = len(state.pending)
    bounded_terminal_keys = {
        tuple(outcome["key"])
        for outcome in state.outcomes
        if outcome.get("bounded")
        and outcome.get("key") is not None
        and outcome.get("status") in TERMINAL_OUTCOMES
    }
    finite_complete = (
        state.submissions == state.count
        and unresolved == 0
        and bounded_terminal_keys == submitted_keys
        and state.producer_end is not None
        and state.drain_end is not None
        and state.drain_end <= drain_end
    )
    queue_reconciliation_complete = not unobserved_keys and not state.firmware_queue_conflicts
    delivery_confirmation_passed = (
        queue_reconciliation_complete
        and accepted_keys == submitted_keys
        and valid_keys == accepted_keys
    )
    host_capture_complete = not accepted_keys or bounded_receipt_keys == accepted_keys
    measurement_valid = (
        finite_complete and delivery_confirmation_passed and host_capture_complete
    )
    if measurement_valid:
        status = "complete"
    elif finite_complete:
        status = "complete_with_untrusted_or_failed_outcomes"
    else:
        status = "inconclusive"
    if state.submissions == 0 and state.count > 0:
        status = "inconclusive_no_submissions"
    elif unresolved and not valid:
        status = "inconclusive_no_response"
    missing = {
        frame.sequence for frame in state.pending.values()
    } | set(range(state.next_sequence, state.count))
    bounded_count = lambda status: sum(
        outcome.get("status") == status and outcome.get("bounded")
        for outcome in state.outcomes
    )
    late_count = lambda status: sum(
        outcome.get("status") == status and not outcome.get("bounded")
        for outcome in state.outcomes
    )
    return {
        "direction": state.direction.label,
        "source": state.direction.source,
        "destination": state.direction.destination,
        "count_requested": state.count,
        "window": state.window,
        "payload_size": PAYLOAD_SIZE,
        "submitted": state.submissions,
        "submission_failures": state.submission_failures,
        "queue_full": state.queue_full,
        "duplicate_submission_keys": state.duplicate_submission_keys,
        "firmware_accepted": len(accepted_keys),
        "firmware_rejected": len(rejected_keys),
        "firmware_unobserved": len(unobserved_keys),
        "firmware_queue_late": len(state.firmware_late_queue_observations),
        "firmware_queue_late_observations": list(
            state.firmware_late_queue_observations
        ),
        "firmware_queue_conflicts": state.firmware_queue_conflicts,
        "receiver_unique_receipts": len(bounded_receipts),
        "receiver_late_receipts": len(state.receipts) - len(bounded_receipts),
        "receiver_duplicates": state.duplicate_receipts,
        "receiver_corrupt_or_unexpected": state.corrupt_receipts,
        "receiver_foreign": state.foreign_receipts,
        "missing_sequences": sorted(missing),
        "denominators": {
            "requested": state.count,
            "host_submitted": state.submissions,
            "firmware_queue_accepted": len(accepted_keys),
            "firmware_queue_rejected": len(rejected_keys),
            "firmware_queue_unobserved": len(unobserved_keys),
            "firmware_queue_late": len(state.firmware_late_queue_observations),
            "bounded_terminal_router_outcome": len(bounded_terminal_keys),
            "receiver_exact_receipt": len(bounded_receipts),
            "authenticated_ack_proof": len(valid),
        },
        "transmission_attempts_observed": None,
        "transmission_observation_note": (
            "The public serial API exposes queue admission but no TX-start event; "
            "ACKs and receipts are reported separately and never used as TX counts."
        ),
        "authenticated_ack_valid": len(valid),
        "authenticated_ack_latency": ack_latency,
        "receiver_receipt_latency": receipt_latency,
        "host_fed_goodput": host_goodput,
        "ack_unproven": bounded_count("ack_unproven") + late_count("ack_unproven"),
        "ack_unproven_bounded": bounded_count("ack_unproven"),
        "ack_unproven_late": late_count("ack_unproven"),
        "ack_foreign": bounded_count("ack_foreign") + late_count("ack_foreign"),
        "ack_foreign_bounded": bounded_count("ack_foreign"),
        "ack_foreign_late": late_count("ack_foreign"),
        "local_terminal_nak": bounded_count("local_nak"),
        "local_terminal_nak_late": late_count("local_nak"),
        "terminal_nak": bounded_count("local_nak"),
        "terminal_nak_errors": [outcome.get("detail") for outcome in local_nak],
        "local_nak_errors": [outcome.get("detail") for outcome in local_nak],
        "remote_nak": (
            bounded_count("remote_nak")
            + late_count("remote_nak")
            + bounded_count("remote_nak_authenticated")
            + late_count("remote_nak_authenticated")
        ),
        "remote_nak_bounded": bounded_count("remote_nak")
        + bounded_count("remote_nak_authenticated"),
        "remote_nak_late": late_count("remote_nak")
        + late_count("remote_nak_authenticated"),
        "remote_nak_errors": [outcome.get("detail") for outcome in remote_nak]
        + [outcome.get("detail") for outcome in authenticated_remote_nak],
        "remote_nak_authenticated": bounded_count("remote_nak_authenticated")
        + late_count("remote_nak_authenticated"),
        "remote_nak_authenticated_bounded": bounded_count(
            "remote_nak_authenticated"
        ),
        "remote_nak_authenticated_late": late_count("remote_nak_authenticated"),
        "remote_nak_authenticated_errors": [
            outcome.get("detail") for outcome in authenticated_remote_nak
        ],
        "unresolved": unresolved,
        "terminal_complete": finite_complete,
        "delivery_confirmation_passed": delivery_confirmation_passed,
        "host_capture_complete": host_capture_complete,
        "queue_reconciliation_complete": queue_reconciliation_complete,
        "measurement_valid": measurement_valid,
        "late_or_duplicate_replies": sum(
            outcome.get("status") in {"late_or_unknown_reply", "duplicate_reply"}
            for outcome in state.outcomes
        ),
        "status": status,
        "producer_wall_seconds": (
            state.producer_end - state.sent_at
            if state.producer_end is not None and state.sent_at is not None
            else None
        ),
        "drain_seconds": (
            state.drain_end - state.producer_end
            if state.drain_end is not None and state.producer_end is not None
            else None
        ),
        "outcomes": list(state.outcomes),
    }


def _direction_for_roles(source_role: str, destination_role: str) -> Direction:
    if source_role not in NODES or destination_role not in NODES:
        raise PilotError("unknown board role")
    if source_role == destination_role:
        raise PilotError("source and destination must differ")
    return Direction(source_role, destination_role)


def _direction_list(direction: str) -> list[Direction]:
    if direction == "base-to-walker":
        return [_direction_for_roles("base", "walker")]
    if direction == "walker-to-base":
        return [_direction_for_roles("walker", "base")]
    if direction == "both":
        return [
            _direction_for_roles("base", "walker"),
            _direction_for_roles("walker", "base"),
        ]
    raise PilotError(f"unsupported direction {direction}")


def _open_sessions(output: Path, command_gap: float) -> dict[str, Any]:
    sessions: dict[str, Any] = {}
    try:
        for role in NODES:
            session = benchmark.BoardSession(role, output, command_gap)
            sessions[role] = session
            _install_raw_capture(session)
    except BaseException as error:
        raise SessionOpenError(
            f"session_open_failed:opened={tuple(sessions)}", sessions
        ) from error
    return sessions


def _fresh_key_check(
    output: Path,
    roles: Sequence[str],
    command_gap: float,
    expected: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Reconnect by USB identity and compare hash-only config/key state."""

    sessions: dict[str, Any] = {}
    checks: dict[str, Any] = {}
    close_results: dict[str, bool] = {}
    close_errors: dict[str, str] = {}
    health_snapshots: dict[str, dict[str, Any]] = {}
    health_failures: dict[str, list[str]] = {}
    try:
        output.mkdir(parents=True, exist_ok=True, mode=0o700)
        for role in roles:
            session = benchmark.BoardSession(role, output, command_gap)
            sessions[role] = session
            _prepare_capture_health(session)
            current = _memory_config_fingerprint(session)
            checks[role] = {
                "current": current,
                "same_as_before": current == expected.get(role),
            }
        ensure_peers(sessions, roles[0], roles[1])
        for role in roles:
            checks[role]["peer_check"] = "passed"
    except Exception as error:
        checks["error"] = str(error)
    finally:
        _close_sessions_and_collect_health(
            sessions,
            close_results,
            health_snapshots,
            health_failures,
            close_errors,
        )
    if close_errors:
        checks["close_errors"] = close_errors
    checks["sessions_closed"] = close_results
    checks["capture_health"] = health_snapshots
    checks["capture_health_failures"] = health_failures
    checks["capture_health_passed"] = not health_failures
    role_checks = [
        checks.get(role)
        for role in roles
        if isinstance(checks.get(role), Mapping)
    ]
    checks["passed"] = (
        "error" not in checks
        and len(role_checks) == len(roles)
        and all(
            value.get("same_as_before") and value.get("peer_check") == "passed"
            for value in role_checks
        )
        and all(close_results.get(role, False) for role in roles)
        and checks["capture_health_passed"]
    )
    return checks


def _persist_capture_snapshots(
    sessions: Mapping[str, Any], output: Path
) -> dict[str, str]:
    """Preserve the original run before opening any fresh verification sessions."""

    errors: dict[str, str] = {}
    for role, session in sessions.items():
        role_errors: list[str] = []
        try:
            benchmark._safe_json_write(
                output / role / "capture-events.json", session.capture.snapshot()
            )
        except Exception as error:
            role_errors.append(f"capture-events: {error}")
        try:
            benchmark._safe_json_write(
                output / role / "capture-health.json",
                _capture_health_snapshot(session),
            )
        except Exception as error:
            role_errors.append(f"capture-health: {error}")
        if role_errors:
            errors[role] = "; ".join(role_errors)
    return errors


def _apply_capture_persistence_result(
    result: dict[str, Any], errors: Mapping[str, str]
) -> None:
    """Make raw-capture persistence failure invalidate an otherwise good run."""

    if not errors:
        result["capture_persistence_passed"] = True
        return
    failure = dict(errors)
    result["capture_persistence_passed"] = False
    result["capture_persist_errors"] = failure
    result["status"] = "inconclusive_capture_persistence_failure"
    for direction in result.get("directions", {}).values():
        direction["capture_persistence_passed"] = False
        direction["capture_persist_errors"] = failure
        direction["host_capture_complete"] = False
        direction["measurement_valid"] = False
        direction["status"] = "inconclusive_capture_persistence_failure"


def _apply_capture_health_result(
    result: dict[str, Any],
    snapshots: Mapping[str, Mapping[str, Any]],
    failures: Mapping[str, Sequence[str]],
) -> None:
    result["capture_health"] = {
        "passed": not failures,
        "roles": dict(snapshots),
        "failures": {role: list(errors) for role, errors in failures.items()},
    }
    if not failures:
        result["capture_health_passed"] = True
        return
    result["capture_health_passed"] = False
    result["status"] = "inconclusive_capture_health"
    for direction in result.get("directions", {}).values():
        direction["capture_health_passed"] = False
        direction["host_capture_complete"] = False
        direction["measurement_valid"] = False
        direction["status"] = "inconclusive_capture_health"


def _apply_configuration_gate_result(
    result: dict[str, Any],
    configuration: Mapping[str, Any],
    failure_status: str = "inconclusive_configuration_check",
) -> None:
    """Invalidate measurements when preservation or session closure is unproven."""

    passed = bool(configuration.get("passed"))
    result["configuration_check_passed"] = passed
    if passed:
        return
    result["status"] = failure_status
    for direction in result.get("directions", {}).values():
        direction["configuration_check_passed"] = False
        direction["measurement_valid"] = False
        direction["status"] = failure_status


def _validate_run_args(args: argparse.Namespace) -> None:
    if not getattr(args, "image", None):
        raise PilotError("at least one --image is required for a verifiable run")
    if not 1 <= args.count <= MAX_PILOT_COUNT:
        raise PilotError(f"count must be in 1..{MAX_PILOT_COUNT}")
    if args.window not in (1, 8):
        raise PilotError("the pilot compares window 1 or window 8")
    submission_gap_seconds = getattr(
        args, "submission_gap_seconds", DEFAULT_SUBMISSION_GAP_SECONDS
    )
    for name, value, upper in (
        ("wall_seconds", args.wall_seconds, MAX_WALL_SECONDS),
        ("drain_seconds", args.drain_seconds, MAX_DRAIN_SECONDS),
        ("command_gap", args.command_gap, MAX_COMMAND_GAP_SECONDS),
        (
            "submission_gap_seconds",
            submission_gap_seconds,
            MAX_SUBMISSION_GAP_SECONDS,
        ),
    ):
        if not math.isfinite(value) or value < 0 or value > upper:
            raise PilotError(f"{name} must be finite and in 0..{upper}")
    if args.wall_seconds <= 0 or args.drain_seconds <= 0:
        raise PilotError("wall and drain seconds must be positive")
    if args.run_id is not None and not 1 <= args.run_id <= 0xFFFFFFFF:
        raise PilotError("run_id must be a nonzero uint32")


def run_pilot(args: argparse.Namespace) -> dict[str, Any]:
    _validate_run_args(args)
    image_provenance = _image_provenance(args.image)
    submission_gap_seconds = getattr(
        args, "submission_gap_seconds", DEFAULT_SUBMISSION_GAP_SECONDS
    )
    directions = _direction_list(args.direction)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    run_id = args.run_id or secrets.randbelow(0xFFFFFFFF) + 1
    result: dict[str, Any] = {
        "status": "error",
        "intent": {
            "run_id": run_id,
            "direction": args.direction,
            "count": args.count,
            "window": args.window,
            "payload_size": PAYLOAD_SIZE,
            "topology": "direct-pair",
            "want_ack": True,
            "pki_encrypted": True,
            "requested_hop_limit": REQUESTED_HOP_LIMIT,
            "hop_limit": REQUESTED_HOP_LIMIT,
            "wall_seconds": args.wall_seconds,
            "drain_seconds": args.drain_seconds,
            "submission_gap_seconds": submission_gap_seconds,
            "text_api": False,
        },
        "directions": {},
        "provenance": {
            "script_sha256": _script_digest(),
            "image_hashes": image_provenance,
        },
    }
    sessions: dict[str, Any] = {}
    close_results: dict[str, bool] = {}
    capture_health_snapshots: dict[str, dict[str, Any]] = {}
    capture_health_failures: dict[str, list[str]] = {}
    states = {
        direction.label: DirectionState(direction, args.count, args.window)
        for direction in directions
    }
    try:
        try:
            sessions = _open_sessions(output, args.command_gap)
        except SessionOpenError as error:
            sessions = error.sessions
            result["startup_error"] = str(error)
            raise
        before = {role: _memory_config_fingerprint(session) for role, session in sessions.items()}
        result["configuration_before"] = before
        result["peer_checks"] = {
            direction.label: ensure_peers(
                sessions, direction.source_role, direction.destination_role
            )
            for direction in directions
        }
        capture_health_snapshots, capture_health_failures = _session_capture_health(
            sessions
        )
        if capture_health_failures:
            raise CaptureHealthError(capture_health_failures)
        for state in states.values():
            state.sent_at = time.monotonic()
        producer_deadline = min(state.sent_at or time.monotonic() for state in states.values()) + args.wall_seconds
        for state in states.values():
            state.producer_end = producer_deadline
        while time.monotonic() < producer_deadline:
            _update_live_states(states.values(), sessions)
            capture_health_snapshots, capture_health_failures = _session_capture_health(
                sessions
            )
            if capture_health_failures:
                raise CaptureHealthError(capture_health_failures)
            made_progress = False
            for state in states.values():
                if state.next_sequence >= state.count or len(state.pending) >= state.window:
                    continue
                if time.monotonic() >= producer_deadline:
                    break
                if state.last_submission_at is not None:
                    remaining_gap = submission_gap_seconds - (
                        time.monotonic() - state.last_submission_at
                    )
                    if remaining_gap > 0:
                        time.sleep(remaining_gap)
                    if time.monotonic() >= producer_deadline:
                        break
                payload = make_payload(
                    run_id,
                    state.direction.source,
                    state.direction.destination,
                    state.next_sequence,
                )
                try:
                    packet = send_data_if_admitted(
                        sessions[state.direction.source_role],
                        payload,
                        state.direction.destination,
                    )
                except _QueueFull:
                    state.queue_full += 1
                    continue
                except PilotError as error:
                    state.submission_failures += 1
                    state.outcomes.append(
                        {
                            "status": "submission_error",
                            "detail": str(error),
                            "timestamp": time.monotonic(),
                        }
                    )
                    raise
                except Exception as error:
                    state.submission_failures += 1
                    state.outcomes.append(
                        {
                            "status": "submission_error",
                            "detail": str(error),
                            "timestamp": time.monotonic(),
                        }
                    )
                    continue
                now = time.monotonic()
                register_submission(state, packet, payload, now)
                state.last_submission_at = now
                made_progress = True
            if not made_progress:
                time.sleep(min(0.05, max(0.005, producer_deadline - time.monotonic())))
        drain_end = time.monotonic() + args.drain_seconds
        for state in states.values():
            state.drain_end = drain_end
        while time.monotonic() < drain_end:
            _update_live_states(states.values(), sessions)
            capture_health_snapshots, capture_health_failures = _session_capture_health(
                sessions
            )
            if capture_health_failures:
                raise CaptureHealthError(capture_health_failures)
            time.sleep(0.05)
        for state in states.values():
            events = []
            for role_session in sessions.values():
                events.extend(role_session.capture.snapshot())
            result["directions"][state.direction.label] = evaluate_direction(
                state,
                events,
                wall_end=producer_deadline,
                drain_end=drain_end,
            )
        result["status"] = (
            "complete"
            if all(item["status"] == "complete" for item in result["directions"].values())
            else "inconclusive"
        )
    except CaptureHealthError as error:
        capture_health_failures = error.failures
        result["status"] = "inconclusive_capture_health"
        result["capture_health_error"] = error.failures
    finally:
        final_snapshots, final_failures = _session_capture_health(sessions)
        _merge_capture_health_observations(
            capture_health_snapshots,
            capture_health_failures,
            final_snapshots,
            final_failures,
        )
        _close_sessions_and_collect_health(
            sessions,
            close_results,
            capture_health_snapshots,
            capture_health_failures,
        )
        result["sessions_closed"] = close_results
        if sessions and all(state.drain_end is not None for state in states.values()):
            for state in states.values():
                events = []
                for role_session in sessions.values():
                    events.extend(role_session.capture.snapshot())
                result["directions"][state.direction.label] = evaluate_direction(
                    state,
                    events,
                    wall_end=state.producer_end or 0.0,
                    drain_end=state.drain_end or 0.0,
                )
            if result["status"] not in {"error", "inconclusive_configuration_check"}:
                result["status"] = (
                    "complete"
                    if all(
                        item["status"] == "complete"
                        for item in result["directions"].values()
                    )
                    else "inconclusive"
                )
        capture_persist_errors = _persist_capture_snapshots(sessions, output)
        fully_opened = (
            set(sessions) == set(NODES)
            and "configuration_before" in result
        )
        if capture_health_failures:
            result["configuration_after"] = {
                "passed": False,
                "error": "capture_health_failed",
            }
            _apply_configuration_gate_result(
                result,
                result["configuration_after"],
                "inconclusive_capture_health",
            )
        elif fully_opened and all(close_results.get(role, False) for role in sessions):
            configuration_after = _fresh_key_check(
                output / "fresh-config",
                tuple(NODES),
                args.command_gap,
                result.get("configuration_before", {}),
            )
            result["configuration_after"] = configuration_after
            _apply_configuration_gate_result(result, configuration_after)
        elif sessions:
            result["configuration_after"] = {
                "passed": False,
                "error": "session_close_not_confirmed",
            }
            _apply_configuration_gate_result(
                result, result["configuration_after"], "error"
            )
        _apply_capture_health_result(
            result, capture_health_snapshots, capture_health_failures
        )
        _apply_capture_persistence_result(result, capture_persist_errors)
        benchmark._safe_json_write(output / "reliable-pilot.json", result)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--direction", choices=("base-to-walker", "walker-to-base", "both"), default="base-to-walker")
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT)
    parser.add_argument("--window", type=int, choices=(1, 8), default=1)
    parser.add_argument("--wall-seconds", type=float, default=DEFAULT_WALL_SECONDS)
    parser.add_argument("--drain-seconds", type=float, default=DEFAULT_DRAIN_SECONDS)
    parser.add_argument("--command-gap", type=float, default=DEFAULT_COMMAND_GAP_SECONDS)
    parser.add_argument(
        "--submission-gap-seconds",
        type=float,
        default=DEFAULT_SUBMISSION_GAP_SECONDS,
        help="host gap between successful submissions, bounded to 0..1 seconds",
    )
    parser.add_argument("--run-id", type=int)
    parser.add_argument(
        "--image",
        action="append",
        default=[],
        help="firmware image to hash into provenance (repeat for each image)",
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        result = run_pilot(_parser().parse_args(argv))
    except Exception as error:
        print(f"reliable pilot failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(_json_safe(result), sort_keys=True))
    return 0 if result.get("status") == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
