"""Pure protocol and lifecycle checks for the W12 RX-liveness probe."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


MODULE_PATH = Path(__file__).with_name("rx_liveness_probe.py")
SPEC = importlib.util.spec_from_file_location("rx_liveness_probe", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
sys.modules["rx_liveness_probe"] = probe
SPEC.loader.exec_module(probe)


def config(**changes):
    values = {
        "run_id": 0x10203040,
        "source": probe.benchmark.BOARD_IDENTITIES["base"][1],
        "destination": probe.benchmark.BOARD_IDENTITIES["walker"][1],
        "count": 1000,
        "size": 219,
        "duration_ms": 60000,
        "window": 16,
        "flags": 0,
    }
    values.update(changes)
    return probe.benchmark.RunConfig(**values)


def liveness_payload(run=None, **changes):
    run = config() if run is None else run
    values = {
        "status": 0x05,
        "pending_tx_count": 0,
        "elapsed_ms": run.duration_ms,
        "snapshot_sequence": 1,
        "snapshot_time_ms": 1000,
        "sample_status": 0x27,
        "sample_source": 1,
        "rearm_count": 0,
        "rearm_result": 0,
        "rearm_before_state": 0,
        "rearm_after_state": 0,
        "rearm_last_time_ms": 0,
        "rearm_last_duration_us": 0,
        "raw_irq_flags": 0x12345678,
        "raw_status": 0x0405,
        "irq_read_result": 0,
        "chip_rx_packets": 12,
        "chip_crc_errors": 3,
        "chip_len_errors": 4,
        "chip_stats_result": 0,
        "rssi_dbm": -70,
        "rssi_read_result": 0,
        "software_state": 0x11,
    }
    values.update(changes)
    payload = bytearray(probe.REPORT_BYTES)
    payload[0:2] = probe.MAGIC.to_bytes(2, "little")
    payload[2:4] = bytes((probe.VERSION, probe.KIND))
    payload[4:8] = run.run_id.to_bytes(4, "little")
    payload[8:12] = run.source.to_bytes(4, "little")
    payload[12:16] = run.destination.to_bytes(4, "little")
    payload[16:20] = values["elapsed_ms"].to_bytes(4, "little")
    payload[20] = values["status"]
    payload[21] = values["pending_tx_count"]
    payload[24:28] = values["snapshot_sequence"].to_bytes(4, "little")
    payload[28:32] = values["snapshot_time_ms"].to_bytes(4, "little")
    payload[32] = values["sample_status"]
    payload[33] = values["sample_source"]
    payload[34:38] = values["rearm_count"].to_bytes(4, "little")
    payload[38] = values["rearm_result"]
    payload[39] = values["rearm_before_state"]
    payload[40] = values["rearm_after_state"]
    payload[44:48] = values["rearm_last_time_ms"].to_bytes(4, "little")
    payload[48:52] = values["rearm_last_duration_us"].to_bytes(4, "little")
    payload[52:56] = values["raw_irq_flags"].to_bytes(4, "little")
    payload[56:58] = values["raw_status"].to_bytes(2, "little")
    for offset, name in (
        (58, "irq_read_result"),
        (66, "chip_stats_result"),
        (68, "rssi_dbm"),
        (70, "rssi_read_result"),
    ):
        payload[offset : offset + 2] = values[name].to_bytes(2, "little", signed=True)
    for offset, name in (
        (60, "chip_rx_packets"),
        (62, "chip_crc_errors"),
        (64, "chip_len_errors"),
    ):
        payload[offset : offset + 2] = values[name].to_bytes(2, "little")
    payload[72:76] = values["software_state"].to_bytes(4, "little")
    return bytes(payload)


class ParserTests(unittest.TestCase):
    def test_exact_report_decodes_signed_values_and_operation_vs_history(self):
        run = config()
        report = probe.decode_rx_liveness_report(
            liveness_payload(
                run,
                rearm_count=1,
                rearm_result=1,
                rearm_last_time_ms=2000,
                sample_status=0x22,
                irq_read_result=probe.INT16_MIN,
                rssi_dbm=probe.INT16_MIN,
                rssi_read_result=-1,
            )
        )
        serialized = probe.rx_liveness_report_dict(report)
        self.assertEqual(report.raw_status, 0x0405)
        self.assertEqual(report.irq_read_result, probe.INT16_MIN)
        self.assertFalse(serialized["operation_rearm_performed"])
        self.assertEqual(serialized["historical_rearm_count"], 1)
        self.assertTrue(serialized["irq_read_result_unavailable"])
        self.assertFalse(serialized["rf_delivery_authoritative"])
        self.assertEqual(serialized["capacity_claim"], "not_evaluated")

    def test_rearm_sample_sets_operation_flags_without_confusing_history(self):
        report = probe.decode_rx_liveness_report(
            liveness_payload(
                rearm_count=1,
                rearm_result=1,
                sample_status=0x3F,
                rearm_before_state=0x05,
                rearm_after_state=0x11,
            )
        )
        self.assertTrue(report.operation_rearm_performed)
        self.assertTrue(report.operation_rearm_software_armed)
        self.assertEqual(report.rearm_count, 1)

    def test_parser_rejects_truncation_identity_status_reserved_and_result_errors(self):
        valid = liveness_payload()
        adverse = {
            "short": valid[:-1],
            "long": valid + b"\x00",
            "kind": valid[:3] + b"\x05" + valid[4:],
            "header_reserved": valid[:22] + b"\x01" + valid[23:],
            "rearm_reserved": valid[:41] + b"\x01" + valid[42:],
            "tail_reserved": valid[:76] + b"\x01" + valid[77:],
            "unknown_header_status": valid[:20] + b"\x40" + valid[21:],
            "running_complete": valid[:20] + b"\x07" + valid[21:],
            "pending_mismatch": valid[:20] + b"\x15\x00" + valid[22:],
            "unknown_sample_status": valid[:32] + b"\x80" + valid[33:],
            "source_mismatch": valid[:32] + b"\x07" + valid[33:],
            "result": valid[:38] + b"\x03" + valid[39:],
            "state": valid[:39] + b"\x20" + valid[40:],
        }
        for name, payload in adverse.items():
            with self.subTest(name=name), self.assertRaises(probe.LivenessError):
                probe.decode_rx_liveness_report(payload)

    def test_unavailable_sentinel_is_preserved_without_synthetic_result(self):
        report = probe.decode_rx_liveness_report(
            liveness_payload(
                sample_status=0x20,
                sample_source=1,
                irq_read_result=probe.INT16_MIN,
                chip_stats_result=probe.INT16_MIN,
                rssi_dbm=probe.INT16_MIN,
                rssi_read_result=probe.INT16_MIN,
            )
        )
        values = probe.rx_liveness_report_dict(report)
        self.assertIsNone(values["chip_stats_result"])
        self.assertTrue(values["chip_stats_result_unavailable"])

    def test_availability_bits_and_sentinels_are_strict_but_partial_failure_survives(self):
        with self.assertRaises(probe.LivenessError):
            probe.decode_rx_liveness_report(
                liveness_payload(sample_status=0x20, irq_read_result=0)
            )
        with self.assertRaises(probe.LivenessError):
            probe.decode_rx_liveness_report(
                liveness_payload(sample_status=0x21, irq_read_result=-1)
            )
        with self.assertRaises(probe.LivenessError):
            probe.decode_rx_liveness_report(
                liveness_payload(sample_status=0x27, rssi_dbm=probe.INT16_MIN)
            )
        partial = probe.decode_rx_liveness_report(
            liveness_payload(sample_status=0x25, chip_stats_result=-1)
        )
        self.assertTrue(partial.sample_source_valid)
        self.assertFalse(partial.chip_stats_read_ok)
        unavailable = probe.decode_rx_liveness_report(
            liveness_payload(
                sample_status=0,
                sample_source=0,
                irq_read_result=probe.INT16_MIN,
                chip_stats_result=probe.INT16_MIN,
                rssi_dbm=probe.INT16_MIN,
                rssi_read_result=probe.INT16_MIN,
            )
        )
        self.assertFalse(unavailable.sample_source_valid)


class ControlAndCounterTests(unittest.TestCase):
    def test_op7_and_op8_use_the_existing_32_byte_control_shape(self):
        run = config()
        for operation in (probe.CONTROL_SNAPSHOT_RX_LIVENESS, probe.CONTROL_REARM_RX_LIVENESS):
            payload = probe.encode_liveness_control(run, operation)
            self.assertEqual(len(payload), probe.CONTROL_BYTES)
            self.assertEqual(probe.decode_liveness_control(payload), (operation, run))

    def test_control_rejects_other_operations(self):
        with self.assertRaises(probe.LivenessError):
            probe.encode_liveness_control(config(), probe.CONTROL_SNAPSHOT)

    def test_counter_decrease_is_unknown_reset_or_wrap(self):
        result = probe.counter_delta(65530, 2)
        self.assertFalse(result["valid"])
        self.assertEqual(result["kind"], "unknown_reset_or_wrap")
        self.assertIsNone(result["delta"])

    def test_valid_samples_have_no_per_or_capacity_headline(self):
        samples = []
        for sequence, packets, monotonic in ((1, 5, 10.0), (2, 7, 11.0)):
            report = probe.decode_rx_liveness_report(
                liveness_payload(snapshot_sequence=sequence, chip_rx_packets=packets)
            )
            sample = probe.rx_liveness_report_dict(report)
            sample["host_monotonic"] = monotonic
            samples.append(sample)
        result = probe.analyze_samples(samples)
        self.assertTrue(result["diagnostic_valid"])
        self.assertFalse(result["rf_delivery_authoritative"])
        self.assertEqual(result["capacity_claim"], "not_evaluated")

    def test_counter_decrease_invalidates_attribution_without_modulo_delta(self):
        samples = []
        for sequence, packets, monotonic in ((1, 5, 10.0), (2, 2, 11.0)):
            report = probe.decode_rx_liveness_report(
                liveness_payload(snapshot_sequence=sequence, chip_rx_packets=packets)
            )
            sample = probe.rx_liveness_report_dict(report)
            sample["host_monotonic"] = monotonic
            samples.append(sample)
        result = probe.analyze_samples(samples)
        self.assertFalse(result["diagnostic_valid"])
        self.assertIn("chip_rx_packets_reset_or_wrap_unknown", result["failure_reasons"])
        packet_delta = next(
            item for item in result["counter_deltas"] if item["counter"] == "chip_rx_packets" and item["delta"] is None
        )
        self.assertIsNone(packet_delta["delta"])

    def test_all_three_chip_counters_are_checked_for_decrease(self):
        samples = []
        for sequence, crc_errors in ((1, 5), (2, 4)):
            report = probe.decode_rx_liveness_report(
                liveness_payload(snapshot_sequence=sequence, chip_crc_errors=crc_errors)
            )
            sample = probe.rx_liveness_report_dict(report)
            sample["host_monotonic"] = float(sequence)
            samples.append(sample)
        result = probe.analyze_samples(samples)
        self.assertIn("chip_crc_errors_reset_or_wrap_unknown", result["failure_reasons"])

    def test_rearm_counter_guard_requires_continuous_three_second_history(self):
        def sample(host_time, rx, crc=2, length=3, readable=True):
            return {
                "host_monotonic": host_time,
                "sample_source_valid": readable,
                "chip_stats_result": 0 if readable else None,
                "chip_rx_packets": rx,
                "chip_crc_errors": crc,
                "chip_len_errors": length,
            }

        self.assertEqual(
            probe.evaluate_receiver_counter_guard(
                [sample(10.0, 4), sample(11.0, 4)]
            )["reason"],
            "insufficient_counter_span",
        )
        self.assertEqual(
            probe.evaluate_receiver_counter_guard(
                [sample(10.0, 4), sample(11.0, 4, readable=False), sample(14.0, 4)]
            )["reason"],
            "intervening_unavailable_sample",
        )
        ready = probe.evaluate_receiver_counter_guard(
            [sample(10.0, 4), sample(13.0, 4)]
        )
        self.assertTrue(ready["eligible"])
        self.assertTrue(ready["latest_read_success"])

    def test_sequence_and_host_timestamp_must_be_monotonic(self):
        samples = []
        for sequence, monotonic in ((2, 10.0), (1, 9.0)):
            report = probe.decode_rx_liveness_report(
                liveness_payload(snapshot_sequence=sequence)
            )
            sample = probe.rx_liveness_report_dict(report)
            sample["host_monotonic"] = monotonic
            samples.append(sample)
        result = probe.analyze_samples(samples)
        self.assertIn("snapshot_sequence_not_monotonic", result["failure_reasons"])
        self.assertIn("host_timestamp_not_monotonic", result["failure_reasons"])

    def test_one_shot_rearm_decision_cannot_become_eligible_twice(self):
        decision = probe.rearm_candidate(25.0, 25.0, 20.0, False, 20.0, 3.0)
        self.assertTrue(decision["eligible"])
        self.assertEqual(
            probe.rearm_candidate(30.0, 30.0, 20.0, True, 20.0, 3.0)["reason"],
            "already_attempted",
        )

    def test_static_historical_source_counters_do_not_authorize_rearm(self):
        result = probe.evaluate_source_tx_progress(
            {"tx_started": 40, "tx_succeeded": 37},
            {"tx_started": 40, "tx_succeeded": 37},
        )
        self.assertTrue(result["valid"])
        self.assertFalse(result["eligible"])
        self.assertEqual(result["reason"], "no_tx_succeeded_progress")

    def test_advancing_sent_counter_authorizes_rearm(self):
        result = probe.evaluate_source_tx_progress(
            {"tx_started": 40, "tx_succeeded": 37},
            {"tx_started": 42, "tx_succeeded": 39},
        )
        self.assertTrue(result["valid"])
        self.assertTrue(result["eligible"])
        self.assertEqual(result["tx_started_delta"], 2)
        self.assertEqual(result["tx_succeeded_delta"], 2)

    def test_started_or_terminal_progress_without_new_success_does_not_authorize(self):
        result = probe.evaluate_source_tx_progress(
            {"tx_started": 40, "tx_succeeded": 37, "tx_terminal": 40},
            {"tx_started": 41, "tx_succeeded": 37, "tx_terminal": 41},
        )
        self.assertTrue(result["valid"])
        self.assertFalse(result["eligible"])
        self.assertEqual(result["tx_succeeded_delta"], 0)

    def test_source_counter_decrease_invalidates_rearm_authority(self):
        result = probe.evaluate_source_tx_progress(
            {"tx_started": 40, "tx_succeeded": 37},
            {"tx_started": 41, "tx_succeeded": 3},
        )
        self.assertFalse(result["valid"])
        self.assertFalse(result["eligible"])
        self.assertEqual(result["reason"], "tx_succeeded_counter_reset_or_wrap_unknown")

    def test_source_progress_requires_exact_run_configuration(self):
        run = config()
        report = {
            "run_id": run.run_id,
            "source": run.source,
            "destination": run.destination,
            "count": run.count,
            "size": run.size,
            "duration_ms": run.duration_ms,
            "window": run.window + 1,
            "flags": run.flags,
        }
        with self.assertRaisesRegex(probe.LivenessError, "source_identity_mismatch"):
            probe._identity_check(report, run, "source")


class ResponseSafetyTests(unittest.TestCase):
    def _session(self, event):
        session = object.__new__(probe.LivenessSession)
        session.node_num = probe.benchmark.BOARD_IDENTITIES["walker"][1]
        session.health = probe._ReaderHealth()
        session.interface = SimpleNamespace(
            _rxThread=None, _wantExit=False, stream=object()
        )

        class Capture:
            def wait_for(self, predicate, _timeout):
                return event if predicate(event) else None

        session.capture = Capture()
        return session

    def test_response_requires_local_addresses(self):
        run = config()
        event = {
            "kind": "liveness_packet",
            "request_id": 9,
            "monotonic": 1.0,
            "to": run.source,
            "from_node": run.source,
            "raw_payload_hex": liveness_payload(run).hex(),
        }
        with self.assertRaisesRegex(probe.LivenessError, "local from/to"):
            self._session(event)._wait_response(9, run, 0.0, 0.1)

    def test_response_requires_matching_run_identity(self):
        run = config()
        event = {
            "kind": "liveness_packet",
            "request_id": 9,
            "monotonic": 1.0,
            "to": run.destination,
            "from_node": run.destination,
            "raw_payload_hex": liveness_payload(
                config(run_id=run.run_id + 1)
            ).hex(),
        }
        with self.assertRaisesRegex(probe.LivenessError, "run/source/destination"):
            self._session(event)._wait_response(9, run, 0.0, 0.1)

    def test_response_before_request_timestamp_cannot_satisfy_wait(self):
        run = config()
        event = {
            "kind": "liveness_packet",
            "request_id": 9,
            "monotonic": 0.5,
            "to": run.destination,
            "from_node": run.destination,
            "raw_payload_hex": liveness_payload(run).hex(),
        }
        with self.assertRaisesRegex(probe.LivenessError, "response_timeout"):
            self._session(event)._wait_response(9, run, 1.0, 0.001)

    def test_receiver_window_keeps_first_auth_anchor_and_elapsed_state(self):
        report = probe.decode_rx_liveness_report(
            liveness_payload(status=0x23, elapsed_ms=0, snapshot_time_ms=1000)
        )
        running = probe.receiver_window_observation(report, 60000)
        self.assertEqual(running["status"], "inconclusive_no_first_authenticated_frame")
        self.assertFalse(running["first_authenticated_rf_frame_observed"])
        report = probe.decode_rx_liveness_report(
            liveness_payload(status=0x23, elapsed_ms=123, snapshot_time_ms=1000)
        )
        running = probe.receiver_window_observation(report, 60000)
        self.assertEqual(running["status"], "running")
        self.assertEqual(running["elapsed_ms"], 123)


class ControlTransportTests(unittest.TestCase):
    def test_sdk_false_ack_markers_do_not_count_as_pending_packets(self):
        mesh_pb2, _ = probe._load_meshtastic_types()
        real = mesh_pb2.ToRadio()
        real.packet.id = 123
        state = probe.inspect_sdk_queue({123: real, 777: False})
        self.assertTrue(state["known"])
        self.assertEqual(state["queued_packets"], 1)
        self.assertEqual(state["pending_packets"], 1)
        self.assertEqual(state["ack_markers"], 1)
        self.assertTrue(state["unknown_details"] == [])

    def test_unknown_sdk_queue_entry_fails_closed(self):
        state = probe.inspect_sdk_queue({123: object()})
        self.assertFalse(state["known"])
        self.assertEqual(state["unknown_entries"], 1)

    def test_to_radio_like_fakes_and_malformed_mapping_items_fail_closed(self):
        class FakePacket:
            def __init__(self, packet_id):
                self.id = packet_id

        class FakeToRadio:
            def __init__(self, packet_id):
                self.packet = FakePacket(packet_id)

            def HasField(self, _name):
                return True

        for packet_id in (1.0, "1"):
            state = probe.inspect_sdk_queue({1: FakeToRadio(packet_id)})
            self.assertFalse(state["known"])
            self.assertEqual(state["unknown_entries"], 1)

        class MalformedDict(dict):
            def items(self):
                return [(1,), (2, object())]

        state = probe.inspect_sdk_queue(MalformedDict())
        self.assertFalse(state["known"])
        self.assertEqual(state["unknown_entries"], 2)

    def test_host_guard_ignores_false_markers_but_blocks_unknown_entries(self):
        session = object.__new__(probe.LivenessSession)
        queue_status = SimpleNamespace(free=16)
        session.interface = SimpleNamespace(queueStatus=queue_status, queue={77: False})
        marker_guard = session.host_rearm_guard()
        self.assertTrue(marker_guard["eligible"])
        self.assertEqual(marker_guard["ack_markers"], 1)
        mesh_pb2, _ = probe._load_meshtastic_types()
        real = mesh_pb2.ToRadio()
        real.packet.id = 77
        session.interface.queue = {77: real}
        real_guard = session.host_rearm_guard()
        self.assertFalse(real_guard["eligible"])
        self.assertEqual(real_guard["pending_packets"], 1)
        session.interface.queue = {77: object()}
        unknown_guard = session.host_rearm_guard()
        self.assertFalse(unknown_guard["eligible"])
        self.assertEqual(unknown_guard["unknown_queue_entries"], 1)
        session.interface.queue = None
        missing_guard = session.host_rearm_guard()
        self.assertFalse(missing_guard["eligible"])
        self.assertEqual(missing_guard["unknown_queue_entries"], 1)
        session.interface.queue = {}
        session.interface.queueStatus = None
        missing_status_guard = session.host_rearm_guard()
        self.assertFalse(missing_status_guard["eligible"])
        self.assertTrue(missing_status_guard["queue_free_invalid"])
        session.interface.queueStatus = SimpleNamespace()
        missing_free_guard = session.host_rearm_guard()
        self.assertFalse(missing_free_guard["eligible"])
        self.assertTrue(missing_free_guard["queue_free_invalid"])
        session.interface.queueStatus = SimpleNamespace(free=True)
        boolean_free_guard = session.host_rearm_guard()
        self.assertFalse(boolean_free_guard["eligible"])
        self.assertTrue(boolean_free_guard["queue_free_invalid"])

    def test_narrow_sender_bypasses_sdk_queue_and_sets_local_safe_fields(self):
        mesh_pb2, portnums_pb2 = probe._load_meshtastic_types()

        class Capture:
            def __init__(self):
                self.events = []

            def record(self, kind, **values):
                self.events.append({"kind": kind, **values})

        class FakeInterface:
            def __init__(self):
                self._command_lock = threading.Lock()
                self.noProto = False
                self.last_command = 0.0
                self.sent = []
                self._mesh_pb2 = mesh_pb2

            def _generatePacketId(self):
                return 123

            def _sendToRadioImpl(self, packet):
                self.sent.append(packet)

        session = object.__new__(probe.LivenessSession)
        session.node_num = probe.benchmark.BOARD_IDENTITIES["walker"][1]
        session.interface = FakeInterface()
        session._mesh_pb2 = mesh_pb2
        session._portnums_pb2 = portnums_pb2
        session.capture = Capture()
        session.health = probe._ReaderHealth()
        session.base = SimpleNamespace(_pace=lambda: None)

        request_id, _ = probe.send_liveness_control(
            session, config(), probe.CONTROL_SNAPSHOT_RX_LIVENESS
        )
        packet = session.interface.sent[0].packet
        self.assertEqual(request_id, 123)
        self.assertEqual(packet.to, session.node_num)
        self.assertEqual(getattr(packet, "from"), 0)
        self.assertFalse(packet.want_ack)
        self.assertFalse(packet.pki_encrypted)
        self.assertEqual(packet.decoded.portnum, int(portnums_pb2.PRIVATE_APP))
        self.assertEqual(packet.decoded.payload[3], probe.CONTROL_SNAPSHOT_RX_LIVENESS)
        self.assertEqual(len(session.interface.sent), 1)


class CaptureHealthTests(unittest.TestCase):
    def test_kind6_wrapper_records_raw_payload_and_matching_identity(self):
        mesh_pb2, portnums_pb2 = probe._load_meshtastic_types()

        class Capture:
            def __init__(self):
                self.events = []

            def record(self, kind, **values):
                event = {"kind": kind, "monotonic": 1.0, **values}
                self.events.append(event)
                return event

        session = object.__new__(probe.LivenessSession)
        session._mesh_pb2 = mesh_pb2
        session._portnums_pb2 = portnums_pb2
        session.capture = Capture()
        session.health = probe._ReaderHealth()
        session._original_handle = lambda _data: None
        session.node_num = probe.benchmark.BOARD_IDENTITIES["walker"][1]

        incoming = mesh_pb2.FromRadio()
        packet = incoming.packet
        packet.id = 42
        packet.to = session.node_num
        setattr(packet, "from", session.node_num)
        packet.decoded.portnum = int(portnums_pb2.PRIVATE_APP)
        packet.decoded.request_id = 123
        packet.decoded.payload = liveness_payload()

        probe.LivenessSession._handle_from_radio(session, incoming.SerializeToString())

        event = next(item for item in session.capture.events if item["kind"] == "liveness_packet")
        self.assertEqual(event["request_id"], 123)
        self.assertEqual(bytes.fromhex(event["raw_payload_hex"]), liveness_payload())

    def test_parser_error_marks_health_and_raises(self):
        mesh_pb2, portnums_pb2 = probe._load_meshtastic_types()

        class Capture:
            def record(self, _kind, **_values):
                return None

        session = object.__new__(probe.LivenessSession)
        session._mesh_pb2 = mesh_pb2
        session._portnums_pb2 = portnums_pb2
        session.capture = Capture()
        session.health = probe._ReaderHealth()
        session._original_handle = lambda _data: None
        session.node_num = probe.benchmark.BOARD_IDENTITIES["walker"][1]
        incoming = mesh_pb2.FromRadio()
        incoming.packet.to = session.node_num
        setattr(incoming.packet, "from", session.node_num)
        incoming.packet.decoded.portnum = int(portnums_pb2.PRIVATE_APP)
        incoming.packet.decoded.payload = liveness_payload()[:-1]

        with self.assertRaises(probe.LivenessError):
            probe.LivenessSession._handle_from_radio(session, incoming.SerializeToString())
        self.assertEqual(session.health.snapshot()["reason"], "parser_error")

    def test_dead_reader_is_fail_closed(self):
        session = object.__new__(probe.LivenessSession)
        session.health = probe._ReaderHealth()
        session.interface = SimpleNamespace(
            _rxThread=SimpleNamespace(is_alive=lambda: False),
            _wantExit=False,
            stream=object(),
        )
        with self.assertRaisesRegex(probe.LivenessError, "reader_exit"):
            session.check_health()

    def test_close_false_is_visible_to_caller(self):
        session = object.__new__(probe.LivenessSession)
        session.health = probe._ReaderHealth()
        session.base = SimpleNamespace(close=lambda timeout: False)
        self.assertFalse(session.close())
        self.assertTrue(session.health.closing)


class FreshConfigTests(unittest.TestCase):
    def test_fresh_reconnect_checks_reader_before_close_and_restores_capture(self):
        class Reader:
            def is_alive(self):
                return True

        class FakeSession:
            def __init__(self, role, _output, _gap):
                self.role = role
                self.interface = SimpleNamespace(_rxThread=Reader())
                self.closed = False

            def snapshot_config(self, _output, _label):
                return {"role": self.role}

            def close(self):
                self.closed = True
                return True

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            snapshots = probe.fresh_config_snapshots_checked(
                output,
                ("base",),
                0.1,
                {"base": [{"kind": "liveness_packet"}]},
                FakeSession,
            )
            self.assertEqual(snapshots["base"], {"role": "base"})
            self.assertEqual(
                json.loads((output / "base" / "capture-events.json").read_text()),
                [{"kind": "liveness_packet"}],
            )

    def test_fresh_reconnect_dead_reader_fails_closed(self):
        class Reader:
            def is_alive(self):
                return False

        class FakeSession:
            def __init__(self, _role, _output, _gap):
                self.interface = SimpleNamespace(_rxThread=Reader())

            def snapshot_config(self, _output, _label):
                return {}

            def close(self):
                return True

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(probe.LivenessError, "reader exited"):
                probe.fresh_config_snapshots_checked(
                    Path(directory), ("base",), 0.1, {}, FakeSession
                )


class MetadataTests(unittest.TestCase):
    def test_probe_protocol_is_self_relative_and_diagnostic_only(self):
        protocol = json.loads(
            MODULE_PATH.with_name("rx-liveness-protocol.json").read_text()
        )
        self.assertEqual(protocol["report"]["bytes"], 80)
        self.assertEqual(protocol["report"]["kind"], 6)
        self.assertEqual(protocol["operations"]["7"]["reply_kind"], 6)
        self.assertEqual(protocol["operations"]["8"]["reply_kind"], 6)

    def test_window_knob_defaults_to_eight_and_rejects_other_values(self):
        args = probe.build_parser().parse_args([])
        self.assertEqual(args.window, 8)
        for value in (0, 4, 12, 32):
            with self.subTest(value=value), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    probe.build_parser().parse_args(["--window", str(value)])


if __name__ == "__main__":
    unittest.main()
