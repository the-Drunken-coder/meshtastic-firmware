import hashlib
import importlib.util
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("radio_gaps.py")
SPEC = importlib.util.spec_from_file_location("radio_gaps", MODULE_PATH)
radio_gaps = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules["radio_gaps"] = radio_gaps
SPEC.loader.exec_module(radio_gaps)


def _wire(*, status=0x0D, pending=0, available=True):
    data = bytearray(radio_gaps.REPORT_BYTES)
    struct.pack_into("<HBBIIII", data, 0, radio_gaps.MAGIC, 1, 8, 1, 2, 3, 60000)
    data[20] = status if available else status & ~radio_gaps.STATUS_AVAILABLE
    data[21] = pending
    data[100] = radio_gaps.OWNER_NOTIFY_SOURCE
    return data


class RadioGapsProtocolTests(unittest.TestCase):
    def test_decodes_zero_page_and_evaluates_software_scope(self):
        report = radio_gaps.decode_report(_wire())
        self.assertTrue(report.available)
        self.assertTrue(report.complete)
        self.assertEqual(report.owner_rx_notify_to_rearm_us.count, 0)
        self.assertEqual(report.owner_tx_notify_to_start_transmit_call_us.sum_us, 0)
        evaluation = radio_gaps.evaluate_report(report)
        self.assertEqual(evaluation["status"], "invalid")
        self.assertIn("radio_gaps_no_observations", evaluation["failure_reasons"])
        self.assertFalse(evaluation["physical_claims"]["rf_delivery"])
        self.assertFalse(evaluation["physical_claims"]["guard_margin"])

    def test_one_metric_with_observations_is_valid(self):
        for offset in (24, 44):
            data = _wire()
            struct.pack_into("<IIIQ", data, offset, 1, 10, 10, 10)
            report = radio_gaps.decode_report(data)
            evaluation = radio_gaps.evaluate_report(report)
            self.assertEqual(evaluation["status"], "valid")
            self.assertTrue(evaluation["measurement_valid"])

    def test_decodes_source_semantics_with_overlapping_rx_invalid(self):
        data = _wire()
        struct.pack_into("<IIII", data, 64, 3, 2, 2, 1)
        struct.pack_into("<IIII", data, 80, 1, 1, 1, 1)
        struct.pack_into("<IIIQ", data, 24, 2, 50, 50, 100)
        struct.pack_into("<IIIQ", data, 44, 1, 75, 75, 75)
        report = radio_gaps.decode_report(data)
        self.assertEqual(report.rx_notifications, 3)
        self.assertEqual(report.rx_valid_done, 2)
        self.assertEqual(report.rx_invalid, 2)
        self.assertEqual(report.owner_rx_notify_to_rearm_us.sum_us, 100)

    def test_rejects_malformed_header_reserved_pending_and_source(self):
        mutations = []
        data = _wire()
        data[22] = 1
        mutations.append(data)
        data = _wire()
        data[21] = 17
        mutations.append(data)
        data = _wire()
        data[100] = 2
        mutations.append(data)
        data = _wire()
        data[111] = 1
        mutations.append(data)
        for invalid in mutations:
            with self.assertRaises(ValueError):
                radio_gaps.decode_report(invalid)

    def test_rejects_metric_bound_and_saturation_errors(self):
        invalid = _wire()
        struct.pack_into("<I", invalid, 28, radio_gaps.MAX_RADIO_GAP_US + 1)
        with self.assertRaises(ValueError):
            radio_gaps.decode_report(invalid)

        invalid = _wire()
        struct.pack_into("<IIIQ", invalid, 24, 1, 10, 9, 10)
        with self.assertRaises(ValueError):
            radio_gaps.decode_report(invalid)

        invalid = _wire()
        struct.pack_into("<IIIQ", invalid, 24, 1, 0, 1, radio_gaps.UINT64_MAX)
        with self.assertRaises(ValueError):
            radio_gaps.decode_report(invalid)

        invalid = _wire()
        struct.pack_into("<IIIQ", invalid, 24, 2, 10, 10, 19)
        with self.assertRaises(ValueError):
            radio_gaps.decode_report(invalid)

    def test_unavailable_requires_zero_page_and_evaluation_fails_closed(self):
        data = _wire(available=False)
        report = radio_gaps.decode_report(data)
        evaluation = radio_gaps.evaluate_report(report)
        self.assertFalse(report.available)
        self.assertFalse(evaluation["measurement_valid"])
        self.assertIn("radio_gaps_unavailable", evaluation["failure_reasons"])

        invalid = _wire(available=False)
        struct.pack_into("<I", invalid, 64, 1)
        with self.assertRaises(ValueError):
            radio_gaps.decode_report(invalid)

    def test_pending_overflow_and_rejected_intervals_fail_closed(self):
        data = _wire(status=0x3D, pending=1)
        report = radio_gaps.decode_report(data)
        reasons = radio_gaps.evaluate_report(report)["failure_reasons"]
        self.assertIn("radio_gaps_pending_tx", reasons)

        data = _wire()
        data[101] = 1
        report = radio_gaps.decode_report(data)
        self.assertIn("radio_gaps_overflow", radio_gaps.evaluate_report(report)["failure_reasons"])

        data = _wire()
        struct.pack_into("<I", data, 96, 1)
        report = radio_gaps.decode_report(data)
        self.assertIn("radio_gaps_interval_rejected", radio_gaps.evaluate_report(report)["failure_reasons"])

    def test_control_is_exactly_32_bytes_and_uses_operation_10(self):
        payload = radio_gaps.encode_snapshot_control(1, 2, 3, 8192, 219, 60000, 16)
        self.assertEqual(len(payload), 32)
        self.assertEqual(struct.unpack_from("<HBB", payload), (radio_gaps.MAGIC, 1, 10))
        self.assertEqual(payload[29:], b"\0\0\0")

    def test_generated_protobuf_handler_records_strict_response_metadata(self):
        try:
            from meshtastic.protobuf import mesh_pb2, portnums_pb2
        except ImportError as error:  # pragma: no cover - pinned client supplies these
            self.skipTest(f"pinned protobuf runtime unavailable: {error}")

        class Capture:
            def __init__(self):
                self.events = []

            def record(self, kind, **values):
                self.events.append({"kind": kind, **values})

        class Interface:
            _radio_gaps_capture = False

            def __init__(self):
                self.seen = []

            def _handleFromRadio(self, data):
                self.seen.append(data)

        class Session:
            def __init__(self):
                self.capture = Capture()
                self.interface = Interface()

        session = Session()
        radio_gaps._install_raw_response_capture(session)
        incoming = mesh_pb2.FromRadio()
        packet = incoming.packet
        packet.id = 42
        packet.to = 3
        setattr(packet, "from", 3)
        packet.want_ack = False
        packet.pki_encrypted = False
        packet.via_mqtt = False
        packet.transport_mechanism = mesh_pb2.MeshPacket.TRANSPORT_INTERNAL
        packet.decoded.portnum = portnums_pb2.PRIVATE_APP
        packet.decoded.request_id = 9
        packet.decoded.payload = bytes(_wire())
        encoded = incoming.SerializeToString()
        session.interface._handleFromRadio(encoded)

        event = session.capture.events[0]
        self.assertEqual(event["portnum"], portnums_pb2.PRIVATE_APP)
        self.assertEqual(event["transport"], radio_gaps.TRANSPORT_INTERNAL)
        self.assertIs(event["want_ack"], False)
        self.assertIs(event["pki_encrypted"], False)
        self.assertIs(event["via_mqtt"], False)
        self.assertEqual(event["request_id"], 9)
        self.assertEqual(session.interface.seen, [encoded])

    def test_gap_matcher_rejects_untrusted_packet_metadata(self):
        class Session:
            node_num = 3

            @staticmethod
            def _response_event_matches(_event, _packet_id, _key, _config, _deadline):
                return True

        event = {
            "portnum": 256,
            "transport": radio_gaps.TRANSPORT_INTERNAL,
            "want_ack": False,
            "pki_encrypted": False,
            "via_mqtt": False,
        }
        self.assertTrue(radio_gaps._radio_gaps_event_matches(Session(), event, 9, object(), 10.0))
        event["transport"] = radio_gaps.TRANSPORT_API
        self.assertTrue(radio_gaps._radio_gaps_event_matches(Session(), event, 9, object(), 10.0))
        event["transport"] = radio_gaps.TRANSPORT_INTERNAL
        for field, value in (
            ("portnum", 1),
            ("transport", 1),
            ("transport", [radio_gaps.TRANSPORT_INTERNAL]),
            ("want_ack", True),
            ("pki_encrypted", True),
            ("via_mqtt", True),
        ):
            invalid = dict(event)
            invalid[field] = value
            self.assertFalse(radio_gaps._radio_gaps_event_matches(Session(), invalid, 9, object(), 10.0))


class _Capture:
    def __init__(self):
        self.events = []

    def snapshot(self):
        return list(self.events)

    def persist(self):
        return None


class _FakeSession:
    rows = {}
    reports = {}

    def __init__(self, role, output, _gap):
        self.role = role
        self.output = output
        self.identity, self.node_num = {
            "base": ("44:B1:76:AE:19:14", 2686237816),
            "walker": ("44:B1:76:AE:20:18", 1273374798),
        }[role]
        self.capture = _Capture()
        self.interface = type("Interface", (), {})()

    def snapshot_config(self, _output, _label):
        return dict(self.rows[self.role])

    def snapshot_radio_gaps(self, _config, _timeout):
        response = self.reports[self.role]
        if isinstance(response, Exception):
            raise response
        return response

    def close(self):
        return True


class _CloseFailure(_FakeSession):
    def close(self):
        return False


class _FailingCapture(_Capture):
    def persist(self):
        raise OSError("capture file is unwritable")


class _PersistenceFailure(_FakeSession):
    def __init__(self, role, output, gap):
        super().__init__(role, output, gap)
        self.capture = _FailingCapture()


class _DeadReader:
    def is_alive(self):
        return False


class _DeadReaderSession(_FakeSession):
    def __init__(self, role, output, gap):
        super().__init__(role, output, gap)
        self.interface._rxThread = _DeadReader()


class _OpenStream:
    is_open = True


class _OpenStreamSession(_FakeSession):
    def __init__(self, role, output, gap):
        super().__init__(role, output, gap)
        self.interface.stream = _OpenStream()


class _MalformedEvents(_FakeSession):
    def __init__(self, role, output, gap):
        super().__init__(role, output, gap)
        self.capture.events = [object()]


class _ProtocolErrorEvents(_FakeSession):
    def __init__(self, role, output, gap):
        super().__init__(role, output, gap)
        self.capture.events = [{"kind": "protocol_error", "message": "bad FromRadio"}]


def _existing_run(run_dir: Path):
    app = run_dir / "application.bin"
    app.write_bytes(b"application image")
    image_hash = hashlib.sha256(app.read_bytes()).hexdigest()
    rows = {}
    for role, identity, node in (
        ("base", "44:B1:76:AE:19:14", 2686237816),
        ("walker", "44:B1:76:AE:20:18", 1273374798),
    ):
        rows[role] = {
            "role": role,
            "usb_identity": identity,
            "node_num": node,
            "local_config_sha256": f"{role}local",
            "module_config_sha256": f"{role}module",
            "channels_sha256": f"{role}channels",
            "lora_sha256": f"{role}lora",
            "private_key_sha256": f"{role}private",
            "public_key_sha256": f"{role}public",
        }
    config = {"run_id": 1, "source": 2686237816, "destination": 1273374798, "count": 8192, "size": 219, "duration_ms": 60000, "window": 16, "flags": 0}
    sender_primary = {
        **config,
        "prepared": True,
        "running": False,
        "complete": True,
        "enqueued": 8192,
        "send_failures": 0,
        "tx_started": 8192,
        "tx_succeeded": 8192,
        "tx_failures": 0,
        "tx_dropped": 0,
        "tx_cancelled": 0,
        "received": 0,
        "missing": 0,
        "duplicates": 0,
        "corrupt": 0,
        "out_of_range": 0,
        "elapsed_ms": 60000,
        "goodput_bps": 0,
    }
    receiver_primary = {
        **config,
        "prepared": True,
        "running": False,
        "complete": True,
        "enqueued": 0,
        "send_failures": 0,
        "tx_started": 0,
        "tx_succeeded": 0,
        "tx_failures": 0,
        "tx_dropped": 0,
        "tx_cancelled": 0,
        "received": 1,
        "missing": 8191,
        "duplicates": 0,
        "corrupt": 0,
        "out_of_range": 0,
        "elapsed_ms": 60000,
        "goodput_bps": 0,
    }
    primary_report = {
        "status": "measurement_valid",
        "measurement_valid": True,
        "failure_reasons": [],
        "run": config,
        "sender": sender_primary,
        "receiver": receiver_primary,
        "capture_validity": {
            "sender_report_present": True,
            "receiver_report_present": True,
            "sender_snapshot_valid": True,
            "receiver_snapshot_valid": True,
            "physical_tx_terminal_complete": True,
            "aggregate_receiver_bitmap_authoritative": True,
        },
        "time_window": {
            "fixed_wall_seconds": 60.0,
            "observed_wall_seconds": 60.0,
            "observed_drain_seconds": 10.0,
            "drain_seconds_required": 10.0,
        },
    }
    result = {
        "status": "measurement_valid",
        "report": primary_report,
        "firmware_reports": {
            "sender": sender_primary,
            "receiver": receiver_primary,
        },
        "configuration_preserved": True,
        "intent": {
            "sender": "base",
            "receiver": "walker",
            "run": config,
            "fixed_wall_seconds": 60.0,
            "drain_seconds": 10.0,
        },
        "configuration_before": rows,
        "configuration_after": rows,
        "provenance": {"image_hashes": {"application.bin": image_hash}},
    }
    (run_dir / "results.json").write_text(json.dumps(result), encoding="utf-8")
    _FakeSession.rows = rows
    wire = _wire()
    struct.pack_into("<III", wire, 4, 1, 2686237816, 1273374798)
    return radio_gaps.decode_report(wire)


class RadioGapsCollectorTests(unittest.TestCase):
    def test_collector_reads_both_roles_and_writes_protected_result(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            output = Path(directory) / "radio-gaps"
            run_dir.mkdir()
            report = _existing_run(run_dir)
            observed = _wire()
            struct.pack_into("<III", observed, 4, 1, 2686237816, 1273374798)
            struct.pack_into("<IIIQ", observed, 44, 1, 10, 10, 10)
            sender_report = radio_gaps.decode_report(observed)
            observed = _wire()
            struct.pack_into("<III", observed, 4, 1, 2686237816, 1273374798)
            struct.pack_into("<IIIQ", observed, 24, 1, 10, 10, 10)
            receiver_report = radio_gaps.decode_report(observed)
            _FakeSession.reports = {"base": sender_report, "walker": receiver_report}
            result = radio_gaps.collect_radio_gaps(run_dir, output, session_factory=_FakeSession)
            self.assertEqual(result["status"], "measurement_valid")
            self.assertEqual(set(result["boards"]), {"base", "walker"})
            self.assertEqual(json.loads((output / "results.json").read_text())["status"], "measurement_valid")
            runtime = result["provenance"]["runtime"]
            self.assertTrue(runtime["python_executable"])
            self.assertTrue(runtime["meshtastic"]["sha256"])
            self.assertTrue(runtime["protobuf"]["generated_mesh_descriptor_sha256"])
            self.assertTrue(runtime["pyserial"]["version"])
            self.assertEqual(radio_gaps.PRIVATE_APP_PORTNUM, 256)
            for module in ("mesh_interface", "serial_interface", "stream_interface", "portnums_pb2"):
                self.assertTrue(runtime["control_modules"][module]["path"])
                self.assertTrue(runtime["control_modules"][module]["sha256"])

    def test_collector_rejects_zero_observation_board(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            run_dir.mkdir()
            zero_report = _existing_run(run_dir)
            observed = _wire()
            struct.pack_into("<III", observed, 4, 1, 2686237816, 1273374798)
            struct.pack_into("<IIIQ", observed, 44, 1, 10, 10, 10)
            sender_report = radio_gaps.decode_report(observed)
            _FakeSession.reports = {"base": sender_report, "walker": zero_report}
            result = radio_gaps.collect_radio_gaps(run_dir, Path(directory) / "empty", session_factory=_FakeSession)
            self.assertFalse(result["measurement_valid"])
            self.assertTrue(result["boards"]["base"]["measurement_valid"])
            self.assertFalse(result["boards"]["walker"]["measurement_valid"])
            self.assertIn("radio_gaps_no_observations", result["boards"]["walker"]["evaluation"]["failure_reasons"])

    def test_close_persistence_dead_reader_and_malformed_events_invalidate_both_rows(self):
        for session_factory, expected_text in (
            (_CloseFailure, "close"),
            (_PersistenceFailure, "persistence"),
            (_DeadReaderSession, "reader_exited"),
            (_OpenStreamSession, "stream"),
            (_MalformedEvents, "capture event"),
            (_ProtocolErrorEvents, "protocol error"),
        ):
            with self.subTest(session_factory=session_factory.__name__):
                with tempfile.TemporaryDirectory() as directory:
                    run_dir = Path(directory) / "run"
                    run_dir.mkdir()
                    report = _existing_run(run_dir)
                    _FakeSession.reports = {"base": report, "walker": report}
                    result = radio_gaps.collect_radio_gaps(
                        run_dir,
                        Path(directory) / "output",
                        session_factory=session_factory,
                    )
                    self.assertFalse(result["measurement_valid"])
                    self.assertTrue(all(not row["measurement_valid"] for row in result["boards"].values()))
                    self.assertTrue(all(not row["evaluation"]["measurement_valid"] for row in result["boards"].values()))
                    self.assertTrue(any(expected_text in failure for failure in result["failure_reasons"]))

    def test_preflight_rejects_incomplete_primary_capture_validity(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            run_dir.mkdir()
            _existing_run(run_dir)
            result = json.loads((run_dir / "results.json").read_text())
            result["report"]["capture_validity"]["sender_snapshot_valid"] = False
            (run_dir / "results.json").write_text(json.dumps(result), encoding="utf-8")
            with self.assertRaises(radio_gaps.BenchmarkError):
                radio_gaps.collect_radio_gaps(
                    run_dir,
                    Path(directory) / "output",
                    session_factory=_FakeSession,
                )

    def test_preflight_rejects_nonterminal_primary_report(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            run_dir.mkdir()
            _existing_run(run_dir)
            result = json.loads((run_dir / "results.json").read_text())
            result["report"]["sender"]["complete"] = False
            result["firmware_reports"]["sender"]["complete"] = False
            (run_dir / "results.json").write_text(json.dumps(result), encoding="utf-8")
            with self.assertRaises(radio_gaps.BenchmarkError):
                radio_gaps.collect_radio_gaps(
                    run_dir,
                    Path(directory) / "output",
                    session_factory=_FakeSession,
                )

    def test_collector_refuses_to_overwrite_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            output = Path(directory) / "output"
            run_dir.mkdir()
            output.mkdir()
            _existing_run(run_dir)
            with self.assertRaises(radio_gaps.BenchmarkError):
                radio_gaps.collect_radio_gaps(run_dir, output, session_factory=_FakeSession)

    def test_collector_fails_closed_for_bad_identity_and_late_response(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            run_dir.mkdir()
            _existing_run(run_dir)

            class BadIdentity(_FakeSession):
                def __init__(self, role, output, gap):
                    super().__init__(role, output, gap)
                    if role == "base":
                        self.node_num += 1

            _FakeSession.reports = {"base": TimeoutError("snapshot response timed out"), "walker": _existing_run(run_dir)}
            result = radio_gaps.collect_radio_gaps(run_dir, Path(directory) / "bad", session_factory=BadIdentity)
            self.assertFalse(result["measurement_valid"])
            self.assertTrue(any("identity" in reason for reason in result["failure_reasons"]))

            _FakeSession.reports = {"base": TimeoutError("snapshot response timed out"), "walker": TimeoutError("snapshot response timed out")}
            result = radio_gaps.collect_radio_gaps(run_dir, Path(directory) / "late", session_factory=_FakeSession)
            self.assertFalse(result["measurement_valid"])
            self.assertTrue(any("timed out" in reason for reason in result["failure_reasons"]))


if __name__ == "__main__":
    unittest.main()
