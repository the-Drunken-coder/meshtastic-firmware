"""Behavioral checks for the W12 host protocol and fail-closed report."""

from __future__ import annotations

import base64
import collections
import importlib.util
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

MODULE_PATH = Path(__file__).with_name("benchmark_probe.py")
SPEC = importlib.util.spec_from_file_location("benchmark_probe", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
benchmark = importlib.util.module_from_spec(SPEC)
sys.modules["benchmark_probe"] = benchmark
SPEC.loader.exec_module(benchmark)


FAKE_PUBLIC_KEYS = {"base": b"B" * 32, "walker": b"W" * 32}


def config(**changes):
    values = {
        "run_id": 0x12345678,
        "source": 2686237816,
        "destination": 1273374798,
        "count": 1000,
        "size": 219,
        "duration_ms": 60_000,
        "window": 16,
        "flags": 0,
    }
    values.update(changes)
    return benchmark.RunConfig(**values)


def report(run, **changes):
    values = {
        "config": run,
        "prepared": True,
        "running": False,
        "complete": True,
        "enqueued": run.count,
        "send_failures": 0,
        "tx_started": run.count,
        "tx_succeeded": run.count,
        "tx_failures": 0,
        "tx_dropped": 0,
        "tx_cancelled": 0,
        "received": run.count,
        "missing": 0,
        "duplicates": 0,
        "corrupt": 0,
        "out_of_range": 0,
        "elapsed_ms": run.duration_ms,
        "goodput_bps": run.count * run.size * 1000 // run.duration_ms,
    }
    values.update(changes)
    return benchmark.FirmwareReport(**values)


def diagnostic_payload(run, **changes):
    """Build a kind-4 fixture using the frozen little-endian offsets."""

    values = {
        "status": 0x0D,
        "pending_tx_count": 0,
        "tx_delay_scheduled_attempts": 11,
        "pre_can_send_deferred": 12,
        "cca_decisions": 13,
        "cca_rssi_sample_count": 8,
        "cca_rssi_min_dbm": -120,
        "cca_rssi_max_dbm": -79,
        "queue_start_duration_count": 14,
        "queue_start_duration_sum_ms": 15,
        "queue_start_duration_max_ms": 16,
        "tx_duration_count": 17,
        "tx_duration_sum_ms": 18,
        "tx_duration_max_ms": 19,
        "tx_started": 20,
        "tx_terminal": 21,
        "producer_blocked_total": 22,
        "producer_queue_free_zero": 23,
        "producer_queue_window": 24,
        "producer_tx_capacity": 25,
        "rx_irq_done": 26,
        "rx_crc_errors": 27,
        "rx_len_errors": 28,
        "rx_header_crc_errors": 29,
        "rx_timeouts": 30,
        "rx_other_errors": 31,
        "rx_read_success": 32,
        "rx_read_failure": 33,
        "rx_queue_enqueued": 34,
        "rx_queue_drop": 35,
        "rx_decode_success": 36,
        "rx_decode_reject": 37,
        "rx_decode_opaque": 38,
        "rx_auth_accepted": 39,
        "module_receive_handler_count": 40,
        "module_receive_handler_sum_ms": 41,
        "module_receive_handler_max_ms": 42,
        "tx_delay_fired": 43,
        "tx_delay_schedule_accepted": 44,
        "tx_delay_schedule_rejected": 45,
    }
    values.update(changes)
    payload = bytearray(benchmark.DIAGNOSTIC_REPORT_BYTES)
    payload[0:2] = benchmark.MAGIC.to_bytes(2, "little")
    payload[2:4] = bytes((benchmark.VERSION, benchmark.DIAGNOSTIC_KIND))
    payload[4:8] = run.run_id.to_bytes(4, "little")
    payload[8:12] = run.source.to_bytes(4, "little")
    payload[12:16] = run.destination.to_bytes(4, "little")
    payload[16:20] = (run.duration_ms).to_bytes(4, "little")
    payload[20] = values["status"]
    payload[21] = values["pending_tx_count"]
    payload[24:28] = values["tx_delay_scheduled_attempts"].to_bytes(4, "little")
    payload[28:32] = values["pre_can_send_deferred"].to_bytes(4, "little")
    payload[32:36] = values["cca_decisions"].to_bytes(4, "little")
    for index in range(7):
        payload[36 + index * 4 : 40 + index * 4] = (index + 1).to_bytes(4, "little")
    payload[64:68] = values["cca_rssi_sample_count"].to_bytes(4, "little")
    payload[68:70] = values["cca_rssi_min_dbm"].to_bytes(2, "little", signed=True)
    payload[70:72] = values["cca_rssi_max_dbm"].to_bytes(2, "little", signed=True)
    for index in range(8):
        payload[72 + index * 4 : 76 + index * 4] = (index + 10).to_bytes(4, "little")
    offsets = {
        104: "queue_start_duration_count",
        108: "queue_start_duration_sum_ms",
        112: "queue_start_duration_max_ms",
        116: "tx_duration_count",
        120: "tx_duration_sum_ms",
        124: "tx_duration_max_ms",
        128: "tx_started",
        132: "tx_terminal",
        136: "producer_blocked_total",
        140: "producer_queue_free_zero",
        144: "producer_queue_window",
        148: "producer_tx_capacity",
        152: "rx_irq_done",
        156: "rx_crc_errors",
        160: "rx_len_errors",
        164: "rx_header_crc_errors",
        168: "rx_timeouts",
        172: "rx_other_errors",
        176: "rx_read_success",
        180: "rx_read_failure",
        184: "rx_queue_enqueued",
        188: "rx_queue_drop",
        192: "rx_decode_success",
        196: "rx_decode_reject",
        200: "rx_decode_opaque",
        204: "rx_auth_accepted",
        208: "module_receive_handler_count",
        212: "module_receive_handler_sum_ms",
        216: "module_receive_handler_max_ms",
        220: "tx_delay_fired",
        224: "tx_delay_schedule_accepted",
        228: "tx_delay_schedule_rejected",
    }
    for offset, name in offsets.items():
        payload[offset : offset + 4] = values[name].to_bytes(4, "little")
    return bytes(payload)


def radio_diagnostic_payload(run, **changes):
    values = {
        "status": 0x05,
        "pending_tx_count": 0,
        "rx_arm_last_result": -7,
        "rx_standby_last_result": -8,
        "rx_start_last_result": -9,
        "rx_irq_map_last_result": -10,
        "poll_rx_last_result": -11,
        "poll_tx_last_done": 0xFF,
        "snapshot_is_receiving": 1,
        "snapshot_rx_offline": 0,
        "snapshot_irq_attachment": 1,
        "snapshot_state_valid": 1,
        "irq_gpio_level": 0xFF,
        "irq_gpio_source": 0,
        "poll_chip_status0": 4,
        "poll_chip_status1": 5,
        "poll_chip_status_observed": 1,
        "poll_chip_status_age_ms": 789,
        "poll_chip_rx_count": 3,
        "poll_chip_nonrx_count": 4,
        "rx_arm_last_stage": 0,
        "last_rx_done_age_ms": 123,
        "last_rx_read_age_ms": benchmark.UINT32_MAX,
        "last_rx_auth_age_ms": 456,
    }
    values.update(changes)
    payload = bytearray(benchmark.DIAGNOSTIC_REPORT_BYTES)
    payload[0:2] = benchmark.MAGIC.to_bytes(2, "little")
    payload[2:4] = bytes((benchmark.VERSION, 5))
    payload[4:8] = run.run_id.to_bytes(4, "little")
    payload[8:12] = run.source.to_bytes(4, "little")
    payload[12:16] = run.destination.to_bytes(4, "little")
    payload[16:20] = run.duration_ms.to_bytes(4, "little")
    payload[20] = values["status"]
    payload[21] = values["pending_tx_count"]
    signed_offsets = {
        44: "rx_standby_last_result",
        54: "rx_start_last_result",
        68: "rx_irq_map_last_result",
        70: "rx_arm_last_result",
        132: "poll_rx_last_result",
    }
    u8_offsets = {
        146: "poll_tx_last_done",
        147: "snapshot_is_receiving",
        148: "snapshot_rx_offline",
        149: "snapshot_irq_attachment",
        150: "snapshot_state_valid",
        151: "irq_gpio_level",
        152: "irq_gpio_source",
        217: "poll_chip_status0",
        218: "poll_chip_status1",
        219: "poll_chip_status_observed",
        216: "rx_arm_last_stage",
    }
    for offset, name in signed_offsets.items():
        payload[offset : offset + 2] = values[name].to_bytes(2, "little", signed=True)
    for offset, name in u8_offsets.items():
        payload[offset] = values[name]
    u32_names = (
        "rx_arm_attempts",
        "rx_arm_successes",
        "rx_arm_failures",
        "rx_standby_calls",
        "rx_standby_failures",
        "rx_start_calls",
        "rx_start_failures",
        "rx_start_retry_calls",
        "rx_irq_map_calls",
        "rx_irq_map_failures",
        "rx_start_duration_count_us",
        "rx_start_duration_sum_us",
        "rx_start_duration_max_us",
        "channel_active_duration_count_us",
        "channel_active_duration_sum_us",
        "channel_active_duration_max_us",
        "start_send_duration_count_us",
        "start_send_duration_sum_us",
        "start_send_duration_max_us",
        "poll_calls",
        "poll_rx_checks",
        "poll_rx_read_success",
        "poll_rx_read_failure",
        "poll_rx_pending",
        "poll_rx_last_flags",
        "poll_rx_flags_or",
        "poll_tx_checks",
        "poll_tx_pending",
    )
    for index, name in enumerate(u32_names):
        values.setdefault(name, index + 1)
    offsets = [24, 28, 32, 36, 40, 46, 50, 56, 60, 64, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124, 128, 134, 138, 142]
    for offset, name in zip(offsets, u32_names):
        payload[offset : offset + 4] = values[name].to_bytes(4, "little")
    for offset, name in (
        (220, "poll_chip_status_age_ms"),
        (224, "poll_chip_rx_count"),
        (228, "poll_chip_nonrx_count"),
    ):
        payload[offset : offset + 4] = values[name].to_bytes(4, "little")
    for index in range(12):
        payload[156 + index * 4 : 160 + index * 4] = (index + 20).to_bytes(4, "little")
    for offset, name in ((204, "last_rx_done_age_ms"), (208, "last_rx_read_age_ms"), (212, "last_rx_auth_age_ms")):
        payload[offset : offset + 4] = values[name].to_bytes(4, "little")
    return bytes(payload)


class ProtocolTests(unittest.TestCase):
    def test_control_frame_is_exact_little_endian_contract(self):
        run = config()
        encoded = benchmark.encode_control(run, benchmark.CONTROL_START)
        self.assertEqual(len(encoded), benchmark.CONTROL_BYTES)
        self.assertEqual(encoded[:4], bytes((0x31, 0x57, 1, 2)))
        self.assertEqual(
            benchmark.decode_control(encoded), (benchmark.CONTROL_START, run)
        )

    def test_report_frame_round_trips_with_physical_terminal_counts(self):
        run = config()
        original = report(
            run,
            tx_started=997,
            tx_succeeded=991,
            tx_failures=2,
            tx_dropped=3,
            tx_cancelled=1,
        )
        encoded = benchmark.encode_report(original)
        self.assertEqual(len(encoded), 86)
        decoded = benchmark.decode_report(encoded)
        self.assertEqual(decoded, original)
        self.assertEqual(decoded.tx_succeeded, 991)

    def test_diagnostic_control_uses_unchanged_32_byte_shape(self):
        run = config()
        encoded = benchmark.encode_control(
            run, benchmark.CONTROL_SNAPSHOT_DIAGNOSTICS
        )
        self.assertEqual(len(encoded), benchmark.CONTROL_BYTES)
        self.assertEqual(
            benchmark.decode_control(encoded),
            (benchmark.CONTROL_SNAPSHOT_DIAGNOSTICS, run),
        )

    def test_radio_diagnostic_control_uses_unchanged_32_byte_shape(self):
        run = config()
        encoded = benchmark.encode_control(
            run, benchmark.CONTROL_SNAPSHOT_RADIO_DIAGNOSTICS
        )
        self.assertEqual(len(encoded), benchmark.CONTROL_BYTES)
        self.assertEqual(
            benchmark.decode_control(encoded),
            (benchmark.CONTROL_SNAPSHOT_RADIO_DIAGNOSTICS, run),
        )

    def test_diagnostic_report_round_trips_all_counter_groups(self):
        run = config()
        decoded = benchmark.decode_diagnostics(diagnostic_payload(run))
        self.assertEqual(decoded.run_id, run.run_id)
        self.assertEqual(decoded.cca_reasons, tuple(range(1, 8)))
        self.assertEqual(decoded.cca_rssi_histogram, tuple(range(10, 18)))
        self.assertEqual(decoded.cca_rssi_min_dbm, -120)
        self.assertEqual(decoded.cca_rssi_max_dbm, -79)
        self.assertEqual(decoded.tx_terminal, 21)
        serialized = benchmark._diagnostic_dict(decoded)
        self.assertEqual(serialized["scope"], "board_local_aggregate")
        self.assertEqual(serialized["status"], "complete")
        self.assertTrue(serialized["coverage_complete"])

    def test_radio_diagnostic_decodes_signed_phase_state_and_unknown_ages(self):
        run = config()
        decoded = benchmark.decode_radio_diagnostics(radio_diagnostic_payload(run))
        self.assertEqual(decoded.rx_standby_last_result, -8)
        self.assertEqual(decoded.rx_start_last_result, -9)
        self.assertEqual(decoded.rx_done_by_5s_bucket, tuple(range(20, 32)))
        self.assertEqual(decoded.last_rx_read_age_ms, benchmark.UINT32_MAX)
        self.assertEqual(decoded.poll_chip_status0, 4)
        self.assertEqual(decoded.poll_chip_rx_count, 3)
        serialized = benchmark._radio_diagnostic_dict(decoded)
        self.assertEqual(serialized["scope"], "board_local_radio_phase")
        self.assertEqual(serialized["status"], "complete")
        self.assertEqual(serialized["rx_arm_last_stage"], "success")
        self.assertEqual(serialized["rx_done_bucket_anchor"], "local_START")
        self.assertTrue(serialized["last_rx_read_age_unknown"])
        self.assertIsNone(serialized["last_rx_read_age_ms"])
        self.assertEqual(serialized["poll_chip_status_age_ms"], 789)
        self.assertEqual(
            serialized["poll_chip_mode_source"], "poll_chip_status1 low three bits"
        )
        self.assertFalse(serialized["rf_coverage_authoritative"])

    def test_radio_diagnostic_parser_rejects_length_reserved_status_and_enum_errors(self):
        run = config()
        valid = radio_diagnostic_payload(run)
        adverse = {
            "short": valid[:-1],
            "long": valid + b"\x00",
            "kind": bytes(valid[:3] + b"\x04" + valid[4:]),
            "header_reserved": bytes(valid[:22] + b"\x01" + valid[23:]),
            "phase_reserved": bytes(valid[:153] + b"\x01" + valid[154:]),
            "tail_reserved": bytes(valid[:232] + b"\x01"),
            "unknown_status": bytes(valid[:20] + b"\x08" + valid[21:]),
            "running_and_complete": bytes(valid[:20] + b"\x27" + valid[21:]),
            "pending_status_mismatch": bytes(valid[:20] + b"\x05\x01" + valid[22:]),
            "poll_done": bytes(valid[:146] + b"\x02" + valid[147:]),
            "attachment": bytes(valid[:149] + b"\x04" + valid[150:]),
            "stage": bytes(valid[:216] + b"\x04" + valid[217:]),
            "chip_status_observed": bytes(valid[:219] + b"\x02" + valid[220:]),
        }
        for name, payload in adverse.items():
            with self.subTest(name=name), self.assertRaises(benchmark.BenchmarkError):
                benchmark.decode_radio_diagnostics(payload)

    def test_protocol_manifest_records_frozen_diagnostic_operation_and_offsets(self):
        manifest = json.loads(
            (MODULE_PATH.with_name("benchmark-protocol.json")).read_text()
        )
        operation = next(
            field for field in manifest["control"]["fields"] if field[2] == "op"
        )
        self.assertEqual(operation[4]["SNAPSHOT_DIAGNOSTICS"], 5)
        self.assertEqual(operation[4]["SNAPSHOT_RADIO_DIAGNOSTICS"], 6)
        self.assertEqual(manifest["diagnostics"]["response_kind"], 4)
        self.assertEqual(manifest["diagnostics"]["response_bytes"], 233)
        fields = {field[2]: field for field in manifest["diagnostic_report"]["fields"]}
        self.assertEqual(fields["tx_delay_schedule_accepted"][:2], [224, 4])
        self.assertEqual(fields["tx_delay_schedule_rejected"][:2], [228, 4])
        phase_fields = {
            field[2]: field for field in manifest["radio_phase_report"]["fields"]
        }
        self.assertEqual(manifest["radio_phase_report"]["status_bits"]["reserved"], 8)
        self.assertEqual(phase_fields["rx_done_by_5s_bucket"][:2], [156, 48])
        self.assertEqual(phase_fields["poll_chip_rx_count"][:2], [224, 4])
        self.assertIn("poll_chip_status1", phase_fields["poll_chip_rx_count"][4])
        self.assertEqual(manifest["host_clock"]["continuity_tolerance_seconds"], 2.0)
        self.assertEqual(manifest["host_clock"]["failure_reason"], "host_clock_discontinuity")

    def test_diagnostic_pending_snapshot_is_explicitly_as_of(self):
        run = config()
        payload = diagnostic_payload(run, status=0x3F, pending_tx_count=2)
        decoded = benchmark.decode_diagnostics(payload)
        serialized = benchmark._diagnostic_dict(decoded)
        self.assertTrue(decoded.as_of_incomplete)
        self.assertFalse(decoded.coverage_complete)
        self.assertEqual(serialized["status"], "as_of_incomplete")
        self.assertTrue(serialized["pending_tx"])

    def test_terminal_diagnostic_requires_exact_fixed_window_for_coverage(self):
        run = config()
        for elapsed_ms in (0, 1, 59_999):
            with self.subTest(elapsed_ms=elapsed_ms):
                payload = bytearray(diagnostic_payload(run))
                payload[16:20] = elapsed_ms.to_bytes(4, "little")
                decoded = benchmark.decode_diagnostics(bytes(payload))
                serialized = benchmark._diagnostic_dict(decoded)
                self.assertTrue(decoded.snapshot_terminal)
                self.assertFalse(decoded.coverage_complete)
                self.assertEqual(serialized["status"], "snapshot_terminal")

    def test_running_diagnostic_is_not_terminal_or_full_window(self):
        run = config()
        decoded = benchmark.decode_diagnostics(
            diagnostic_payload(run, status=0x2B)
        )
        self.assertTrue(decoded.running)
        self.assertTrue(decoded.as_of_incomplete)
        self.assertFalse(decoded.snapshot_terminal)
        self.assertFalse(decoded.coverage_complete)

    def test_diagnostic_parser_rejects_header_length_reserved_and_status_errors(self):
        run = config()
        valid = diagnostic_payload(run)
        adverse = {
            "short": valid[:-1],
            "long": valid + b"\x00",
            "kind": bytes(valid[:3] + b"\x03" + valid[4:]),
            "reserved": bytes(valid[:22] + b"\x01" + valid[23:]),
            "unknown_status": bytes(valid[:20] + b"\x40" + valid[21:]),
            "unprepared": bytes(valid[:20] + b"\x00" + valid[21:]),
            "rssi_status_mismatch": bytes(valid[:20] + b"\x05" + valid[21:]),
            "pending_status_mismatch": bytes(valid[:20] + b"\x0D\x01" + valid[22:]),
            "tail": bytes(valid[:232] + b"\x01"),
        }
        for name, payload in adverse.items():
            with self.subTest(name=name), self.assertRaises(benchmark.BenchmarkError):
                benchmark.decode_diagnostics(payload)

    def test_host_clock_continuity_guard_rejects_positive_and_negative_gaps(self):
        normal = benchmark.assess_host_clock_continuity(10.0, 100.0, 70.0, 160.5)
        positive = benchmark.assess_host_clock_continuity(10.0, 100.0, 70.0, 175.0)
        negative = benchmark.assess_host_clock_continuity(10.0, 100.0, 70.0, 145.0)
        self.assertFalse(normal["discontinuous"])
        self.assertTrue(positive["discontinuous"])
        self.assertTrue(negative["discontinuous"])
        self.assertEqual(positive["monotonic_elapsed_seconds"], 60.0)
        self.assertEqual(positive["wall_elapsed_seconds"], 75.0)
        self.assertEqual(negative["wall_elapsed_seconds"], 45.0)

    def test_old_short_report_is_rejected(self):
        with self.assertRaises(benchmark.BenchmarkError):
            benchmark.decode_report(bytes(64))

    def test_data_identity_rejects_size_mismatch(self):
        payload = bytearray(benchmark.DATA_HEADER_BYTES)
        payload[0:2] = (benchmark.MAGIC).to_bytes(2, "little")
        payload[2:4] = bytes((benchmark.VERSION, benchmark.DATA_KIND))
        payload[20:22] = (219).to_bytes(2, "little")
        with self.assertRaises(benchmark.BenchmarkError):
            benchmark.decode_data(bytes(payload))

    def test_acceptance_run_requires_full_payload_and_fixed_sixty_second_window(self):
        with self.assertRaises(benchmark.BenchmarkError):
            benchmark.validate_config(config(size=200))
        with self.assertRaises(benchmark.BenchmarkError):
            benchmark.validate_config(config(duration_ms=120_000))

    def test_fresh_config_snapshot_change_fails_preservation_check(self):
        before = {
            "base": {"local_config_sha256": "before-base"},
            "walker": {"local_config_sha256": "before-walker"},
        }

        class FakeSession:
            closed = []

            def __init__(self, role, _output, _command_gap):
                self.role = role

            def snapshot_config(self, _output, _label):
                return {"local_config_sha256": f"fresh-{self.role}"}

            def close(self):
                self.closed.append(self.role)

        after = benchmark._fresh_config_snapshots(
            Path("."),
            ("base", "walker"),
            0.2,
            FakeSession,
        )
        self.assertFalse(benchmark._configuration_preserved(before, after))
        self.assertEqual(FakeSession.closed, ["base", "walker"])

    def test_fresh_config_snapshot_close_false_fails_closed(self):
        class FakeSession:
            def __init__(self, role, _output, _command_gap):
                self.role = role

            def snapshot_config(self, _output, _label):
                return {"local_config_sha256": f"fresh-{self.role}"}

            def close(self):
                return False

        with self.assertRaisesRegex(benchmark.BenchmarkError, "port remains occupied"):
            benchmark._fresh_config_snapshots(Path("."), ("base",), 0.2, FakeSession)

    def _peer_sessions(self, sender_peer_key, receiver_peer_key):
        base_key = FAKE_PUBLIC_KEYS["base"]
        walker_key = FAKE_PUBLIC_KEYS["walker"]

        def session(role, local_key, peer_key):
            peer_role = "walker" if role == "base" else "base"
            return SimpleNamespace(
                node_num=benchmark.BOARD_IDENTITIES[role][1],
                interface=SimpleNamespace(
                    nodesByNum={
                        benchmark.BOARD_IDENTITIES[peer_role][1]: {
                            "user": {"publicKey": peer_key}
                        }
                    },
                    localNode=SimpleNamespace(
                        localConfig=SimpleNamespace(
                            security=SimpleNamespace(public_key=local_key)
                        )
                    ),
                ),
            )

        return {
            "base": session("base", base_key, sender_peer_key),
            "walker": session("walker", walker_key, receiver_peer_key),
        }

    def test_peer_keys_match_in_bytes_and_report_only_hashes(self):
        sessions = self._peer_sessions(
            FAKE_PUBLIC_KEYS["walker"], FAKE_PUBLIC_KEYS["base"]
        )

        result = benchmark._peer_bitmap(sessions, "base", "walker")

        self.assertEqual(result["mask"], 3)
        self.assertTrue(result["sender_knows_receiver"])
        self.assertNotIn("public_key", result)
        self.assertEqual(
            result["receiver_local_public_key_sha256"],
            benchmark.sha256_bytes(FAKE_PUBLIC_KEYS["walker"]),
        )

    def test_peer_keys_accept_base64_representations(self):
        sessions = self._peer_sessions(
            base64.b64encode(FAKE_PUBLIC_KEYS["walker"]).decode(),
            base64.urlsafe_b64encode(FAKE_PUBLIC_KEYS["base"]),
        )

        result = benchmark._peer_bitmap(sessions, "base", "walker")

        self.assertEqual(result["mask"], 3)

    def test_missing_peer_key_fails_before_run(self):
        sessions = self._peer_sessions(None, FAKE_PUBLIC_KEYS["base"])

        with self.assertRaisesRegex(
            benchmark.BenchmarkError, "peer_public_key_missing_or_invalid"
        ):
            benchmark._peer_bitmap(sessions, "base", "walker")

    def test_wrong_peer_key_fails_before_run(self):
        sessions = self._peer_sessions(b"X" * 32, FAKE_PUBLIC_KEYS["base"])

        with self.assertRaisesRegex(
            benchmark.BenchmarkError, "peer_public_key_mismatch"
        ):
            benchmark._peer_bitmap(sessions, "base", "walker")

    def test_truncated_peer_key_fails_before_run(self):
        sessions = self._peer_sessions(
            base64.b64encode(FAKE_PUBLIC_KEYS["walker"][:31]).decode(),
            FAKE_PUBLIC_KEYS["base"],
        )

        with self.assertRaisesRegex(
            benchmark.BenchmarkError, "peer_public_key_missing_or_invalid"
        ):
            benchmark._peer_bitmap(sessions, "base", "walker")

    def test_malformed_peer_key_representations_fail_closed(self):
        for malformed in (
            "!" + base64.b64encode(FAKE_PUBLIC_KEYS["walker"])[1:].decode(),
            "é" * 44,
        ):
            with self.subTest(malformed=malformed[:4]):
                sessions = self._peer_sessions(malformed, FAKE_PUBLIC_KEYS["base"])
                with self.assertRaisesRegex(
                    benchmark.BenchmarkError, "peer_public_key_missing_or_invalid"
                ):
                    benchmark._peer_bitmap(sessions, "base", "walker")


class BoardResponseTests(unittest.TestCase):
    def setUp(self):
        self.session = object.__new__(benchmark.BoardSession)
        self.session.node_num = benchmark.BOARD_IDENTITIES["base"][1]
        self.run = config(
            source=benchmark.BOARD_IDENTITIES["base"][1],
            destination=benchmark.BOARD_IDENTITIES["walker"][1],
        )

    def _event(self, response_key, **changes):
        response = {
            "run_id": self.run.run_id,
            "source": self.run.source,
            "destination": self.run.destination,
        }
        response.update(changes.pop("response", {}))
        event = {
            "kind": "packet",
            "request_id": 77,
            "to": self.session.node_num,
            "from": self.session.node_num,
            response_key: response,
        }
        event.update(changes)
        return event

    def test_every_report_kind_requires_local_address_and_identity(self):
        for response_key in ("report", "diagnostics", "radio_diagnostics"):
            with self.subTest(response_key=response_key):
                valid = self._event(response_key)
                self.assertTrue(
                    self.session._response_event_matches(
                        valid, 77, response_key, self.run
                    )
                )
                for field in ("to", "from"):
                    invalid = dict(valid)
                    invalid[field] = self.run.destination
                    self.assertFalse(
                        self.session._response_event_matches(
                            invalid, 77, response_key, self.run
                        )
                    )
                for identity_field in ("run_id", "source", "destination"):
                    invalid_response = dict(valid[response_key])
                    invalid_response[identity_field] += 1
                    invalid = dict(valid)
                    invalid[response_key] = invalid_response
                    self.assertFalse(
                        self.session._response_event_matches(
                            invalid, 77, response_key, self.run
                        )
                    )

    def test_missing_address_cannot_match_local_report(self):
        event = self._event("report")
        del event["from"]
        self.assertFalse(
            self.session._response_event_matches(event, 77, "report", self.run)
        )


class ReportingTests(unittest.TestCase):
    def evaluate(self, sender=None, receiver=None, **kwargs):
        run = config()
        kwargs.setdefault("observed_wall_seconds", 60.0)
        kwargs.setdefault("observed_drain_seconds", 10.0)
        return benchmark.evaluate_reports(
            run,
            report(run) if sender is None else sender,
            report(run) if receiver is None else receiver,
            **kwargs,
        )

    def test_zero_results_fail_closed(self):
        run = config()
        empty = report(
            run,
            enqueued=0,
            tx_started=0,
            tx_succeeded=0,
            received=0,
            missing=run.count,
        )
        result = self.evaluate(sender=empty, receiver=empty)
        self.assertEqual(result["status"], "measurement_invalid")
        self.assertFalse(result["measurement_valid"])
        self.assertIn("sender_count_mismatch", result["failure_reasons"])

    def test_receiver_zero_results_fail_closed_even_with_complete_denominator(self):
        run = config()
        receiver = report(run, received=0, missing=run.count)
        result = self.evaluate(receiver=receiver)
        self.assertIn("receiver_zero_results", result["failure_reasons"])

    def test_missing_stats_fail_closed(self):
        result = self.evaluate(sender=None)
        # Explicit None must remain distinguishable from a valid zero report.
        result = benchmark.evaluate_reports(
            config(),
            None,
            report(config()),
            observed_wall_seconds=60.0,
            observed_drain_seconds=10.0,
        )
        self.assertIn("missing_sender_stats", result["failure_reasons"])

    def test_count_mismatch_and_physical_terminal_gap_fail_closed(self):
        run = config()
        sender = report(
            run,
            enqueued=run.count - 1,
            tx_started=run.count - 1,
            tx_succeeded=run.count - 2,
        )
        result = self.evaluate(sender=sender)
        self.assertIn("sender_count_mismatch", result["failure_reasons"])
        self.assertIn("sender_physical_terminal_incomplete", result["failure_reasons"])
        self.assertFalse(result["capture_validity"]["physical_tx_terminal_complete"])

    def test_timeout_fail_closed(self):
        result = self.evaluate(observed_wall_seconds=59.99)
        self.assertIn("wall_window_timeout", result["failure_reasons"])

    def test_non_sixty_second_wall_is_rejected(self):
        result = self.evaluate(wall_seconds=30.0, observed_wall_seconds=30.0)
        self.assertIn("fixed_wall_not_60_seconds", result["failure_reasons"])

    def test_identity_mismatch_fail_closed(self):
        run = config()
        receiver = report(config(run_id=run.run_id + 1))
        result = self.evaluate(receiver=receiver)
        self.assertIn("receiver_identity_mismatch", result["failure_reasons"])
        self.assertFalse(result["capture_validity"]["receiver_snapshot_valid"])
        self.assertFalse(
            result["capture_validity"]["aggregate_receiver_bitmap_authoritative"]
        )

    def test_goodput_uses_fixed_wall_denominator(self):
        run = config()
        receiver = report(run, received=500, missing=500, elapsed_ms=1000)
        result = self.evaluate(receiver=receiver)
        self.assertEqual(result["fixed_wall_goodput_Bps"], 500 * run.size / 60.0)
        self.assertEqual(
            result["fixed_wall_goodput_pattern_Bps"],
            500 * (run.size - benchmark.DATA_HEADER_BYTES) / 60.0,
        )
        self.assertEqual(result["goodput_payload_bytes"], run.size)
        self.assertEqual(
            result["goodput_pattern_bytes"], run.size - benchmark.DATA_HEADER_BYTES
        )

    def test_duration_bounded_admission_is_classified_as_cap(self):
        run = config(count=8192)
        sender = report(run, enqueued=1500, tx_started=1500, tx_succeeded=1500)
        receiver = report(
            run,
            enqueued=0,
            tx_started=0,
            tx_succeeded=0,
            received=1200,
            missing=run.count - 1200,
        )
        result = benchmark.evaluate_reports(
            run,
            sender,
            receiver,
            observed_wall_seconds=60.0,
            observed_drain_seconds=10.0,
        )
        self.assertEqual(result["status"], "measurement_valid")
        self.assertTrue(result["measurement_valid"])
        self.assertFalse(result["admission"]["producer_cap_reached"])
        self.assertEqual(result["admission"]["configured_cap"], 8192)
        self.assertEqual(result["admission"]["admitted"], 1500)
        self.assertEqual(result["transport_acceptance"], "not_evaluated_no_ack")
        self.assertEqual(result["counts"]["tx_receipt_count_gap"], 300)
        self.assertEqual(result["counts"]["firmware_missing"], 8192 - 1200)
        self.assertEqual(result["delivery_fraction"], 1200 / 1500)
        self.assertEqual(
            result["diagnostic_authenticated_rx_over_tx_done"], 1200 / 1500
        )
        self.assertIn(
            "independent sender and receiver windows",
            result["delivery_fraction_semantics"],
        )
        self.assertFalse(
            result["capture_validity"]["host_sequence_capture_authoritative"]
        )

    def test_reaching_configured_cap_is_reported_without_requiring_more_packets(self):
        run = config(count=8192)
        result = benchmark.evaluate_reports(
            run,
            sender=report(run),
            receiver=report(run),
            observed_wall_seconds=60.0,
            observed_drain_seconds=10.0,
        )
        self.assertEqual(result["status"], "measurement_valid")
        self.assertTrue(result["admission"]["producer_cap_reached"])
        self.assertEqual(result["admission"]["admitted"], run.count)

    def test_report_elapsed_must_match_fixed_window(self):
        run = config()
        sender = report(run, elapsed_ms=run.duration_ms - 1)
        receiver = report(run, elapsed_ms=run.duration_ms - 1)
        result = self.evaluate(sender=sender, receiver=receiver)
        self.assertIn("sender_elapsed_out_of_window", result["failure_reasons"])
        self.assertIn("receiver_elapsed_out_of_window", result["failure_reasons"])
        self.assertFalse(result["capture_validity"]["sender_snapshot_valid"])
        self.assertFalse(result["capture_validity"]["receiver_snapshot_valid"])
        self.assertFalse(result["capture_validity"]["physical_tx_terminal_complete"])
        self.assertFalse(
            result["capture_validity"]["aggregate_receiver_bitmap_authoritative"]
        )

    def test_missing_denominator_fails_closed_when_physical_results_are_small(self):
        run = config(count=8192)
        sender = report(run, enqueued=900, tx_started=900, tx_succeeded=900)
        receiver = report(run, received=800)
        result = benchmark.evaluate_reports(
            run,
            sender,
            receiver,
            observed_wall_seconds=60.0,
            observed_drain_seconds=10.0,
        )
        self.assertIn("receiver_denominator_incomplete", result["failure_reasons"])


class QueueSafetyTests(unittest.TestCase):
    def setUp(self):
        _, self.capturing_serial, self.mesh_pb2, self.portnums_pb2 = (
            benchmark._make_capture_serial_classes()
        )

    def _interface(self, node_num=2686237816):
        interface = object.__new__(self.capturing_serial)
        interface.node_num = node_num
        interface.noProto = False
        interface.queueStatus = self.mesh_pb2.QueueStatus(free=0)
        interface.queue = collections.OrderedDict()
        return interface

    def _control_packet(self, run, destination, payload=None):
        packet = self.mesh_pb2.ToRadio()
        packet.packet.to = destination
        setattr(packet.packet, "from", 0)
        packet.packet.decoded.portnum = int(self.portnums_pb2.PRIVATE_APP)
        packet.packet.decoded.payload = (
            benchmark.encode_control(run, benchmark.CONTROL_START)
            if payload is None
            else payload
        )
        return packet

    def test_local_control_bypasses_cached_zero_queue(self):
        run = config()
        interface = self._interface(run.source)
        sent = []
        interface._sendToRadioImpl = sent.append

        interface._sendToRadio(self._control_packet(run, run.source))

        self.assertEqual(len(sent), 1)

    def test_nonlocal_and_noncontrol_packets_retain_queue_gate(self):
        run = config()
        interface = self._interface(run.source)
        interface._sendToRadioImpl = lambda _packet: self.fail("queue bypassed")

        def queue_gate():
            raise AssertionError("queue gate reached")

        interface._queueHasFreeSpace = queue_gate
        with self.assertRaisesRegex(AssertionError, "queue gate reached"):
            interface._sendToRadio(self._control_packet(run, run.destination))
        with self.assertRaisesRegex(AssertionError, "queue gate reached"):
            interface._sendToRadio(self._control_packet(run, run.source, b"invalid"))

    def test_nonpacket_disconnect_bypasses_cached_zero_queue(self):
        interface = self._interface()
        sent = []
        interface._sendToRadioImpl = sent.append
        disconnect = self.mesh_pb2.ToRadio(disconnect=True)

        interface._sendToRadio(disconnect)

        self.assertEqual(sent, [disconnect])

    def test_close_lets_reader_own_normal_stream_close(self):
        class FakeStream:
            def __init__(self):
                self.closed = False
                self.close_count = 0
                self.lock = threading.Lock()

            def close(self):
                with self.lock:
                    if not self.closed:
                        self.close_count += 1
                        self.closed = True

        class FakeHeartbeat:
            def __init__(self):
                self.cancelled = False

            def cancel(self):
                self.cancelled = True

        class FakeInterface:
            def __init__(self):
                self._wantExit = False
                self.stream = FakeStream()
                self.initial_stream = self.stream
                self.heartbeatTimer = FakeHeartbeat()
                self.reader_exited = threading.Event()

                def reader_main():
                    while not self._wantExit:
                        self.reader_exited.wait(0.001)
                    if not self.stream.closed:
                        self.stream.close()
                    self.stream = None
                    self.reader_exited.set()

                self._rxThread = threading.Thread(target=reader_main, daemon=True)
                self._rxThread.start()

        with tempfile.TemporaryDirectory() as directory:
            session = object.__new__(benchmark.BoardSession)
            session._interface = FakeInterface()
            session.capture = benchmark._EventCapture("fake", Path(directory))

            self.assertTrue(session.close(timeout=0.5))
            interface = session._interface
            self.assertTrue(interface._wantExit)
            self.assertTrue(interface.heartbeatTimer.cancelled)
            self.assertFalse(interface._rxThread.is_alive())
            self.assertIsNone(interface.stream)
            self.assertEqual(interface.initial_stream.close_count, 1)

    def test_close_timeout_fails_closed_and_keeps_live_reader_from_reuse(self):
        class FakeStream:
            def __init__(self):
                self.closed = False
                self.close_count = 0

            def close(self):
                if not self.closed:
                    self.close_count += 1
                    self.closed = True

        class FakeInterface:
            def __init__(self):
                self._wantExit = False
                self.stream = FakeStream()
                self.release_reader = threading.Event()

                def reader_main():
                    self.release_reader.wait()
                    if not self.stream.closed:
                        self.stream.close()
                    self.stream = None

                self._rxThread = threading.Thread(target=reader_main, daemon=True)
                self._rxThread.start()

        with tempfile.TemporaryDirectory() as directory:
            session = object.__new__(benchmark.BoardSession)
            session._interface = FakeInterface()
            session.capture = benchmark._EventCapture("fake", Path(directory))

            self.assertFalse(session.close(timeout=0.01))
            interface = session._interface
            self.assertTrue(interface._rxThread.is_alive())
            self.assertIsNotNone(interface.stream)
            self.assertEqual(interface.stream.close_count, 1)

            interface.release_reader.set()
            interface._rxThread.join(0.5)
            self.assertFalse(interface._rxThread.is_alive())
            self.assertIsNone(interface.stream)

    def test_capture_events_can_be_flushed_before_close(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = benchmark._EventCapture("fake", Path(directory))
            capture.record("control_attempt", run_id=config().run_id)
            capture.persist()

            saved = json.loads(
                (Path(directory) / "fake" / "capture-events.json").read_text()
            )
            self.assertEqual(saved[0]["kind"], "control_attempt")
            self.assertEqual(saved[0]["run_id"], config().run_id)


class BoardSessionConstructionTests(unittest.TestCase):
    def _fake_classes(self, failure_phase, stuck_reader=False):
        expected_node = benchmark.BOARD_IDENTITIES["base"][1]

        class FakeStream:
            def __init__(self):
                self.close_count = 0

            def close(self):
                self.close_count += 1

        class FakeReader:
            def __init__(self):
                self.alive = True

            def is_alive(self):
                return self.alive

            def join(self, _timeout):
                if not stuck_reader:
                    self.alive = False

        class FakeInterface:
            instances = []

            def __init__(self, _path, connectNow=False, timeout=0, capture=None):
                del connectNow, timeout
                self.capture = capture
                self._wantExit = False
                self._rxThread = None
                self.stream = None
                self.heartbeatTimer = None
                self.myInfo = SimpleNamespace(my_node_num=expected_node)
                type(self).instances.append(self)

            def connect(self):
                self.stream = FakeStream()
                self.initial_stream = self.stream
                self._rxThread = FakeReader()
                if failure_phase == "connect":
                    raise RuntimeError("reader started before connect failure")

            def waitForConfig(self):
                if failure_phase == "config":
                    raise TimeoutError("config wait failed")

        return FakeInterface

    def _construct_failing_session(self, failure_phase, *, stuck_reader=False):
        fake_interface = self._fake_classes(failure_phase, stuck_reader)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            port = SimpleNamespace(
                serial_number=benchmark.BOARD_IDENTITIES["base"][0],
                device="/dev/fake-w12",
            )
            with mock.patch.object(
                benchmark,
                "_make_capture_serial_classes",
                lambda: (object, fake_interface, object, object),
            ), mock.patch(
                "serial.tools.list_ports.comports", return_value=[port]
            ):
                try:
                    benchmark.BoardSession("base", output)
                except BaseException as error:
                    events_path = output / "base" / "capture-events.json"
                    events = json.loads(events_path.read_text())
                    return error, fake_interface.instances[0], events
            self.fail("constructor unexpectedly succeeded")

    def test_connect_failure_after_reader_start_is_cleaned_and_original_error_survives(self):
        error, interface, events = self._construct_failing_session("connect")

        self.assertIsInstance(error, RuntimeError)
        self.assertIn("reader started before connect failure", str(error))
        self.assertFalse(interface._rxThread.is_alive())
        self.assertEqual(interface.initial_stream.close_count, 1)
        self.assertEqual(events[-1]["kind"], "session_construction_failed")

    def test_config_wait_failure_is_cleaned_and_capture_is_persisted(self):
        error, interface, events = self._construct_failing_session("config")

        self.assertIsInstance(error, TimeoutError)
        self.assertIn("config wait failed", str(error))
        self.assertFalse(interface._rxThread.is_alive())
        self.assertEqual(interface.initial_stream.close_count, 1)
        self.assertEqual(events[-1]["error_type"], "TimeoutError")

    def test_cleanup_timeout_fails_closed_and_chains_original_failure(self):
        error, interface, events = self._construct_failing_session(
            "connect", stuck_reader=True
        )

        self.assertIsInstance(error, benchmark.BenchmarkError)
        self.assertIn("port reuse prohibited", str(error))
        self.assertIsInstance(error.__cause__, RuntimeError)
        self.assertTrue(interface._rxThread.is_alive())
        self.assertEqual(interface.initial_stream.close_count, 1)
        self.assertEqual(events[-1]["kind"], "session_construction_failed")

    def test_cleanup_exception_fails_closed_and_chains_original_failure(self):
        fake_interface = self._fake_classes("connect")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            port = SimpleNamespace(
                serial_number=benchmark.BOARD_IDENTITIES["base"][0],
                device="/dev/fake-w12",
            )
            with mock.patch.object(
                benchmark,
                "_make_capture_serial_classes",
                lambda: (object, fake_interface, object, object),
            ), mock.patch(
                "serial.tools.list_ports.comports", return_value=[port]
            ), mock.patch.object(
                benchmark.BoardSession,
                "close",
                side_effect=OSError("close failed"),
            ):
                with self.assertRaisesRegex(
                    benchmark.BenchmarkError,
                    "cleanup raised OSError; port reuse prohibited",
                ) as raised:
                    benchmark.BoardSession("base", output)
            self.assertIsInstance(raised.exception.__cause__, RuntimeError)
            self.assertTrue(
                (output / "base" / "capture-events.json").exists()
            )


class HardwareHarnessTests(unittest.TestCase):
    def test_run_hardware_captures_controls_closes_and_freshly_reconnects(self):
        class FakeClock:
            def __init__(self):
                self.now = 0.0
                self.wall_start = 1_000.0

            def monotonic(self):
                return self.now

            def time(self):
                return self.wall_start + self.now

            def sleep(self, duration):
                self.now += duration

        class FakeSession:
            instances = []

            def __init__(self, role, output, command_gap, checkpoint=None):
                self.role = role
                self.output = output
                self.command_gap = command_gap
                self.node_num = benchmark.BOARD_IDENTITIES[role][1]
                self.identity = benchmark.BOARD_IDENTITIES[role][0]
                self.capture = benchmark._EventCapture(role, output, checkpoint)
                peer_role = "walker" if role == "base" else "base"
                self.interface = SimpleNamespace(
                    nodesByNum={
                        benchmark.BOARD_IDENTITIES[peer_role][1]: {
                            "user": {"publicKey": FAKE_PUBLIC_KEYS[peer_role]}
                        }
                    },
                    localNode=SimpleNamespace(
                        localConfig=SimpleNamespace(
                            security=SimpleNamespace(public_key=FAKE_PUBLIC_KEYS[role])
                        )
                    ),
                )
                self._packet_id = 100
                self.closed = False
                self.config_snapshot = {
                    "role": role,
                    "usb_identity": self.identity,
                    "port": f"fake-{role}",
                    "node_num": self.node_num,
                    "local_config_sha256": f"local-{role}",
                    "module_config_sha256": f"module-{role}",
                    "channels_sha256": f"channels-{role}",
                    "local_config_bytes": 1,
                    "module_config_bytes": 1,
                    "channel_count": 1,
                    "region": 1,
                    "lora_sha256": f"lora-{role}",
                    "private_key_sha256": f"private-{role}",
                    "public_key_sha256": f"public-{role}",
                }
                type(self).instances.append(self)

            def control(self, operation, run, *, want_response=False):
                payload = benchmark.encode_control(run, operation)
                self.capture.record(
                    "control_attempt",
                    operation=operation,
                    run_id=run.run_id,
                    payload_sha256=benchmark.sha256_bytes(payload),
                )
                self._packet_id += 1
                self.capture.record(
                    "control_intent",
                    operation=operation,
                    packet_id=self._packet_id,
                    run_id=run.run_id,
                    payload_sha256=benchmark.sha256_bytes(payload),
                )
                return self._packet_id

            def snapshot(self, run, _timeout):
                packet_id = self.control(
                    benchmark.CONTROL_SNAPSHOT, run, want_response=True
                )
                sender = self.role == "base"
                values = {
                    "config": run,
                    "prepared": True,
                    "running": False,
                    "complete": True,
                    "enqueued": run.count if sender else 0,
                    "send_failures": 0,
                    "tx_started": run.count if sender else 0,
                    "tx_succeeded": run.count if sender else 0,
                    "tx_failures": 0,
                    "tx_dropped": 0,
                    "tx_cancelled": 0,
                    "received": 0 if sender else run.count,
                    "missing": 0,
                    "duplicates": 0,
                    "corrupt": 0,
                    "out_of_range": 0,
                    "elapsed_ms": run.duration_ms,
                    "goodput_bps": run.count * run.size * 1000 // run.duration_ms,
                }
                self.capture.record(
                    "packet",
                    request_id=packet_id,
                    report=benchmark._report_dict(benchmark.FirmwareReport(**values)),
                )
                return benchmark.FirmwareReport(**values)

            def snapshot_diagnostics(self, run, _timeout):
                packet_id = self.control(
                    benchmark.CONTROL_SNAPSHOT_DIAGNOSTICS,
                    run,
                    want_response=True,
                )
                parsed = benchmark.decode_diagnostics(diagnostic_payload(run))
                diagnostics = benchmark._diagnostic_dict(parsed)
                self.capture.record(
                    "packet", request_id=packet_id, diagnostics=diagnostics
                )
                return diagnostics

            def snapshot_radio_diagnostics(self, run, _timeout):
                packet_id = self.control(
                    benchmark.CONTROL_SNAPSHOT_RADIO_DIAGNOSTICS,
                    run,
                    want_response=True,
                )
                parsed = benchmark.decode_radio_diagnostics(
                    radio_diagnostic_payload(run)
                )
                diagnostics = benchmark._radio_diagnostic_dict(parsed)
                self.capture.record(
                    "packet", request_id=packet_id, radio_diagnostics=diagnostics
                )
                return diagnostics

            def snapshot_config(self, _output, _label):
                return dict(self.config_snapshot)

            def close(self, _timeout=5.0):
                self.closed = True
                self.capture.persist()
                return True

        def fresh_snapshots(output, roles, command_gap):
            snapshots = {}
            for role in roles:
                session = FakeSession(role, output, command_gap)
                try:
                    snapshots[role] = session.snapshot_config(output, "after")
                finally:
                    session.close()
            return snapshots

        clock = FakeClock()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run"
            image = Path(directory) / "firmware.bin"
            image.write_bytes(b"test image")
            args = benchmark.build_parser().parse_args(
                [
                    "--output",
                    str(output),
                    "--count",
                    "1000",
                    "--wall-seconds",
                    "60",
                    "--drain-seconds",
                    "10",
                    "--run-id",
                    "305419896",
                    "--image",
                    str(image),
                    "--diagnostics",
                ]
            )
            with mock.patch.object(
                benchmark, "BoardSession", FakeSession
            ), mock.patch.object(
                benchmark, "_fresh_config_snapshots", fresh_snapshots
            ), mock.patch.object(
                benchmark.time, "monotonic", clock.monotonic
            ), mock.patch.object(
                benchmark.time, "time", clock.time
            ), mock.patch.object(
                benchmark.time, "sleep", clock.sleep
            ):
                result = benchmark.run_hardware(args)

            self.assertEqual(result["status"], "measurement_valid")
            self.assertTrue(result["configuration_preserved"])
            self.assertEqual(result["report"]["status"], "measurement_valid")
            self.assertEqual(result["firmware_reports"]["sender"]["enqueued"], 1000)
            self.assertEqual(result["diagnostics"]["status"], "valid_identity")
            self.assertEqual(
                result["diagnostics"]["validity"], "parsed_identity_match_only"
            )
            self.assertEqual(
                set(result["diagnostics"]["boards"]), {"base", "walker"}
            )
            self.assertTrue(
                all(
                    board["aggregate"]["scope"] == "board_local_aggregate"
                    and board["radio_phase"]["scope"] == "board_local_radio_phase"
                    for board in result["diagnostics"]["boards"].values()
                )
            )
            self.assertTrue(all(session.closed for session in FakeSession.instances))
            self.assertGreaterEqual(len(FakeSession.instances), 4)
            saved = json.loads((output / "results.json").read_text())
            self.assertEqual(saved["firmware_reports"], result["firmware_reports"])
            for role in ("base", "walker"):
                events = json.loads((output / role / "capture-events.json").read_text())
                self.assertTrue(
                    any(event["kind"] == "control_attempt" for event in events)
                )
                diagnostic_controls = [
                    event
                    for event in events
                    if event.get("kind") == "control_attempt"
                    and event.get("operation")
                    == benchmark.CONTROL_SNAPSHOT_DIAGNOSTICS
                ]
                self.assertEqual(len(diagnostic_controls), 1)
                radio_controls = [
                    event
                    for event in events
                    if event.get("kind") == "control_attempt"
                    and event.get("operation")
                    == benchmark.CONTROL_SNAPSHOT_RADIO_DIAGNOSTICS
                ]
                self.assertEqual(len(radio_controls), 1)
                self.assertTrue(
                    any(
                        event.get("kind") == "packet"
                        and event.get("diagnostics", {}).get("scope")
                        == "board_local_aggregate"
                        for event in events
                    )
                )
                self.assertTrue(
                    any(
                        event.get("kind") == "packet"
                        and event.get("radio_diagnostics", {}).get("scope")
                        == "board_local_radio_phase"
                        for event in events
                    )
                )

    def test_run_hardware_receiver_timeout_stops_and_preserves_lifecycle(self):
        class FakeClock:
            def __init__(self):
                self.now = 0.0
                self.wall_start = 2_000.0

            def monotonic(self):
                return self.now

            def time(self):
                return self.wall_start + self.now

            def sleep(self, duration):
                self.now += duration

        class FakeSession:
            instances = []

            def __init__(self, role, output, command_gap, checkpoint=None):
                self.role = role
                self.output = output
                self.command_gap = command_gap
                self.node_num = benchmark.BOARD_IDENTITIES[role][1]
                self.identity = benchmark.BOARD_IDENTITIES[role][0]
                self.capture = benchmark._EventCapture(role, output, checkpoint)
                peer_role = "walker" if role == "base" else "base"
                self.interface = SimpleNamespace(
                    nodesByNum={
                        benchmark.BOARD_IDENTITIES[peer_role][1]: {
                            "user": {"publicKey": FAKE_PUBLIC_KEYS[peer_role]}
                        }
                    },
                    localNode=SimpleNamespace(
                        localConfig=SimpleNamespace(
                            security=SimpleNamespace(public_key=FAKE_PUBLIC_KEYS[role])
                        )
                    ),
                )
                self.packet_id = 200
                self.stopped = False
                self.closed = False
                self.config_snapshot = {
                    "role": role,
                    "usb_identity": self.identity,
                    "port": f"timeout-{role}",
                    "node_num": self.node_num,
                    "local_config_sha256": f"local-{role}",
                    "module_config_sha256": f"module-{role}",
                    "channels_sha256": f"channels-{role}",
                    "local_config_bytes": 1,
                    "module_config_bytes": 1,
                    "channel_count": 1,
                    "region": 1,
                    "lora_sha256": f"lora-{role}",
                    "private_key_sha256": f"private-{role}",
                    "public_key_sha256": f"public-{role}",
                }
                type(self).instances.append(self)

            def control(self, operation, run, *, want_response=False):
                payload = benchmark.encode_control(run, operation)
                self.capture.record(
                    "control_attempt",
                    operation=operation,
                    run_id=run.run_id,
                    payload_sha256=benchmark.sha256_bytes(payload),
                )
                self.packet_id += 1
                if operation == benchmark.CONTROL_STOP:
                    self.stopped = True
                self.capture.record(
                    "control_intent",
                    operation=operation,
                    packet_id=self.packet_id,
                    run_id=run.run_id,
                    payload_sha256=benchmark.sha256_bytes(payload),
                )
                return self.packet_id

            def snapshot(self, run, _timeout):
                packet_id = self.control(
                    benchmark.CONTROL_SNAPSHOT, run, want_response=True
                )
                sender = self.role == "base"
                values = {
                    "config": run,
                    "prepared": True,
                    "running": not sender and not self.stopped,
                    "complete": sender or self.stopped,
                    "enqueued": run.count if sender else 0,
                    "send_failures": 0,
                    "tx_started": run.count if sender else 0,
                    "tx_succeeded": run.count if sender else 0,
                    "tx_failures": 0,
                    "tx_dropped": 0,
                    "tx_cancelled": 0,
                    "received": 0,
                    "missing": run.count,
                    "duplicates": 0,
                    "corrupt": 0,
                    "out_of_range": 0,
                    "elapsed_ms": run.duration_ms if sender else 0,
                    "goodput_bps": (
                        run.count * run.size * 1000 // run.duration_ms if sender else 0
                    ),
                }
                parsed = benchmark.FirmwareReport(**values)
                self.capture.record(
                    "packet",
                    request_id=packet_id,
                    report=benchmark._report_dict(parsed),
                )
                return parsed

            def snapshot_config(self, _output, _label):
                return dict(self.config_snapshot)

            def close(self, _timeout=5.0):
                self.closed = True
                self.capture.persist()
                return True

        def fresh_snapshots(output, roles, command_gap):
            snapshots = {}
            for role in roles:
                session = FakeSession(role, output, command_gap)
                try:
                    snapshots[role] = session.snapshot_config(output, "after")
                finally:
                    session.close()
            return snapshots

        clock = FakeClock()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "timeout-run"
            image = Path(directory) / "firmware.bin"
            image.write_bytes(b"timeout image")
            args = benchmark.build_parser().parse_args(
                [
                    "--output",
                    str(output),
                    "--count",
                    "1000",
                    "--wall-seconds",
                    "60",
                    "--drain-seconds",
                    "10",
                    "--completion-timeout",
                    "1",
                    "--run-id",
                    "305419896",
                    "--image",
                    str(image),
                ]
            )
            with mock.patch.object(
                benchmark, "BoardSession", FakeSession
            ), mock.patch.object(
                benchmark, "_fresh_config_snapshots", fresh_snapshots
            ), mock.patch.object(
                benchmark.time, "monotonic", clock.monotonic
            ), mock.patch.object(
                benchmark.time, "time", clock.time
            ), mock.patch.object(
                benchmark.time, "sleep", clock.sleep
            ):
                result = benchmark.run_hardware(args)

            self.assertEqual(result["status"], "measurement_invalid")
            self.assertIn(
                "no_first_authenticated_frame_in_finite_window",
                result["report"]["failure_reasons"],
            )
            completion = result["receiver_completion_poll"]
            self.assertTrue(completion["timed_out"])
            self.assertTrue(completion["stop_sent"])
            self.assertTrue(completion["final_snapshot"])
            self.assertTrue(result["configuration_preserved"])
            self.assertTrue(all(session.closed for session in FakeSession.instances))
            receiver_events = json.loads(
                (output / "walker" / "capture-events.json").read_text()
            )
            self.assertTrue(
                any(
                    event["kind"] == "control_attempt"
                    and event["operation"] == benchmark.CONTROL_STOP
                    for event in receiver_events
                )
            )
            saved = json.loads((output / "results.json").read_text())
            self.assertEqual(saved["status"], "measurement_invalid")
            self.assertIn("firmware_reports", saved)

    def test_run_hardware_rejects_peer_key_before_any_start_control(self):
        class FakeSession:
            def __init__(self, role, output, _command_gap, checkpoint=None):
                self.role = role
                self.output = output
                self.node_num = benchmark.BOARD_IDENTITIES[role][1]
                self.capture = benchmark._EventCapture(role, output, checkpoint)
                peer_role = "walker" if role == "base" else "base"
                peer_key = FAKE_PUBLIC_KEYS[peer_role]
                if role == "base":
                    peer_key = b"wrong" * 6 + b"xx"
                self.interface = SimpleNamespace(
                    nodesByNum={
                        benchmark.BOARD_IDENTITIES[peer_role][1]: {
                            "user": {"publicKey": peer_key}
                        }
                    },
                    localNode=SimpleNamespace(
                        localConfig=SimpleNamespace(
                            security=SimpleNamespace(public_key=FAKE_PUBLIC_KEYS[role])
                        )
                    ),
                )

            def snapshot_config(self, _output, _label):
                return {
                    "role": self.role,
                    "usb_identity": benchmark.BOARD_IDENTITIES[self.role][0],
                    "port": f"preflight-{self.role}",
                    "node_num": self.node_num,
                    "local_config_sha256": f"local-{self.role}",
                    "module_config_sha256": f"module-{self.role}",
                    "channels_sha256": f"channels-{self.role}",
                    "local_config_bytes": 1,
                    "module_config_bytes": 1,
                    "channel_count": 1,
                    "region": 1,
                    "lora_sha256": f"lora-{self.role}",
                    "private_key_sha256": f"private-{self.role}",
                    "public_key_sha256": f"public-{self.role}",
                }

            def control(self, *_args, **_kwargs):
                self.capture.record("control_attempt")
                raise AssertionError("control sent before peer key verification")

            def close(self, _timeout=5.0):
                self.capture.persist()
                return True

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "preflight-run"
            image = Path(directory) / "firmware.bin"
            image.write_bytes(b"preflight image")
            args = benchmark.build_parser().parse_args(
                [
                    "--output",
                    str(output),
                    "--run-id",
                    "305419896",
                    "--image",
                    str(image),
                ]
            )
            with mock.patch.object(benchmark, "BoardSession", FakeSession):
                with self.assertRaisesRegex(
                    benchmark.BenchmarkError, "peer_public_key_mismatch"
                ):
                    benchmark.run_hardware(args)

            for role in ("base", "walker"):
                events = json.loads((output / role / "capture-events.json").read_text())
                self.assertFalse(
                    any(event["kind"] == "control_attempt" for event in events)
                )


if __name__ == "__main__":
    unittest.main()
