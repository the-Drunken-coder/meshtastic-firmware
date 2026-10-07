"""Pure protocol and lifecycle checks for the W12 RX-liveness probe."""

from __future__ import annotations

import contextlib
import dataclasses
import importlib.util
import io
import json
import struct
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


def kind3_report(run=None, **changes):
    run = config() if run is None else run
    values = {
        "run_id": run.run_id,
        "source": run.source,
        "destination": run.destination,
        "count": run.count,
        "size": run.size,
        "duration_ms": run.duration_ms,
        "window": run.window,
        "flags": run.flags,
        "prepared": True,
        "running": True,
        "complete": False,
        "elapsed_ms": 100,
        "received": 10,
        "duplicates": 1,
        "corrupt": 0,
        "out_of_range": 0,
        "enqueued": 100,
        "send_failures": 0,
        "tx_started": 100,
        "tx_succeeded": 99,
        "tx_failures": 0,
        "tx_dropped": 0,
        "tx_cancelled": 0,
    }
    values.update(changes)
    return values


def pre_send_payload(run=None, **changes):
    run = config() if run is None else run
    values = {
        "status": 0x23,
        "pending_tx_count": 0,
        "busy_tx_deferrals": 2,
        "busy_rx_active_deferrals": 3,
        "busy_rx_irq_read_failure_deferrals": 4,
        "tx_timer_accepted": 10,
        "tx_timer_dispatches": 9,
        "tx_timer_late_count": 2,
        "tx_timer_late_sum_ms": 12,
        "tx_timer_late_max_ms": 7,
        "tx_timer_overwritten": 1,
        "tx_timer_stale": 1,
        "tx_timer_cancelled": 1,
        "tx_timer_irq_displaced": 1,
        "tx_timer_active": 0,
        "rx_sample_valid": 1,
        "rx_sample_status": 31,
        "rx_dio_level": 1,
        "rx_busy_level": 0,
        "rx_active_receive_start_ms": 100,
        "rx_sampled_at_ms": 200,
        "rx_raw_irq_flags": 0x20,
        "rx_raw_status": 0x524,
        "rx_fifo_level": 4,
        "rx_fifo_flags": 1,
        "tx_fifo_flags": 2,
        "rx_chip_errors": 0,
        "rx_irq_read_result": 0,
        "rx_fifo_flags_result": 0,
        "rx_fifo_level_result": 0,
        "rx_errors_result": 0,
        "rx_software_state": 0x01,
        "tx_timer_due_at_ms": 0,
        "elapsed_ms": 20000,
    }
    values.update(changes)
    payload = bytearray(probe.pre_send.REPORT_BYTES)
    struct.pack_into(
        "<HBBIIII",
        payload,
        0,
        probe.pre_send.MAGIC,
        probe.pre_send.VERSION,
        probe.pre_send.KIND,
        run.run_id,
        run.source,
        run.destination,
        values["elapsed_ms"],
    )
    payload[20] = values["status"]
    payload[21] = values["pending_tx_count"]
    for offset, name in (
        (24, "busy_tx_deferrals"),
        (28, "busy_rx_active_deferrals"),
        (32, "busy_rx_irq_read_failure_deferrals"),
        (36, "tx_timer_accepted"),
        (40, "tx_timer_dispatches"),
        (44, "tx_timer_late_count"),
        (48, "tx_timer_late_sum_ms"),
        (52, "tx_timer_late_max_ms"),
        (56, "tx_timer_overwritten"),
        (60, "tx_timer_stale"),
        (64, "tx_timer_cancelled"),
        (68, "tx_timer_irq_displaced"),
        (78, "rx_active_receive_start_ms"),
        (82, "rx_sampled_at_ms"),
        (86, "rx_raw_irq_flags"),
        (106, "rx_software_state"),
        (110, "tx_timer_due_at_ms"),
    ):
        struct.pack_into("<I", payload, offset, values[name])
    payload[72] = values["tx_timer_active"]
    payload[73] = values["rx_sample_valid"]
    payload[74] = values["rx_sample_status"]
    payload[75] = values["rx_dio_level"]
    payload[76] = values["rx_busy_level"]
    struct.pack_into("<H", payload, 90, values["rx_raw_status"])
    struct.pack_into("<H", payload, 92, values["rx_fifo_level"])
    payload[94] = values["rx_fifo_flags"]
    payload[95] = values["tx_fifo_flags"]
    struct.pack_into("<H", payload, 96, values["rx_chip_errors"])
    for offset, name in (
        (98, "rx_irq_read_result"),
        (100, "rx_fifo_flags_result"),
        (102, "rx_fifo_level_result"),
        (104, "rx_errors_result"),
    ):
        struct.pack_into("<h", payload, offset, values[name])
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

    def test_rearm_kind3_receipt_progress_accepts_exact_authenticated_unique_delta(self):
        run = config()
        before = kind3_report(run, elapsed_ms=200, received=10)
        after = kind3_report(run, elapsed_ms=1200, received=13)
        result = probe.authenticated_unique_progress(before, after, run)
        self.assertEqual(result["authenticated_unique_count_before"], 10)
        self.assertEqual(result["authenticated_unique_count_after"], 13)
        self.assertEqual(result["authenticated_unique_count_delta"], 3)
        self.assertIn(
            "not packet-level TX/RX matching or PER", result["interpretation"]
        )

    def test_rearm_kind3_receipt_progress_fails_wrong_config_incomplete_or_decrease(self):
        run = config()
        with self.assertRaisesRegex(probe.LivenessError, "identity_mismatch"):
            probe.authenticated_unique_progress(
                kind3_report(run), kind3_report(config(run_id=run.run_id + 1)), run
            )
        with self.assertRaisesRegex(probe.LivenessError, "incomplete"):
            probe.authenticated_unique_progress(
                kind3_report(run, prepared=False), kind3_report(run), run
            )
        with self.assertRaisesRegex(probe.LivenessError, "received decreased"):
            probe.authenticated_unique_progress(
                kind3_report(run, received=10), kind3_report(run, received=9), run
            )
        with self.assertRaisesRegex(probe.LivenessError, "elapsed time decreased"):
            probe.authenticated_unique_progress(
                kind3_report(run, elapsed_ms=1200),
                kind3_report(run, elapsed_ms=1000),
                run,
            )

    def test_rearm_kind3_rejects_boundary_terminal_and_invalid_uint32_counters(self):
        run = config()
        with self.assertRaisesRegex(probe.LivenessError, "time_invalid"):
            probe.validate_rearm_kind3_report(
                kind3_report(run, elapsed_ms=run.duration_ms), run, "boundary"
            )
        with self.assertRaisesRegex(probe.LivenessError, "incomplete"):
            probe.validate_rearm_kind3_report(
                kind3_report(
                    run,
                    running=False,
                    complete=True,
                    elapsed_ms=run.duration_ms + 1,
                ),
                run,
                "terminal",
            )
        with self.assertRaisesRegex(probe.LivenessError, "counter_invalid"):
            probe.validate_rearm_kind3_report(
                kind3_report(run, received=run.count + 1), run, "received"
            )
        for field, invalid in (
            ("duplicates", -1),
            ("corrupt", True),
            ("tx_succeeded", probe.UINT32_MAX + 1),
        ):
            with self.subTest(field=field, invalid=invalid), self.assertRaisesRegex(
                probe.LivenessError, "counter_invalid"
            ):
                probe.validate_rearm_kind3_report(
                    kind3_report(run, **{field: invalid}), run, field
                )

    def test_source_progress_across_rearm_records_exact_interval_and_tail(self):
        run = config()
        before = kind3_report(run, elapsed_ms=100, tx_started=10, tx_succeeded=9)
        after = kind3_report(run, elapsed_ms=1200, tx_started=12, tx_succeeded=11)
        result = probe.evaluate_source_progress_across_rearm(
            before,
            after,
            run,
            start_host_monotonic=20.0,
            end_host_monotonic=21.5,
        )
        self.assertTrue(result["eligible"])
        self.assertEqual(result["interval_start_sample"], "after_tx_progress_check")
        self.assertEqual(result["interval_end_sample"], "after_rearm")
        self.assertEqual(result["interval_start_elapsed_ms"], 100)
        self.assertEqual(result["interval_end_elapsed_ms"], 1200)
        self.assertTrue(result["receiver_pre_op8_tail_included"])
        self.assertIn("pre-op8", result["interval_note"])

    def test_source_progress_across_rearm_requires_elapsed_and_host_progress(self):
        run = config()
        before = kind3_report(run, elapsed_ms=100, tx_started=10, tx_succeeded=9)
        same_elapsed = kind3_report(
            run, elapsed_ms=100, tx_started=12, tx_succeeded=11
        )
        with self.assertRaisesRegex(probe.LivenessError, "elapsed time did not advance"):
            probe.evaluate_source_progress_across_rearm(
                before,
                same_elapsed,
                run,
                start_host_monotonic=20.0,
                end_host_monotonic=21.5,
            )
        with self.assertRaisesRegex(probe.LivenessError, "host time did not advance"):
            probe.evaluate_source_progress_across_rearm(
                before,
                kind3_report(run, elapsed_ms=200, tx_started=12, tx_succeeded=11),
                run,
                start_host_monotonic=20.0,
                end_host_monotonic=20.0,
            )

    def test_rearm_evidence_margin_skips_near_end_window(self):
        sufficient = probe.rearm_evidence_margin(58000, 60000)
        self.assertTrue(sufficient["eligible"])
        self.assertEqual(sufficient["remaining_ms"], 2000)
        near_end = probe.rearm_evidence_margin(58001, 60000)
        self.assertFalse(near_end["eligible"])
        self.assertEqual(near_end["remaining_ms"], 1999)
        self.assertEqual(near_end["reason"], "rearm_evidence_window_margin")

    def test_pre_op8_host_delay_can_cross_margin_without_marking_rearm_attempted(self):
        fresh = probe.rearm_evidence_margin_with_host_elapsed(
            58000, 60000, 10.0, 10.0
        )
        self.assertTrue(fresh["eligible"])
        delayed = probe.rearm_evidence_margin_with_host_elapsed(
            58000, 60000, 10.0, 10.001
        )
        self.assertFalse(delayed["eligible"])
        self.assertEqual(delayed["reason"], "rearm_evidence_window_margin")
        self.assertEqual(delayed["host_elapsed_ms"], 1)
        self.assertEqual(delayed["conservative_elapsed_ms"], 58001)
        self.assertTrue(delayed["host_elapsed_upper_bound"])
        decision = probe.rearm_candidate(20.0, 20.0, 10.0, False, 20.0, 3.0)
        self.assertTrue(decision["eligible"])

    def test_rearm_decision_copies_guard_and_window_at_decision_time(self):
        guard = {"valid_counter_samples": 2}
        host_guard = {"queued_packets": 0, "ack_markers": 3}
        window = {"status": "running", "elapsed_ms": 1200}
        progress = {"tx_succeeded_delta": 2}
        decision = probe.freeze_rearm_decision(
            guard, host_guard, window, progress, [{"tx_succeeded": 5}], 12.0
        )
        guard["valid_counter_samples"] = 99
        host_guard["queued_packets"] = 12
        window["status"] = "complete"
        self.assertEqual(decision["receiver_counter_guard"]["valid_counter_samples"], 2)
        self.assertEqual(decision["host_guard"]["queued_packets"], 0)
        self.assertEqual(decision["receiver_window"]["status"], "running")


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

    def test_pre_send_response_requires_matching_request_identity_and_timestamp(self):
        run = config()
        valid_event = {
            "kind": "pre_send_packet",
            "request_id": 9,
            "monotonic": 1.0,
            "to": run.destination,
            "from_node": run.destination,
            "raw_payload_hex": pre_send_payload(run).hex(),
        }
        report = self._session(valid_event)._wait_pre_send_response(
            9, run, 0.0, 0.1
        )
        self.assertEqual(report.run_id, run.run_id)

        foreign = dict(valid_event, to=run.source)
        with self.assertRaisesRegex(probe.LivenessError, "local from/to"):
            self._session(foreign)._wait_pre_send_response(9, run, 0.0, 0.1)

        wrong_config = dict(
            valid_event,
            raw_payload_hex=pre_send_payload(config(run_id=run.run_id + 1)).hex(),
        )
        with self.assertRaisesRegex(probe.LivenessError, "run/source/destination"):
            self._session(wrong_config)._wait_pre_send_response(9, run, 0.0, 0.1)

        stale = dict(valid_event, monotonic=-1.0)
        with self.assertRaisesRegex(probe.LivenessError, "response_timeout"):
            self._session(stale)._wait_pre_send_response(9, run, 0.0, 0.001)

        late_request = dict(valid_event, request_id=8)
        with self.assertRaisesRegex(probe.LivenessError, "response_timeout"):
            self._session(late_request)._wait_pre_send_response(9, run, 0.0, 0.001)

        malformed = dict(valid_event, raw_payload_hex=pre_send_payload(run)[:-1].hex())
        malformed_session = self._session(malformed)
        with self.assertRaisesRegex(probe.LivenessError, "parser_error"):
            malformed_session._wait_pre_send_response(9, run, 0.0, 0.1)
        self.assertEqual(malformed_session.health.snapshot()["reason"], "parser_error")

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

    def test_pre_send_control_is_exact_local_self_no_ack_no_pki(self):
        mesh_pb2, portnums_pb2 = probe._load_meshtastic_types()

        class Capture:
            def record(self, _kind, **_values):
                return None

        class FakeInterface:
            def __init__(self):
                self._command_lock = threading.Lock()
                self.noProto = False
                self.last_command = 0.0
                self.sent = []

            def _generatePacketId(self):
                return 456

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

        request_id, _ = probe.send_pre_send_control(session, config())
        packet = session.interface.sent[0].packet
        self.assertEqual(request_id, 456)
        self.assertEqual(packet.to, session.node_num)
        self.assertEqual(getattr(packet, "from"), 0)
        self.assertFalse(packet.want_ack)
        self.assertFalse(packet.pki_encrypted)
        self.assertEqual(packet.decoded.portnum, int(portnums_pb2.PRIVATE_APP))
        self.assertEqual(packet.decoded.payload[3], probe.CONTROL_SNAPSHOT_PRE_SEND)
        self.assertEqual(bytes(packet.decoded.payload), probe.encode_pre_send_control(config()))
        self.assertEqual(len(session.interface.sent), 1)

    def test_source_pre_send_is_opt_in_and_requested_failure_propagates(self):
        run = config()

        class FakeSession:
            def __init__(self, fail=False):
                self.fail = fail
                self.calls = 0

            def check_health(self):
                return None

            def request_pre_send(self, _config, _timeout):
                self.calls += 1
                if self.fail:
                    raise probe.LivenessError("response_timeout: kind-7 response did not arrive")
                return probe.pre_send.decode_report(pre_send_payload(run)), 2.0, 7

        default_session = FakeSession()
        default_state = probe.optional_source_pre_send(
            default_session, run, 0.1, "base", False
        )
        self.assertEqual(default_session.calls, 0)
        self.assertFalse(default_state["requested"])
        self.assertFalse(default_state["support_expected"])
        self.assertEqual(default_state["status"], "not_requested")

        captured_session = FakeSession()
        captured_state = probe.optional_source_pre_send(
            captured_session, run, 0.1, "base", True
        )
        self.assertEqual(captured_session.calls, 1)
        self.assertTrue(captured_state["requested"])
        self.assertTrue(captured_state["support_expected"])
        self.assertEqual(captured_state["status"], "captured")
        self.assertEqual(captured_state["record"]["report_kind"], probe.PRE_SEND_KIND)

        requested_session = FakeSession(fail=True)
        failed_state = {
            "requested": True,
            "support_expected": True,
            "status": "pending",
        }
        with self.assertRaisesRegex(probe.LivenessError, "response_timeout"):
            probe.optional_source_pre_send(
                requested_session, run, 0.1, "base", True, failed_state
            )
        self.assertEqual(requested_session.calls, 1)
        self.assertEqual(failed_state["status"], "failed")
        self.assertIn("response_timeout", failed_state["error"])

    def test_receiver_baseline_orders_decoded_op9_before_sender_start(self):
        run = config()
        payload = pre_send_payload(run, elapsed_ms=0)
        events = []

        class Receiver:
            _last_pre_send_raw_payload_hex = payload.hex()

            def base_control(self, operation, _config):
                events.append(f"receiver_{operation}")

            def request_pre_send(self, _config, _timeout):
                events.append("receiver_op9")
                return probe.pre_send.decode_report(payload), 1.0, 8

        class Sender:
            def base_control(self, operation, _config):
                events.append(f"sender_{operation}")

        receiver = Receiver()
        receiver.base_control(probe.CONTROL_RESET, run)
        receiver.base_control(probe.CONTROL_START, run)
        baseline = probe.capture_receiver_pre_send_baseline(
            receiver, run, 0.1, "walker"
        )
        Sender().base_control(probe.CONTROL_START, run)

        self.assertEqual(events, ["receiver_1", "receiver_2", "receiver_op9", "sender_2"])
        self.assertEqual(baseline["report"]["elapsed_ms"], 0)
        self.assertEqual(baseline["config"], dataclasses.asdict(run))
        self.assertEqual(baseline["raw_payload_hex"], payload.hex())
        self.assertEqual(baseline["stage"], "receiver_started_before_sender_started")

    def test_receiver_baseline_failure_prevents_sender_start(self):
        run = config()
        events = []

        class Receiver:
            def request_pre_send(self, _config, _timeout):
                events.append("receiver_op9")
                raise probe.LivenessError("response_timeout: kind-7 response did not arrive")

        with self.assertRaisesRegex(probe.LivenessError, "response_timeout"):
            probe.capture_receiver_pre_send_baseline(Receiver(), run, 0.1, "walker")
        self.assertEqual(events, ["receiver_op9"])

    def test_baseline_failure_cleanup_stops_receiver_that_already_started(self):
        run = config()
        events = []

        class Receiver:
            def base_control(self, operation, _config):
                events.append(("walker", operation))

            def request_pre_send(self, _config, _timeout):
                raise probe.LivenessError("response_timeout: kind-7 response did not arrive")

        receiver = Receiver()
        receiver.base_control(probe.CONTROL_RESET, run)
        receiver.base_control(probe.CONTROL_START, run)
        started = {"walker"}
        with self.assertRaises(probe.LivenessError):
            probe.capture_receiver_pre_send_baseline(receiver, run, 0.1, "walker")
        stop_result = probe.stop_started_roles({"walker": receiver}, started, run)
        self.assertEqual(stop_result["failed_roles"], [])
        self.assertEqual(
            events,
            [
                ("walker", probe.CONTROL_RESET),
                ("walker", probe.CONTROL_START),
                ("walker", probe.CONTROL_STOP),
            ],
        )

    def test_sender_start_failure_cleanup_does_not_stop_unstarted_sender(self):
        run = config()
        events = []

        class Session:
            def __init__(self, role):
                self.role = role

            def base_control(self, operation, _config):
                events.append((self.role, operation))
                if self.role == "base" and operation == probe.CONTROL_START:
                    raise probe.LivenessError("control_write_error: sender start failed")

        receiver = Session("walker")
        sender = Session("base")
        started = set()
        receiver.base_control(probe.CONTROL_RESET, run)
        receiver.base_control(probe.CONTROL_START, run)
        started.add("walker")
        sender.base_control(probe.CONTROL_RESET, run)
        with self.assertRaisesRegex(probe.LivenessError, "sender start failed"):
            sender.base_control(probe.CONTROL_START, run)
        stop_result = probe.stop_started_roles(
            {"walker": receiver, "base": sender}, started, run
        )
        self.assertEqual(stop_result["failed_roles"], [])
        self.assertEqual(
            events,
            [
                ("walker", probe.CONTROL_RESET),
                ("walker", probe.CONTROL_START),
                ("base", probe.CONTROL_RESET),
                ("base", probe.CONTROL_START),
                ("walker", probe.CONTROL_STOP),
            ],
        )


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

    def test_kind7_wrapper_records_raw_report_and_parser_errors_are_sticky(self):
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
        packet.id = 43
        packet.to = session.node_num
        setattr(packet, "from", session.node_num)
        packet.decoded.portnum = int(portnums_pb2.PRIVATE_APP)
        packet.decoded.request_id = 124
        packet.decoded.payload = pre_send_payload()

        probe.LivenessSession._handle_from_radio(session, incoming.SerializeToString())
        event = next(item for item in session.capture.events if item["kind"] == "pre_send_packet")
        self.assertEqual(event["request_id"], 124)
        self.assertEqual(bytes.fromhex(event["raw_payload_hex"]), pre_send_payload())
        self.assertEqual(event["report"]["run_id"], config().run_id)
        decoded = probe.pre_send.decode_report(pre_send_payload())
        serialized = probe.pre_send_record(decoded, "walker", 124, 1.0)
        self.assertEqual(serialized["report"], probe.pre_send_report_dict(decoded))
        self.assertNotIn("raw_payload_hex", serialized)
        self.assertEqual(event["raw_payload_hex"], pre_send_payload().hex())

        malformed = mesh_pb2.FromRadio()
        malformed.packet.to = session.node_num
        setattr(malformed.packet, "from", session.node_num)
        malformed.packet.decoded.portnum = int(portnums_pb2.PRIVATE_APP)
        malformed.packet.decoded.payload = pre_send_payload()[:-1]
        with self.assertRaises(probe.LivenessError):
            probe.LivenessSession._handle_from_radio(
                session, malformed.SerializeToString()
            )
        self.assertEqual(session.health.snapshot()["reason"], "parser_error")

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
        self.assertFalse(args.source_pre_send)
        self.assertTrue(probe.build_parser().parse_args(["--source-pre-send"]).source_pre_send)
        for value in (0, 4, 12, 32):
            with self.subTest(value=value), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    probe.build_parser().parse_args(["--window", str(value)])


if __name__ == "__main__":
    unittest.main()
