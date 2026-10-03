#!/usr/bin/env python3
"""Focused analysis tests for malformed and mismatched measurement records."""

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import measure  # noqa: E402


class MeasureAnalysisTests(unittest.TestCase):
    def write_fixture(self, directory: Path) -> None:
        phase = {
            "phase_id": 0,
            "state": "complete",
            "sender": "base",
            "receiver": "walker",
            "length": 12,
            "delay_us": 100,
            "count": 3,
            "started_monotonic": 10.0,
            "ended_monotonic": 20.0,
            "sender_run": 7,
        }
        (directory / "phases.jsonl").write_text(json.dumps(phase) + "\n")
        base = [
            {"event": "info", "build": measure.EXPECTED_BUILD, "run": 7, "ready": True},
            {
                "event": "attempt",
                "run": 7,
                "seq": 1,
                "length": 12,
                "tx_status": 0,
                "tx_done": True,
                "start_call_us": 100,
                "tx_done_us": 120,
                "finish_tx_us": 130,
                "stage_tx_us": 5,
                "launch_call_us": 6,
                "launch_to_tx_done_us": 110,
                "rx_ready_after_tx_done_us": 9,
                "rx_arm_us": 140,
                "rx_arm_status": 0,
                "rx_arm_attempted": True,
                "rtt_us": 200,
                "driver_toa_us": 90,
                "echo": True,
            },
            {
                "event": "attempt",
                "run": 7,
                "seq": 2,
                "length": 12,
                "tx_status": 0,
                "tx_done": True,
                "echo": False,
            },
            {
                "event": "attempt",
                "run": 7,
                "seq": 3,
                "length": 12,
                "tx_status": -7,
                "tx_done": False,
                "echo": False,
            },
            {"event": "run_end", "run": 7, "attempts": 3},
        ]
        walker = [
            {
                "event": "info",
                "build": measure.EXPECTED_BUILD,
                "run": 4,
                "ready": True,
            },
            {
                "event": "rx",
                "peer_run": 7,
                "seq": 1,
                "length": 12,
                "status": 0,
                "payload_valid": True,
                "echo_status": 0,
                "read_us": 7,
                "echo_start_us": 8,
                "echo_done_us": 90,
                "rx_rearm_us": 10,
            },
            # A reboot/run change must not join the current phase by seq alone.
            {
                "event": "rx",
                "peer_run": 8,
                "seq": 2,
                "length": 12,
                "status": 0,
                "payload_valid": True,
                "echo_status": 0,
            },
        ]
        for role, records in (("base", base), ("walker", walker)):
            with (directory / f"{role}-serial.jsonl").open("w") as output:
                for index, record in enumerate(records):
                    output.write(
                        json.dumps(
                            {
                                "direction": "rx",
                                "monotonic": 11.0 + index,
                                "role": role,
                                "utc": "2026-01-01T00:00:00Z",
                                "record": record,
                            }
                        )
                        + "\n"
                    )

    def test_summary_matches_run_sequence_and_reports_success_only_timing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.write_fixture(directory)
            summary = measure.summarize(directory)
            phase = summary["phases"][0]
            self.assertEqual(phase["attempts"], 3)
            self.assertEqual(phase["matched_successes"], 1)
            self.assertEqual(phase["unmatched_attempts"], 2)
            self.assertEqual(phase["unmatched_receiver_records"], 1)
            self.assertEqual(
                phase["receiver_local_run_validation"],
                "unvalidated_missing_pre_phase_info",
            )
            self.assertEqual(phase["receiver_local_run_unvalidated_records"], 2)
            self.assertEqual(phase["tx_errors_by_status"], {"-7": 1})
            self.assertEqual(
                phase["no_ack_rates"]["all_local_tx_completed_descriptive"]["no_echo"],
                1,
            )
            self.assertEqual(phase["no_ack_rates"]["rx_arm_observed"]["denominator"], 1)
            metrics = phase["metrics_matched_success_only"]
            self.assertEqual(metrics["software_completion_us"]["p50"], 120.0)
            self.assertEqual(metrics["rx_arm_us"]["p50"], 140.0)
            self.assertEqual(metrics["read_us"]["p50"], 7.0)
            self.assertEqual(
                phase["metrics_local_tx_completed"]["stage_tx_us"]["p50"], 5.0
            )
            self.assertEqual(summary["totals"]["matched_successes"], 1)
            self.assertEqual(
                summary["normal_measurement_totals"]["matched_successes"], 1
            )
            self.assertEqual(summary["crc_negative_control_totals"]["phases"], 0)

    def test_poll_irq_timing_is_excluded_and_reported_separately(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.write_fixture(directory)
            path = directory / "walker-serial.jsonl"
            lines = path.read_text().splitlines()
            first = json.loads(lines[1])
            first["record"]["irq_source"] = "poll"
            lines[1] = json.dumps(first)
            path.write_text("\n".join(lines) + "\n")

            phase = measure.summarize(directory)["phases"][0]
            self.assertEqual(phase["receiver_irq_source_counts"], {"poll": 1})
            self.assertEqual(phase["receiver_irq_poll_excluded_records"], 1)
            self.assertEqual(
                phase["metrics_matched_success_only"]["read_us"]["count"], 0
            )
            self.assertEqual(
                phase["metrics_receiver_irq_poll_excluded"]["read_us"]["p50"],
                7.0,
            )

    def test_receiver_local_run_filters_stale_records(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.write_fixture(directory)
            phase_path = directory / "phases.jsonl"
            phase = json.loads(phase_path.read_text())
            phase["pre_phase_info"] = {"walker": {"run": 4}}
            phase_path.write_text(json.dumps(phase) + "\n")

            path = directory / "walker-serial.jsonl"
            lines = path.read_text().splitlines()
            first = json.loads(lines[1])
            second = json.loads(lines[2])
            first["record"]["run"] = 4
            second["record"]["run"] = 5
            lines[1] = json.dumps(first)
            lines[2] = json.dumps(second)
            path.write_text("\n".join(lines) + "\n")

            phase_summary = measure.summarize(directory)["phases"][0]
            self.assertEqual(phase_summary["receiver_records_raw"], 2)
            self.assertEqual(phase_summary["receiver_records"], 1)
            self.assertEqual(phase_summary["receiver_wrong_local_run_records"], 1)
            self.assertEqual(
                phase_summary["receiver_local_run_validation"], "validated"
            )

    def test_negative_crc_errors_are_kept_when_run_cannot_be_joined(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            phase = {
                "phase_id": 0,
                "state": "complete",
                "kind": "crc_negative_control",
                "sender": "base",
                "receiver": "walker",
                "length": 32,
                "delay_us": 0,
                "count": 2,
                "started_monotonic": 10.0,
                "ended_monotonic": 20.0,
                "sender_run": 9,
            }
            (directory / "phases.jsonl").write_text(json.dumps(phase) + "\n")
            base_records = [
                {
                    "event": "attempt",
                    "run": 9,
                    "seq": 0,
                    "length": 32,
                    "tx_status": 0,
                    "tx_done": True,
                    "rx_status": -6,
                    "rx_arm_status": 0,
                    "rx_arm_attempted": True,
                    "rx_arm_us": 8,
                    "echo": False,
                },
                {
                    "event": "attempt",
                    "run": 9,
                    "seq": 1,
                    "length": 32,
                    "tx_status": 0,
                    "tx_done": True,
                    "rx_arm_status": -7,
                    "rx_arm_attempted": True,
                    "rx_status": -7,
                    "echo": False,
                },
                {"event": "run_end", "run": 9, "attempts": 2},
            ]
            walker_records = [
                {
                    "event": "rx",
                    "peer_run": 0,
                    "seq": 0,
                    "length": 32,
                    "status": -7,
                    "payload_valid": False,
                    "irq": 4,
                    "echo_status": -6,
                    "rearm_status": 0,
                }
            ]
            for role, records in (("base", base_records), ("walker", walker_records)):
                with (directory / f"{role}-serial.jsonl").open("w") as output:
                    for index, record in enumerate(records):
                        output.write(
                            json.dumps(
                                {
                                    "direction": "rx",
                                    "monotonic": 11.0 + index,
                                    "role": role,
                                    "utc": "2026-01-01T00:00:00Z",
                                    "record": record,
                                }
                            )
                            + "\n"
                        )
            summary = measure.summarize(directory)
            phase_summary = summary["phases"][0]
            observations = phase_summary["receiver_error_observations"]
            self.assertEqual(phase_summary["matched_successes"], 0)
            self.assertEqual(phase_summary["unmatched_receiver_records"], 1)
            self.assertEqual(observations["status_by_status"], {"-7": 1})
            self.assertEqual(observations["status_by_irq"], {"4": 1})
            self.assertEqual(observations["status_by_length"], {"32": 1})
            self.assertEqual(observations["unjoined_status_error_records"], 1)
            self.assertEqual(
                phase_summary["local_rx_setup_errors_by_status"], {"-7": 1}
            )
            self.assertEqual(phase_summary["local_rx_setup_unknown"], 0)
            self.assertEqual(
                phase_summary["local_rx_errors_by_status"], {"-6": 1, "-7": 1}
            )
            self.assertEqual(phase_summary["rx_timeout_count"], 1)
            self.assertEqual(
                phase_summary["no_ack_rates"]["all_local_tx_completed_descriptive"][
                    "no_echo"
                ],
                2,
            )
            self.assertEqual(
                phase_summary["no_ack_rates"]["rx_arm_observed"]["denominator"], 1
            )
            self.assertEqual(
                phase_summary["receiver_error_observations"][
                    "echo_status_errors_by_status"
                ],
                {"-6": 1},
            )
            self.assertEqual(summary["normal_measurement_totals"]["phases"], 0)
            self.assertEqual(
                summary["crc_negative_control_totals"]["receiver_error_records"], 1
            )

            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    measure.main(["--output", str(directory), "--analyze-only"]), 0
                )

    def test_seen_run_end_with_truncated_attempts_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            phase = {
                "phase_id": 0,
                "state": "complete",
                "sender": "base",
                "receiver": "walker",
                "length": 16,
                "delay_us": 0,
                "count": 3,
                "started_monotonic": 10.0,
                "ended_monotonic": 20.0,
                "sender_run": 12,
            }
            (directory / "phases.jsonl").write_text(json.dumps(phase) + "\n")
            base_records = [
                {
                    "event": "attempt",
                    "run": 12,
                    "seq": 0,
                    "length": 16,
                    "tx_status": 0,
                    "tx_done": True,
                    "echo": False,
                },
                {
                    "event": "run_end",
                    "run": 12,
                    "attempts": 1,
                    "stopped": True,
                },
            ]
            with (directory / "base-serial.jsonl").open("w") as output:
                for index, record in enumerate(base_records):
                    output.write(
                        json.dumps(
                            {
                                "direction": "rx",
                                "monotonic": 11.0 + index,
                                "role": "base",
                                "utc": "2026-01-01T00:00:00Z",
                                "record": record,
                            }
                        )
                        + "\n"
                    )
            (directory / "walker-serial.jsonl").write_text("")
            summary = measure.summarize(directory)
            phase_summary = summary["phases"][0]
            self.assertFalse(phase_summary["run_complete"])
            self.assertEqual(phase_summary["run_completion"]["observed_attempts"], 1)
            self.assertEqual(phase_summary["run_completion"]["run_end_attempts"], 1)
            self.assertTrue(phase_summary["run_completion"]["stopped"])
            self.assertEqual(summary["normal_measurement_totals"]["complete_phases"], 0)
            self.assertEqual(
                summary["normal_measurement_totals"]["incomplete_phases"], 1
            )

    def test_malformed_serial_record_is_counted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "phases.jsonl").write_text("")
            (directory / "base-serial.jsonl").write_text(
                '{"direction":"rx","role":"base","monotonic":1,"parse_error":"invalid JSON"}\n'
            )
            summary = measure.summarize(directory)
            self.assertEqual(summary["protocol_errors_by_role"], {"base": 1})


if __name__ == "__main__":
    unittest.main()
