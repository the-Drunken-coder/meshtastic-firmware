#!/usr/bin/env python3
"""Focused analysis tests for malformed and mismatched measurement records."""

import contextlib
import io
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import measure  # noqa: E402


class FakeRunnerSession:
    """Small line-protocol peer that enforces the firmware's RX/CRC guard."""

    def __init__(
        self,
        role: str,
        *,
        fail_run: bool = False,
        run_exception: BaseException | None = None,
        fail_crc4_calls: set[int] | None = None,
        fail_stop_calls: set[int] | None = None,
    ) -> None:
        self.role = role
        self.identity = {"role": role}
        self.events: list[measure.SerialEvent] = []
        self.queue: list[measure.SerialEvent] = []
        self.calls: list[tuple[str, int | bool]] = []
        self.receiving = False
        self.crc = 4
        self.fail_run = fail_run
        self.run_exception = run_exception
        self.fail_crc4_calls = fail_crc4_calls or set()
        self.fail_stop_calls = fail_stop_calls or set()
        self.stop_calls = 0
        self.crc4_calls = 0

    def _event(self, record: dict[str, object], *, queued: bool = False) -> measure.SerialEvent:
        event = measure.SerialEvent(
            self.role,
            time.monotonic(),
            "2026-01-01T00:00:00Z",
            record,
        )
        self.events.append(event)
        if queued:
            self.queue.append(event)
        return event

    def stop(self, timeout: float = 10) -> measure.SerialEvent:
        del timeout
        self.stop_calls += 1
        self.calls.append(("stop", self.receiving))
        if self.stop_calls in self.fail_stop_calls:
            raise RuntimeError(f"{self.role} STOP failed")
        self.receiving = False
        return self._event({"event": "stopped", "status": 0, "quiescent": True})

    def set_crc(self, byte_count: int, timeout: float = 10) -> dict[str, object]:
        del timeout
        self.calls.append(("crc", byte_count))
        if byte_count == 4:
            self.crc4_calls += 1
        if self.receiving:
            raise RuntimeError(f"{self.role} CRC changed while RX active")
        if byte_count == 4 and self.crc4_calls in self.fail_crc4_calls:
            raise RuntimeError(f"{self.role} CRC4 restore failed")
        self.crc = byte_count
        return {"event": "crc", "status": 0, "bytes": byte_count}

    def stats(self, timeout: float = 10) -> dict[str, object]:
        del timeout
        return {"event": "stats", "status": 0}

    def receive(self) -> dict[str, object]:
        self.receiving = True
        return {"event": "rx_ready", "status": 0}

    def command(self, text: str, event_name: str, timeout: float = 10) -> measure.SerialEvent:
        del timeout
        if text == "INFO":
            return self._event(
                {
                    "event": "info",
                    "build": measure.EXPECTED_BUILD,
                    "run": 7,
                    "ready": True,
                    "board_id": measure.IDENTITIES[self.role],
                }
            )
        if text.startswith("RUN "):
            if self.run_exception is not None:
                raise self.run_exception
            if self.fail_run:
                raise RuntimeError("RUN failed")
            count = int(text.split()[2])
            for sequence in range(count):
                self._event(
                    {
                        "event": "attempt",
                        "run": 7,
                        "seq": sequence,
                        "length": int(text.split()[1]),
                    }
                )
            self._event(
                {
                    "event": "run_end",
                    "run": 7,
                    "attempts": count,
                    "requested_count": count,
                    "complete": True,
                    "stopped": False,
                },
                queued=True,
            )
            return self._event({"event": event_name, "run": 7})
        return self._event({"event": event_name, "status": 0})

    def _take_event(self, event_name: str, predicate=None) -> measure.SerialEvent | None:
        for index, event in enumerate(self.queue):
            if event.record.get("event") == event_name and (
                predicate is None or predicate(event.record)
            ):
                return self.queue.pop(index)
        return None

    def poll(self) -> None:
        return


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


class RunnerCleanupTests(unittest.TestCase):
    def make_runner(
        self,
        directory: Path,
        *,
        base: FakeRunnerSession | None = None,
        walker: FakeRunnerSession | None = None,
    ) -> measure.Runner:
        runner = measure.Runner(
            directory,
            duration_seconds=60,
            count=1,
            gap_ms=0,
            lengths=(12,),
            delays_us=(0,),
        )
        runner.sessions = {
            "base": base or FakeRunnerSession("base"),
            "walker": walker or FakeRunnerSession("walker"),
        }
        runner.state["boards"] = {
            role: {"info": {"run": 7}}
            for role in ("base", "walker")
        }
        return runner

    def test_crc_restore_stops_rx_before_each_crc_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runner = self.make_runner(Path(temporary))
            runner.run_crc_negative_control(time.monotonic() + 10, 0)
            for session in runner.sessions.values():
                self.assertEqual(session.crc, 4)
                self.assertFalse(session.receiving)
                crc_index = max(
                    index
                    for index, call in enumerate(session.calls)
                    if call == ("crc", 4)
                )
                stop_index = max(
                    index
                    for index, call in enumerate(session.calls[:crc_index])
                    if call[0] == "stop"
                )
                self.assertLess(stop_index, crc_index)
            self.assertTrue(runner.phases[0]["crc_restored"])
            self.assertEqual(runner.phases[0]["cleanup_errors"], [])

    def test_run_failure_while_receiver_rx_preserves_original_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receiver = FakeRunnerSession("walker")
            runner = self.make_runner(
                Path(temporary),
                base=FakeRunnerSession("base", fail_run=True),
                walker=receiver,
            )
            with self.assertRaisesRegex(RuntimeError, "RUN failed"):
                runner.run_crc_negative_control(time.monotonic() + 10, 0)
            self.assertFalse(receiver.receiving)
            self.assertEqual(runner.sessions["base"].crc, 4)
            self.assertEqual(receiver.crc, 4)
            self.assertEqual(runner.phases[0]["state"], "failed")
            self.assertIn("RUN failed", runner.phases[0]["error"])

    def test_keyboard_interrupt_still_cleans_up_receiver(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receiver = FakeRunnerSession("walker")
            runner = self.make_runner(
                Path(temporary),
                base=FakeRunnerSession("base", run_exception=KeyboardInterrupt()),
                walker=receiver,
            )
            with self.assertRaises(KeyboardInterrupt):
                runner.run_crc_negative_control(time.monotonic() + 10, 0)
            self.assertFalse(receiver.receiving)
            self.assertEqual(runner.sessions["base"].crc, 4)
            self.assertEqual(receiver.crc, 4)
            self.assertEqual(runner.phases[0]["state"], "failed")

    def test_failed_receiver_stop_does_not_block_sender_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receiver = FakeRunnerSession("walker", fail_stop_calls={2, 3})
            runner = self.make_runner(Path(temporary), walker=receiver)
            with self.assertRaisesRegex(RuntimeError, "STOP failed"):
                runner.run_crc_negative_control(time.monotonic() + 10, 0)
            sender = runner.sessions["base"]
            self.assertEqual(sender.crc, 4)
            self.assertEqual(receiver.crc, 4)
            self.assertEqual(runner.phases[0]["cleanup"]["crc_restore"]["base"], "restored")
            self.assertEqual(
                runner.phases[0]["cleanup"]["crc_restore"]["walker"],
                "skipped_stop_failed",
            )
            self.assertFalse(runner.phases[0]["crc_restored"])
            self.assertTrue(runner.state["cleanup_errors"])

    def test_cleanup_crc_failure_without_run_failure_is_phase_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receiver = FakeRunnerSession("walker", fail_crc4_calls={2})
            runner = self.make_runner(Path(temporary), walker=receiver)
            with self.assertRaisesRegex(RuntimeError, "cleanup failed"):
                runner.run_crc_negative_control(time.monotonic() + 10, 0)
            phase = runner.phases[0]
            self.assertEqual(phase["state"], "failed")
            self.assertFalse(phase["crc_restored"])
            self.assertFalse(phase["run_completion"]["complete"])
            self.assertTrue(phase["cleanup_errors"])

    def test_initial_crc_failure_remains_original_when_restore_also_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            receiver = FakeRunnerSession("walker", fail_crc4_calls={1, 2})
            runner = self.make_runner(Path(temporary), walker=receiver)
            with self.assertRaisesRegex(RuntimeError, "CRC4 restore failed"):
                runner.run_crc_negative_control(time.monotonic() + 10, 0)
            phase = runner.phases[0]
            self.assertEqual(phase["state"], "failed")
            self.assertEqual(phase["error"], "RuntimeError: walker CRC4 restore failed")
            self.assertIn("CRC4 restore failed", phase["cleanup_errors"][0])


if __name__ == "__main__":
    unittest.main()
