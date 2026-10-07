"""Pure adverse checks for the bounded reliable W12 host pilot."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


MODULE_PATH = Path(__file__).with_name("reliable_pilot.py")
SPEC = importlib.util.spec_from_file_location("reliable_pilot", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
pilot = importlib.util.module_from_spec(SPEC)
sys.modules["reliable_pilot"] = pilot
SPEC.loader.exec_module(pilot)


SOURCE = pilot.NODES["base"][1]
DESTINATION = pilot.NODES["walker"][1]
RUN_ID = 0x10203040


def event(**values):
    defaults = {
        "kind": "pilot_raw_packet",
        "role": "base",
        "monotonic": 1.0,
        "packet_id": 0,
        "from_node": 0,
        "to": 0,
        "portnum": pilot.ROUTING_APP,
        "request_id": 0,
        "transport": pilot.TRANSPORT_LORA,
        "via_mqtt": False,
        "want_ack": True,
        "pki_encrypted": True,
        "hop_start": pilot.REQUESTED_HOP_LIMIT,
        "hop_limit": pilot.REQUESTED_HOP_LIMIT,
        "ack_proof_status": 0,
        "routing_error": 0,
        "routing_error_name": "NONE",
    }
    defaults.update(values)
    return defaults


def state_with_frames(count: int) -> pilot.DirectionState:
    direction = pilot.Direction("base", "walker")
    state = pilot.DirectionState(direction, count, 1)
    state.submissions = count
    state.sent_at = 0.0
    state.producer_end = 1.0
    state.drain_end = 2.0
    for sequence in range(count):
        packet_id = 0x1000 + sequence
        payload = pilot.make_payload(RUN_ID, SOURCE, DESTINATION, sequence)
        frame = pilot.PendingFrame(
            SOURCE,
            DESTINATION,
            packet_id,
            sequence,
            pilot.sha256_bytes(payload),
            0.1,
        )
        state.pending[frame.key] = frame
        state.submitted_frames[frame.key] = frame
        state.firmware_accepted.add(frame.key)
    return state


class ReliablePilotTest(unittest.TestCase):
    def test_payload_is_exactly_200_bytes_and_detects_tampering(self):
        payload = pilot.make_payload(RUN_ID, SOURCE, DESTINATION, 7)
        self.assertEqual(len(payload), pilot.PAYLOAD_SIZE)
        self.assertEqual(
            pilot.decode_payload(payload), (RUN_ID, SOURCE, DESTINATION, 7)
        )
        tampered = bytearray(payload)
        tampered[-1] ^= 0x01
        with self.assertRaises(pilot.PilotError):
            pilot.decode_payload(bytes(tampered))

    def test_valid_ack_requires_expected_sender_and_proof(self):
        state = state_with_frames(1)
        data = pilot.make_payload(RUN_ID, SOURCE, DESTINATION, 0)
        events = [
            event(
                role="walker",
                monotonic=1.1,
                packet_id=0x1000,
                from_node=SOURCE,
                to=DESTINATION,
                portnum=pilot.PRIVATE_APP,
                payload_sha256=pilot.sha256_bytes(data),
                pki_encrypted=True,
            ),
            event(
                monotonic=1.2,
                packet_id=0xB001,
                from_node=DESTINATION,
                to=SOURCE,
                request_id=0x1000,
                ack_proof_status=pilot.ACK_PROOF_VALID,
            ),
        ]
        result = pilot.evaluate_direction(state, events, wall_end=1.0, drain_end=2.0)
        self.assertEqual(result["receiver_unique_receipts"], 1)
        self.assertEqual(result["authenticated_ack_valid"], 1)
        self.assertEqual(result["ack_unproven"], 0)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["denominators"]["authenticated_ack_proof"], 1)
        latency = result["authenticated_ack_latency"]
        self.assertEqual(latency["count"], 1)
        self.assertAlmostEqual(latency["min"], 1.1)
        self.assertAlmostEqual(latency["median"], 1.1)
        self.assertAlmostEqual(latency["p95"], 1.1)
        self.assertAlmostEqual(latency["max"], 1.1)
        receipt_latency = result["receiver_receipt_latency"]
        self.assertEqual(receipt_latency["count"], 1)
        self.assertAlmostEqual(receipt_latency["min"], 1.0)
        self.assertAlmostEqual(receipt_latency["median"], 1.0)
        self.assertAlmostEqual(receipt_latency["p95"], 1.0)
        self.assertAlmostEqual(receipt_latency["max"], 1.0)
        self.assertEqual(
            result["host_fed_goodput"]["declared_producer_drain"][
                "confirmed_payload_bytes"
            ],
            pilot.PAYLOAD_SIZE,
        )
        self.assertAlmostEqual(
            result["host_fed_goodput"]["first_submit_to_last_confirmation"][
                "seconds"
            ],
            1.1,
        )

    def test_zero_hop_valid_ack_is_classified_by_proof_without_hop_gate(self):
        state = state_with_frames(1)
        receipt = event(
            role="walker",
            monotonic=1.5,
            packet_id=0x1000,
            from_node=SOURCE,
            to=DESTINATION,
            portnum=pilot.PRIVATE_APP,
            payload_sha256=next(iter(state.submitted_frames.values())).payload_sha256,
        )
        valid_ack = event(
            monotonic=2.0,
            packet_id=0xB005,
            from_node=DESTINATION,
            to=SOURCE,
            request_id=0x1000,
            hop_start=0,
            hop_limit=0,
            ack_proof_status=pilot.ACK_PROOF_VALID,
        )
        result = pilot.evaluate_direction(
            state, [receipt, valid_ack], wall_end=1.0, drain_end=2.0
        )
        self.assertEqual(result["authenticated_ack_valid"], 1)
        self.assertEqual(result["status"], "complete")
        self.assertIn("hop_start=0", result["ack_hop_contract"])

    def test_serialized_run_window_preserves_exact_inclusive_boundaries(self):
        state = state_with_frames(1)
        state.sent_at = 100.125
        state.producer_end = 101.25
        state.drain_end = 102.5
        valid_ack = event(
            monotonic=102.5,
            packet_id=0xB006,
            from_node=DESTINATION,
            to=SOURCE,
            request_id=0x1000,
            ack_proof_status=pilot.ACK_PROOF_VALID,
        )
        result = pilot.evaluate_direction(
            state, [valid_ack], wall_end=101.25, drain_end=102.5
        )
        serialized = json.dumps(result, allow_nan=False)
        restored = json.loads(serialized)["run_window"]
        self.assertEqual(restored["start_monotonic"], 100.125)
        self.assertEqual(restored["producer_deadline_monotonic"], 101.25)
        self.assertEqual(restored["drain_end_monotonic"], 102.5)
        self.assertTrue(restored["start_inclusive"])
        self.assertTrue(restored["end_inclusive"])
        self.assertEqual(result["authenticated_ack_valid"], 1)

    def test_saved_frame_admission_explains_pre_admission_ack_and_deadline_mismatch(self):
        state = state_with_frames(1)
        original = next(iter(state.submitted_frames.values()))
        admitted = pilot.PendingFrame(
            original.source,
            original.destination,
            original.packet_id,
            original.sequence,
            original.payload_sha256,
            101.0,
        )
        state.submitted_frames[original.key] = admitted
        state.pending[original.key] = admitted
        state.sent_at = 100.0
        state.producer_end = 1.0
        state.drain_end = 102.0
        pre_admission_ack = event(
            monotonic=100.5,
            packet_id=0xB007,
            from_node=DESTINATION,
            to=SOURCE,
            request_id=original.packet_id,
            ack_proof_status=pilot.ACK_PROOF_VALID,
        )
        result = pilot.evaluate_direction(
            state, [pre_admission_ack], wall_end=900.0, drain_end=102.0
        )
        saved = json.loads(json.dumps(result, allow_nan=False))
        outcome = saved["outcomes"][0]
        metadata = saved["run_window"]
        frame = saved["submitted_frame_admissions"][0]

        self.assertFalse(outcome["bounded"])
        self.assertEqual(saved["authenticated_ack_valid"], 0)
        self.assertEqual(frame["packet_id"], original.packet_id)
        self.assertEqual(frame["sequence"], 0)
        self.assertEqual(frame["admitted_at"], 101.0)
        self.assertEqual(metadata["start_monotonic"], 100.0)
        self.assertEqual(metadata["producer_deadline_monotonic"], 1.0)
        self.assertEqual(metadata["supplied_wall_end_monotonic"], 900.0)
        self.assertEqual(metadata["producer_deadline_source"], "state.producer_end")
        self.assertFalse(metadata["producer_deadline_matches_supplied"])
        self.assertIn("frame.admitted_at", metadata["effective_lower_bound_rule"])

    def test_foreign_and_unproven_ack_are_terminal_but_never_authenticated(self):
        state = state_with_frames(3)
        foreign_data = pilot.make_payload(RUN_ID, 0xDEADBEEF, DESTINATION, 9)
        events = [
            event(
                role="walker",
                monotonic=1.05,
                packet_id=0xD101,
                from_node=0xDEADBEEF,
                to=DESTINATION,
                portnum=pilot.PRIVATE_APP,
                payload_sha256=pilot.sha256_bytes(foreign_data),
                pki_encrypted=True,
            ),
            event(
                role="base",
                monotonic=1.1,
                packet_id=0xB101,
                from_node=DESTINATION,
                to=SOURCE,
                request_id=0x1000,
                ack_proof_status=0,
            ),
            event(
                role="base",
                monotonic=1.2,
                packet_id=0xB102,
                from_node=0xDEADBEEF,
                to=SOURCE,
                request_id=0x1001,
                ack_proof_status=pilot.ACK_PROOF_VALID,
            ),
            event(
                role="base",
                monotonic=1.3,
                packet_id=0xB103,
                from_node=DESTINATION,
                to=SOURCE,
                request_id=0x1002,
                routing_error=5,
                routing_error_name="MAX_RETRANSMIT",
            ),
        ]
        result = pilot.evaluate_direction(state, events, wall_end=1.0, drain_end=2.0)
        self.assertEqual(result["authenticated_ack_valid"], 0)
        self.assertEqual(result["ack_unproven"], 1)
        self.assertEqual(result["ack_foreign"], 1)
        self.assertEqual(result["remote_nak"], 1)
        self.assertEqual(result["remote_nak_errors"], ["MAX_RETRANSMIT"])
        self.assertEqual(result["unresolved"], 3)
        self.assertEqual(result["receiver_foreign"], 1)
        self.assertEqual(result["status"], "inconclusive_no_response")
        self.assertFalse(result["measurement_valid"])

    def test_late_valid_ack_is_retained_but_finite_result_is_inconclusive(self):
        state = state_with_frames(1)
        late = event(
            role="base",
            monotonic=3.0,
            packet_id=0xB201,
            from_node=DESTINATION,
            to=SOURCE,
            request_id=0x1000,
            ack_proof_status=pilot.ACK_PROOF_VALID,
        )
        result = pilot.evaluate_direction(state, [late], wall_end=1.0, drain_end=2.0)
        self.assertEqual(result["authenticated_ack_valid"], 0)
        self.assertEqual(result["status"], "inconclusive_no_response")
        self.assertEqual(result["unresolved"], 1)
        self.assertFalse(result["outcomes"][0]["bounded"])

    def test_late_untrusted_ack_and_remote_nak_have_separate_counters(self):
        state = state_with_frames(2)
        events = [
            event(
                role="base",
                monotonic=3.0,
                packet_id=0xB203,
                from_node=DESTINATION,
                to=SOURCE,
                request_id=0x1000,
                ack_proof_status=0,
            ),
            event(
                role="base",
                monotonic=3.1,
                packet_id=0xB204,
                from_node=DESTINATION,
                to=SOURCE,
                request_id=0x1001,
                routing_error=5,
                routing_error_name="MAX_RETRANSMIT",
            ),
        ]
        result = pilot.evaluate_direction(state, events, wall_end=1.0, drain_end=2.0)
        self.assertEqual(result["ack_unproven_bounded"], 0)
        self.assertEqual(result["ack_unproven_late"], 1)
        self.assertEqual(result["remote_nak_bounded"], 0)
        self.assertEqual(result["remote_nak_late"], 1)
        self.assertEqual(result["unresolved"], 2)

    def test_pre_run_ack_is_outside_the_finite_window(self):
        state = state_with_frames(1)
        state.sent_at = 1.0
        early = event(
            role="base",
            monotonic=0.9,
            packet_id=0xB202,
            from_node=DESTINATION,
            to=SOURCE,
            request_id=0x1000,
            ack_proof_status=pilot.ACK_PROOF_VALID,
        )
        result = pilot.evaluate_direction(state, [early], wall_end=2.0, drain_end=3.0)
        self.assertEqual(result["authenticated_ack_valid"], 0)
        self.assertEqual(result["status"], "inconclusive_no_response")
        self.assertFalse(result["outcomes"][0]["bounded"])

    def test_no_response_does_not_become_a_successful_zero_loss_run(self):
        state = state_with_frames(1)
        result = pilot.evaluate_direction(state, [], wall_end=1.0, drain_end=2.0)
        self.assertEqual(result["authenticated_ack_valid"], 0)
        self.assertEqual(result["unresolved"], 1)
        self.assertEqual(result["missing_sequences"], [0])
        self.assertEqual(result["status"], "inconclusive_no_response")

    def test_negative_timestamp_is_never_a_bounded_confirmation(self):
        state = state_with_frames(1)
        negative = event(
            role="base",
            monotonic=-1.0,
            packet_id=0xB250,
            from_node=DESTINATION,
            to=SOURCE,
            request_id=0x1000,
            ack_proof_status=pilot.ACK_PROOF_VALID,
        )
        result = pilot.evaluate_direction(state, [negative], wall_end=1.0, drain_end=2.0)
        self.assertEqual(result["authenticated_ack_valid"], 0)
        self.assertEqual(result["unresolved"], 1)
        self.assertFalse(result["outcomes"][0]["bounded"])

    def test_empty_and_orphan_capture_stays_inconclusive_and_null_safe(self):
        empty = pilot.DirectionState(pilot.Direction("base", "walker"), 1, 1)
        result = pilot.evaluate_direction(empty, [], wall_end=1.0, drain_end=2.0)
        self.assertEqual(result["status"], "inconclusive_no_submissions")
        self.assertEqual(result["authenticated_ack_latency"]["count"], 0)
        self.assertIsNone(
            result["authenticated_ack_latency"]["median"]
        )
        self.assertEqual(result["receiver_receipt_latency"]["count"], 0)
        self.assertIsNone(result["receiver_receipt_latency"]["p95"])
        self.assertIsNone(
            result["host_fed_goodput"]["first_submit_to_last_confirmation"][
                "seconds"
            ]
        )

        orphan = pilot.DirectionState(pilot.Direction("base", "walker"), 1, 1)
        orphan_ack = event(
            role="base",
            monotonic=1.1,
            packet_id=0xB251,
            from_node=DESTINATION,
            to=SOURCE,
            request_id=0x1000,
            ack_proof_status=pilot.ACK_PROOF_VALID,
        )
        result = pilot.evaluate_direction(
            orphan, [orphan_ack], wall_end=1.0, drain_end=2.0
        )
        self.assertEqual(result["authenticated_ack_valid"], 0)
        self.assertEqual(result["late_or_duplicate_replies"], 1)
        self.assertEqual(result["status"], "inconclusive_no_submissions")

    def test_live_ack_releases_window_once_and_does_not_duplicate_outcome(self):
        state = state_with_frames(2)
        state.window = 1
        ack = event(
            role="base",
            monotonic=1.1,
            packet_id=0xB301,
            from_node=DESTINATION,
            to=SOURCE,
            request_id=0x1000,
            ack_proof_status=pilot.ACK_PROOF_VALID,
        )
        session = SimpleNamespace(capture=SimpleNamespace(snapshot=lambda: [ack]))
        pilot._update_live_states([state], {"walker": session})
        self.assertEqual(len(state.pending), 1)
        self.assertEqual(state.pending[next(iter(state.pending))].sequence, 1)
        pilot._update_live_states([state], {"walker": session})
        self.assertEqual(
            [outcome["status"] for outcome in state.outcomes], ["ack_proof_valid"]
        )

    def test_duplicate_valid_ack_after_retirement_is_observation_only(self):
        state = state_with_frames(1)
        first = event(
            role="base",
            monotonic=1.1,
            packet_id=0xB302,
            from_node=DESTINATION,
            to=SOURCE,
            request_id=0x1000,
            ack_proof_status=pilot.ACK_PROOF_VALID,
        )
        duplicate = dict(first, monotonic=1.2, packet_id=0xB303)
        result = pilot.evaluate_direction(
            state, [first, duplicate], wall_end=1.0, drain_end=2.0
        )
        self.assertEqual(result["authenticated_ack_valid"], 1)
        self.assertEqual(result["late_or_duplicate_replies"], 1)
        self.assertEqual(result["status"], "complete_with_untrusted_or_failed_outcomes")

    def test_unknown_reply_does_not_mask_later_admission_for_same_id(self):
        state = pilot.DirectionState(pilot.Direction("base", "walker"), 1, 1)
        unknown = event(
            role="base",
            monotonic=0.5,
            packet_id=0xB401,
            from_node=DESTINATION,
            to=SOURCE,
            request_id=0x1000,
            ack_proof_status=pilot.ACK_PROOF_VALID,
        )
        pilot._record_replies(state, [unknown])
        payload = pilot.make_payload(RUN_ID, SOURCE, DESTINATION, 0)
        frame = pilot.PendingFrame(
            SOURCE, DESTINATION, 0x1000, 0, pilot.sha256_bytes(payload), 0.9
        )
        state.pending[frame.key] = frame
        state.submitted_frames[frame.key] = frame
        state.firmware_accepted.add(frame.key)
        state.submissions = 1
        state.sent_at = 0.8
        state.producer_end = 1.0
        state.drain_end = 2.0
        valid = dict(unknown, monotonic=1.1, packet_id=0xB402)
        receipt = event(
            role="walker",
            monotonic=1.15,
            packet_id=0x1000,
            from_node=SOURCE,
            to=DESTINATION,
            portnum=pilot.PRIVATE_APP,
            payload_sha256=frame.payload_sha256,
        )
        result = pilot.evaluate_direction(
            state, [valid, receipt], wall_end=1.0, drain_end=2.0
        )
        self.assertEqual(result["authenticated_ack_valid"], 1)
        self.assertEqual(result["status"], "complete")

    def test_receipt_requires_original_physical_id_and_flags(self):
        state = state_with_frames(1)
        payload_hash = next(iter(state.submitted_frames.values())).payload_sha256
        wrong_id = event(
            role="walker",
            monotonic=1.1,
            packet_id=0x9999,
            from_node=SOURCE,
            to=DESTINATION,
            portnum=pilot.PRIVATE_APP,
            payload_sha256=payload_hash,
        )
        wrong_flags = event(
            role="walker",
            monotonic=1.2,
            packet_id=0x1000,
            from_node=SOURCE,
            to=DESTINATION,
            portnum=pilot.PRIVATE_APP,
            payload_sha256=payload_hash,
            want_ack=False,
        )
        exact = dict(wrong_flags, monotonic=1.3, want_ack=True)
        duplicate = dict(exact, monotonic=1.4)
        wrong_hop = dict(exact, monotonic=1.5, hop_limit=3)
        result = pilot.evaluate_direction(
            state,
            [wrong_id, wrong_flags, exact, duplicate, wrong_hop],
            wall_end=1.0,
            drain_end=2.0,
        )
        self.assertEqual(result["receiver_unique_receipts"], 1)
        self.assertEqual(result["receiver_duplicates"], 1)
        self.assertEqual(result["receiver_corrupt_or_unexpected"], 3)

    def test_submission_map_rejects_active_or_reused_physical_id(self):
        state = pilot.DirectionState(pilot.Direction("base", "walker"), 2, 1)
        payload = pilot.make_payload(RUN_ID, SOURCE, DESTINATION, 0)
        packet = SimpleNamespace(id=0xABC0)
        pilot.register_submission(state, packet, payload, 1.0)
        with self.assertRaises(pilot.PilotError):
            pilot.register_submission(state, packet, payload, 1.1)
        self.assertEqual(state.submissions, 1)
        self.assertEqual(state.duplicate_submission_keys, 1)
        self.assertEqual(len(state.pending), 1)

    def test_queue_status_reconciles_accept_reject_and_unobserved(self):
        accepted = state_with_frames(1)
        key = next(iter(accepted.submitted_frames))
        pilot._record_queue_status(
            accepted,
            [
                event(
                    kind="pilot_raw_queue_status",
                    role="base",
                    monotonic=1.1,
                    mesh_packet_id=key[1],
                    res=0,
                )
            ],
        )
        self.assertIn(key, accepted.firmware_accepted)

        rejected = state_with_frames(1)
        rejected.firmware_accepted.clear()
        pilot._record_queue_status(
            rejected,
            [
                event(
                    kind="pilot_raw_queue_status",
                    role="base",
                    monotonic=1.1,
                    mesh_packet_id=key[1],
                    res=7,
                )
            ],
        )
        self.assertNotIn(key, rejected.pending)
        self.assertEqual(rejected.outcomes[0]["status"], "local_queue_rejected")

        unobserved = state_with_frames(1)
        unobserved.firmware_accepted.clear()
        result = pilot.evaluate_direction(unobserved, [], wall_end=1.0, drain_end=2.0)
        self.assertEqual(result["firmware_unobserved"], 1)
        self.assertFalse(result["queue_reconciliation_complete"])

        late = state_with_frames(1)
        late.firmware_accepted.clear()
        late_status = event(
            kind="pilot_raw_queue_status",
            role="base",
            monotonic=999.0,
            mesh_packet_id=key[1],
            res=0,
        )
        pilot._record_queue_status(late, [late_status])
        self.assertNotIn(key, late.firmware_accepted)
        result = pilot.evaluate_direction(
            late, [late_status], wall_end=1.0, drain_end=2.0
        )
        self.assertEqual(result["firmware_accepted"], 0)
        self.assertEqual(result["firmware_queue_late"], 1)
        self.assertEqual(result["firmware_unobserved"], 1)
        self.assertEqual(result["unresolved"], 1)

        boundary = state_with_frames(1)
        boundary.firmware_accepted.clear()
        boundary_status = dict(late_status, monotonic=2.0)
        pilot._record_queue_status(boundary, [boundary_status])
        self.assertIn(key, boundary.firmware_accepted)

        nan_status = dict(late_status, monotonic=float("nan"))
        nan_state = state_with_frames(1)
        nan_state.firmware_accepted.clear()
        pilot._record_queue_status(nan_state, [nan_status])
        self.assertNotIn(key, nan_state.firmware_accepted)
        self.assertEqual(len(nan_state.firmware_late_queue_observations), 1)

    def test_rejected_queue_entry_is_removed_without_resend(self):
        interface = SimpleNamespace(queue={7: object()})
        pilot._drop_rejected_host_entry(
            interface, {"mesh_packet_id": 7, "res": 5}
        )
        self.assertEqual(interface.queue, {})

    def test_local_internal_nak_retires_only_that_submitted_frame(self):
        state = state_with_frames(1)
        local_nak = event(
            role="base",
            transport=pilot.TRANSPORT_INTERNAL,
            from_node=SOURCE,
            to=SOURCE,
            request_id=0x1000,
            routing_error=4,
        )
        result = pilot.evaluate_direction(state, [local_nak], wall_end=1.0, drain_end=2.0)
        self.assertEqual(result["local_terminal_nak"], 1)
        self.assertEqual(result["unresolved"], 0)
        self.assertFalse(result["delivery_confirmation_passed"])

    def test_authenticated_remote_nak_releases_window_but_never_delivery(self):
        authenticated = state_with_frames(1)
        remote_nak = event(
            role="base",
            monotonic=1.1,
            packet_id=0xB410,
            from_node=DESTINATION,
            to=SOURCE,
            request_id=0x1000,
            routing_error=5,
            routing_error_name="MAX_RETRANSMIT",
            ack_proof_status=pilot.ACK_PROOF_VALID,
        )
        pilot._update_live_states(
            [authenticated],
            {"base": SimpleNamespace(capture=SimpleNamespace(snapshot=lambda: [remote_nak]))},
        )
        self.assertEqual(len(authenticated.pending), 0)
        result = pilot.evaluate_direction(
            authenticated, [remote_nak], wall_end=1.0, drain_end=2.0
        )
        self.assertEqual(result["remote_nak_authenticated"], 1)
        self.assertEqual(result["authenticated_ack_valid"], 0)
        self.assertFalse(result["delivery_confirmation_passed"])
        self.assertEqual(result["status"], "complete_with_untrusted_or_failed_outcomes")

        untrusted = state_with_frames(1)
        untrusted_nak = dict(remote_nak, packet_id=0xB411, ack_proof_status=0)
        pilot._update_live_states(
            [untrusted],
            {"base": SimpleNamespace(capture=SimpleNamespace(snapshot=lambda: [untrusted_nak]))},
        )
        self.assertEqual(len(untrusted.pending), 1)
        result = pilot.evaluate_direction(
            untrusted, [untrusted_nak], wall_end=1.0, drain_end=2.0
        )
        self.assertEqual(result["remote_nak_authenticated"], 0)
        self.assertEqual(result["remote_nak"], 1)
        self.assertEqual(result["unresolved"], 1)

    def test_untrusted_ack_does_not_release_before_later_valid_ack(self):
        state = state_with_frames(1)
        unproven = event(
            role="base",
            monotonic=1.1,
            from_node=DESTINATION,
            to=SOURCE,
            request_id=0x1000,
            ack_proof_status=0,
        )
        valid = dict(unproven, monotonic=1.2, packet_id=0xB501, ack_proof_status=pilot.ACK_PROOF_VALID)
        receipt = event(
            role="walker",
            monotonic=1.15,
            packet_id=0x1000,
            from_node=SOURCE,
            to=DESTINATION,
            portnum=pilot.PRIVATE_APP,
            payload_sha256=next(iter(state.submitted_frames.values())).payload_sha256,
        )
        pilot._update_live_states(
            [state], {"base": SimpleNamespace(capture=SimpleNamespace(snapshot=lambda: [unproven]))}
        )
        self.assertEqual(len(state.pending), 1)
        result = pilot.evaluate_direction(
            state,
            [unproven, valid, receipt],
            wall_end=1.0,
            drain_end=2.0,
        )
        self.assertEqual(result["ack_unproven_bounded"], 1)
        self.assertEqual(result["authenticated_ack_valid"], 1)

    def test_authenticated_ack_and_host_receipt_are_separate_gates(self):
        state = state_with_frames(1)
        valid = event(
            role="base",
            monotonic=1.1,
            packet_id=0xB502,
            from_node=DESTINATION,
            to=SOURCE,
            request_id=0x1000,
            ack_proof_status=pilot.ACK_PROOF_VALID,
        )
        result = pilot.evaluate_direction(
            state, [valid], wall_end=1.0, drain_end=2.0
        )
        self.assertEqual(result["authenticated_ack_valid"], 1)
        self.assertTrue(result["delivery_confirmation_passed"])
        self.assertFalse(result["host_capture_complete"])
        self.assertFalse(result["measurement_valid"])

    def test_run_limits_reject_nan_infinity_and_large_deadlines(self):
        args = SimpleNamespace(
            count=1,
            window=1,
            wall_seconds=float("nan"),
            drain_seconds=1.0,
            command_gap=0.1,
            run_id=None,
            image=["placeholder.bin"],
        )
        with self.assertRaises(pilot.PilotError):
            pilot._validate_run_args(args)
        args.wall_seconds = float("inf")
        with self.assertRaises(pilot.PilotError):
            pilot._validate_run_args(args)
        args.wall_seconds = pilot.MAX_WALL_SECONDS + 1
        with self.assertRaises(pilot.PilotError):
            pilot._validate_run_args(args)
        args.wall_seconds = 1.0
        args.window = 2
        with self.assertRaises(pilot.PilotError):
            pilot._validate_run_args(args)

    def test_run_requires_image_before_opening_sessions(self):
        args = SimpleNamespace(
            direction="base-to-walker",
            count=1,
            window=1,
            wall_seconds=1.0,
            drain_seconds=1.0,
            command_gap=0.1,
            run_id=1,
            output=Path("/tmp/reliable-pilot-no-image"),
            image=[],
        )
        old_open = pilot._open_sessions
        try:
            pilot._open_sessions = lambda *_args: (_ for _ in ()).throw(
                AssertionError("ports must not open without image provenance")
            )
            with self.assertRaises(pilot.PilotError):
                pilot.run_pilot(args)
        finally:
            pilot._open_sessions = old_open

    def test_image_provenance_hashes_each_declared_image(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "firmware.bin"
            image.write_bytes(b"image bytes")
            provenance = pilot._image_provenance([image])
        self.assertEqual(
            provenance[str(image.resolve())]["sha256"],
            pilot.sha256_bytes(b"image bytes"),
        )

    def test_scratch_and_committed_copies_import_same_benchmark(self):
        workspace = pilot.ROOT
        scratch_path = workspace / ".scratch" / "w12-throughput-20261007" / "reliable_pilot.py"
        spec = importlib.util.spec_from_file_location(
            "reliable_pilot_scratch_copy", scratch_path
        )
        self.assertIsNotNone(spec)
        assert spec is not None and spec.loader is not None
        scratch = importlib.util.module_from_spec(spec)
        sys.modules["reliable_pilot_scratch_copy"] = scratch
        spec.loader.exec_module(scratch)
        self.assertEqual(scratch.BENCHMARK_DIR, pilot.BENCHMARK_DIR)

    def test_fresh_check_uses_separate_output_and_reports_close_failure(self):
        class FakeCapture:
            def __init__(self, role, marker):
                self.role = role
                self.marker = marker

            def snapshot(self):
                return [{"role": self.role, "capture": self.marker}]

        class FakeSession:
            def __init__(self, role, output, close_ok, marker):
                self.role = role
                self.identity = f"usb-{role}"
                self.node_num = SOURCE if role == "base" else DESTINATION
                self.capture = FakeCapture(role, marker)
                self.output = Path(output)
                self.close_ok = close_ok

            def close(self):
                pilot.benchmark._safe_json_write(
                    self.output / self.role / "capture-events.json",
                    self.capture.snapshot(),
                )
                return self.close_ok

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original_sessions = {
                role: FakeSession(role, root, True, "original")
                for role in ("base", "walker")
            }
            pilot._persist_capture_snapshots(original_sessions, root)
            original = (root / "base" / "capture-events.json").read_text()
            old_board_session = pilot.benchmark.BoardSession
            old_fingerprint = pilot._memory_config_fingerprint
            old_ensure_peers = pilot.ensure_peers
            try:
                pilot.benchmark.BoardSession = lambda role, output, gap: FakeSession(
                    role, output, role == "base", "fresh"
                )
                pilot._memory_config_fingerprint = lambda session: {"role": session.role}
                pilot.ensure_peers = lambda sessions, source, destination: {"ok": True}
                expected = {role: {"role": role} for role in ("base", "walker")}
                checks = pilot._fresh_key_check(
                    root / "fresh-config", ("base", "walker"), 0.0, expected
                )
            finally:
                pilot.benchmark.BoardSession = old_board_session
                pilot._memory_config_fingerprint = old_fingerprint
                pilot.ensure_peers = old_ensure_peers
            self.assertFalse(checks["passed"])
            self.assertEqual((root / "base" / "capture-events.json").read_text(), original)
            self.assertNotEqual(
                json.loads((root / "fresh-config" / "base" / "capture-events.json").read_text()),
                json.loads(original),
            )

    def test_disk_full_capture_persistence_invalidates_complete_result(self):
        class FakeCapture:
            def snapshot(self):
                return [{"event": "raw"}]

        with tempfile.TemporaryDirectory() as directory:
            old_safe_write = pilot.benchmark._safe_json_write
            try:
                def fail_disk_full(path, value):
                    raise OSError(28, "No space left on device")

                pilot.benchmark._safe_json_write = fail_disk_full
                errors = pilot._persist_capture_snapshots(
                    {"base": SimpleNamespace(capture=FakeCapture())}, Path(directory)
                )
            finally:
                pilot.benchmark._safe_json_write = old_safe_write
        self.assertIn("base", errors)
        self.assertIn("No space left", errors["base"])
        result = {
            "status": "complete",
            "directions": {
                "base-to-walker": {
                    "status": "complete",
                    "host_capture_complete": True,
                    "measurement_valid": True,
                }
            },
        }
        pilot._apply_capture_persistence_result(result, errors)
        self.assertEqual(result["status"], "inconclusive_capture_persistence_failure")
        direction = result["directions"]["base-to-walker"]
        self.assertFalse(direction["host_capture_complete"])
        self.assertFalse(direction["measurement_valid"])
        self.assertEqual(direction["capture_persist_errors"], errors)

    def test_configuration_gate_invalidates_directions_but_preserves_facts(self):
        def complete_result():
            return {
                "status": "complete",
                "directions": {
                    "base-to-walker": {
                        "status": "complete",
                        "measurement_valid": True,
                        "firmware_admitted": 3,
                        "receiver_receipt_count": 3,
                        "authenticated_ack_valid": 2,
                        "delivery_confirmation_passed": True,
                    }
                },
            }

        fresh_result = complete_result()
        pilot._apply_configuration_gate_result(
            fresh_result,
            {"passed": False, "error": "fresh_config_mismatch"},
        )
        self.assertFalse(fresh_result["configuration_check_passed"])
        self.assertEqual(fresh_result["status"], "inconclusive_configuration_check")
        fresh_direction = fresh_result["directions"]["base-to-walker"]
        self.assertFalse(fresh_direction["measurement_valid"])
        self.assertEqual(fresh_direction["status"], "inconclusive_configuration_check")
        self.assertEqual(fresh_direction["firmware_admitted"], 3)
        self.assertEqual(fresh_direction["receiver_receipt_count"], 3)
        self.assertEqual(fresh_direction["authenticated_ack_valid"], 2)
        self.assertTrue(fresh_direction["delivery_confirmation_passed"])

        close_result = complete_result()
        pilot._apply_configuration_gate_result(
            close_result,
            {"passed": False, "error": "session_close_not_confirmed"},
            "error",
        )
        self.assertFalse(close_result["configuration_check_passed"])
        self.assertEqual(close_result["status"], "error")
        close_direction = close_result["directions"]["base-to-walker"]
        self.assertFalse(close_direction["measurement_valid"])
        self.assertEqual(close_direction["status"], "error")
        self.assertEqual(close_direction["firmware_admitted"], 3)
        self.assertEqual(close_direction["authenticated_ack_valid"], 2)

    def test_capture_health_fails_closed_for_protocol_error_and_dead_reader(self):
        class DeadReader:
            def is_alive(self):
                return False

        session = SimpleNamespace(
            interface=SimpleNamespace(
                _rxThread=DeadReader(),
                _wantExit=False,
                failure=None,
            ),
            _pilot_capture_health={
                "protocol_errors": ["invalid FromRadio protobuf"],
                "write_errors": [],
                "reader_alive": None,
                "reader_exited": False,
                "disconnected": False,
            },
        )
        snapshots, failures = pilot._session_capture_health({"base": session})
        self.assertIn("base", failures)
        self.assertIn("reader_exited", failures["base"])
        self.assertIn("invalid FromRadio protobuf", failures["base"])
        result = {
            "status": "complete",
            "directions": {
                "base-to-walker": {
                    "status": "complete",
                    "host_capture_complete": True,
                    "measurement_valid": True,
                }
            },
        }
        pilot._apply_capture_health_result(result, snapshots, failures)
        self.assertEqual(result["status"], "inconclusive_capture_health")
        self.assertFalse(result["directions"]["base-to-walker"]["measurement_valid"])

        closing_session = SimpleNamespace(
            interface=SimpleNamespace(
                _rxThread=DeadReader(), _wantExit=True, failure=None
            ),
            _pilot_capture_health={
                "protocol_errors": [],
                "write_errors": [],
                "reader_alive": None,
                "reader_exited": False,
                "disconnected": False,
            },
        )
        _, closing_failures = pilot._session_capture_health({"base": closing_session})
        self.assertEqual(closing_failures, {})

    def test_close_health_is_sampled_after_each_close_and_invalidates_result(self):
        class CloseFailingSession:
            def __init__(self):
                self.interface = SimpleNamespace(
                    _rxThread=None,
                    _wantExit=False,
                    failure=None,
                )
                self._pilot_capture_health = {
                    "protocol_errors": [],
                    "write_errors": [],
                    "reader_alive": None,
                    "reader_exited": False,
                    "disconnected": False,
                }

            def close(self):
                self._pilot_capture_health["protocol_errors"].append(
                    "close parser failure"
                )
                self.interface._wantExit = True
                return True

        session = CloseFailingSession()
        close_results = {}
        snapshots = {}
        failures = {}
        pilot._close_sessions_and_collect_health(
            {"base": session}, close_results, snapshots, failures
        )

        self.assertEqual(close_results, {"base": True})
        self.assertIn("close parser failure", snapshots["base"]["protocol_errors"])
        self.assertEqual(failures, {"base": ["close parser failure"]})
        result = {
            "status": "complete",
            "directions": {
                "base-to-walker": {
                    "status": "complete",
                    "capture_health_passed": True,
                    "measurement_valid": True,
                }
            },
        }
        pilot._apply_capture_health_result(result, snapshots, failures)
        self.assertEqual(result["status"], "inconclusive_capture_health")
        self.assertFalse(result["directions"]["base-to-walker"]["measurement_valid"])

    def test_close_sampling_catches_other_reader_death_before_its_close(self):
        class Reader:
            def __init__(self, alive):
                self.alive = alive

            def is_alive(self):
                return self.alive

        sessions = {}

        class Session:
            def __init__(self, role):
                self.role = role
                self.interface = SimpleNamespace(
                    _rxThread=Reader(True),
                    _wantExit=False,
                    failure=None,
                )
                self._pilot_capture_health = {
                    "protocol_errors": [],
                    "write_errors": [],
                    "reader_alive": None,
                    "reader_exited": False,
                    "disconnected": False,
                }

            def close(self):
                if self.role == "base":
                    sessions["walker"].interface._rxThread.alive = False
                self.interface._wantExit = True
                return True

        sessions.update({role: Session(role) for role in ("base", "walker")})
        close_results = {}
        snapshots = {}
        failures = {}
        pilot._close_sessions_and_collect_health(
            sessions, close_results, snapshots, failures
        )

        self.assertEqual(close_results, {"base": True, "walker": True})
        self.assertTrue(snapshots["walker"]["reader_exited"])
        self.assertEqual(failures, {"walker": ["reader_exited"]})

    def test_fresh_check_fails_if_reader_dies_before_later_close(self):
        class Reader:
            def __init__(self, alive=True):
                self.alive = alive

            def is_alive(self):
                return self.alive

        fresh_sessions = {}

        class FreshSession:
            def __init__(self, role, output, _gap):
                self.role = role
                self.output = Path(output)
                self.identity = f"usb-{role}"
                self.node_num = SOURCE if role == "base" else DESTINATION
                self.interface = SimpleNamespace(
                    _rxThread=Reader(),
                    _wantExit=False,
                    failure=None,
                )
                fresh_sessions[role] = self

            def close(self):
                if self.role == "base":
                    fresh_sessions["walker"].interface._rxThread.alive = False
                self.interface._wantExit = True
                return True

        old_board_session = pilot.benchmark.BoardSession
        old_fingerprint = pilot._memory_config_fingerprint
        old_ensure_peers = pilot.ensure_peers
        try:
            pilot.benchmark.BoardSession = FreshSession
            pilot._memory_config_fingerprint = lambda session: {"role": session.role}
            pilot.ensure_peers = lambda sessions, source, destination: {"ok": True}
            with tempfile.TemporaryDirectory() as directory:
                expected = {role: {"role": role} for role in ("base", "walker")}
                checks = pilot._fresh_key_check(
                    Path(directory), ("base", "walker"), 0.0, expected
                )
        finally:
            pilot.benchmark.BoardSession = old_board_session
            pilot._memory_config_fingerprint = old_fingerprint
            pilot.ensure_peers = old_ensure_peers

        self.assertFalse(checks["capture_health_passed"])
        self.assertIn("reader_exited", checks["capture_health_failures"]["walker"])
        self.assertFalse(checks["passed"])

    def test_host_write_metadata_is_hash_only_and_not_admission(self):
        events = []

        class FakeToRadio:
            def __init__(self):
                self.packet = SimpleNamespace(id=77)

            def ParseFromString(self, value):
                if value != b"frame":
                    raise ValueError("bad frame")

            def HasField(self, name):
                return name == "packet"

        class FakeMesh:
            ToRadio = FakeToRadio

        stream = SimpleNamespace(write=lambda value: len(value))

        def original_write(data):
            return stream.write(data)

        interface = SimpleNamespace(stream=stream, _writeBytes=original_write)
        session = SimpleNamespace(
            interface=interface,
            capture=SimpleNamespace(
                record=lambda kind, **values: events.append({"kind": kind, **values})
            ),
        )
        pilot._install_host_write_capture(session, FakeMesh)
        interface._writeBytes(b"frame")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["packet_id"], 77)
        self.assertEqual(events[0]["serialized_frame_len"], 5)
        self.assertEqual(events[0]["return_len"], 5)
        self.assertTrue(events[0]["complete"])
        self.assertEqual(events[0]["frame_sha256"], pilot.sha256_bytes(b"frame"))

    def test_submission_gap_is_finite_bounded_and_parser_visible(self):
        args = SimpleNamespace(
            count=1,
            window=1,
            wall_seconds=1.0,
            drain_seconds=1.0,
            command_gap=0.1,
            submission_gap_seconds=0.1,
            run_id=None,
            image=["placeholder.bin"],
        )
        pilot._validate_run_args(args)
        args.submission_gap_seconds = 1.1
        with self.assertRaises(pilot.PilotError):
            pilot._validate_run_args(args)
        args.submission_gap_seconds = float("nan")
        with self.assertRaises(pilot.PilotError):
            pilot._validate_run_args(args)
        parsed = pilot._parser().parse_args(
            ["--output", "/tmp/reliable-pilot", "--image", "firmware.bin"]
        )
        self.assertEqual(parsed.submission_gap_seconds, 0.0)

    def test_partial_startup_retains_all_opened_sessions_for_cleanup(self):
        opened = []

        class FakeSession:
            def __init__(self, role, output, gap):
                self.role = role
                self.closed = False
                opened.append(self)

        old_board_session = pilot.benchmark.BoardSession
        old_install = pilot._install_raw_capture
        try:
            pilot.benchmark.BoardSession = FakeSession

            def fail_on_walker(session):
                if session.role == "walker":
                    raise RuntimeError("capture install failed")

            pilot._install_raw_capture = fail_on_walker
            with self.assertRaises(pilot.SessionOpenError) as raised:
                pilot._open_sessions(Path("/tmp/unused"), 0.0)
            self.assertEqual(set(raised.exception.sessions), {"base", "walker"})
            for session in raised.exception.sessions.values():
                session.closed = True
            self.assertTrue(all(session.closed for session in opened))
        finally:
            pilot.benchmark.BoardSession = old_board_session
            pilot._install_raw_capture = old_install

    def test_queue_gate_refuses_zero_cached_capacity_before_write(self):
        class FakeToRadio:
            def HasField(self, name):
                return name == "packet"

            packet = SimpleNamespace(id=1)

        interface = SimpleNamespace(
            queueStatus=SimpleNamespace(free=0), queue={}, _queueClaim=lambda: None
        )
        with self.assertRaises(pilot._QueueFull):
            pilot._send_to_radio_immediate(interface, FakeToRadio())
        self.assertEqual(interface.queue, {})

    def test_send_data_captures_cached_backpressure_before_packet_id_allocation(self):
        import threading

        events = []

        class FakeCapture:
            def record(self, kind, **values):
                captured = {
                    "kind": kind,
                    "role": "base",
                    "monotonic": 40.5,
                    **values,
                }
                events.append(captured)
                return captured

        interface = SimpleNamespace(
            _command_lock=threading.Lock(),
            queueStatus=SimpleNamespace(free=0),
            queue={},
        )
        state = pilot.DirectionState(pilot.Direction("base", "walker"), 2, 1)
        state.next_sequence = 4
        session = SimpleNamespace(interface=interface, role="base", capture=FakeCapture())
        with self.assertRaises(pilot._QueueFull):
            pilot.send_data_if_admitted(
                session,
                pilot.make_payload(RUN_ID, SOURCE, DESTINATION, 4),
                DESTINATION,
                state=state,
            )

        self.assertEqual(len(events), 1)
        captured = events[0]
        self.assertEqual(captured["kind"], "pilot_host_cached_backpressure")
        self.assertEqual(captured["source"], SOURCE)
        self.assertEqual(captured["destination"], DESTINATION)
        self.assertEqual(captured["next_sequence"], 4)
        self.assertEqual(captured["free"], 0)
        self.assertEqual(captured["state"], "host_cached_backpressure")
        self.assertFalse(captured["packet_id_allocated"])
        self.assertNotIn("packet_id", captured)
        self.assertEqual(state.cached_backpressure_observations[0]["monotonic"], 40.5)
        self.assertEqual(state.submissions, 0)
        self.assertEqual(state.firmware_rejected, {})

    def test_inner_queue_race_records_actual_constructed_id_without_submission(self):
        import threading

        events = []

        class FakeCapture:
            def record(self, kind, **values):
                captured = {
                    "kind": kind,
                    "role": "base",
                    "monotonic": 41.5,
                    **values,
                }
                events.append(captured)
                return captured

        class FakeToRadio:
            packet = SimpleNamespace(id=77)

            def HasField(self, name):
                return name == "packet"

        class FakePacket:
            id = 77
            to = DESTINATION
            want_ack = True
            pki_encrypted = True
            hop_limit = pilot.REQUESTED_HOP_LIMIT
            decoded = SimpleNamespace(
                portnum=pilot.PRIVATE_APP,
                payload=pilot.make_payload(RUN_ID, SOURCE, DESTINATION, 0),
            )

            def HasField(self, name):
                return name == "decoded"

        class FakeInterface:
            def __init__(self):
                self._command_lock = threading.Lock()
                self.queueStatus = SimpleNamespace(free=1)
                self.queue = {}
                self._sendToRadio = lambda packet: None

            def sendData(self, *args, **kwargs):
                self.queueStatus.free = 0
                self._sendToRadio(FakeToRadio())
                return FakePacket()

        state = pilot.DirectionState(pilot.Direction("base", "walker"), 1, 1)
        session = SimpleNamespace(
            interface=FakeInterface(), role="base", capture=FakeCapture()
        )
        with self.assertRaises(pilot._QueueFull):
            pilot.send_data_if_admitted(
                session,
                pilot.make_payload(RUN_ID, SOURCE, DESTINATION, 0),
                DESTINATION,
                state=state,
            )

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["packet_id"], 77)
        self.assertTrue(events[0]["packet_id_allocated"])
        self.assertEqual(state.cached_backpressure_observations[0]["packet_id"], 77)
        self.assertTrue(state.cached_backpressure_observations[0]["packet_id_allocated"])
        self.assertEqual(state.submissions, 0)
        self.assertEqual(state.submitted_frames, {})
        self.assertEqual(state.firmware_accepted, set())
        self.assertEqual(state.firmware_rejected, {})

    def test_send_data_requests_hop_one_direct_pair_contract(self):
        payload = pilot.make_payload(RUN_ID, SOURCE, DESTINATION, 0)
        calls = []

        class FakePacket:
            id = 9
            to = DESTINATION
            want_ack = True
            pki_encrypted = True
            hop_limit = pilot.REQUESTED_HOP_LIMIT
            decoded = SimpleNamespace(portnum=pilot.PRIVATE_APP, payload=payload)

            def HasField(self, name):
                return name == "decoded"

        class FakeInterface:
            def __init__(self):
                import threading

                self._command_lock = threading.Lock()
                self.queueStatus = SimpleNamespace(free=1)
                self.queue = {}
                self._sendToRadio = lambda packet: None

            def sendData(self, *args, **kwargs):
                calls.append((args, kwargs))
                return FakePacket()

        packet = pilot.send_data_if_admitted(
            SimpleNamespace(interface=FakeInterface()), payload, DESTINATION
        )
        self.assertEqual(packet.hop_limit, pilot.REQUESTED_HOP_LIMIT)
        self.assertEqual(
            calls[0],
            (
                (payload,),
                {
                    "destinationId": DESTINATION,
                    "portNum": pilot.PRIVATE_APP,
                    "wantAck": True,
                    "wantResponse": False,
                    "pkiEncrypted": True,
                    "hopLimit": pilot.REQUESTED_HOP_LIMIT,
                },
            ),
        )

    def test_immediate_admission_claims_one_slot_and_writes_once(self):
        class FakeToRadio:
            def HasField(self, name):
                return name == "packet"

            packet = SimpleNamespace(id=2)

        writes = []
        status = SimpleNamespace(free=1)
        interface = SimpleNamespace(
            queueStatus=status,
            queue={},
            _queueClaim=lambda: setattr(status, "free", status.free - 1),
            _sendToRadioImpl=lambda packet: writes.append(packet),
        )
        packet = FakeToRadio()
        pilot._send_to_radio_immediate(interface, packet)
        self.assertEqual(status.free, 0)
        self.assertEqual(writes, [packet])
        self.assertEqual(interface.queue, {2: packet})


if __name__ == "__main__":
    unittest.main()
