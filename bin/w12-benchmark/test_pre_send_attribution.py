import struct
import unittest

from pre_send_attribution import (
    INT16_MIN,
    KIND,
    MAGIC,
    REPORT_BYTES,
    VERSION,
    decode_report,
    encode_snapshot_control,
)


class PreSendAttributionProtocolTest(unittest.TestCase):
    def report(self):
        data = bytearray(REPORT_BYTES)
        struct.pack_into("<HBBIIII", data, 0, MAGIC, VERSION, KIND, 1, 2, 3, 4)
        data[20] = 0x33
        data[21] = 2
        struct.pack_into("<I", data, 36, 3)
        struct.pack_into("<I", data, 40, 3)
        struct.pack_into("<I", data, 44, 3)
        struct.pack_into("<I", data, 48, 9)
        struct.pack_into("<I", data, 52, 5)
        data[73] = 1
        data[74] = 31
        struct.pack_into("<H", data, 92, 0x4567)
        return data

    def report_without_sample(self):
        data = self.report()
        data[73] = 0
        data[74] = 0
        for offset in (98, 100, 102, 104):
            struct.pack_into("<h", data, offset, INT16_MIN)
        return data

    def test_decodes_fixed_layout(self):
        report = decode_report(self.report())
        self.assertEqual(report.tx_timer_late_count, 3)
        self.assertEqual(report.tx_timer_late_sum_ms, 9)
        self.assertEqual(report.tx_timer_late_max_ms, 5)
        self.assertEqual(report.rx_fifo_level, 0x4567)
        self.assertEqual(report.burst_armed, 0)
        self.assertEqual(report.burst_frames, 0)
        self.assertEqual(report.burst_aborted, 0)
        self.assertEqual(report.burst_count, 0)
        self.assertFalse(report.phase_timing_available)
        self.assertEqual(report.producer_us_count, 0)

    def test_decodes_burst_counters_and_keeps_reserved_tail_strict(self):
        report = self.report()
        struct.pack_into("<IIII", report, 114, 3, 4, 1, 1)
        decoded = decode_report(report)
        self.assertEqual(decoded.burst_armed, 3)
        self.assertEqual(decoded.burst_frames, 4)
        self.assertEqual(decoded.burst_aborted, 1)
        self.assertEqual(decoded.burst_count, 1)

        invalid = bytearray(report)
        invalid[130] = 1
        with self.assertRaises(ValueError):
            decode_report(invalid)

        invalid = bytearray(report)
        struct.pack_into("<I", invalid, 126, 4)
        with self.assertRaises(ValueError):
            decode_report(invalid)

    def test_decodes_phase_timing_triplets_and_availability(self):
        report = self.report()
        report[178] = 1
        struct.pack_into("<III", report, 130, 3, 90, 40)
        struct.pack_into("<III", report, 142, 2, 12, 8)
        struct.pack_into("<III", report, 154, 1, 4, 4)
        struct.pack_into("<III", report, 166, 4, 100, 30)

        decoded = decode_report(report)
        self.assertTrue(decoded.phase_timing_available)
        self.assertEqual(decoded.producer_us_count, 3)
        self.assertEqual(decoded.producer_us_sum, 90)
        self.assertEqual(decoded.producer_us_max, 40)
        self.assertEqual(decoded.burst_prepare_us_count, 2)
        self.assertEqual(decoded.burst_guard_request_late_ms_max, 4)
        self.assertEqual(decoded.rx_gate_decode_us_sum, 100)
        self.assertEqual(decoded.failed_tx_count, 0)

        struct.pack_into("<IIII", report, 179, 1, 0x1234, 37, 99)
        report[195] = 0
        struct.pack_into("<h", report, 196, INT16_MIN)
        decoded = decode_report(report)
        self.assertEqual(decoded.failed_tx_count, 1)
        self.assertEqual(decoded.failed_tx_last_packet_id, 0x1234)
        self.assertEqual(decoded.failed_tx_last_sequence, 37)
        self.assertEqual(decoded.failed_tx_last_at_ms, 99)

    def test_rejects_invalid_phase_timing_availability_and_triplets(self):
        adverse = []
        unavailable = self.report()
        struct.pack_into("<I", unavailable, 130, 1)
        adverse.append(unavailable)

        invalid_availability = self.report()
        invalid_availability[178] = 2
        adverse.append(invalid_availability)

        zero_count = self.report()
        zero_count[178] = 1
        struct.pack_into("<I", zero_count, 134, 1)
        adverse.append(zero_count)

        sum_below_max = self.report()
        sum_below_max[178] = 1
        struct.pack_into("<III", sum_below_max, 130, 2, 3, 4)
        adverse.append(sum_below_max)

        failure_without_count = self.report()
        failure_without_count[178] = 1
        struct.pack_into("<I", failure_without_count, 183, 0x55)
        adverse.append(failure_without_count)

        invalid_stage = self.report()
        invalid_stage[178] = 1
        struct.pack_into("<I", invalid_stage, 179, 1)
        invalid_stage[195] = 6
        adverse.append(invalid_stage)

        unknown_stage_with_result = self.report()
        unknown_stage_with_result[178] = 1
        struct.pack_into("<I", unknown_stage_with_result, 179, 1)
        struct.pack_into("<h", unknown_stage_with_result, 196, -7)
        adverse.append(unknown_stage_with_result)

        for mutated in adverse:
            with self.assertRaises(ValueError):
                decode_report(mutated)

    def test_rejects_length_header_reserved_and_tail_changes(self):
        report = self.report()
        for mutated in (report[:-1], report + b"\0"):
            with self.assertRaises(ValueError):
                decode_report(mutated)
        for offset in (0, 2, 3, 22, 77, 130, 198):
            mutated = bytearray(report)
            mutated[offset] = 0xFF
            with self.assertRaises(ValueError):
                decode_report(mutated)

    def test_rejects_inconsistent_state_and_pending_fields(self):
        report = self.report()
        adverse = []
        for status in (0x00, 0x37, 0x13, 0x23):
            mutated = bytearray(report)
            mutated[20] = status
            adverse.append(mutated)
        mutated = bytearray(report)
        mutated[21] = 0
        adverse.append(mutated)
        mutated = bytearray(report)
        mutated[21] = 17
        adverse.append(mutated)
        for mutated in adverse:
            with self.assertRaises(ValueError):
                decode_report(mutated)

        complete = bytearray(report)
        complete[20] = 0x35
        self.assertTrue(decode_report(complete).status & 0x04)

    def test_rejects_sample_validity_result_and_sentinel_mismatches(self):
        report = self.report()
        adverse = []
        mutated = bytearray(report)
        mutated[73] = 0
        adverse.append(mutated)
        mutated = bytearray(report)
        mutated[74] &= ~0x01
        adverse.append(mutated)
        mutated = bytearray(report)
        struct.pack_into("<h", mutated, 98, -5)
        adverse.append(mutated)
        mutated = bytearray(report)
        struct.pack_into("<h", mutated, 98, INT16_MIN)
        adverse.append(mutated)
        mutated = self.report_without_sample()
        mutated[74] = 1
        adverse.append(mutated)
        mutated = self.report()
        struct.pack_into("<I", mutated, 106, 0x20)
        adverse.append(mutated)
        for mutated in adverse:
            with self.assertRaises(ValueError):
                decode_report(mutated)

        decoded = decode_report(self.report_without_sample())
        self.assertFalse(decoded.rx_sample_valid)

    def test_rejects_timer_counter_relationships(self):
        adverse = []
        mutated = self.report()
        struct.pack_into("<I", mutated, 40, 4)
        adverse.append(mutated)
        mutated = self.report()
        struct.pack_into("<I", mutated, 44, 4)
        adverse.append(mutated)
        mutated = self.report()
        struct.pack_into("<I", mutated, 44, 0)
        adverse.append(mutated)
        mutated = self.report()
        struct.pack_into("<I", mutated, 48, 4)
        adverse.append(mutated)
        mutated = self.report()
        struct.pack_into("<I", mutated, 52, 0)
        adverse.append(mutated)
        for mutated in adverse:
            with self.assertRaises(ValueError):
                decode_report(mutated)

    def test_rejects_inactive_timer_with_due_timestamp_and_accepts_active_timer(self):
        mutated = self.report()
        struct.pack_into("<I", mutated, 110, 123)
        with self.assertRaises(ValueError):
            decode_report(mutated)

        active = self.report()
        active[72] = 1
        struct.pack_into("<I", active, 110, 123)
        self.assertTrue(decode_report(active).tx_timer_active)

    def test_op9_control_is_fixed_32_bytes(self):
        control = encode_snapshot_control(1, 2, 3, 1000, 219, 60000, 16)
        self.assertEqual(len(control), 32)
        self.assertEqual(control[3], 9)
        self.assertEqual(control[29:], b"\0\0\0")


if __name__ == "__main__":
    unittest.main()
