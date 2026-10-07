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

    def test_rejects_length_header_reserved_and_tail_changes(self):
        report = self.report()
        for mutated in (report[:-1], report + b"\0"):
            with self.assertRaises(ValueError):
                decode_report(mutated)
        for offset in (0, 2, 3, 22, 77, 130):
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
