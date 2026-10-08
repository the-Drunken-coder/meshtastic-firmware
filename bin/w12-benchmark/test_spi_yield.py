"""Pure protocol and collection-boundary tests for the kind-9 SPI-yield page."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import struct
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock
from pathlib import Path


HERE = Path(__file__).parent


def _load(name: str):
    path = HERE / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


benchmark = _load("benchmark_probe")
spi_yield = _load("spi_yield")
radio_gaps = _load("radio_gaps")


def _wire(
    *,
    status: int = 0x0D,
    pending: int = 0,
    run_id: int = 1,
    source: int = 2,
    destination: int = 3,
    requested_hz: int = 8_000_000,
) -> bytearray:
    data = bytearray(spi_yield.REPORT_BYTES)
    struct.pack_into(
        "<HBBIIII",
        data,
        0,
        spi_yield.MAGIC,
        spi_yield.VERSION,
        spi_yield.KIND,
        run_id,
        source,
        destination,
        60000,
    )
    data[20] = status
    data[21] = pending
    struct.pack_into("<I", data, 24, requested_hz)
    struct.pack_into("<I", data, 28, 1)
    struct.pack_into("<Q", data, 32, 219)
    struct.pack_into("<Q", data, 40, 10)
    struct.pack_into("<I", data, 48, 10)
    struct.pack_into("<I", data, 52, 1)
    struct.pack_into("<Q", data, 56, 2)
    struct.pack_into("<I", data, 64, 2)
    data[68] = spi_yield.PUBLIC_HAL_SOURCE
    if not status & spi_yield.STATUS_AVAILABLE:
        data[28:68] = b"\0" * 40
    return data


def _run_with_clock_provenance(
    root: Path,
    *,
    requested: bool = True,
    base_hz: int = 8_000_000,
    walker_hz: int = 8_000_000,
    hal_timing: bool = True,
) -> Path:
    run_dir = root / "run"
    run_dir.mkdir(parents=True)
    identities = {
        "base": ("44:B1:76:AE:19:14", 2686237816),
        "walker": ("44:B1:76:AE:20:18", 1273374798),
    }
    image_hashes = {}
    image_hashes_by_role = {}
    for role in identities:
        image = root / f"{role}.bin"
        image.write_bytes(f"{role}-image".encode())
        image_hash = hashlib.sha256(image.read_bytes()).hexdigest()
        image_hashes[str(image)] = image_hash
        image_hashes_by_role[role] = {"path": str(image), "sha256": image_hash}
    configuration_before = {
        role: {"usb_identity": identity, "node_num": node}
        for role, (identity, node) in identities.items()
    }
    results = {
        "intent": {
            "sender": "base",
            "receiver": "walker",
            "spi_yield_requested": requested,
        },
        "configuration_before": configuration_before,
        "provenance": {
            "image_hashes": image_hashes,
            "image_hashes_by_role": image_hashes_by_role,
        },
    }
    results_path = run_dir / "results.json"
    results_path.write_text(json.dumps(results), encoding="utf-8")
    source_revision = "a" * 40
    source_records = {}
    boards = {}
    for role, (identity, node) in identities.items():
        hz = base_hz if role == "base" else walker_hz
        application_hash = image_hashes[str(root / f"{role}.bin")]
        build_path = root / f"{role}-build.json"
        build_path.write_text(
            json.dumps(
                {
                    "application_source_revision": source_revision,
                    "files": {"firmware.bin": {"sha256": application_hash}},
                    "experimental_flags": {
                        "requested_spi_hz": hz,
                        "hal_timing": hal_timing,
                    },
                }
            ),
            encoding="utf-8",
        )
        flash_path = root / f"{role}-flash.json"
        flash_path.write_text(
            json.dumps(
                {
                    "identity": identity,
                    "app_only": True,
                    "status": spi_yield.FLASH_VERIFIED_STATUS,
                    "application_sha256": application_hash,
                    "application_source_revision": source_revision,
                }
            ),
            encoding="utf-8",
        )
        source_records[f"{role}_build"] = {
            "path": str(build_path),
            "sha256": hashlib.sha256(build_path.read_bytes()).hexdigest(),
        }
        source_records[f"{role}_flash"] = {
            "path": str(flash_path),
            "sha256": hashlib.sha256(flash_path.read_bytes()).hexdigest(),
        }
        boards[role] = {
            "usb_identity": identity,
            "node_num": node,
            "source_revision": source_revision,
            "application_sha256": application_hash,
            "requested_spi_hz": hz,
            "hal_timing": hal_timing,
        }
    results_hash = hashlib.sha256(results_path.read_bytes()).hexdigest()
    (run_dir / spi_yield.FIRMWARE_PROVENANCE_NAME).write_text(
        json.dumps(
            {
                "result_sha256": results_hash,
                "boards": boards,
                "source_records": source_records,
                "policy": {"requested_spi_hz": base_hz},
            }
        ),
        encoding="utf-8",
    )
    return run_dir


def _mutate_source_record(record: dict, name: str, mutate) -> None:
    source = record["source_records"][name]
    path = Path(source["path"])
    value = json.loads(path.read_text(encoding="utf-8"))
    mutate(value)
    path.write_text(json.dumps(value), encoding="utf-8")
    source["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()


def _run_fake_spi_collection(
    root: Path,
    *,
    report_status: int = 0x0D,
    report_clock: int = 8_000_000,
    close_ok: bool = True,
    health_ok: bool = True,
) -> dict:
    run_dir = _run_with_clock_provenance(root)
    output = root / "page"
    identities = benchmark.BOARD_IDENTITIES
    config = SimpleNamespace(
        run_id=1,
        source=identities["base"][1],
        destination=identities["walker"][1],
        duration_ms=60_000,
    )
    config_fields = {
        field: f"{field}-digest"
        for field in (
            "local_config_sha256",
            "module_config_sha256",
            "channels_sha256",
            "lora_sha256",
            "private_key_sha256",
            "public_key_sha256",
        )
    }
    expected_configs = {
        role: json.dumps(config_fields, sort_keys=True)
        for role in identities
    }
    report = spi_yield.decode_report(
        _wire(
            status=report_status,
            run_id=config.run_id,
            source=config.source,
            destination=config.destination,
            requested_hz=report_clock,
        )
    )

    class Capture:
        def __init__(self) -> None:
            self.events: list[dict] = []

        def snapshot(self) -> list[dict]:
            return list(self.events)

        def persist(self) -> bool:
            return True

    class Session:
        def __init__(self, role: str, _output: Path, _command_gap: float) -> None:
            self.role = role
            self.identity, self.node_num = identities[role]
            self.capture = Capture()
            self.interface = SimpleNamespace(stream=None)

        def snapshot_config(self, _output: Path, _label: str) -> dict:
            return {
                **config_fields,
                "usb_identity": self.identity,
                "node_num": self.node_num,
            }

        def snapshot_spi_yield(self, _config: object, _timeout: float) -> spi_yield.SpiYieldReport:
            return report

        def _response_event_matches(self, *_args: object) -> bool:
            return True

    class Benchmark:
        BOARD_IDENTITIES = identities
        __file__ = str((HERE / "benchmark_probe.py").resolve())

        @staticmethod
        def sha256_file(path: Path) -> str:
            return hashlib.sha256(Path(path).read_bytes()).hexdigest()

        @staticmethod
        def _utc_now() -> str:
            return "2026-10-08T00:00:00Z"

        @staticmethod
        def _safe_json_write(path: Path, value: object) -> None:
            path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")

    def prepare(_session: Session) -> None:
        return None

    def health(sessions: dict[str, Session]) -> tuple[dict, dict]:
        if health_ok:
            return ({role: {"serial_open": True} for role in sessions}, {})
        return ({role: {} for role in sessions}, {role: ["health failed"] for role in sessions})

    def close(
        sessions: dict[str, Session],
        close_results: dict[str, bool],
        _merged_health: dict,
        _merged_failures: dict,
        close_errors: dict,
    ) -> None:
        for role in sessions:
            close_results[role] = close_ok
            if not close_ok:
                close_errors[role] = "fake close failed"

    radio_gaps._load_health_helpers()
    reliable_module = sys.modules["reliable_pilot"]
    for helper in (prepare, health, close):
        helper.__module__ = reliable_module.__name__

    with (
        mock.patch.object(radio_gaps, "_load_benchmark", return_value=Benchmark),
        mock.patch.object(
            radio_gaps,
            "_validate_existing_run",
            return_value=(config, expected_configs, {"base": "a", "walker": "b"}),
        ),
        mock.patch.object(radio_gaps, "_runtime_provenance", return_value={}),
        mock.patch.object(radio_gaps, "_load_health_helpers", return_value=(prepare, health, close)),
        mock.patch.object(
            spi_yield,
            "_required_spi_clock_provenance",
            return_value={"base": 8_000_000, "walker": 8_000_000},
        ),
    ):
        return spi_yield.collect_spi_yield(run_dir, output, session_factory=Session)


class SpiYieldProtocolTests(unittest.TestCase):
    def test_active_page_round_trips_and_makes_only_local_claims(self):
        report = spi_yield.decode_report(_wire())
        self.assertTrue(report.available)
        self.assertTrue(report.snapshot_terminal)
        self.assertEqual(report.requested_hz, 8_000_000)
        evaluation = spi_yield.evaluate_report(report)
        self.assertTrue(evaluation["measurement_valid"])
        self.assertTrue(all(value is False for value in evaluation["physical_claims"].values()))
        with self.assertRaisesRegex(spi_yield.BenchmarkError, "does not match recorded"):
            spi_yield._validate_report_clock("base", report, {"base": 4_000_000})
        spi_yield._validate_report_clock("base", report, {"base": 8_000_000})

    def test_inactive_page_is_decodable_metadata_with_zero_metrics(self):
        report = spi_yield.decode_report(_wire(status=0x05))
        self.assertFalse(report.available)
        self.assertEqual(report.transfer_count, 0)
        self.assertEqual(report.yield_count, 0)
        evaluation = spi_yield.evaluate_report(report)
        self.assertIn("spi_yield_unavailable", evaluation["failure_reasons"])
        self.assertEqual(evaluation["requested_clock_hz"], 8_000_000)

    def test_duration_bounds_empty_and_saturated(self):
        invalid = _wire()
        struct.pack_into("<I", invalid, 28, 0)
        with self.assertRaises(ValueError):
            spi_yield.decode_report(invalid)

        invalid = _wire()
        struct.pack_into("<Q", invalid, 40, spi_yield.UINT64_MAX)
        with self.assertRaises(ValueError):
            spi_yield.decode_report(invalid)

        overflow = _wire()
        overflow[69] = 1
        struct.pack_into("<Q", overflow, 40, spi_yield.UINT64_MAX)
        report = spi_yield.decode_report(overflow)
        self.assertIn("spi_yield_overflow", spi_yield.evaluate_report(report)["failure_reasons"])

    def test_strict_adverse_bounds_and_identity(self):
        mutations = []
        invalid = _wire()
        invalid[22] = 1
        mutations.append(invalid)
        invalid = _wire()
        invalid[68] = 2
        mutations.append(invalid)
        invalid = _wire()
        struct.pack_into("<I", invalid, 24, 915_000_000)
        mutations.append(invalid)
        invalid = _wire()
        invalid[21] = 1
        mutations.append(invalid)
        invalid = _wire(status=0x0F)
        mutations.append(invalid)
        invalid = _wire()
        struct.pack_into("<Q", invalid, 40, 11)
        mutations.append(invalid)
        for payload in mutations:
            with self.subTest(payload=bytes(payload)):
                with self.assertRaises(ValueError):
                    spi_yield.decode_report(payload)

    def test_control_operations_are_accepted_without_version_change(self):
        run = benchmark.RunConfig(1, 2, 3, 1000, 219, 60000, 16, 0)
        for operation in (benchmark.CONTROL_SNAPSHOT_SPI_YIELD, benchmark.CONTROL_ENABLE_SPI_YIELD):
            payload = benchmark.encode_control(run, operation)
            self.assertEqual(len(payload), benchmark.CONTROL_BYTES)
            self.assertEqual(benchmark.decode_control(payload), (operation, run))
            self.assertEqual(payload[2], benchmark.VERSION)

    def test_enable_is_default_off_and_run_metadata_is_explicit(self):
        parser = benchmark.build_parser()
        args = parser.parse_args([])
        self.assertFalse(args.spi_yield)
        self.assertEqual(
            benchmark.start_control_operations(False),
            (benchmark.CONTROL_RESET, benchmark.CONTROL_START),
        )
        self.assertEqual(
            benchmark.start_control_operations(True),
            (
                benchmark.CONTROL_RESET,
                benchmark.CONTROL_ENABLE_SPI_YIELD,
                benchmark.CONTROL_START,
            ),
        )
        run = benchmark.RunConfig(1, 2, 3, 1000, 219, 60000, 16, 0)
        self.assertEqual(benchmark.encode_control(run, benchmark.CONTROL_ENABLE_SPI_YIELD)[3], 12)

    def test_finite_provenance_gate_rejects_missing_completed_run_before_open(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(spi_yield.BenchmarkError):
                spi_yield.collect_spi_yield(Path(directory) / "missing", Path(directory) / "out")
            for kwargs, expected_text in (
                ({"requested": False}, "spi_yield_requested"),
                ({"hal_timing": False}, "hal_timing"),
                ({"base_hz": 915_000_000}, "clock disagrees"),
                ({"base_hz": 4_000_000, "walker_hz": 8_000_000}, "mixed SPI clocks"),
            ):
                with self.subTest(expected_text=expected_text), tempfile.TemporaryDirectory() as nested:
                    run_dir = _run_with_clock_provenance(Path(nested), **kwargs)
                    with mock.patch.object(
                        radio_gaps,
                        "_collect_page",
                        side_effect=AssertionError("session collector opened"),
                    ):
                        with self.assertRaisesRegex(spi_yield.BenchmarkError, expected_text):
                            spi_yield.collect_spi_yield(run_dir, Path(nested) / "out")

            valid_dir = _run_with_clock_provenance(Path(directory) / "valid")
            self.assertEqual(
                spi_yield._required_spi_clock_provenance(valid_dir),
                {"base": 8_000_000, "walker": 8_000_000},
            )
            stale_cases = (
                ("result_sha256", lambda record: record.update(result_sha256="0" * 64), "result_sha256"),
                (
                    "usb_identity",
                    lambda record: record["boards"]["base"].update(usb_identity="stale"),
                    "BOARD_IDENTITIES",
                ),
                (
                    "node_num",
                    lambda record: record["boards"]["base"].update(node_num=1),
                    "BOARD_IDENTITIES",
                ),
                (
                    "source_revision",
                    lambda record: record["boards"]["base"].update(source_revision="b" * 40),
                    "source_revision",
                ),
                (
                    "application_sha256",
                    lambda record: record["boards"]["base"].update(application_sha256="0" * 64),
                    "primary provenance",
                ),
                (
                    "source_hash",
                    lambda record: record["source_records"]["base_build"].update(sha256="0" * 64),
                    "source hash changed",
                ),
                (
                    "error_flash_status",
                    lambda record: _mutate_source_record(
                        record,
                        "base_flash",
                        lambda value: value.update(status="error"),
                    ),
                    "identity/application scope",
                ),
                (
                    "missing_build_clock",
                    lambda record: _mutate_source_record(
                        record,
                        "base_build",
                        lambda value: value["experimental_flags"].pop("requested_spi_hz"),
                    ),
                    "clock disagrees",
                ),
                (
                    "missing_build_hal_timing",
                    lambda record: _mutate_source_record(
                        record,
                        "base_build",
                        lambda value: value["experimental_flags"].pop("hal_timing"),
                    ),
                    "hal_timing",
                ),
            )
            for label, mutate, expected_text in stale_cases:
                with self.subTest(stale=label):
                    stale_root = Path(directory) / f"stale-{label}"
                    stale_dir = _run_with_clock_provenance(stale_root)
                    provenance_path = stale_dir / spi_yield.FIRMWARE_PROVENANCE_NAME
                    record = json.loads(provenance_path.read_text(encoding="utf-8"))
                    mutate(record)
                    provenance_path.write_text(json.dumps(record), encoding="utf-8")
                    with mock.patch.object(
                        radio_gaps,
                        "_collect_page",
                        side_effect=AssertionError("session collector opened"),
                    ):
                        with self.assertRaisesRegex(spi_yield.BenchmarkError, expected_text):
                            spi_yield.collect_spi_yield(stale_dir, stale_root / "out")

            swapped_root = Path(directory) / "swapped-role-image"
            swapped_dir = _run_with_clock_provenance(swapped_root)
            swapped_results_path = swapped_dir / "results.json"
            swapped_results = json.loads(swapped_results_path.read_text(encoding="utf-8"))
            by_role = swapped_results["provenance"]["image_hashes_by_role"]
            by_role["base"], by_role["walker"] = by_role["walker"], by_role["base"]
            swapped_results_path.write_text(json.dumps(swapped_results), encoding="utf-8")
            swapped_provenance_path = swapped_dir / spi_yield.FIRMWARE_PROVENANCE_NAME
            swapped_provenance = json.loads(swapped_provenance_path.read_text(encoding="utf-8"))
            swapped_provenance["result_sha256"] = hashlib.sha256(
                swapped_results_path.read_bytes()
            ).hexdigest()
            swapped_provenance_path.write_text(json.dumps(swapped_provenance), encoding="utf-8")
            with mock.patch.object(
                radio_gaps,
                "_collect_page",
                side_effect=AssertionError("session collector opened"),
            ):
                with self.assertRaisesRegex(spi_yield.BenchmarkError, "role-bound primary provenance"):
                    spi_yield.collect_spi_yield(swapped_dir, swapped_root / "out")

    def test_missing_collector_provenance_is_rejected_before_session_open(self):
        factory_calls = []

        def factory(*args):
            factory_calls.append(args)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "run"
            run_dir.mkdir()
            (run_dir / "results.json").write_text("{}", encoding="utf-8")
            benchmark_stub = object()
            with mock.patch.object(radio_gaps, "_load_benchmark", return_value=benchmark_stub), mock.patch.object(
                radio_gaps,
                "_validate_existing_run",
                return_value=(object(), {}, {}),
            ), mock.patch.object(radio_gaps, "_runtime_provenance", return_value={}):
                with self.assertRaisesRegex(radio_gaps.BenchmarkError, "provenance file is missing"):
                    radio_gaps._collect_page(
                        run_dir,
                        root / "output",
                        session_factory=factory,
                        operation=spi_yield.SNAPSHOT_OP,
                        field_name="spi_yield",
                        page_label="spi-yield",
                        page_decoder=spi_yield.decode_report,
                        page_mapping_decoder=spi_yield.report_from_mapping,
                        page_report_dict=spi_yield._report_dict,
                        page_evaluator=spi_yield.evaluate_report,
                        session_method=None,
                        scope="board_local_public_hal_spi_yield",
                        software_budget="timing",
                        provenance_files=(root / "missing.py",),
                    )
        self.assertEqual(factory_calls, [])

    def test_wrong_reply_metadata_fails_closed(self):
        class Session:
            @staticmethod
            def _response_event_matches(_event, _packet_id, _key, _config, _deadline):
                return True

        event = {
            "portnum": spi_yield.PRIVATE_APP_PORTNUM,
            "transport": spi_yield.TRANSPORT_INTERNAL,
            "want_ack": False,
            "pki_encrypted": False,
            "via_mqtt": False,
        }
        self.assertTrue(radio_gaps._page_event_matches(Session(), event, 1, object(), 2.0, "spi_yield"))
        for field, value in (
            ("portnum", 1),
            ("transport", 1),
            ("want_ack", True),
            ("pki_encrypted", True),
            ("via_mqtt", True),
        ):
            invalid = dict(event)
            invalid[field] = value
            self.assertFalse(
                radio_gaps._page_event_matches(Session(), invalid, 1, object(), 2.0, "spi_yield")
            )

    def test_collection_output_requires_new_directory_and_preserves_close_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            run_dir.mkdir()
            (run_dir / "results.json").write_text("{}", encoding="utf-8")
            with self.assertRaises(spi_yield.BenchmarkError):
                spi_yield.collect_spi_yield(run_dir, run_dir)

            valid = _run_fake_spi_collection(Path(directory) / "valid")
            self.assertTrue(valid["measurement_valid"])
            self.assertTrue(all(row["measurement_valid"] for row in valid["boards"].values()))
            self.assertEqual(valid["collection_window"]["scope"], "per_board")
            self.assertEqual(
                valid["collection_window"]["anchor"],
                "each board's accepted START handler",
            )
            self.assertTrue(valid["collection_window"]["receiver_includes_pre_sender_armed_interval"])
            self.assertEqual(
                valid["collection_window"]["host_sender_wall_anchor"],
                "sender START return (producer wall-clock only)",
            )
            collector_files = valid["provenance"]["collector_files"]
            self.assertIn(str((HERE / "benchmark_probe.py").resolve()), collector_files)
            self.assertIn(str(Path(radio_gaps.__file__).resolve()), collector_files)
            self.assertIn(str((HERE / "spi_yield.py").resolve()), collector_files)
            self.assertIn(str((HERE / "spi-yield-protocol.json").resolve()), collector_files)
            self.assertIn(
                str((Path(valid["existing_run"]) / spi_yield.FIRMWARE_PROVENANCE_NAME).resolve()),
                collector_files,
            )
            self.assertIn(
                str(Path(sys.modules["reliable_pilot"].__file__).resolve()),
                collector_files,
            )
            for label, kwargs in (
                ("wrong-clock", {"report_clock": 4_000_000}),
                ("inactive", {"report_status": 0x05}),
                ("close-false", {"close_ok": False}),
                ("health-fail", {"health_ok": False}),
            ):
                with self.subTest(collection_failure=label):
                    result = _run_fake_spi_collection(Path(directory) / label, **kwargs)
                    self.assertFalse(result["measurement_valid"])
                    self.assertTrue(
                        all(
                            row["measurement_valid"] is False and row["status"] == "invalid"
                            for row in result["boards"].values()
                        )
                    )


if __name__ == "__main__":
    unittest.main()
