from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
import unittest

from baseline.netcluster.anomaly_detector.metric.detector import (
    DetectionRules,
    MetricDetectionRule,
    ResidualAdConfig,
    detect_local_mad_points,
    detect_single_metric,
    has_minimum_change,
    load_detection_rules,
    resolve_metric_rule,
)


class LocalMadTests(unittest.TestCase):
    def setUp(self):
        start = datetime(2026, 8, 19, 4)
        self.times = [start + timedelta(minutes=index) for index in range(130)]

    def test_sustained_shift_keeps_previous_normal_reference(self):
        values = [10.0] * 100 + [20.0] * 10 + [10.0] * 20
        points = detect_local_mad_points(
            self.times, values, mad_floor=1.0, direction_filter="high",
        )
        self.assertEqual([point["point_index"] for point in points], list(range(100, 110)))
        self.assertTrue(all(point["baseline"] == 10.0 for point in points))

    def test_wrong_direction_and_short_history_do_not_alert(self):
        values = [10.0] * 100 + [20.0] * 10 + [10.0] * 20
        self.assertEqual(detect_local_mad_points(self.times, values, mad_floor=1.0, direction_filter="low"), [])
        self.assertEqual(detect_local_mad_points(self.times[:15], values[:15], mad_floor=1.0), [])

    def test_aio_ps3_warmup_detects_spike_after_three_normal_points(self):
        self.assertEqual(ResidualAdConfig().mad_min_history, 3)
        values = [10.0, 10.0, 10.0, 30.0, 10.0]
        points = detect_local_mad_points(
            self.times[:5], values, mad_floor=1.0,
            direction_filter="high", config=ResidualAdConfig(mad_min_history=3),
        )
        self.assertEqual([point["point_index"] for point in points], [3])

    def test_isolated_strong_local_spike_is_kept_without_run_gate(self):
        values = [10.0] * 100 + [30.0] + [10.0] * 29
        points = detect_local_mad_points(
            self.times, values, mad_floor=1.0, direction_filter="high",
        )
        self.assertEqual([point["point_index"] for point in points], [100])

    def test_metric_specific_relative_floor_detects_small_ratio_drop(self):
        values = [0.9] * 100 + [0.85] + [0.9] * 29
        points = detect_local_mad_points(
            self.times, values, mad_floor=0.005, direction_filter="low",
            relative_floor=0.0,
        )
        self.assertEqual([point["point_index"] for point in points], [100])

    def test_optional_two_minute_gate_keeps_points_separate(self):
        values = [10.0] * 100 + [20.0] + [10.0] * 4 + [20.0] * 2 + [10.0] * 23
        points = detect_local_mad_points(
            self.times, values, mad_floor=1.0, direction_filter="high", min_run_points=2,
        )
        self.assertEqual([point["point_index"] for point in points], [105, 106])

    def test_two_point_gate_allows_one_normal_minute_between_outliers_when_configured(self):
        values = [10.0] * 100 + [20.0, 20.0, 10.0, 25.0] + [10.0] * 26
        without_gap = detect_local_mad_points(
            self.times, values, mad_floor=1.0, direction_filter="high",
            min_run_points=2, max_gap_minutes=0,
        )
        with_gap = detect_local_mad_points(
            self.times, values, mad_floor=1.0, direction_filter="high",
            min_run_points=2, max_gap_minutes=1,
        )
        self.assertEqual([point["point_index"] for point in without_gap], [100, 101])
        self.assertEqual([point["point_index"] for point in with_gap], [100, 101, 103])

    def test_rule_selects_mad_without_ecod(self):
        values = [10.0] * 100 + [20.0] * 10 + [10.0] * 20
        rules = DetectionRules(
            default_rule=MetricDetectionRule(numeric_detectors="ecod"),
            rules=(("beida.service-vm-1.node_metrics.cpu_usage", MetricDetectionRule(
                numeric_detectors="mad", mad_floor=1.0, tail="upper",
            )),),
        )
        outcome = detect_single_metric(
            "beida.service-vm-1.node_metrics.cpu_usage", values, self.times,
            ResidualAdConfig(), rules, False, Path("."),
        )
        self.assertEqual(len(outcome.events), 10)
        self.assertTrue(all(event["detector"] == "local_mad_raw" for event in outcome.events))

    def test_both_methods_emit_one_event_per_minute(self):
        values = [10.0] * 100 + [20.0] * 10 + [10.0] * 20
        rules = DetectionRules(default_rule=MetricDetectionRule(
            numeric_detectors="both", mad_floor=1.0, tail="upper",
        ))
        outcome = detect_single_metric(
            "beida.service-vm-1.node_metrics.cpu_usage", values, self.times,
            ResidualAdConfig(), rules, False, Path("."),
        )
        self.assertEqual(len(outcome.events), 10)
        self.assertEqual(len({event["start_time"] for event in outcome.events}), 10)

    def test_config_selects_local_mad_for_fault_anchors_and_ecod_for_volume(self):
        rules = load_detection_rules()
        cpu = resolve_metric_rule("beida.service-vm-1.node_metrics.cpu_usage", rules)
        disk = resolve_metric_rule("beida.service-vm-1.node_metrics.disk_io_util", rules)
        memory = resolve_metric_rule("beida.service-vm-1.node_metrics.memory_available_ratio", rules)
        drop = resolve_metric_rule("beida.br-1.interface_metrics.ens4_rx_drop_rate", rules)
        traffic = resolve_metric_rule("beida.br-1.interface_metrics.ens4_rx_bytes_rate", rules)
        cost = resolve_metric_rule("beida.br-1.routing_metrics.ospf6_interface_cost", rules)
        state = resolve_metric_rule("beida.br-1.routing_metrics.bgp_peer_up", rules)
        self.assertEqual((cpu.numeric_detectors, cpu.mad_floor, cpu.mad_min_run_points), ("both", 2.0, 3))
        self.assertEqual((disk.numeric_detectors, disk.mad_floor, disk.mad_min_run_points), ("both", 5.0, 1))
        self.assertEqual((memory.numeric_detectors, memory.mad_relative_floor), ("both", 0.0))
        self.assertEqual(drop.numeric_detectors, "mad")
        self.assertEqual(traffic.numeric_detectors, "ecod")
        self.assertEqual(cost.numeric_detectors, "mad")
        self.assertEqual(state.workflow, "state")

    def test_minimum_change_uses_raw_units_after_residual_detection(self):
        rule = MetricDetectionRule(min_absolute_change=0.005)
        point = {"point_index": 0, "baseline": 0.719}
        self.assertFalse(has_minimum_change(point, [0.7191], rule))
        self.assertTrue(has_minimum_change(point, [0.729], rule))

    def test_relative_change_scales_with_scrape_sample_baseline(self):
        rule = MetricDetectionRule(min_relative_change=0.02)
        self.assertFalse(has_minimum_change({"point_index": 0, "baseline": 1580.0}, [1570.0], rule))
        self.assertTrue(has_minimum_change({"point_index": 0, "baseline": 1580.0}, [0.0], rule))


if __name__ == "__main__":
    unittest.main()
