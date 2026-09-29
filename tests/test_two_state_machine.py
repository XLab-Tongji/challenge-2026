"""Minute replay checks for the NORMAL/FAULT inference path."""

import json
from pathlib import Path
import unittest
from unittest.mock import patch

from baseline.netcluster.fault_detection.evidence_cluster_machine.events import _prepare, minute_number
from baseline.netcluster.fault_detection.evidence_cluster_machine.missing import _missing_context
from baseline.netcluster.fault_detection.evidence_cluster_machine.two_state_engine import _startup, _value, infer_two_state
from test_two_state_support import event


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "baseline/netcluster/config"
FAMILY = json.loads((CONFIG / "evidence_cluster_family_priors.json").read_text(encoding="utf-8"))
SEMANTIC = json.loads((CONFIG / "two_state_semantic_priors.json").read_text(encoding="utf-8"))
FAMILY["event_diagnosticity"] = SEMANTIC["event_diagnosticity"]
FAMILY["coactivity_weight"] = SEMANTIC["coactivity_weight"]
FAMILY["missing_relation_same_entity"] = SEMANTIC["missing_relation_same_entity"]
FAULT = json.loads((CONFIG / "evidence_cluster_fault_priors.json").read_text(encoding="utf-8"))
RUNTIME = json.loads((CONFIG / "two_state_runtime.json").read_text(encoding="utf-8"))


class TwoStateTest(unittest.TestCase):
    def test_semantic_prior_covers_every_event_family_and_known_fault(self):
        self.assertEqual(set(SEMANTIC["coactivity_weight"]), set(FAMILY["family_salience"]))
        self.assertEqual(set(SEMANTIC["event_diagnosticity"]), set(FAMILY["family_salience"]))
        self.assertLessEqual(set(SEMANTIC["fault_weight_overrides"]), set(FAULT["fault_priors"]))

    def test_single_reliable_weak_resource_signal_is_only_a_candidate(self):
        row = event("disk-single", 0, "beida-service-vm-3", "disk_io_util", score=20.0)
        result = infer_two_state([row], FAMILY, FAULT, RUNTIME)
        self.assertFalse(result["incidents"])
        self.assertEqual(len(result["suspects"]), 1)
        self.assertEqual(result["suspects"][0]["start"], result["suspects"][0]["end"] - 1)

    def test_correlated_disk_families_add_bounded_startup_support(self):
        util = _prepare(event("util", 0, "beida-service-vm-3", "disk_io_util"), FAMILY, {})
        throughput = _prepare(event("rate", 0, "beida-service-vm-3", "disk_read_rate"), FAMILY, {})
        self.assertIsNotNone(util)
        self.assertIsNotNone(throughput)
        baseline, _ = _startup([util], util.start, FAMILY, RUNTIME)
        combined, _ = _startup([util, throughput], util.start, FAMILY, RUNTIME)
        self.assertGreater(combined, baseline)
        self.assertLess(combined, RUNTIME["start_threshold"])

    def test_same_family_metrics_do_not_gain_corroboration_bonus(self):
        cpu = _prepare(event("cpu", 0, "beida-service-vm-3", "cpu_usage"), FAMILY, {})
        load = _prepare(event("load", 0, "beida-service-vm-3", "load5"), FAMILY, {})
        self.assertIsNotNone(cpu)
        self.assertIsNotNone(load)
        score, _ = _startup([cpu, load], cpu.start, FAMILY, RUNTIME)
        self.assertAlmostEqual(score, max(_startup([cpu], cpu.start, FAMILY, RUNTIME)[0],
                                          _startup([load], load.start, FAMILY, RUNTIME)[0]))

    def test_low_quality_weak_signal_is_not_retained(self):
        row = event("disk-noise", 0, "beida-service-vm-3", "disk_io_util", score=0.0)
        result = infer_two_state([row], FAMILY, FAULT, RUNTIME)
        self.assertFalse(result["incidents"])
        self.assertFalse(result["suspects"])

    def test_strong_state_signal_starts_one_incident(self):
        row = event("bgp", 0, "beida-br-1", "bgp_peer_up", kind="state_anomaly",
                    direction=None, score=1, attributes={"raw_value": 0.0})
        result = infer_two_state([row], FAMILY, FAULT, RUNTIME)
        self.assertEqual(len(result["incidents"]), 1)
        self.assertEqual(result["incidents"][0]["fault_type"], "route_bgp_session_down")
        self.assertEqual(len(result["decision_trace"]), 1)

    def test_related_weak_resource_minutes_can_start(self):
        rows = [event(f"disk-{minute}", minute, "beida-service-vm-3", "disk_io_util")
                for minute in (0, 1, 2)]
        for row in rows:
            row["attributes"]["dependency_id"] = "same_disk_series"
        result = infer_two_state(rows, FAMILY, FAULT, RUNTIME)
        self.assertEqual(len(result["incidents"]), 1)
        self.assertEqual(result["incidents"][0]["start"], result["incidents"][0]["end"] - 3)

    def test_three_low_quality_new_observations_can_confirm_one_disk_fault(self):
        rows = [event(f"disk-{minute}", minute, "beida-service-vm-3", "disk_io_util", score=4.5)
                for minute in (0, 1, 2)]
        for row in rows:
            row["attributes"]["dependency_id"] = "same_disk_series"
        calibration = {"metric|disk_io_util|local_mad_z": {"count": 10, "q50": 10, "q90": 20}}
        result = infer_two_state(rows, FAMILY, FAULT, RUNTIME, calibration=calibration)
        self.assertEqual(len(result["incidents"]), 1)

    def test_repeated_identical_weak_value_cannot_start_or_extend(self):
        rows = [event(f"space-{minute}", minute, "beida-service-vm-3",
                      "filesystem_used_ratio", score=4.5,
                      attributes={"dependency_id": "same_space_series", "raw_value": 0.752})
                for minute in range(12)]
        calibration = {"metric|filesystem_used_ratio|local_mad_z":
                       {"count": 10, "q50": 10, "q90": 20}}
        result = infer_two_state(rows, FAMILY, FAULT, RUNTIME, calibration=calibration)
        self.assertFalse(result["incidents"])

    def test_large_ratio_step_may_hold_a_constant_fault_plateau(self):
        rows = [event(f"space-{minute}", minute, "beida-service-vm-3",
                      "filesystem_used_ratio", score=12.0,
                      attributes={"dependency_id": "same_space_series",
                                  "raw_value": 0.752, "baseline_value": 0.193})
                for minute in range(8)]
        calibration = {"metric|filesystem_used_ratio|local_mad_z":
                       {"count": 10, "q50": 12, "q90": 12}}
        result = infer_two_state(rows, FAMILY, FAULT, RUNTIME, calibration=calibration)
        self.assertEqual(len(result["incidents"]), 1)
        self.assertEqual(result["incidents"][0]["end"] - result["incidents"][0]["start"], 8)

    def test_tiny_ratio_offset_does_not_gain_plateau_support(self):
        rows = [event(f"space-{minute}", minute, "beida-service-vm-3",
                      "filesystem_used_ratio", score=12.0,
                      attributes={"dependency_id": "same_space_series",
                                  "raw_value": 0.7188, "baseline_value": 0.7187})
                for minute in range(8)]
        calibration = {"metric|filesystem_used_ratio|local_mad_z":
                       {"count": 10, "q50": 12, "q90": 12}}
        result = infer_two_state(rows, FAMILY, FAULT, RUNTIME, calibration=calibration)
        self.assertFalse(result["incidents"])

    def test_strong_ospf_cost_step_can_start_with_constant_new_state(self):
        rows = [event(f"cost-{minute}", minute, "beida-br-1", "ospf6_interface_cost",
                      score=12.0, attributes={"dependency_id": "same_ospf_interface",
                                              "raw_value": 100.0})
                for minute in range(5)]
        calibration = {"metric|ospf6_interface_cost|local_mad_z":
                       {"count": 10, "q50": 12, "q90": 12}}
        result = infer_two_state(rows, FAMILY, FAULT, RUNTIME, calibration=calibration)
        self.assertEqual(len(result["incidents"]), 1)
        self.assertEqual(result["incidents"][0]["end"] - result["incidents"][0]["start"], 5)

    def test_missingness_alone_cannot_start(self):
        row = event("missing", 0, "beida-service-vm-3", "cpu_usage")
        row.update({"observed": False, "anomaly_kind": "missing_value"})
        row["attributes"]["metric_source"] = "node_metrics"
        result = infer_two_state([row], FAMILY, FAULT, RUNTIME)
        self.assertFalse(result["incidents"])
        self.assertEqual(result["missing_source_count"], 1)

    def test_expected_missing_value_supports_a_related_fault(self):
        missing = event("missing", 0, "beida-br-1", "bgp_peer_up")
        missing.update({"observed": False, "anomaly_kind": "missing_value",
                        "score_kind": "historical_null_indicator", "raw_score": 1.0})
        missing["attributes"].update({"metric_source": "routing_metrics",
                                      "expected_basis": "historical_null_check"})
        down = event("bgp", 0, "beida-br-1", "bgp_peer_up", kind="state_anomaly",
                     direction=None, score=1, attributes={"raw_value": 0.0})
        result = infer_two_state([missing, down], FAMILY, FAULT, RUNTIME)
        self.assertEqual(result["evidence_count"], 2)
        self.assertEqual(len(result["incidents"]), 1)
        self.assertTrue(any(ident.startswith("missing-")
                            for ident in result["clusters"][0]["event_ids"]))

    def test_missing_quality_uses_collector_health_at_that_minute(self):
        rows = []
        for minute in (0, 1):
            row = event(f"missing-{minute}", minute, "beida-br-1", "cpu_usage")
            row["attributes"]["metric_source"] = "node_metrics"
            rows.append(row)
        events, _ = _missing_context(rows, {("beida-br-1", "node_metrics",
                                             minute_number(rows[1]["start_minute"]))}, RUNTIME)
        self.assertEqual(len(events), 2)
        self.assertGreater(events[0].quality, events[1].quality)
        contribution = _value(events[0], events[0].start, FAMILY, RUNTIME)
        self.assertGreaterEqual(contribution, RUNTIME["old_support_threshold"])
        self.assertLess(contribution, RUNTIME["same_fault_threshold"])

    def test_real_scrape_feature_downweights_expected_missing_event(self):
        missing = event("missing", 0, "beida-br-1", "cpu_usage")
        missing.update({"observed": False, "anomaly_kind": "missing_value"})
        missing["attributes"]["metric_source"] = "node_metrics"
        scrape = event("scrape", 0, "beida-br-1", "node_exporter__scrape_up",
                       kind="state_anomaly", direction=None, score=1,
                       attributes={"raw_value": 0.0})
        result = infer_two_state([missing, scrape], FAMILY, FAULT, RUNTIME)
        self.assertEqual(result["missing_context_events"][0]["attributes"]
                         ["collector_unhealthy_fraction"], 1.0)

    def test_node_scrape_failure_does_not_downweight_routing_missing(self):
        missing = event("missing", 0, "beida-br-1", "bgp_peer_up")
        missing.update({"observed": False, "anomaly_kind": "missing_value"})
        missing["attributes"]["metric_source"] = "routing_metrics"
        scrape = event("scrape", 0, "beida-br-1", "node_exporter__scrape_up",
                       kind="state_anomaly", direction=None, score=1,
                       attributes={"raw_value": 0.0})
        result = infer_two_state([missing, scrape], FAMILY, FAULT, RUNTIME)
        self.assertEqual(result["missing_context_events"][0]["attributes"]
                         ["collector_unhealthy_fraction"], 0.0)

    def test_unrelated_signal_is_not_attached_to_old_fault(self):
        rows = [event("bgp", 0, "beida-br-1", "bgp_peer_up", kind="state_anomaly",
                      direction=None, score=1, attributes={"raw_value": 0.0})]
        rows.append(event("cpu", 1, "xian-service-vm-3", "cpu_usage"))
        result = infer_two_state(rows, FAMILY, FAULT, RUNTIME)
        self.assertEqual(len(result["incidents"]), 1)
        self.assertTrue(any("cpu" in point.get("unassigned_event_ids", [])
                            for point in result["incidents"][0]["trace"]))

    def test_repeated_weak_points_in_one_episode_do_not_start(self):
        row = event("cpu-episode", 0, "beida-service-vm-3", "cpu_usage", last=12)
        result = infer_two_state([row], FAMILY, FAULT, RUNTIME)
        self.assertFalse(result["incidents"])

    def test_successor_switches_without_overlap(self):
        rows = [event("old", 0, "beida-br-1", "bgp_peer_up", kind="state_anomaly",
                      direction=None, score=1, attributes={"raw_value": 0.0})]
        for minute in (1, 2):
            rows.append(event(f"next-{minute}", minute, "xian-br-1", "bgp_peer_up",
                              kind="state_anomaly", direction=None, score=1,
                              attributes={"raw_value": 0.0}))
        result = infer_two_state(rows, FAMILY, FAULT, RUNTIME)
        self.assertEqual(len(result["incidents"]), 2)
        self.assertLessEqual(result["incidents"][0]["end"], result["incidents"][1]["start"])

    def test_recovery_takes_one_unsupported_minute(self):
        rows = [event("old", 0, "beida-br-1", "bgp_peer_up", kind="state_anomaly",
                      direction=None, score=1, attributes={"raw_value": 0.0})]
        result = infer_two_state(rows, FAMILY, FAULT, RUNTIME,
                                 coverage={"range": ("2026-08-19 04:00:00",
                                                     "2026-08-19 04:02:00")})
        recovered = [point for point in result["decision_trace"]
                     if point.get("transition") == "recovered"]
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0]["minute"], "2026-08-19 04:01:00")

    def test_strong_unrelated_signal_switches_on_first_recovery_minute(self):
        rows = [event("old", 0, "beida-br-1", "bgp_peer_up", kind="state_anomaly",
                      direction=None, score=1, attributes={"raw_value": 0.0}),
                event("new", 1, "xian-br-1", "bgp_peer_up", kind="state_anomaly",
                      direction=None, score=1, attributes={"raw_value": 0.0})]
        result = infer_two_state(rows, FAMILY, FAULT, RUNTIME)
        self.assertEqual(len(result["incidents"]), 2)
        self.assertEqual(result["incidents"][0]["end"], result["incidents"][1]["start"])
        self.assertTrue(any(point.get("transition") == "switch"
                            for point in result["decision_trace"]))

    def test_strong_old_support_keeps_stronger_new_evidence_in_same_fault(self):
        rows = [event("old", 0, "beida-br-1", "bgp_peer_up", kind="state_anomaly",
                      direction=None, score=1, attributes={"raw_value": 0.0}, last=3),
                event("new", 1, "xian-br-1", "bgp_peer_up", kind="state_anomaly",
                      direction=None, score=1, attributes={"raw_value": 0.0})]
        result = infer_two_state(rows, FAMILY, FAULT, RUNTIME)
        self.assertEqual(len(result["incidents"]), 1)
        self.assertIn("new", result["clusters"][0]["event_ids"])
        concurrent = next(point for point in result["decision_trace"] if point["minute"].endswith("04:01:00"))
        self.assertGreater(concurrent["S_new"], concurrent["S_old"])
        self.assertEqual(concurrent["transition"], "same_fault")

    def test_material_disk_util_and_rate_spike_stays_a_candidate_for_one_minute(self):
        rows = [event("util", 0, "beida-service-vm-3", "disk_io_util", score=12,
                      attributes={"raw_value": 51.0, "baseline_value": 0.4}),
                event("rate", 0, "beida-service-vm-3", "disk_write_rate", score=12,
                      attributes={"raw_value": 5_000_000.0, "baseline_value": 50_000.0})]
        result = infer_two_state(rows, FAMILY, FAULT, RUNTIME)
        self.assertFalse(result["incidents"])
        self.assertEqual(len(result["suspects"]), 1)

    def test_two_material_disk_util_minutes_need_regular_start_threshold(self):
        rows = [event(f"util-{minute}", minute, "beida-service-vm-3", "disk_io_util",
                      score=15.0, attributes={"dependency_id": "one_disk",
                                              "raw_value": 51.0, "baseline_value": 0.4})
                for minute in (0, 1)]
        calibration = {"metric|disk_io_util|local_mad_z":
                       {"count": 10, "q50": 10, "q90": 25}}
        result = infer_two_state(rows, FAMILY, FAULT, RUNTIME, calibration=calibration)
        self.assertFalse(result["incidents"])

    def test_two_material_cpu_minutes_need_regular_start_threshold(self):
        rows = [event(f"cpu-{minute}", minute, "beida-service-vm-3", "cpu_usage", score=15.0,
                      attributes={"dependency_id": "one_cpu", "raw_value": 20.0,
                                  "baseline_value": 0.5}) for minute in (0, 1)]
        calibration = {"metric|cpu_usage|local_mad_z": {"count": 10, "q50": 10, "q90": 25}}
        result = infer_two_state(rows, FAMILY, FAULT, RUNTIME, calibration=calibration)
        self.assertFalse(result["incidents"])

    def test_synchronous_cpu_on_multiple_entities_is_one_continuous_incident(self):
        rows = []
        for minute in range(8):
            for entity in ("chengdu-cr-1", "chengdu-traffic-vm", "xian-fw"):
                row = event(f"{entity}-{minute}", minute, entity, "cpu_usage",
                            attributes={"raw_value": 24.0 + minute * 0.02,
                                        "baseline_value": 0.7,
                                        "dependency_id": f"{entity}-cpu"})
                rows.append(row)
        result = infer_two_state(rows, FAMILY, FAULT, RUNTIME)
        self.assertEqual(len(result["incidents"]), 1)
        self.assertEqual(result["incidents"][0]["end"] - result["incidents"][0]["start"], 8)
        selected = result["clusters"][0]["event_ids"]
        self.assertTrue(any(event_id.startswith("xian-fw-") for event_id in selected))
        self.assertFalse(any(row["fault_type"] == "firewall_cpu_pressure"
                             for row in result["suspects"]))

    def test_material_cpu_plateau_keeps_fault_open(self):
        rows = [event(f"cpu-{minute}", minute, "xian-fw", "cpu_usage",
                      attributes={"raw_value": 30.0, "baseline_value": 0.7,
                                  "dependency_id": "xian-fw-cpu"})
                for minute in range(8)]
        result = infer_two_state(rows, FAMILY, FAULT, RUNTIME)
        self.assertEqual(len(result["incidents"]), 1)
        self.assertEqual(result["incidents"][0]["end"] - result["incidents"][0]["start"], 8)

    def test_strong_old_state_absorbs_sustained_new_resource_evidence(self):
        rows = [event("bgp", 0, "beida-br-1", "bgp_peer_up", kind="state_anomaly",
                      direction=None, score=1, attributes={"raw_value": 0.0}, last=7)]
        rows += [event(f"cpu-{minute}", minute, "xian-fw", "cpu_usage",
                       attributes={"raw_value": 30.0, "baseline_value": 0.7,
                                   "dependency_id": "xian-fw-cpu"})
                 for minute in range(2, 7)]
        result = infer_two_state(rows, FAMILY, FAULT, RUNTIME)
        self.assertEqual(len(result["incidents"]), 1)
        self.assertTrue(any(item.startswith("cpu-") for item in result["clusters"][0]["event_ids"]))

    def test_new_event_checks_earlier_accepted_event_after_anchor_replacement(self):
        rows = [event(ident, minute, "beida-br-1", "bgp_peer_up", kind="state_anomaly",
                      direction=None, score=1, attributes={"raw_value": 0.0})
                for ident, minute in (("first", 0), ("replacement", 1), ("later", 2))]

        def relation(left, right, _family, _minute):
            pair = {left.ident, right.ident}
            return 1.0 if left.ident == right.ident else (
                .9 if pair in ({"first", "replacement"}, {"first", "later"}) else 0.0)

        with patch("baseline.netcluster.fault_detection.evidence_cluster_machine.two_state_engine._relation",
                   side_effect=relation):
            result = infer_two_state(rows, FAMILY, FAULT, RUNTIME)
        self.assertEqual(len(result["incidents"]), 1)
        self.assertEqual(len(result["clusters"][0]["event_ids"]), 3)


if __name__ == "__main__":
    unittest.main()
