"""Post-interval root ranking must keep observed and inferred bindings distinct."""

import json
from pathlib import Path
import unittest

from baseline.netcluster.fault_detection.evidence_cluster_machine.events import _prepare
from baseline.netcluster.fault_detection.evidence_cluster_machine.rca import rank_root_candidates
from test_two_state_support import event


CONFIG = Path(__file__).resolve().parents[1] / "baseline/netcluster/config"
FAMILY = json.loads((CONFIG / "evidence_cluster_family_priors.json").read_text(encoding="utf-8"))
FAULT = json.loads((CONFIG / "evidence_cluster_fault_priors.json").read_text(encoding="utf-8"))


def prepared(*rows):
    return [_prepare(row, FAMILY, {}) for row in rows]


class RootRankingTest(unittest.TestCase):
    def rank(self, fault_type, rows, context=(), start=None, end=None):
        return rank_root_candidates(prepared(*rows), fault_type,
                                    FAULT["fault_priors"][fault_type], FAULT,
                                    context_events=prepared(*context), start=start, end=end)

    def test_route_flap_localizes_observed_border_router(self):
        rows = [event("change", 0, "beida-br-1", "ipv6_route_change_total")]
        roots = self.rank("route_bgp_route_flap", rows)
        self.assertEqual(roots[0]["root"], "beida-br-1")
        self.assertEqual(roots[0]["tier"], "observed_effect")
        self.assertIn("change", roots[0]["evidence_ids"])

    def test_dns_target_region_yields_tied_low_confidence_service_candidates(self):
        rows = [event("dns", 0, "xian-traffic-vm", "request_error_ratio",
                      modality="traffic_flow", kind="degradation",
                      attributes={"flow_type": "dns", "target_region": "beida",
                                  "target_domain": "dns.beida.aiops.local"})]
        roots = self.rank("service_dns_down", rows)
        self.assertEqual({row["root"] for row in roots},
                         {f"beida-service-vm-{index}" for index in (1, 2, 3)})
        self.assertTrue(all(row["tier"] == "region_hypothesis" for row in roots))
        self.assertTrue(all(row["score"] == roots[0]["score"] for row in roots))

    def test_firewall_hypothesis_uses_target_not_probe_source_region(self):
        rows = [event("timeout", 0, "xian-traffic-vm", "batch_timeout_ratio",
                      modality="traffic_flow", kind="degradation",
                      attributes={"flow_type": "web", "target_region": "beida"})]
        roots = self.rank("firewall_acl_drop", rows)
        self.assertEqual([row["root"] for row in roots], ["beida-fw"])
        self.assertEqual(roots[0]["tier"], "region_hypothesis")

    def test_link_observation_router_precedes_regional_guesses(self):
        rows = [event("flow", 0, "beida-br-1", "interface_bytes", modality="netflow",
                      direction="down", kind="volume_change",
                      attributes={"interface_id": "ens5"}),
                event("probe", 0, "xian-traffic-vm", "batch_timeout_ratio",
                      modality="traffic_flow", kind="degradation",
                      attributes={"flow_type": "web", "target_region": "shanghai"})]
        roots = self.rank("link_loss", rows)
        self.assertEqual(roots[0]["root"], "beida-br-1")
        self.assertEqual(roots[0]["tier"], "observation_point")
        self.assertLessEqual(len(roots), 5)

    def test_unrelated_event_provides_no_root(self):
        roots = self.rank("service_dns_down", [event("cpu", 0, "beida-fw", "cpu_usage")])
        self.assertEqual(roots, [])

    def test_target_region_anomaly_prioritizes_service_instance(self):
        probe = event("dns", 0, "xian-traffic-vm", "request_error_ratio",
                      modality="traffic_flow", kind="degradation",
                      attributes={"flow_type": "dns", "target_region": "beida"})
        local = event("service-cpu", 1, "beida-service-vm-2", "cpu_usage")
        other_region = event("remote-cpu", 1, "xian-service-vm-1", "cpu_usage")
        roots = self.rank("service_dns_down", [probe], [local, other_region])
        self.assertEqual(roots[0]["root"], "beida-service-vm-2")
        self.assertEqual(roots[0]["tier"], "regional_context")
        self.assertIn("service-cpu", roots[0]["evidence_ids"])
        self.assertNotIn("remote-cpu", roots[0]["evidence_ids"])

    def test_accepted_region_resource_anomaly_also_prioritizes_service_instance(self):
        probe = event("dns", 0, "xian-traffic-vm", "request_error_ratio",
                      modality="traffic_flow", kind="degradation",
                      attributes={"flow_type": "dns", "target_region": "beida"})
        local = event("accepted-cpu", 1, "beida-service-vm-3", "cpu_usage")
        roots = self.rank("service_dns_down", [probe, local], [probe, local])
        self.assertEqual(roots[0]["root"], "beida-service-vm-3")
        self.assertEqual(roots[0]["tier"], "regional_context")

    def test_late_anomaly_does_not_rank_target_region_component(self):
        probe = event("dns", 0, "xian-traffic-vm", "request_error_ratio",
                      modality="traffic_flow", kind="degradation",
                      attributes={"flow_type": "dns", "target_region": "beida"})
        late = event("late-cpu", 20, "beida-service-vm-2", "cpu_usage")
        roots = self.rank("service_dns_down", [probe], [late],
                          start=prepared(probe)[0].start, end=prepared(probe)[0].start + 3)
        self.assertTrue(all(root["tier"] == "region_hypothesis" for root in roots))

    def test_target_region_link_metric_prioritizes_affected_router(self):
        probe = event("timeout", 0, "xian-traffic-vm", "batch_timeout_ratio",
                      modality="traffic_flow", kind="degradation",
                      attributes={"flow_type": "web", "target_region": "beida"})
        interface = event("router-drop", 1, "beida-cr-2", "rx_bytes_rate", direction="down")
        roots = self.rank("link_loss", [probe], [interface])
        self.assertEqual(roots[0]["root"], "beida-cr-2")
        self.assertEqual(roots[0]["tier"], "regional_corrob")

    def test_disk_io_spike_does_not_localize_link_loss(self):
        probe = event("timeout", 0, "xian-traffic-vm", "batch_timeout_ratio",
                      modality="traffic_flow", kind="degradation",
                      attributes={"flow_type": "web", "target_region": "beida"})
        disk = event("router-disk", 1, "beida-br-1", "disk_io_util")
        roots = self.rank("link_loss", [probe], [disk])
        self.assertTrue(all(root["tier"] == "region_hypothesis" for root in roots))
        self.assertTrue(all("router-disk" not in root["evidence_ids"] for root in roots))


if __name__ == "__main__":
    unittest.main()
