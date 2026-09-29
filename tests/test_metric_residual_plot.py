from datetime import datetime
from pathlib import Path
import tempfile
import unittest

from baseline.netcluster.anomaly_detector.metric.baselines import BaselineResult, safe_filename
from baseline.netcluster.anomaly_detector.metric.detector import MetricProfile, plot_path_for_metric, write_plot_html


class MetricResidualPlotTests(unittest.TestCase):
    def test_plot_path_groups_metrics_by_source_type(self):
        with tempfile.TemporaryDirectory() as directory:
            path = plot_path_for_metric(
                Path(directory),
                "beida.br-1.interface_metrics.ens10_drop_rate",
            )

        self.assertEqual(path.parent.name, "interface_metrics")
        self.assertEqual(path.name, "beida.br-1.interface_metrics.ens10_drop_rate.html")

    def test_safe_filename_shortens_long_metric_names_without_collisions(self):
        prefix = "beida.br-1.routing_metrics.ipv6_route_info__label_urlencoded_"
        left = safe_filename(prefix + "a" * 240)
        right = safe_filename(prefix + "b" * 240)

        self.assertLessEqual(len(left), 120)
        self.assertNotEqual(left, right)

    def test_first_panel_keeps_raw_values_without_baseline_trace(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plot.html"
            write_plot_html(
                "beida.br-1.node_metrics.cpu_usage",
                [datetime(2026, 8, 19, 4, 0)], [2.5], [2.0], [0.0], [0.0], [0.5], [],
                MetricProfile("metric", None, "none", 0.0, 0.0, 0.0),
                BaselineResult("metric", "direct_ecod_raw", [2.0], [0.5], "residual", {}), path,
            )
            content = path.read_text(encoding="utf-8")

        self.assertIn('name: "raw value"', content)
        self.assertNotIn('name: "normal baseline"', content)


if __name__ == "__main__":
    unittest.main()
