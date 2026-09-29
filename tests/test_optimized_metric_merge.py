from __future__ import annotations

import csv
import json
from pathlib import Path
import tempfile
import unittest

from baseline.netcluster.cli.build_optimized_metric_results import merge_coverage, merge_events, merge_evidence


class OptimizedMetricMergeTests(unittest.TestCase):
    def test_replaces_changed_metric_and_preserves_unchanged_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old_evidence = root / "old.jsonl"
            new_evidence = root / "new.jsonl"
            unchanged = "beida.vm.node_metrics.disk_read_rate"
            changed = "beida.vm.node_metrics.cpu_usage"

            def evidence(metric: str, minute: str, score: int) -> str:
                return json.dumps({"start_minute": minute, "raw_score": score,
                                   "attributes": {"metric_id": metric}}) + "\n"

            old_line = evidence(unchanged, "2026-08-19 04:00:00", 1)
            old_evidence.write_text(old_line + evidence(changed, "2026-08-19 04:01:00", 2), encoding="utf-8")
            new_evidence.write_text(evidence(changed, "2026-08-19 04:02:00", 3), encoding="utf-8")
            output = root / "merged.jsonl"
            self.assertEqual(merge_evidence(old_evidence, [new_evidence], output, {changed}), (2, 1))
            self.assertTrue(output.read_text(encoding="utf-8").startswith(old_line))
            self.assertEqual([json.loads(line)["raw_score"] for line in output.read_text(encoding="utf-8").splitlines()], [1, 3])

            header = ["地区", "实体名称", "名称", "开始时间"]
            old_csv, new_csv, merged_csv = (root / name for name in ("old.csv", "new.csv", "merged.csv"))
            for path, rows in ((old_csv, [["beida", "vm", "disk_read_rate", "2026-08-19 04:00:00"],
                                          ["beida", "vm", "cpu_usage", "2026-08-19 04:01:00"]]),
                               (new_csv, [["beida", "vm", "cpu_usage", "2026-08-19 04:02:00"]])):
                with path.open("w", encoding="utf-8", newline="") as handle:
                    writer = csv.writer(handle)
                    writer.writerow(header)
                    writer.writerows(rows)
            self.assertEqual(merge_events(old_csv, [new_csv], merged_csv, {("beida", "vm", "cpu_usage")}), 2)
            with merged_csv.open("r", encoding="utf-8", newline="") as handle:
                self.assertEqual([row[2:] for row in list(csv.reader(handle))[1:]],
                                 [["disk_read_rate", "2026-08-19 04:00:00"],
                                  ["cpu_usage", "2026-08-19 04:02:00"]])

            old_coverage, new_coverage, merged_coverage = (root / name for name in ("old_cov.jsonl", "new_cov.jsonl", "merged_cov.jsonl"))
            old_coverage.write_text("".join(json.dumps({"feature_or_source": metric}) + "\n"
                                            for metric in (unchanged, changed)), encoding="utf-8")
            new_coverage.write_text(json.dumps({"feature_or_source": changed}) + "\n", encoding="utf-8")
            self.assertEqual(merge_coverage(old_coverage, [new_coverage], merged_coverage, {changed}), 2)
            self.assertEqual([json.loads(line)["feature_or_source"] for line in merged_coverage.read_text(encoding="utf-8").splitlines()],
                             [unchanged, changed])


if __name__ == "__main__":
    unittest.main()
