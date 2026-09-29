"""Detect traffic_flow anomalies and export standardized evidence episodes."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from baseline.netcluster.anomaly_detector.network_flow import traffic_flow_v3


CSV_FIELDS = ("地区", "实体名称", "数据类型", "名称", "异常类型", "开始时间", "结束时间",
              "异常值", "基线值", "source", "flow_type", "source_region",
              "target_region", "target_domain", "series_key", "interface_id",
              "family", "score", "anchor", "tsad_role")


def _csv_row(event: dict) -> dict:
    meta = event["attributes"]
    feature = event["feature"]
    family = "service.degradation" if feature != "batch_timeout_ratio" else "service.timeout"
    observed = meta["last_observed"]
    return {"地区": meta["source_region"], "实体名称": "traffic-vm",
            "数据类型": "网络流", "名称": (f"{meta['flow_type']}__{meta['target_domain']}__"
                                        f"{meta['series_key']}__{feature}"),
            "异常类型": "突增", "开始时间": event["start_minute"],
            "结束时间": event["last_seen_minute"],
            "异常值": next(iter(observed.values())),
            "基线值": meta.get("baseline") if meta.get("baseline") is not None else "",
            "source": "traffic", "flow_type": meta["flow_type"],
            "source_region": meta["source_region"],
            "target_region": meta["target_region"],
            "target_domain": meta["target_domain"], "series_key": meta["series_key"],
            "interface_id": "", "family": family, "score": event["raw_score"],
            "anchor": False, "tsad_role": meta["detector_version"]}


def run(data_root: Path, output_dir: Path, config_path: Path,
        city: str | None = None, max_files: int | None = None) -> dict:
    if max_files is not None and max_files < 1:
        raise ValueError("max_files must be positive")
    detector = traffic_flow_v3
    config = detector.load_config(config_path)
    files = sorted(path for path in data_root.glob("*/traffic-vm/traffic_flow/*.csv")
                   if path.name != "series_index.csv"
                   and (city is None or path.parents[2].name == city))
    if max_files is not None:
        files = files[:max_files]
    if not files:
        raise FileNotFoundError(f"No traffic_flow series under {data_root}")
    output_dir.mkdir(parents=True, exist_ok=True)
    event_path = output_dir / "evidence_events.jsonl"
    coverage_path = output_dir / "observation_coverage.jsonl"
    csv_path = output_dir / "traffic_flow_anomaly_events.csv"
    summaries = []
    counts: dict[str, int] = {}
    coverage_records = unknown_intervals = 0
    with event_path.open("w", encoding="utf-8") as event_file, coverage_path.open(
            "w", encoding="utf-8") as coverage_file, csv_path.open(
            "w", encoding="utf-8", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for path in files:
            events, coverage, summary = detector.detect_file(path, config)
            summaries.append(summary)
            for event in events:
                event_file.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
                writer.writerow(_csv_row(event))
                counts[event["feature"]] = counts.get(event["feature"], 0) + 1
            for record in coverage:
                coverage_file.write(json.dumps(record, ensure_ascii=False,
                                               separators=(",", ":")) + "\n")
                coverage_records += 1
                unknown_intervals += record["status"] == "unknown"
    manifest = {"detector_version": detector.VERSION,
                "config_path": str(config_path),
                "config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
                "data_root": str(data_root), "file_count": len(files),
                "sample_limited": max_files is not None,
                "rows": sum(item["rows"] for item in summaries),
                "elephant_valid_throughputs": sum(
                    item.get("elephant_valid_throughputs", 0) for item in summaries),
                "coverage_records": coverage_records,
                "unknown_intervals": unknown_intervals,
                "episode_count": sum(item["episodes"] for item in summaries),
                "episode_counts_by_feature": dict(sorted(counts.items())),
                "evidence_file": str(event_path), "coverage_file": str(coverage_path),
                "compatibility_csv": str(csv_path), "series": summaries}
    (output_dir / "run_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path,
                        default=REPO / "data/updated/first_stage")
    parser.add_argument("--output-dir", type=Path,
                        default=REPO / "outputs/traffic_flow_anomalies")
    parser.add_argument("--config", type=Path,
                        default=REPO / "baseline/netcluster/config/traffic_flow_detection_v3.json")
    parser.add_argument("--include-city")
    parser.add_argument("--max-files", type=int)
    args = parser.parse_args(argv)
    summary = run(args.data_root, args.output_dir, args.config, args.include_city,
                  args.max_files)
    print(json.dumps({key: summary[key] for key in
                      ("file_count", "rows", "episode_count", "episode_counts_by_feature",
                       "sample_limited")}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
