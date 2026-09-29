"""Rerun tuned metric series and splice them into the original full result set."""

from __future__ import annotations

import argparse
import csv
from contextlib import ExitStack
from dataclasses import asdict
from fnmatch import fnmatchcase
import hashlib
import heapq
import json
from pathlib import Path
import sys
from typing import Iterator


ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from baseline.netcluster.anomaly_detector.metric.detector import ResidualAdConfig, run_detection


CHANGED_PATTERNS = (
    "*.node_metrics.cpu_usage",
    "*.node_metrics.load1",
    "*.node_metrics.load5",
    "*.node_metrics.memory_available_ratio",
    "*.node_metrics.disk_io_util",
    "*.node_metrics.filesystem_used_ratio",
    "*.node_metrics.inode_used_ratio",
    "*.scrape_health.*scrape_samples",
)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def changed_columns(header: list[str]) -> dict[str, list[tuple[int, str]]]:
    selected: dict[str, list[tuple[int, str]]] = {}
    for index, metric_id in enumerate(header[1:], start=1):
        if any(fnmatchcase(metric_id, pattern) for pattern in CHANGED_PATTERNS):
            selected.setdefault(metric_id.split(".", 1)[0], []).append((index, metric_id))
    if not selected:
        raise ValueError("No tuned metric columns found in the original testset")
    return selected


def extract_city_testsets(source_csv: Path, input_dir: Path) -> dict[str, list[str]]:
    input_dir.mkdir(parents=True, exist_ok=True)
    with source_csv.open("r", encoding="utf-8-sig", newline="") as source, ExitStack() as stack:
        reader = csv.reader(source)
        header = next(reader)
        selected = changed_columns(header)
        writers = {}
        for city, columns in selected.items():
            handle = stack.enter_context((input_dir / f"{city}.csv").open("w", encoding="utf-8", newline=""))
            writer = csv.writer(handle)
            writer.writerow(["timestamp", *(name for _, name in columns)])
            writers[city] = writer
        for row in reader:
            for city, columns in selected.items():
                writers[city].writerow([row[0], *(row[index] for index, _ in columns)])
    return {city: [name for _, name in columns] for city, columns in selected.items()}


def original_evidence_rows(path: Path, replaced: set[str]) -> Iterator[tuple[str, str]]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            item = json.loads(line)
            if item["attributes"]["metric_id"] not in replaced:
                yield item["start_minute"], line


def updated_evidence_rows(path: Path) -> Iterator[tuple[str, str]]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            yield json.loads(line)["start_minute"], line


def merge_evidence(original: Path, updated: list[Path], output: Path, replaced: set[str]) -> tuple[int, int]:
    streams = [original_evidence_rows(original, replaced), *(updated_evidence_rows(path) for path in updated)]
    count = 0
    unchanged = 0
    with output.open("w", encoding="utf-8") as handle:
        for _, line in heapq.merge(*streams, key=lambda item: item[0]):
            handle.write(line)
            count += 1
            if json.loads(line)["attributes"]["metric_id"] not in replaced:
                unchanged += 1
    return count, unchanged


def event_rows(path: Path, replaced_keys: set[tuple[str, str, str]] | None) -> Iterator[tuple[str, list[str]]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        header = next(reader)
        city_index = header.index("地区")
        node_index = header.index("实体名称")
        metric_index = header.index("名称")
        time_index = header.index("开始时间")
        for row in reader:
            if replaced_keys is None or (row[city_index], row[node_index], row[metric_index]) not in replaced_keys:
                yield row[time_index], row


def merge_events(original: Path, updated: list[Path], output: Path,
                 replaced_keys: set[tuple[str, str, str]]) -> int:
    with original.open("r", encoding="utf-8-sig", newline="") as handle:
        header = next(csv.reader(handle))
    streams = [event_rows(original, replaced_keys), *(event_rows(path, None) for path in updated)]
    count = 0
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        for _, row in heapq.merge(*streams, key=lambda item: item[0]):
            writer.writerow(row)
            count += 1
    return count


def merge_coverage(original: Path, updated: list[Path], output: Path, replaced: set[str]) -> int:
    count = 0
    with output.open("w", encoding="utf-8") as destination:
        for source in [original, *updated]:
            with source.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if source != original or json.loads(line)["feature_or_source"] not in replaced:
                        destination.write(line)
                        count += 1
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original-dir", type=Path, default=Path("outputs/metric_anomalies/_base"))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/metric_anomalies"))
    parser.add_argument("--rules-config", type=Path, default=Path("baseline/netcluster/config/metric_detection_rules.json"))
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--reuse-updated", action="store_true")
    args = parser.parse_args()
    original = args.original_dir
    output = args.output_dir
    output.mkdir(parents=True, exist_ok=True)
    base_summary = json.loads((original / "updated_metric_ad_summary.json").read_text(encoding="utf-8"))
    base_detection = base_summary["detection"]
    original_csv = original / "updated_metric_testset.csv"
    if file_sha256(args.rules_config) == base_detection["rules_config_sha256"]:
        raise ValueError("Rules have not changed from the original detection run")
    inputs = output / "updated" / "inputs"
    if args.reuse_updated:
        with original_csv.open("r", encoding="utf-8-sig", newline="") as handle:
            selected = changed_columns(next(csv.reader(handle)))
        by_city = {city: [name for _, name in columns] for city, columns in selected.items()}
    else:
        print("[optimized-metric] extracting tuned series from original testset", flush=True)
        by_city = extract_city_testsets(original_csv, inputs)
    config_values = dict(base_detection["detector_config"])
    config_values["period_candidate_minutes"] = tuple(config_values["period_candidate_minutes"])
    config = ResidualAdConfig(**config_values)
    for city in sorted(by_city):
        city_output = output / "updated" / city
        if not args.reuse_updated:
            print(f"[optimized-metric] detecting {city}: {len(by_city[city])} metrics", flush=True)
            run_detection(inputs / f"{city}.csv", city_output, config, rules_config=args.rules_config,
                          verbose=False, write_plots=False, write_modeled_series=False, workers=args.workers)
    replaced = {metric for names in by_city.values() for metric in names}
    keys = {(parts[0], parts[1], parts[3]) for metric in replaced if (parts := metric.split(".", 3))}
    if len(keys) != len(replaced):
        raise ValueError("A tuned metric cannot be uniquely identified in metric_anomaly_events.csv")
    city_dirs = [output / "updated" / city for city in sorted(by_city)]
    evidence_count, unchanged_count = merge_evidence(
        original / "evidence_events.jsonl", [path / "evidence_events.jsonl" for path in city_dirs],
        output / "evidence_events.jsonl", replaced,
    )
    event_count = merge_events(
        original / "metric_anomaly_events.csv", [path / "metric_anomaly_events.csv" for path in city_dirs],
        output / "metric_anomaly_events.csv", keys,
    )
    coverage_count = merge_coverage(
        original / "observation_coverage.jsonl", [path / "observation_coverage.jsonl" for path in city_dirs],
        output / "observation_coverage.jsonl", replaced,
    )
    if event_count != evidence_count:
        raise ValueError(f"CSV/evidence event counts differ: {event_count} != {evidence_count}")
    detection_summary = dict(base_detection)
    detection_summary.update(
        rules_config=str(args.rules_config), rules_config_sha256=file_sha256(args.rules_config),
        event_count=event_count, event_file=str(output / "metric_anomaly_events.csv"),
        evidence_file=str(output / "evidence_events.jsonl"),
        coverage_file=str(output / "observation_coverage.jsonl"), coverage_interval_count=coverage_count,
        plot_count=0, plot_dir=None,
    )
    (output / "metric_anomaly_summary.json").write_text(
        json.dumps(detection_summary, ensure_ascii=False, indent=2), encoding="utf-8")
    (output / "updated_metric_ad_summary.json").write_text(
        json.dumps({"build": base_summary["build"], "detection": detection_summary}, ensure_ascii=False, indent=2),
        encoding="utf-8")
    manifest = {
        "original_dir": str(original), "original_rules_sha256": base_detection["rules_config_sha256"],
        "optimized_rules_sha256": detection_summary["rules_config_sha256"],
        "changed_patterns": list(CHANGED_PATTERNS), "replaced_metric_count": len(replaced),
        "replaced_metrics_by_city": {city: len(names) for city, names in by_city.items()},
        "unchanged_evidence_count": unchanged_count, "merged_event_count": event_count,
        "merged_coverage_interval_count": coverage_count,
        "detector_config": asdict(config),
    }
    (output / "merge_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
