from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from baseline.netcluster.anomaly_detector.metric.series import parse_timestamp
from baseline.netcluster.anomaly_detector.metric.baselines import safe_filename
from baseline.netcluster.anomaly_detector.metric.detector import DEFAULT_RULES_CONFIG, ResidualAdConfig, run_detection


@dataclass(frozen=True)
class MetricFile:
    city: str
    node: str
    source: str
    path: Path


def discover_metric_files(
    data_root: Path,
    include_city: str | None = None,
    include_node: str | None = None,
    include_source: str | None = None,
    max_files: int | None = None,
) -> list[MetricFile]:
    files: list[MetricFile] = []

    def add_candidate(path: Path, city: str, node: str) -> bool:
        source = path.stem
        if include_city and city != include_city:
            return False
        if include_node and node != include_node:
            return False
        if include_source and source != include_source:
            return False
        files.append(MetricFile(city, node, source, path))
        return max_files is not None and len(files) >= max_files

    for path in sorted(data_root.glob("*/*/metric/*.csv")):
        city, node = path.relative_to(data_root).parts[:2]
        if add_candidate(path, city, node):
            return files
    if files:
        return files

    city = data_root.name
    for path in sorted(data_root.glob("*/metric/*.csv")):
        node = path.relative_to(data_root).parts[0]
        if add_candidate(path, city, node):
            return files
    return files


def metric_id_for(metric_file: MetricFile, column: str) -> str:
    return f"{metric_file.city}.{metric_file.node}.{metric_file.source}.{column}"


def normalized_timestamp(raw_timestamp: str) -> str | None:
    timestamp = parse_timestamp(raw_timestamp)
    if timestamp is None:
        return None
    return timestamp.strftime("%Y-%m-%d %H:%M:%S")


def build_wide_testset(
    metric_files: list[MetricFile],
    output_path: Path,
    max_series: int | None = None,
    progress_every: int = 10,
) -> dict[str, Any]:
    rows_by_timestamp: dict[str, dict[str, str]] = {}
    metric_columns: list[str] = []
    used_metric_ids: set[str] = set()

    for ordinal, metric_file in enumerate(metric_files, start=1):
        if ordinal == 1 or ordinal == len(metric_files) or ordinal % max(1, progress_every) == 0:
            print(
                f"[updated-metric-ad] reading {ordinal}/{len(metric_files)}: "
                f"{metric_file.city}/{metric_file.node}/{metric_file.source}",
                flush=True,
            )
        with metric_file.path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames or "timestamp" not in reader.fieldnames:
                print(f"[updated-metric-ad] skipped file without timestamp: {metric_file.path}", flush=True)
                continue
            source_columns = [column for column in reader.fieldnames if column != "timestamp"]
            active_columns: dict[str, str] = {}
            for column in source_columns:
                if max_series is not None and len(metric_columns) >= max_series:
                    break
                metric_id = metric_id_for(metric_file, column)
                if metric_id in used_metric_ids:
                    metric_id = f"{metric_id}.{safe_filename(str(metric_file.path))}"
                used_metric_ids.add(metric_id)
                active_columns[column] = metric_id
                metric_columns.append(metric_id)
            if not active_columns:
                continue
            for row in reader:
                timestamp = normalized_timestamp(row.get("timestamp", ""))
                if timestamp is None:
                    continue
                output_row = rows_by_timestamp.setdefault(timestamp, {})
                for source_column, metric_id in active_columns.items():
                    output_row[metric_id] = (row.get(source_column) or "").strip()
        if max_series is not None and len(metric_columns) >= max_series:
            print(f"[updated-metric-ad] reached max_series={max_series}", flush=True)
            break

    output_path.parent.mkdir(parents=True, exist_ok=True)
    timestamps = sorted(rows_by_timestamp)
    print(
        f"[updated-metric-ad] writing wide testset rows={len(timestamps)} "
        f"metrics={len(metric_columns)} -> {output_path}",
        flush=True,
    )
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["timestamp", *metric_columns])
        writer.writeheader()
        for timestamp in timestamps:
            row = {"timestamp": timestamp}
            row.update(rows_by_timestamp[timestamp])
            writer.writerow(row)

    return {
        "row_count": len(timestamps),
        "metric_count": len(metric_columns),
        "testset_csv": str(output_path),
    }


def cached_build_summary(testset_csv: Path, summary_path: Path) -> dict[str, Any]:
    if summary_path.exists():
        try:
            cached_summary = json.loads(summary_path.read_text(encoding="utf-8"))
            build_summary = cached_summary.get("build")
            if isinstance(build_summary, dict):
                return build_summary
        except (OSError, json.JSONDecodeError):
            pass

    with testset_csv.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        header = next(reader, [])
        row_count = sum(1 for _ in reader)
    return {
        "row_count": row_count,
        "metric_count": max(0, len(header) - 1),
        "testset_csv": str(testset_csv),
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run NetCluster metric anomaly detection on updated challenge data.")
    parser.add_argument(
        "--data-root",
        type=Path,
        default=Path("data/updated/first_stage"),
        help="Root containing <city>/<node>/metric/*.csv.",
    )
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/metric_anomalies/_base"))
    parser.add_argument(
        "--cache-csv",
        type=Path,
        default=None,
        help="Optional existing updated_metric_testset.csv to reuse as detection input.",
    )
    parser.add_argument("--include-city", type=str, default=None)
    parser.add_argument("--include-node", type=str, default=None)
    parser.add_argument("--include-source", type=str, default=None)
    parser.add_argument("--max-files", type=int, default=None)
    parser.add_argument("--max-series", type=int, default=None)
    parser.add_argument("--workers", type=int, default=1, help="Number of metric detection worker processes.")
    parser.add_argument(
        "--representative-plot-limit",
        type=int,
        default=0,
        help="Plot only this many representative metrics; 0 plots every processed metric.",
    )
    parser.add_argument(
        "--rebuild-cache",
        action="store_true",
        help="Rebuild updated_metric_testset.csv instead of reusing it.",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=10,
        help="Print progress after this many input files or metric series.",
    )
    parser.add_argument("--rolling-window", type=int, default=ResidualAdConfig.rolling_window)
    parser.add_argument("--anomaly-fraction", type=float, default=ResidualAdConfig.anomaly_fraction)
    parser.add_argument("--min-effect-size", type=float, default=ResidualAdConfig.min_effect_size)
    parser.add_argument(
        "--period-candidate-minutes",
        type=str,
        default=",".join(str(value) for value in ResidualAdConfig.period_candidate_minutes),
    )
    parser.add_argument(
        "--rules-config",
        type=Path,
        default=DEFAULT_RULES_CONFIG,
        help="Metric classification and ECOD/N-sigma parameter configuration.",
    )
    parser.add_argument("--write-plots", action="store_true", help="Generate one interactive HTML plot per processed metric.")
    parser.add_argument("--write-modeled-series", action="store_true", help="Also export the large wide modeled-series CSV.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    output_dir: Path = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    output_testset_csv = output_dir / "updated_metric_testset.csv"
    requested_cache = args.cache_csv
    cache_is_usable = (
        requested_cache is not None
        and requested_cache.is_file()
        and requested_cache.stat().st_size > 0
        and not args.rebuild_cache
    )
    testset_csv = requested_cache if cache_is_usable else output_testset_csv
    summary_path = output_dir / "updated_metric_ad_summary.json"
    if testset_csv.is_file() and testset_csv.stat().st_size > 0 and not args.rebuild_cache:
        print(f"[updated-metric-ad] cache hit, reusing {testset_csv}", flush=True)
        build_summary = cached_build_summary(testset_csv, summary_path)
    else:
        metric_files = discover_metric_files(
            args.data_root,
            include_city=args.include_city,
            include_node=args.include_node,
            include_source=args.include_source,
            max_files=args.max_files,
        )
        print(f"[updated-metric-ad] discovered metric files={len(metric_files)} under {args.data_root}", flush=True)
        if not metric_files:
            raise SystemExit("No metric csv files found.")
        build_summary = build_wide_testset(
            metric_files,
            output_testset_csv,
            max_series=args.max_series,
            progress_every=args.progress_every,
        )
        testset_csv = output_testset_csv
    period_candidates = tuple(int(item.strip()) for item in args.period_candidate_minutes.split(",") if item.strip())
    detection_summary = run_detection(
        testset_csv,
        output_dir,
        ResidualAdConfig(
            rolling_window=args.rolling_window,
            anomaly_fraction=args.anomaly_fraction,
            min_effect_size=args.min_effect_size,
            period_candidate_minutes=period_candidates,
        ),
        rules_config=args.rules_config,
        verbose=True,
        progress_every=args.progress_every,
        write_plots=args.write_plots,
        write_modeled_series=args.write_modeled_series,
        workers=args.workers,
        representative_plot_limit=args.representative_plot_limit,
    )
    summary = {
        "build": build_summary,
        "detection": detection_summary,
    }
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
