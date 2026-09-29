from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from baseline.netcluster.anomaly_detector.metric.runner import (
    build_arg_parser as build_updated_metric_arg_parser,
    main as run_updated_metric_ad,
)


DEFAULT_DATA_ROOT = "data/updated/first_stage"
DEFAULT_OUTPUT_DIR = "outputs/metric_anomalies/_base"
DEFAULT_RULES_CONFIG = "baseline/netcluster/config/metric_detection_rules.json"


def build_runner_arguments(
    data_root: str = DEFAULT_DATA_ROOT,
    output_dir: str = DEFAULT_OUTPUT_DIR,
    cache_csv: str | None = None,
    rules_config: str = DEFAULT_RULES_CONFIG,
    progress_every: int = 25,
    workers: int = 8,
    representative_plot_limit: int = 40,
    write_plots: bool = True,
    rebuild_cache: bool = False,
    include_city: str | None = None,
    include_node: str | None = None,
    include_source: str | None = None,
    max_files: int | None = None,
    max_series: int | None = None,
) -> list[str]:
    arguments = [
        "--data-root",
        data_root,
        "--output-dir",
        output_dir,
        "--rules-config",
        rules_config,
        "--progress-every",
        str(progress_every),
        "--workers",
        str(workers),
        "--representative-plot-limit",
        str(representative_plot_limit),
    ]
    if cache_csv:
        arguments.extend(["--cache-csv", cache_csv])
    for option, value in (
        ("--include-city", include_city),
        ("--include-node", include_node),
        ("--include-source", include_source),
        ("--max-files", max_files),
        ("--max-series", max_series),
    ):
        if value is not None:
            arguments.extend([option, str(value)])
    if write_plots:
        arguments.append("--write-plots")
    if rebuild_cache:
        arguments.append("--rebuild-cache")
    return arguments


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Detect anomalies in raw metric/*.csv files, or in a supplied wide metric CSV."
    )
    parser.add_argument("--data-root", default=DEFAULT_DATA_ROOT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--cache-csv",
        default=None,
        help="Optional wide CSV, such as chengdu_selected_metrics.csv with traffic-flow latency. By default, build from raw metric/*.csv files.",
    )
    parser.add_argument("--rules-config", default=DEFAULT_RULES_CONFIG)
    parser.add_argument("--progress-every", type=int, default=25)
    parser.add_argument("--workers", type=int, default=8, help="Number of metric detection worker processes.")
    parser.add_argument("--include-city", default=None)
    parser.add_argument("--include-node", default=None)
    parser.add_argument("--include-source", default=None)
    parser.add_argument("--max-files", type=int, default=None)
    parser.add_argument("--max-series", type=int, default=None)
    parser.add_argument(
        "--representative-plot-limit",
        type=int,
        default=40,
        help="Number of representative anomaly/normal metric plots to generate.",
    )
    parser.add_argument(
        "--rebuild-cache",
        action="store_true",
        help="Rebuild the wide metric CSV in output-dir even when it already exists.",
    )
    parser.add_argument(
        "--no-write-plots",
        action="store_true",
        help="Skip HTML plots. By default plots are generated exactly as in the result directory.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    subset_requested = any(
        value is not None
        for value in (args.include_city, args.include_node, args.include_source, args.max_files, args.max_series)
    )
    if args.cache_csv and subset_requested:
        raise SystemExit("--cache-csv cannot be combined with raw-file selection options")
    if args.cache_csv and args.rebuild_cache:
        raise SystemExit("--cache-csv cannot be combined with --rebuild-cache")
    runner_arguments = build_runner_arguments(
        data_root=args.data_root,
        output_dir=args.output_dir,
        cache_csv=args.cache_csv,
        rules_config=args.rules_config,
        progress_every=args.progress_every,
        workers=args.workers,
        representative_plot_limit=args.representative_plot_limit,
        write_plots=not args.no_write_plots,
        rebuild_cache=args.rebuild_cache or subset_requested,
        include_city=args.include_city,
        include_node=args.include_node,
        include_source=args.include_source,
        max_files=args.max_files,
        max_series=args.max_series,
    )

    os.chdir(REPO_ROOT)
    print(f"[metric-ad-runner] repo_root={REPO_ROOT}", flush=True)
    print(f"[metric-ad-runner] data_root={args.data_root}", flush=True)
    print(f"[metric-ad-runner] output_dir={args.output_dir}", flush=True)
    print(f"[metric-ad-runner] cache_csv={args.cache_csv}", flush=True)
    print(f"[metric-ad-runner] rules_config={args.rules_config}", flush=True)
    print(
        f"[metric-ad-runner] progress_every={args.progress_every} "
        f"workers={args.workers} write_plots={not args.no_write_plots} "
        f"representative_plot_limit={args.representative_plot_limit} "
        f"rebuild_cache={args.rebuild_cache}",
        flush=True,
    )
    supported_arguments = {action.dest for action in build_updated_metric_arg_parser()._actions}
    required_arguments = {"cache_csv", "workers", "representative_plot_limit", "rebuild_cache"}
    missing_arguments = sorted(required_arguments - supported_arguments)
    if missing_arguments:
        raise SystemExit(
            "Metric detection core files are older than this launcher. "
            "Update baseline/netcluster/anomaly_detector/metric/runner.py and "
            "baseline/netcluster/anomaly_detector/metric/detector.py together. "
            f"Missing options: {', '.join(missing_arguments)}"
        )
    return run_updated_metric_ad(runner_arguments)


if __name__ == "__main__":
    raise SystemExit(main())
