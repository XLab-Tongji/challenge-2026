"""Train Drain templates and detect minute-level log anomalies in raw challenge logs."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from baseline.netcluster.anomaly_detector.log.detector import run_builder
    from baseline.netcluster.anomaly_detector.log.templates import run_parser
except ModuleNotFoundError as exc:
    if exc.name == "drain3":
        raise SystemExit('Log detection requires Drain3: python -m pip install ".[log]"') from exc
    raise


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-root",
        type=Path,
        default=Path("data/updated/first_stage"),
        help="Root containing <city>/<node>/log/*.csv.",
    )
    parser.add_argument("--template-dir", type=Path, default=Path("outputs/log_anomalies/templates"))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/log_anomalies"))
    parser.add_argument("--keywords-config", type=Path, default=REPO_ROOT / "baseline/netcluster/config/log_anomaly_keywords.json")
    parser.add_argument(
        "--drain-config",
        type=Path,
        default=REPO_ROOT / "baseline/netcluster/config/drain3.ini",
    )
    parser.add_argument("--reuse-model", action="store_true", help="Reuse an existing Drain model in template-dir.")
    parser.add_argument("--include-city", default=None)
    parser.add_argument("--include-node", default=None)
    parser.add_argument("--include-source", default=None)
    parser.add_argument("--time-column", default="event_time")
    parser.add_argument("--message-column", default="message")
    parser.add_argument("--max-files", type=int, default=None)
    parser.add_argument("--progress-every", type=int, default=10)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    os.chdir(REPO_ROOT)
    model_path = args.template_dir / "drain_log_template_miner.pkl"
    template_summary = None
    if args.reuse_model:
        if not model_path.is_file():
            raise SystemExit(f"Drain model does not exist: {model_path}")
    else:
        template_summary = run_parser(
            data_root=args.data_root,
            output_dir=args.template_dir,
            config_path=args.drain_config,
            include_city=args.include_city,
            include_node=args.include_node,
            include_source=args.include_source,
            message_column=args.message_column,
            max_files=args.max_files,
            progress_every=args.progress_every,
        )

    event_summary = run_builder(
        data_root=args.data_root,
        output_dir=args.output_dir,
        drain_model=model_path,
        include_city=args.include_city,
        include_node=args.include_node,
        include_source=args.include_source,
        time_column=args.time_column,
        message_column=args.message_column,
        max_files=args.max_files,
        progress_every=args.progress_every,
        keywords_config=args.keywords_config,
    )
    print(json.dumps({"templates": template_summary, "events": event_summary}, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
