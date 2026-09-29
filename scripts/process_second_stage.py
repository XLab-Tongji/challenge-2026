"""Convert the second-stage regional exports to the first-stage directory layout."""

from __future__ import annotations

import argparse
from pathlib import Path
import re

from scripts.process_interface_metrics import process_interface_metrics_file
from scripts.process_netflow_5tuple import process_netflow_5tuple_file
from scripts.process_node_metrics import process_node_metrics_file
from scripts.process_routing_metrics import process_routing_metrics_file
from scripts.process_scrape_health import process_scrape_health_file


PROCESSORS = {
    "node_metrics": process_node_metrics_file,
    "interface_metrics": process_interface_metrics_file,
    "scrape_health": process_scrape_health_file,
    "routing_metrics": process_routing_metrics_file,
    "netflow_5tuple_minute_readable": process_netflow_5tuple_file,
}
REGION_DIR = re.compile(r"^([a-z]+)_(\d{14})_(\d{14})$")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-root", type=Path, default=Path("data/second_stage"))
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("data/updated/second_stage"),
    )
    parser.add_argument("--region", help="Process one region; default is all regions.")
    parser.add_argument(
        "--kind", choices=(*PROCESSORS, "all"), default="all",
        help="Process one export type; default is all types.",
    )
    args = parser.parse_args()

    region_dirs = sorted(path for path in args.input_root.iterdir() if path.is_dir())
    if args.region:
        region_dirs = [path for path in region_dirs if path.name.startswith(f"{args.region}_")]
    if not region_dirs:
        parser.error("no matching region directories found")

    kinds = PROCESSORS if args.kind == "all" else {args.kind: PROCESSORS[args.kind]}
    for region_dir in region_dirs:
        match = REGION_DIR.fullmatch(region_dir.name)
        if match is None:
            raise ValueError(f"unexpected region directory: {region_dir}")
        region, start, end = match.groups()
        for kind, processor in kinds.items():
            input_path = region_dir / f"{kind}_{start}_{end}.csv"
            if not input_path.is_file():
                raise FileNotFoundError(input_path)
            print(f"processing region={region} kind={kind}", flush=True)
            summary = processor(input_path, args.output_root, region)
            print(f"completed region={region} kind={kind} entities={len(summary['entities'])}", flush=True)


if __name__ == "__main__":
    main()
