"""Run bounded-memory five-tuple anomaly detection on router CSV files.

Example (from the repository root):
  python -m baseline.netcluster.cli.run_netflow_5tuple_detection --data-root data/updated/first_stage \
    --output-dir outputs/netflow_anomalies --workers 2

The output keeps per-router evidence and also writes symptom_groups.jsonl
for duplicate-aware review.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
import hashlib
import json
import os
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from baseline.netcluster.anomaly_detector.network_flow.five_tuple import (
    VERSION, detect_router, load_config)


def find_routers(data_root: Path, city: str | None, node: str | None):
    result = {}
    for path in sorted(data_root.glob("*/*/netflow/netflow_5tuple*.csv")):
        router_city, router_node = path.parents[2].name, path.parents[3].name
        if city and city != router_city or node and node != router_node:
            continue
        result.setdefault((router_city, router_node), []).append(path)
    return {key: tuple(paths) for key, paths in result.items()}


def group_symptoms(events: list[dict]) -> list[dict]:
    """Group repeated router observations without discarding their evidence."""
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for event in events:
        if event["feature"] not in {"regional_opposite_presence", "region_port_bytes",
                                    "interface_udp_small_packets"}:
            continue
        attrs = event["attributes"]
        # Directional flows may repeat across routers; interface pressure only
        # groups the two interfaces of the same observing router.
        scope = event["entity_id"] if event["feature"] == "interface_udp_small_packets" else ""
        key = (event["feature"], event["direction"], event["start_minute"],
               event["last_seen_minute"], attrs["protocol"], attrs["port_group"],
               attrs["region_a_inferred"], attrs["region_b_inferred"],
               attrs.get("active_direction", attrs.get("flow_direction")), scope)
        groups[key].append(event)
    output = []
    for key, members in sorted(groups.items()):
        signature = json.dumps(key, ensure_ascii=False, separators=(",", ":"))
        output.append({"symptom_id": hashlib.sha256(signature.encode()).hexdigest()[:24],
                       "feature": key[0], "direction": key[1],
                       "start_minute": key[2], "last_seen_minute": key[3],
                       "protocol": key[4], "port_group": key[5],
                       "region_a_inferred": key[6], "region_b_inferred": key[7],
                       "flow_direction": key[8], "scope": key[9] or None,
                       "observer_count": len({e["entity_id"] for e in members}),
                       "evidence_count": len(members),
                       "observers": sorted({e["entity_id"] for e in members}),
                       "interfaces": sorted({e["attributes"].get("interface_id", "")
                                             for e in members if e["attributes"].get("interface_id")}),
                       "evidence_ids": sorted(e["evidence_id"] for e in members)})
    return output


def run(data_root: Path, output_dir: Path, config_path: Path, workers: int = 1,
        city: str | None = None, node: str | None = None,
        max_rows: int | None = None) -> dict:
    if workers < 1 or max_rows is not None and max_rows < 1:
        raise ValueError("workers and max_rows must be positive")
    config = load_config(config_path)
    routers = find_routers(data_root, city, node)
    if not routers:
        raise FileNotFoundError(f"No netflow_5tuple CSVs under {data_root}")
    output_dir.mkdir(parents=True, exist_ok=True)
    results = []
    if workers == 1:
        for paths in routers.values():
            result = detect_router(paths, output_dir, config, max_rows)
            results.append(result)
            print(f"{result['city']}/{result['node']}: {result['scanned_rows']} rows, "
                  f"{result['evidence_episodes']} episodes", flush=True)
    else:
        with ProcessPoolExecutor(max_workers=min(workers, len(routers))) as pool:
            futures = [pool.submit(detect_router, paths, output_dir, config, max_rows)
                       for paths in routers.values()]
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                print(f"{result['city']}/{result['node']}: {result['scanned_rows']} rows, "
                      f"{result['evidence_episodes']} episodes", flush=True)
    results.sort(key=lambda item: (item["city"], item["node"]))
    merged_events = []
    for name in ("evidence_events.jsonl", "observation_coverage.jsonl"):
        with (output_dir / name).open("w", encoding="utf-8") as merged:
            for item in results:
                source = output_dir / str(item["evidence_file" if name.startswith("evidence")
                                                else "coverage_file"])
                with source.open(encoding="utf-8") as handle:
                    for line in handle:
                        merged.write(line)
                        if name == "evidence_events.jsonl":
                            merged_events.append(json.loads(line))
    symptom_groups = group_symptoms(merged_events)
    feature_counts: dict[str, int] = defaultdict(int)
    for event in merged_events:
        feature_counts[event["feature"]] += 1
    symptom_counts: dict[str, int] = defaultdict(int)
    for group in symptom_groups:
        symptom_counts[group["feature"]] += 1
    symptom_path = output_dir / "symptom_groups.jsonl"
    with symptom_path.open("w", encoding="utf-8") as handle:
        for group in symptom_groups:
            handle.write(json.dumps(group, ensure_ascii=False,
                                    separators=(",", ":")) + "\n")
    manifest = {"detector_version": VERSION, "config_path": str(config_path),
                "config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
                "data_root": str(data_root),
                "router_count": len(results), "scanned_rows": sum(x["scanned_rows"] for x in results),
                "invalid_rows": sum(x["invalid_rows"] for x in results),
                "evidence_episodes": sum(x["evidence_episodes"] for x in results),
                "feature_counts": dict(sorted(feature_counts.items())),
                "symptom_group_count": len(symptom_groups),
                "symptom_group_counts_by_feature": dict(sorted(symptom_counts.items())),
                "symptom_group_file": str(symptom_path),
                "sample_limited": max_rows is not None, "routers": results}
    (output_dir / "run_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, required=True,
                        help="first_stage directory containing city/router/netflow CSV files")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--config", type=Path,
                        default=REPO / "baseline/netcluster/config/netflow_5tuple_detection.json")
    parser.add_argument("--workers", type=int, default=min(2, os.cpu_count() or 1))
    parser.add_argument("--include-city")
    parser.add_argument("--include-node")
    parser.add_argument("--max-rows", type=int,
                        help="Smoke test only; caps rows separately for each router")
    args = parser.parse_args(argv)
    summary = run(args.data_root, args.output_dir, args.config, args.workers,
                  args.include_city, args.include_node, args.max_rows)
    print(json.dumps({key: summary[key] for key in
                      ("router_count", "scanned_rows", "invalid_rows",
                       "evidence_episodes", "feature_counts", "symptom_group_count",
                       "sample_limited")}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
