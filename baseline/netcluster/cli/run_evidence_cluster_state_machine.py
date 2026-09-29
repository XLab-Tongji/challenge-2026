"""Run the current two-state fault inference over four anomaly event streams."""

from __future__ import annotations

import argparse
from collections import defaultdict
from hashlib import sha256
import json
from pathlib import Path
import sys
from time import perf_counter

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from baseline.netcluster.fault_detection.evidence_cluster_machine.events import derive_name, minute_number, minute_text
from baseline.netcluster.fault_detection.evidence_cluster_machine.two_state_engine import infer_two_state
from baseline.netcluster.fault_detection.evidence_cluster_machine.output import write_results
from baseline.netcluster.fault_detection.evidence_cluster_machine.coverage import read_coverage


CONFIG = ROOT / "baseline/netcluster/config"
DEFAULT_OUTPUT = ROOT / "outputs/submission/raw"
DEFAULT_EVENTS = {
    "metric": ROOT / "outputs/metric_anomalies/evidence_events.jsonl",
    "log": ROOT / "outputs/log_anomalies/evidence_events.jsonl",
    "traffic_flow": ROOT / "outputs/traffic_flow_anomalies/evidence_events.jsonl",
    "netflow": ROOT / "outputs/netflow_anomalies/evidence_events.jsonl",
}
DEFAULT_COVERAGE = {name: path.with_name("observation_coverage.jsonl")
                    for name, path in DEFAULT_EVENTS.items()}


def _digest(path: Path) -> str:
    result = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            result.update(block)
    return result.hexdigest()


def _calibrate(paths: dict[str, Path], names: dict) -> dict:
    values: dict[str, list[float]] = defaultdict(list)
    for path in paths.values():
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                raw = json.loads(line)
                name = derive_name(raw, names)
                if name is None or names["event_name_to_family"][name] in {
                    "collection_context", "persistent_background"
                }:
                    continue
                value = raw.get("raw_score")
                if isinstance(value, (int, float)):
                    values[f"{raw['modality']}|{raw['feature']}|{raw.get('score_kind')}"].append(float(value))
    calibration = {}
    for key, scores in values.items():
        scores.sort()
        calibration[key] = {"count": len(scores), "q50": scores[(len(scores)-1)//2],
                            "q90": scores[int((len(scores)-1)*0.9)]}
    return calibration


def _events(paths: dict[str, Path], snapshot: Path):
    with snapshot.open("w", encoding="utf-8", newline="\n") as copy:
        for modality, path in paths.items():
            with path.open(encoding="utf-8") as stream:
                for line in stream:
                    raw = json.loads(line)
                    if raw.get("modality") != modality:
                        raise ValueError(f"modality mismatch in {path}")
                    if raw.get("observed") and raw.get("anomaly_kind") != "missing_value":
                        copy.write(line if line.endswith("\n") else line + "\n")
                    yield raw


def _entity_coverage(paths: dict[str, Path]) -> dict:
    """Index observed intervals by the actual entity and data modality."""
    spans = defaultdict(list)
    for modality, path in paths.items():
        if modality == "log" or not path.exists():
            continue
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                row = json.loads(line)
                if row.get("status") != "observed":
                    continue
                first = row.get("minute", row.get("start_minute"))
                spans[row["entity_id"], modality].append((
                    minute_number(first), minute_number(row.get("last_seen_minute", first))))
    indexed = {}
    for key, intervals in spans.items():
        merged = []
        for first, last in sorted(intervals):
            if merged and first <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], last))
            else:
                merged.append((first, last))
        indexed[key] = ([start for start, _ in merged], [end for _, end in merged])
    return indexed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--family-prior", type=Path, default=CONFIG / "evidence_cluster_family_priors.json")
    parser.add_argument("--fault-prior", type=Path, default=CONFIG / "evidence_cluster_fault_priors.json")
    parser.add_argument("--runtime", type=Path,
                        default=CONFIG / "two_state_runtime.json")
    parser.add_argument("--semantic-prior", type=Path,
                        default=CONFIG / "two_state_semantic_priors.json")
    for modality in DEFAULT_EVENTS:
        parser.add_argument(f"--{modality.replace('_', '-')}-events", type=Path, default=DEFAULT_EVENTS[modality])
        parser.add_argument(f"--{modality.replace('_', '-')}-coverage", type=Path, default=DEFAULT_COVERAGE[modality])
    args = parser.parse_args()
    began = perf_counter()
    paths = {name: getattr(args, f"{name}_events") for name in DEFAULT_EVENTS}
    cover_paths = {name: getattr(args, f"{name}_coverage") for name in DEFAULT_COVERAGE}
    family = json.loads(args.family_prior.read_text(encoding="utf-8"))
    faults = json.loads(args.fault_prior.read_text(encoding="utf-8"))
    runtime = json.loads(args.runtime.read_text(encoding="utf-8"))
    semantic = json.loads(args.semantic_prior.read_text(encoding="utf-8"))
    if set(semantic["event_diagnosticity"]) != set(family["family_salience"]):
        raise ValueError("two-state semantic prior does not cover observed event families")
    if set(semantic["coactivity_weight"]) != set(family["family_salience"]):
        raise ValueError("two-state coactivity prior does not cover observed event families")
    family = {**family, "event_diagnosticity": semantic["event_diagnosticity"],
              "coactivity_weight": semantic["coactivity_weight"],
              "missing_relation_same_entity": semantic["missing_relation_same_entity"]}
    faults = json.loads(json.dumps(faults))
    for fault_type, override in semantic["fault_weight_overrides"].items():
        if fault_type not in faults["fault_priors"]:
            raise ValueError(f"unknown two-state fault prior: {fault_type}")
        for role, weights in override.items():
            if role not in {"direct", "effect"} or not set(weights) <= set(family["family_salience"]):
                raise ValueError(f"invalid two-state fault weights: {fault_type}/{role}")
            faults["fault_priors"][fault_type][role].update(weights)
    taxonomy = json.loads((ROOT / "aiops_challenge_2026/config/fault_taxonomy.json").read_text(encoding="utf-8"))
    if set(faults["fault_priors"]) != {row["fault_name"] for row in taxonomy["fault_categories"]}:
        raise ValueError("fault prior does not cover official taxonomy")
    if set(family["event_name_rules"]) != set(family["event_name_to_family"]):
        raise ValueError("event name rules and family map differ")
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "effective_fault_priors.json").write_text(
        json.dumps(faults, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    calibration = _calibrate(paths, family)
    (args.output / "score_calibration.json").write_text(
        json.dumps(calibration, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    _, coverage_stats = read_coverage(cover_paths)
    coverage = {"entity_intervals": _entity_coverage(cover_paths),
                "range": coverage_stats.get("range")}
    result = infer_two_state(_events(paths, args.output / "evidence_events.jsonl"), family, faults, runtime,
                    calibration=calibration, coverage=coverage)
    manifest = {
        "version": "two-state-current",
        "source_document": "docs/fault_detection_and_rca_technical_report.md",
        "event_sources": {str(path): _digest(path) for path in paths.values()},
        "coverage_sources": {str(path): _digest(path) for path in cover_paths.values() if path.exists()},
        "family_prior_sha256": _digest(args.family_prior),
        "fault_prior_sha256": _digest(args.fault_prior),
        "effective_fault_prior_sha256": _digest(args.output / "effective_fault_priors.json"),
        "runtime_sha256": _digest(args.runtime),
        "semantic_prior_sha256": _digest(args.semantic_prior),
        "coverage_summary": coverage_stats,
        "elapsed_seconds": round(perf_counter() - began, 2),
        "epistemic_status": "unlabeled_candidate_rules_not_fault_probabilities",
    }
    for row in [*result["incidents"], *result["suspects"]]:
        row["start_minute"] = minute_text(row.pop("start"))
        row["end_minute_exclusive"] = minute_text(row.pop("end"))
        row["last_support_minute"] = minute_text(row.pop("last_support"))
        row["cluster_ids"] = sorted(row["cluster_ids"])
        row.pop("confirm_streak", None)
    summary = write_results(result, taxonomy, args.output, manifest)
    print(json.dumps({"output": str(args.output), "incidents": summary["incident_count"],
                      "suspects": summary["suspect_count"], "clusters": summary["cluster_count"],
                      "unknown_signatures": len(summary["unknown_signatures"]),
                      "elapsed_seconds": manifest["elapsed_seconds"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
