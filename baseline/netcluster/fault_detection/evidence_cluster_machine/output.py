"""Write strict submissions and auditable intermediate artifacts."""

from __future__ import annotations

from collections import Counter
import csv
from datetime import datetime, timezone
import json
from pathlib import Path

from aiops_challenge_2026.schema import VALID_NETWORK_ELEMENTS, validate_prediction


def _jsonl(path: Path, rows) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def _utc(value: str) -> str:
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc).isoformat(
        timespec="milliseconds").replace("+00:00", "Z")


def write_results(result: dict, taxonomy: dict, output: Path, manifest: dict) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    trace_dir = output / "trace"
    trace_dir.mkdir(exist_ok=True)
    mapping = {row["fault_name"]: row for row in taxonomy["fault_categories"]}
    predictions = []
    incidents = []
    rca_rows = []
    for row in result["incidents"]:
        roots = [name for name in row["root_cause_candidates"] if name in VALID_NETWORK_ELEMENTS]
        category = mapping[row["fault_type"]]
        prediction = {
            "prediction_id": row["incident_id"],
            "start_time": _utc(row["start_minute"]),
            "end_time": _utc(row["end_minute_exclusive"]),
            "root_cause_top5": [{"rank": index, "network_element_id": name}
                                for index, name in enumerate(roots[:5], 1)],
            "fault_category": {"major_category": category["major_category"],
                               "sub_category": category["sub_category"]},
        }
        validate_prediction(prediction)
        predictions.append(prediction)
        trace_path = trace_dir / f"{row['incident_id']}.json"
        trace_path.write_text(json.dumps(row["trace"], ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        internal = {key: value for key, value in row.items() if key not in {"trace", "cluster_rca"}}
        internal["decision_trace_ref"] = f"trace/{row['incident_id']}.json"
        incidents.append(internal)
        rca_rows.append({"incident_id": row["incident_id"], "selected_cluster_id": row["selected_cluster_id"],
                         "cluster_rankings": row["cluster_rca"]})
    if len({row["prediction_id"] for row in predictions}) != len(predictions):
        raise ValueError("duplicate prediction IDs")
    if any(previous["end_time"] > following["start_time"]
           for previous, following in zip(predictions, predictions[1:])):
        raise ValueError("overlapping predictions")
    _jsonl(output / "predictions.jsonl", predictions)
    _jsonl(output / "incidents.jsonl", incidents)
    _jsonl(output / "suspect_candidates.jsonl", result["suspects"])
    candidates = []
    submitted_ids = {item["prediction_id"] for item in predictions}
    for row in [*result["incidents"], *result["suspects"]]:
        if row["incident_id"] in submitted_ids:
            status = "submitted"
        elif row["end_reason"] == "overlap_with_stronger":
            status = "overlap_excluded"
        elif row["end_reason"] == "shadow_global":
            status = "shadow"
        else:
            status = "unconfirmed"
        fault_type = row.get("fault_type")
        category = mapping.get(fault_type)
        rankings = row.get("cluster_rca") or []
        best_hypothesis = rankings[0]["best"] if rankings else None
        candidates.append({**row, "selection_status": status,
                           "best_hypothesis": best_hypothesis,
                           "candidate_fault_category": (
                               {"major_category": category["major_category"],
                                "sub_category": category["sub_category"]} if category else None),
                           "start_time": _utc(row["start_minute"]),
                           "end_time": _utc(row["end_minute_exclusive"])})
    candidates.sort(key=lambda row: (row["start_time"], row["end_time"], row["incident_id"]))
    if len({row["incident_id"] for row in candidates}) != len(candidates):
        raise ValueError("duplicate candidate IDs")
    _jsonl(output / "all_candidates.jsonl", candidates)
    with (output / "all_candidates.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("candidate_id", "start_time", "end_time", "selection_status",
                         "fault_type", "relative_score", "root_top1", "best_hypothesis_type",
                         "best_hypothesis_score", "region", "end_reason", "cluster_ids"))
        for row in candidates:
            best = row["best_hypothesis"] or {}
            roots = row.get("root_cause_candidates") or []
            writer.writerow((row["incident_id"], row["start_time"], row["end_time"],
                             row["selection_status"], row.get("fault_type") or "",
                             row.get("score", ""), roots[0] if roots else "",
                             best.get("fault_type", ""), best.get("score", ""),
                             row["region"], row["end_reason"], ";".join(row["cluster_ids"])))
    _jsonl(output / "clusters.jsonl", result["clusters"])
    _jsonl(output / "cluster_rca.jsonl", rca_rows)
    if "decision_trace" in result:
        _jsonl(output / "decision_trace.jsonl", result["decision_trace"])
    if "missing_context_events" in result:
        _jsonl(output / "missing_context_events.jsonl", result["missing_context_events"])
    summary = {"incident_count": len(predictions), "suspect_count": len(result["suspects"]),
               "candidate_count": len(candidates),
               "candidate_status_counts": dict(sorted(Counter(row["selection_status"] for row in candidates).items())),
               "cluster_count": len(result["clusters"]), "evidence_count": result["evidence_count"],
               "missing_source_count": result.get("missing_source_count", 0),
               "missing_context_count": len(result.get("missing_context_events", [])),
               "fault_type_counts": dict(sorted(Counter(row["fault_type"] for row in incidents).items())),
               "name_counts": result["name_counts"], "excluded_counts": result["excluded_counts"],
               "unknown_signatures": result["unknown_signatures"],
               "unresolved_root_count": sum(not row["root_cause_top5"] for row in predictions)}
    (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output / "run_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return summary
