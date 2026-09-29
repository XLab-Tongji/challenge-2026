"""Cap inferred fault durations at 30 minutes without changing other diagnoses."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aiops_challenge_2026.schema import validate_prediction
from baseline.netcluster.fault_detection.evidence_cluster_machine.events import _prepare, minute_number
from baseline.netcluster.fault_detection.postprocess import FaultInterval, trim_to_max_duration

DEFAULT_SOURCE = ROOT / "outputs/submission/raw"
DEFAULT_OUTPUT = ROOT / "outputs/submission/result"
FAMILY_PRIOR = ROOT / "baseline/netcluster/config/evidence_cluster_family_priors.json"


def _read_jsonl(path: Path):
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            yield json.loads(line)


def _write_jsonl(path: Path, rows) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def _digest(path: Path) -> str:
    result = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            result.update(block)
    return result.hexdigest()


def _utc(minute: int) -> str:
    return datetime.fromtimestamp(minute * 60, timezone.utc).isoformat(
        timespec="milliseconds").replace("+00:00", "Z")


def _load_events(source: Path, wanted: set[str], family: dict,
                 calibration: dict) -> dict:
    events = {}
    for raw in _read_jsonl(source / "evidence_events.jsonl"):
        if raw["evidence_id"] in wanted:
            event = _prepare(raw, family, calibration)
            if event is not None:
                events[event.ident] = event
    return events


def run(source: Path = DEFAULT_SOURCE, output: Path = DEFAULT_OUTPUT) -> dict:
    source, output = source.resolve(), output.resolve()
    if source == output or source in output.parents or output in source.parents:
        raise ValueError("Submission output must be separate from the source result")

    source_file = source / "predictions.jsonl"
    source_sha = _digest(source_file)
    originals = list(_read_jsonl(source_file))
    original_by_id = {row["prediction_id"]: row for row in originals}
    if len(original_by_id) != len(originals):
        raise ValueError("Duplicate source prediction IDs")

    manifest = json.loads((source / "run_manifest.json").read_text(encoding="utf-8"))
    effective_prior = source / "effective_fault_priors.json"
    if manifest["family_prior_sha256"] != _digest(FAMILY_PRIOR):
        raise ValueError("Family prior differs from the inference run")
    if manifest["effective_fault_prior_sha256"] != _digest(effective_prior):
        raise ValueError("Effective fault prior differs from the inference run")
    family = json.loads(FAMILY_PRIOR.read_text(encoding="utf-8"))
    faults = json.loads(effective_prior.read_text(encoding="utf-8"))
    calibration = json.loads((source / "score_calibration.json").read_text(encoding="utf-8"))

    incidents = list(_read_jsonl(source / "incidents.jsonl"))
    incident_ids = {row["incident_id"] for row in incidents}
    if incident_ids != set(original_by_id):
        raise ValueError("Source incidents and predictions do not match")
    long_incidents = [row for row in incidents
                      if minute_number(row["end_minute_exclusive"])
                      - minute_number(row["start_minute"]) > 30]
    wanted_clusters = {ident for row in long_incidents for ident in row["cluster_ids"]}
    clusters = {row["cluster_id"]: row["event_ids"]
                for row in _read_jsonl(source / "clusters.jsonl")
                if row["cluster_id"] in wanted_clusters}
    if set(clusters) != wanted_clusters:
        raise ValueError("A long fault references a missing evidence cluster")
    wanted_events = {ident for row in long_incidents for cluster_id in row["cluster_ids"]
                     for ident in clusters[cluster_id]}
    events = _load_events(source, wanted_events, family, calibration)

    predictions = dict(original_by_id)
    changes = []
    for row in long_incidents:
        event_ids = frozenset(ident for cluster_id in row["cluster_ids"]
                              for ident in clusters[cluster_id])
        interval = FaultInterval(
            start=minute_number(row["start_minute"]),
            end=minute_number(row["end_minute_exclusive"]),
            fault_type=row.get("fault_type"),
            root=(row.get("root_cause_candidates") or [None])[0],
            event_ids=event_ids,
        )
        trimmed = trim_to_max_duration(interval, events, faults)
        original = original_by_id[row["incident_id"]]
        prediction = {**original, "start_time": _utc(trimmed.start),
                      "end_time": _utc(trimmed.end)}
        predictions[row["incident_id"]] = prediction
        changes.append({
            "prediction_id": row["incident_id"],
            "original_start_time": original["start_time"],
            "original_end_time": original["end_time"],
            "start_time": prediction["start_time"],
            "end_time": prediction["end_time"],
            "diagnostic_event_count": len(event_ids & events.keys()),
        })

    result = sorted(predictions.values(),
                    key=lambda row: (row["start_time"], row["end_time"], row["prediction_id"]))
    for prediction in result:
        validate_prediction(prediction)
        duration = (minute_number(prediction["end_time"])
                    - minute_number(prediction["start_time"]))
        if duration > 30:
            raise ValueError(f"Fault exceeds 30 minutes: {prediction['prediction_id']}")
    if _digest(source_file) != source_sha:
        raise RuntimeError("Source predictions changed during postprocessing")

    output.mkdir(parents=True, exist_ok=True)
    _write_jsonl(output / "predictions.jsonl", result)
    _write_jsonl(output / "changes.jsonl", changes)
    summary = {
        "source_count": len(originals),
        "submission_count": len(result),
        "trimmed_count": len(changes),
        "maximum_duration_minutes": max(
            (minute_number(row["end_time"]) - minute_number(row["start_time"])
             for row in result), default=0),
    }
    (output / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    submission_manifest = {
        "source_result": str(source),
        "source_predictions_sha256": source_sha,
        "source_manifest_sha256": _digest(source / "run_manifest.json"),
        "policy": {"maximum_fault_duration_minutes": 30},
        "prediction_count": len(result),
    }
    (output / "run_manifest.json").write_text(
        json.dumps(submission_manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    print(json.dumps({"output": str(args.output), **run(args.source, args.output)},
                     ensure_ascii=False))


if __name__ == "__main__":
    main()
