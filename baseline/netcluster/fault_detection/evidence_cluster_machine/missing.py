"""Consolidate expected metric gaps into independent evidence episodes."""

from __future__ import annotations

from collections import defaultdict
from hashlib import sha256

from .events import Event, minute_number, minute_text
def _scrape_sources(feature: str) -> tuple[str, ...]:
    if feature == "node_exporter__scrape_up":
        return ("node_metrics", "interface_metrics")
    if feature == "routing_exporter__scrape_up":
        return ("routing_metrics",)
    return ()



def _missing_context(rows: list[dict], unhealthy: set[tuple[str, str, int]],
                     runtime: dict) -> tuple[list[Event], list[dict]]:
    """Collapse missing metric columns into entity/source episodes in memory."""
    groups: dict[tuple[str, str], dict[int, list[str]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        source = str((row.get("attributes") or {}).get("metric_source") or "unknown")
        groups[row["entity_id"], source][minute_number(row["start_minute"])].append(row["evidence_id"])
    events, records = [], []
    for (entity, source), minutes in sorted(groups.items()):
        ordered = sorted(minutes)
        runs: list[list[int]] = []
        for minute in ordered:
            if (runs and minute == runs[-1][-1] + 1
                    and ((entity, source, minute) in unhealthy)
                    == ((entity, source, runs[-1][-1]) in unhealthy)):
                runs[-1].append(minute)
            else:
                runs.append([minute])
        for run in runs:
            member_ids = [ident for minute in run for ident in minutes[minute]]
            ident = "missing-" + sha256(f"{entity}|{source}|{run[0]}|{run[-1]}".encode()).hexdigest()[:16]
            unhealthy_share = sum((entity, source, minute) in unhealthy for minute in run) / len(run)
            quality = runtime.get("missing_context_quality", 0.6) * (
                1 - unhealthy_share * (1 - runtime.get("missing_unhealthy_multiplier", 0.5)))
            raw = {"evidence_id": ident, "episode_id": ident,
                   "start_minute": minute_text(run[0]), "last_seen_minute": minute_text(run[-1]),
                   "entity_id": entity, "modality": "metric", "feature": "expected_metric_missing",
                   "anomaly_kind": "missing_value", "direction": None, "observed": False,
                   "raw_score": 1.0, "score_kind": "historical_null_indicator",
                   "attributes": {"metric_source": source, "source_event_count": len(member_ids),
                                  "source_event_ids_sample": member_ids[:10], "dependency_id": ident,
                                  "collector_unhealthy_fraction": round(unhealthy_share, 4)}}
            events.append(Event(raw, "metric.expected_missing", "observation_gap",
                                run[0], run[-1], entity.split("-")[0], quality, ident))
            records.append(raw)
    return events, records

