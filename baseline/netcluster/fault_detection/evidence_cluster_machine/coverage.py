"""Summarize detector observation coverage for fault inference."""

from __future__ import annotations

from collections import Counter, defaultdict
import json
from pathlib import Path

from .events import minute_number, minute_text


def read_coverage(paths: dict[str, Path]) -> tuple[dict[int, int], dict]:
    """Keep only global minute coverage; no silent source is treated as normal."""
    changes = defaultdict(lambda: [0, 0, 0])
    status_count = Counter()
    bounds = [10**18, 0]
    for modality, path in paths.items():
        if not path.exists():
            status_count[f"{modality}:file_missing"] += 1
            continue
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                row = json.loads(line)
                first_minute = row.get("minute", row.get("start_minute"))
                start = minute_number(first_minute)
                end = minute_number(row.get("last_seen_minute", first_minute))
                bounds[0] = min(bounds[0], start)
                bounds[1] = max(bounds[1], end)
                status = row.get("status", "unknown")
                status_count[f"{modality}:{status}"] += 1
                if status == "observed" and modality != "log":
                    index = {"metric": 0, "traffic_flow": 1, "netflow": 2}[modality]
                    region = row["entity_id"].split("-")[0]
                    changes[region, start][index] += 1
                    changes[region, end + 1][index] -= 1
    if bounds[1] < bounds[0]:
        return {}, {"status_count": dict(status_count), "range": None}
    mask = {}
    regions = sorted({region for region, _ in changes})
    for region in regions:
        active = [0, 0, 0]
        for minute in range(bounds[0], bounds[1] + 1):
            change = changes.get((region, minute))
            if change:
                for index in range(3):
                    active[index] += change[index]
            mask[region, minute] = sum(1 << index for index, count in enumerate(active) if count > 0)
    return mask, {"status_count": dict(status_count),
                  "range": [minute_text(bounds[0]), minute_text(bounds[1])],
                  "observed_region_minutes": sum(bool(value) for value in mask.values()),
                  "regions": regions}


