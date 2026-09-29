"""Bounded-memory, source-grounded anomaly detection for router five-tuples."""

from __future__ import annotations

import csv
from collections import defaultdict, deque
from contextlib import ExitStack
from datetime import datetime, timedelta
import hashlib
import heapq
import json
from pathlib import Path
from statistics import median
from tempfile import TemporaryDirectory


REQUIRED = {"minute_utc", "interface_id", "protocol", "src_addr", "src_port",
            "src_region_inferred", "dst_addr", "dst_port", "dst_region_inferred",
            "packets", "bytes"}
VERSION = "netflow-5tuple-v3"


def load_config(path: Path) -> dict:
    config = json.loads(path.read_text(encoding="utf-8"))
    if config.get("schema_version") != 1:
        raise ValueError("Unsupported five-tuple detection config")
    for key in ("chunk_rows", "history_minutes", "min_history_samples",
                "min_run_minutes", "min_baseline_bytes", "min_baseline_control_packets",
                "min_active_direction_packets", "min_baseline_region_port_bytes",
                "min_baseline_region_port_presence_bytes",
                "min_region_port_change_bytes", "min_interface_coverage_packets",
                "udp_small_max_bytes_per_packet",
                "min_baseline_control_presence_packets",
                "min_baseline_udp_small_packets", "min_udp_small_packet_increase"):
        if type(config.get(key)) is not int or config[key] < 1:
            raise ValueError(f"{key} must be a positive integer")
    for key in ("volume_drop_fraction", "min_normal_opposite_rate",
                "min_normal_volume_presence"):
        if not 0 < config[key] < 1:
            raise ValueError(f"{key} must be between 0 and 1")
    if (config["volume_rise_fraction"] <= 1 or config["min_robust_z"] <= 0
            or config["udp_small_rise_fraction"] <= 1):
        raise ValueError("Invalid rise or robust z threshold")
    return config


def _records(row: dict[str, str], udp_small_max_bytes_per_packet: int):
    """Emit source-derived aggregation keys; never infer a physical link."""
    minute = row["minute_utc"]
    interface = row["interface_id"]
    protocol = row["protocol"]
    if not interface:
        return
    yield (minute, "interface", interface, protocol, "", "", "", "all")
    packets, byte_count = int(row["packets"]), int(row["bytes"])
    if (protocol == "17" and packets > 0
            and byte_count <= packets * udp_small_max_bytes_per_packet):
        yield (minute, "udp_small", interface, protocol, "", "", "", "all")
    if protocol == "89" or protocol == "6" and (
            row["src_port"] == "179" or row["dst_port"] == "179"):
        yield (minute, "control", interface, protocol,
               "179" if protocol == "6" else "", "", "", "all")
    src_region, dst_region = row["src_region_inferred"], row["dst_region_inferred"]
    if (not src_region or not dst_region or src_region == "NULL"
            or dst_region == "NULL" or src_region == dst_region):
        return
    try:
        src_port, dst_port = int(row["src_port"]), int(row["dst_port"])
    except ValueError:
        return
    if not (0 <= src_port <= 65535 and 0 <= dst_port <= 65535):
        return
    port = str(min(src_port, dst_port))
    region_a, region_b = sorted((src_region, dst_region))
    direction = "a_to_b" if src_region == region_a else "b_to_a"
    yield (minute, "region_port", interface, protocol, port, region_a,
           region_b, direction)


def aggregate_chunks(paths: tuple[Path, ...], temp_dir: Path, chunk_rows: int,
                     max_rows: int | None = None,
                     udp_small_max_bytes_per_packet: int = 256):
    """External sort of compact aggregates; raw input order is unrestricted."""
    chunks: list[Path] = []
    current: dict[tuple[str, ...], list[int]] = {}
    scanned = invalid = 0

    def flush() -> None:
        if not current:
            return
        path = temp_dir / f"{len(chunks):06d}.csv"
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerows((*key, *current[key]) for key in sorted(current))
        chunks.append(path)
        current.clear()

    for path in paths:
        with path.open(encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            missing = REQUIRED - set(reader.fieldnames or ())
            if missing:
                raise ValueError(f"Missing columns in {path}: {sorted(missing)}")
            for row in reader:
                if max_rows is not None and scanned >= max_rows:
                    break
                scanned += 1
                if scanned % chunk_rows == 0:
                    flush()
                try:
                    packets, byte_count = int(row["packets"]), int(row["bytes"])
                    datetime.fromisoformat(row["minute_utc"])
                    if packets < 0 or byte_count < 0:
                        raise ValueError("negative count")
                except (ValueError, TypeError):
                    invalid += 1
                    continue
                for key in _records(row, udp_small_max_bytes_per_packet):
                    values = current.setdefault(key, [0, 0, 0])
                    values[0] += packets
                    values[1] += byte_count
                    values[2] += 1
        if max_rows is not None and scanned >= max_rows:
            break
    flush()
    return chunks, scanned, invalid


def merged_aggregates(chunks: list[Path]):
    with ExitStack() as stack:
        readers = [csv.reader(stack.enter_context(path.open(encoding="utf-8", newline="")))
                   for path in chunks]
        previous = None
        totals = [0, 0, 0]
        for row in heapq.merge(*readers, key=lambda item: tuple(item[:-3])):
            key = tuple(row[:-3])
            if previous is not None and key != previous:
                yield previous, tuple(totals)
                totals = [0, 0, 0]
            for index, value in enumerate(row[-3:]):
                totals[index] += int(value)
            previous = key
        if previous is not None:
            yield previous, tuple(totals)


def _stable_id(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:24]


class EpisodeWriter:
    def __init__(self, handle, city: str, node: str, min_run: int):
        self.handle = handle
        self.city = city
        self.node = node
        self.min_run = min_run
        self.active: dict[tuple, dict] = {}
        self.count = 0
        self.feature_counts: dict[str, int] = defaultdict(int)

    def _write(self, key: tuple, event: dict) -> None:
        if event["duration_minutes"] < self.min_run:
            return
        identity = _stable_id(VERSION, self.city, self.node, *map(str, key),
                              event["start_minute"])
        event.pop("duration_minutes")
        event["evidence_id"] = identity
        event["episode_id"] = identity
        self.handle.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
        self.count += 1
        self.feature_counts[event["feature"]] += 1

    def observe(self, minute: str, key: tuple, signal: dict) -> None:
        old = self.active.get(key)
        if old and datetime.fromisoformat(minute) != (
                datetime.fromisoformat(old["last_seen_minute"]) + timedelta(minutes=1)):
            self._write(key, old)
            old = None
        if old is None:
            old = {"start_minute": minute, "last_seen_minute": minute,
                   "entity_id": f"{self.city}-{self.node}", "modality": "netflow",
                   "feature": signal["feature"], "anomaly_kind": signal["anomaly_kind"],
                   "direction": signal["direction"], "raw_score": signal["raw_score"],
                   "score_kind": "relative_change", "reliability": None,
                   "observed": True, "attributes": signal["attributes"],
                   "duration_minutes": 0}
            self.active[key] = old
        old["last_seen_minute"] = minute
        old["duration_minutes"] += 1
        old["raw_score"] = max(old["raw_score"], signal["raw_score"])
        old["attributes"]["last_observed"] = signal["attributes"]["last_observed"]
        if "inferred_zero" in signal["attributes"]:
            old["attributes"]["contains_inferred_zero"] = (
                old["attributes"].get("contains_inferred_zero", False)
                or signal["attributes"]["inferred_zero"])
            old["attributes"]["last_inferred_zero"] = signal["attributes"]["inferred_zero"]
            old["attributes"]["last_interface_coverage_packets"] = signal[
                "attributes"]["interface_coverage_packets"]

    def close_absent(self, seen: set[tuple]) -> None:
        for key in list(self.active):
            if key not in seen:
                self._write(key, self.active.pop(key))


def _volume_signal(value: int, history: deque, config: dict, minimum: int,
                   *, min_change: int = 0, up_only: bool = False,
                   down_only: bool = False,
                   rise_fraction: float | None = None):
    if len(history) < config["min_history_samples"]:
        return None
    values = list(history)
    base = median(values)
    if base < minimum:
        return None
    if (value == 0 and sum(item > 0 for item in values) / len(values)
            < config["min_normal_volume_presence"]):
        return None
    if abs(value - base) < min_change:
        return None
    mad = median(abs(item - base) for item in values)
    scale = max(1.0, 1.4826 * mad, 0.05 * base)
    change = abs(value - base) / base
    z = abs(value - base) / scale
    if z < config["min_robust_z"]:
        return None
    if not up_only and value <= base * config["volume_drop_fraction"]:
        return "down", round(change, 6), base, z
    if not down_only and value >= base * (rise_fraction or config["volume_rise_fraction"]):
        return "up", round(change, 6), base, z
    return None


def detect_router(paths: tuple[Path, ...], output_dir: Path, config: dict,
                  max_rows: int | None = None) -> dict:
    paths = tuple(paths)
    city, node = paths[0].parents[2].name, paths[0].parents[1].name
    destination = output_dir / "routers" / city / node
    destination.mkdir(parents=True, exist_ok=True)
    evidence_path = destination / "evidence_events.jsonl"
    coverage_path = destination / "observation_coverage.jsonl"
    histories: dict[tuple, deque] = {}
    last_seen: dict[tuple, datetime] = {}
    coverage_minutes = 0
    unknown_minutes = 0
    with TemporaryDirectory(prefix="netflow_5tuple_", dir=destination) as temp:
        chunks, scanned, invalid = aggregate_chunks(
            paths, Path(temp), config["chunk_rows"], max_rows,
            config["udp_small_max_bytes_per_packet"])
        with evidence_path.open("w", encoding="utf-8") as evidence, coverage_path.open(
                "w", encoding="utf-8") as coverage:
            episodes = EpisodeWriter(evidence, city, node, config["min_run_minutes"])
            minute = None
            groups: dict[tuple, list[int]] = {}
            row_count = 0

            def score_volume(current: str, now: datetime, series: tuple,
                             values: list[int], seen: set[tuple],
                             *, inferred_zero: bool = False,
                             interface_coverage_packets: int | None = None) -> None:
                kind, interface, protocol, port, region_a, region_b, flow_direction = series
                history = histories.setdefault(series, deque())
                while history and history[0][0] < now - timedelta(
                        minutes=config["history_minutes"]):
                    history.popleft()
                if kind == "control":
                    minimum = config["min_baseline_control_presence_packets"] if inferred_zero else (
                        config["min_baseline_control_packets"])
                    value, unit, feature = values[0], "packets/min", "control_packets"
                    options = {}
                elif kind == "udp_small":
                    minimum = config["min_baseline_udp_small_packets"]
                    value, unit, feature = values[0], "packets/min", "interface_udp_small_packets"
                    options = {"min_change": config["min_udp_small_packet_increase"],
                               "rise_fraction": config["udp_small_rise_fraction"],
                               "up_only": True}
                else:
                    minimum = ((config["min_baseline_region_port_presence_bytes"]
                                if inferred_zero else config["min_baseline_region_port_bytes"])
                               if kind == "region_port" else config["min_baseline_bytes"])
                    value, unit, feature = values[1], "bytes/min", f"{kind}_bytes"
                    options = {"min_change": 0 if inferred_zero else config["min_region_port_change_bytes"],
                               "down_only": True}
                    if kind != "region_port":
                        options = {}
                reference = deque(item[1] for item in history)
                signal = _volume_signal(value, reference, config, minimum, **options)
                if signal:
                    direction_name, score, base, z = signal
                    event_key = (series, "volume", direction_name)
                    episodes.observe(current, event_key, {
                        "feature": feature, "anomaly_kind": "volume_change",
                        "direction": direction_name, "raw_score": score,
                        "attributes": {
                            "interface_id": interface, "protocol": protocol,
                            "port_group": port or None,
                            "region_a_inferred": region_a or None,
                            "region_b_inferred": region_b or None,
                            "dependency_id": _stable_id(city, node, kind, interface,
                                                        protocol, port, region_a, region_b),
                            "flow_direction": flow_direction,
                            "baseline": base, "robust_z": round(z, 3),
                            "baseline_samples": len(reference),
                            "baseline_presence": round(
                                sum(item > 0 for item in reference) / len(reference), 6),
                            "inferred_zero": inferred_zero,
                            "interface_coverage_packets": interface_coverage_packets,
                            "unit": unit,
                            "last_observed": {"packets": values[0], "bytes": values[1]},
                            "source_files": [str(path) for path in paths],
                            "detector_version": VERSION,
                        }})
                    seen.add(event_key)
                # A valid observation belongs to the reference even when it
                # crossed an alert threshold; otherwise a new normal mode can
                # leave the reference permanently locked to the old mode.
                history.append((now, value))
                if any(item[1] > 0 for item in history):
                    last_seen[series] = now
                else:
                    histories.pop(series, None)
                    last_seen.pop(series, None)

            def process(current: str) -> None:
                nonlocal coverage_minutes
                now = datetime.fromisoformat(current)
                seen: set[tuple] = set()
                coverage.write(json.dumps({
                    "minute": current, "modality": "netflow",
                    "entity_id": f"{city}-{node}", "feature_or_source": "netflow_export",
                    "status": "observed", "expected": None,
                    "observed_count": row_count,
                    "source_ref": [str(path) for path in paths]
                }, ensure_ascii=False, separators=(",", ":")) + "\n")
                coverage_minutes += 1
                region_pairs: dict[tuple, list[int]] = defaultdict(lambda: [0, 0])
                covered_interfaces: dict[str, int] = defaultdict(int)
                for key, values in groups.items():
                    if key[0] == "interface":
                        covered_interfaces[key[1]] += values[0]
                observed_series = set(groups)
                for key, values in groups.items():
                    kind, interface, protocol, port, region_a, region_b, direction = key
                    if kind == "region_port":
                        pair = (interface, protocol, port, region_a, region_b)
                        region_pairs[pair][0 if direction == "a_to_b" else 1] += values[0]
                    series = (kind, interface, protocol, port, region_a, region_b, direction)
                    score_volume(current, now, series, values, seen)
                for series in list(histories):
                    if series[0] not in {"interface", "control", "region_port", "udp_small"}:
                        continue
                    if series in observed_series:
                        continue
                    interface = series[1]
                    if (covered_interfaces.get(interface, 0) <
                            config["min_interface_coverage_packets"]):
                        continue
                    if last_seen.get(series) != now - timedelta(minutes=1):
                        continue
                    score_volume(current, now, series, [0, 0, 0], seen,
                                 inferred_zero=True,
                                 interface_coverage_packets=covered_interfaces[interface])
                for pair, counts in region_pairs.items():
                    for index, flow_direction in enumerate(("a_to_b", "b_to_a")):
                        active, opposite = counts[index], counts[1 - index]
                        series = ("opposite_presence", *pair, flow_direction)
                        history = histories.setdefault(series, deque())
                        while history and history[0][0] < now - timedelta(
                                minutes=config["history_minutes"]):
                            history.popleft()
                        normal = [value for _, value in history]
                        anomalous = (active >= config["min_active_direction_packets"]
                                     and opposite == 0
                                     and len(normal) >= config["min_history_samples"]
                                     and sum(normal) / len(normal)
                                     >= config["min_normal_opposite_rate"])
                        if anomalous:
                            event_key = (series, "opposite_absent")
                            interface, protocol, port, region_a, region_b = pair
                            episodes.observe(current, event_key, {
                                "feature": "regional_opposite_presence",
                                "anomaly_kind": "opposite_direction_absence",
                                "direction": "absent", "raw_score": 1.0,
                                "attributes": {"interface_id": interface, "protocol": protocol,
                                               "port_group": port,
                                               "region_a_inferred": region_a,
                                               "region_b_inferred": region_b,
                                               "active_direction": flow_direction,
                                               "dependency_id": _stable_id(
                                                   city, node, "region_port", interface,
                                                   protocol, port, region_a, region_b),
                                               "active_packets": active,
                                               "opposite_packets": opposite,
                                               "baseline_opposite_presence":
                                                   sum(normal) / len(normal),
                                               "baseline_samples": len(normal),
                                               "interface_coverage_packets":
                                                   covered_interfaces.get(interface, 0),
                                               "last_observed": {"active_packets": active,
                                                                 "opposite_packets": opposite},
                                               "source_files": [str(path) for path in paths],
                                               "detector_version": VERSION}})
                            seen.add(event_key)
                        if active >= config["min_active_direction_packets"] and not anomalous:
                            history.append((now, int(opposite > 0)))
                            last_seen[series] = now
                episodes.close_absent(seen)
                # Retain only active histories, bounding memory over long recordings.
                if coverage_minutes % 60 == 0:
                    expired = [key for key, stamp in last_seen.items()
                               if stamp < now - timedelta(minutes=config["history_minutes"])]
                    for key in expired:
                        histories.pop(key, None)
                        last_seen.pop(key, None)

            for key, values in merged_aggregates(chunks):
                current = key[0]
                if minute is not None and current != minute:
                    process(minute)
                    gap = datetime.fromisoformat(minute) + timedelta(minutes=1)
                    while gap < datetime.fromisoformat(current):
                        coverage.write(json.dumps({
                            "minute": gap.strftime("%Y-%m-%d %H:%M:%S"),
                            "modality": "netflow", "entity_id": f"{city}-{node}",
                            "feature_or_source": "netflow_export", "status": "unknown",
                            "expected": None, "observed_count": 0,
                            "source_ref": [str(path) for path in paths]
                        }, ensure_ascii=False, separators=(",", ":")) + "\n")
                        unknown_minutes += 1
                        gap += timedelta(minutes=1)
                    groups = {}
                    row_count = 0
                minute = current
                _, kind, interface, protocol, port, region_a, region_b, direction = key
                groups[(kind, interface, protocol, port, region_a, region_b, direction)] = list(values)
                if kind == "interface":
                    row_count += values[2]
            if minute is not None:
                process(minute)
            episodes.close_absent(set())
    return {"city": city, "node": node, "input_files": [str(path) for path in paths],
            "scanned_rows": scanned, "invalid_rows": invalid,
            "observed_minutes": coverage_minutes, "unknown_minutes": unknown_minutes,
            "evidence_episodes": episodes.count,
            "feature_counts": dict(sorted(episodes.feature_counts.items())),
            "evidence_file": str(evidence_path.relative_to(output_dir)),
            "coverage_file": str(coverage_path.relative_to(output_dir)),
            "sample_limited": max_rows is not None}
