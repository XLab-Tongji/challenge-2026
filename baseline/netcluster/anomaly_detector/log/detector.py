from __future__ import annotations

import argparse
import csv
import hashlib
import json
import pickle
import re
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from baseline.netcluster.anomaly_detector.log.templates import LogFile, discover_log_files
from baseline.netcluster.anomaly_detector.events import write_event_rows


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
DEFAULT_KEYWORDS_CONFIG = Path(__file__).resolve().parents[2] / "config" / "log_anomaly_keywords.json"
VERSION = "frr-log-v2"


@dataclass(frozen=True)
class LogKeywordRules:
    error_severities: tuple[str, ...]
    warning_severities: tuple[str, ...]
    obvious_keywords: tuple[str, ...]
    possible_keywords: tuple[str, ...]
    template_rules: tuple[dict[str, str], ...]


def load_keyword_rules(path: Path = DEFAULT_KEYWORDS_CONFIG) -> LogKeywordRules:
    payload = json.loads(path.read_text(encoding="utf-8"))
    base_fields = {"error_severities", "warning_severities",
                   "obvious_keywords", "possible_keywords"}
    is_legacy = set(payload) == base_fields
    is_current = (payload.get("schema_version") == 2
                  and set(payload) == base_fields | {"schema_version", "template_rules"})
    if (not (is_legacy or is_current)
            or any(not isinstance(payload[key], list) for key in base_fields)
            or (is_current and not isinstance(payload["template_rules"], list))):
        raise ValueError(f"Invalid log keyword configuration: {path}")
    needed = {"name", "template_contains", "level", "feature", "dependency_family"}
    rules = []
    for item in payload.get("template_rules", []):
        if (not isinstance(item, dict) or set(item) != needed
                or any(not isinstance(item[key], str) or not item[key].strip()
                       for key in needed)
                or item["level"] not in {"background", "possible_anomaly", "obvious_anomaly"}):
            raise ValueError(f"Invalid template rule in {path}: {item}")
        rules.append({key: value.casefold() if key == "template_contains" else value
                      for key, value in item.items()})
    return LogKeywordRules(
        error_severities=tuple(value.casefold() for value in payload["error_severities"]),
        warning_severities=tuple(value.casefold() for value in payload["warning_severities"]),
        obvious_keywords=tuple(value.casefold() for value in payload["obvious_keywords"]),
        possible_keywords=tuple(value.casefold() for value in payload["possible_keywords"]),
        template_rules=tuple(rules),
    )


def match_template_rule(template: str, rules: LogKeywordRules) -> dict[str, str] | None:
    text = template.casefold()
    return next((rule for rule in rules.template_rules
                 if rule["template_contains"] in text), None)


@dataclass(frozen=True)
class LogPoint:
    city: str
    node: str
    source: str
    entity: str
    aligned_minute: datetime
    template_id: str
    template: str
    anomaly_level: str
    feature: str
    dependency_family: str
    rule_name: str
    severity: str
    program: str
    message: str


@dataclass
class EventAccumulator:
    city: str
    node: str
    source: str
    entity: str
    template_id: str
    template: str
    anomaly_level: str
    feature: str
    dependency_family: str
    rule_name: str
    start_time: datetime
    end_time: datetime
    count: int = 0
    severity_counts: dict[str, int] | None = None
    program_counts: dict[str, int] | None = None
    first_message: str = ""
    last_message: str = ""


def parse_timestamp(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                parsed = None
        if parsed is None:
            return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed.replace(second=0, microsecond=0)


def load_miner(model_path: Path):
    with model_path.open("rb") as handle:
        return pickle.load(handle)


def template_for_message(miner: Any, message: str) -> tuple[str, str]:
    cluster = None
    try:
        cluster = miner.match(message)
    except Exception:
        cluster = None
    if cluster is None:
        try:
            result = miner.add_log_message(message)
        except Exception:
            result = {}
        template = str(result.get("template_mined") or message) if isinstance(result, dict) else message
        fallback_id = hashlib.sha256(template.encode("utf-8")).hexdigest()[:16]
        template_id = str(result.get("cluster_id") or result.get("cluster_id_str") or fallback_id) if isinstance(result, dict) else fallback_id
        return template_id, template
    try:
        template = str(cluster.get_template())
    except Exception:
        template = message
    template_id = str(getattr(cluster, "cluster_id", "")
                      or hashlib.sha256(template.encode("utf-8")).hexdigest()[:16])
    return template_id, template


def classify_template(template: str, severity: str, rules: LogKeywordRules | None = None) -> str:
    rules = rules or load_keyword_rules()
    explicit = match_template_rule(template, rules)
    if explicit is not None:
        return explicit["level"]
    sev = severity.strip().lower()
    text = f" {template.strip().lower()} "
    if sev in rules.error_severities:
        return "obvious_anomaly"
    if any(keyword in text for keyword in rules.obvious_keywords):
        return "obvious_anomaly"
    if sev in rules.warning_severities:
        return "possible_anomaly"
    if any(keyword in text for keyword in rules.possible_keywords):
        return "possible_anomaly"
    return "background"


def read_log_points(
    log_file: LogFile,
    miner: Any,
    time_column: str,
    message_column: str,
    keyword_rules: LogKeywordRules | None = None,
) -> list[LogPoint]:
    points: list[LogPoint] = []
    with log_file.path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            timestamp = parse_timestamp(row.get(time_column, "") or row.get("event_time", "") or row.get("received_at", ""))
            raw_message = row.get(message_column, "") or row.get("message", "")
            message = _ANSI_RE.sub("", str(raw_message).strip())
            if timestamp is None or not message:
                continue
            template_id, template = template_for_message(miner, message)
            severity = str(row.get("severity", "")).strip().lower()
            explicit = match_template_rule(template, keyword_rules or load_keyword_rules())
            points.append(
                LogPoint(
                    city=log_file.city,
                    node=log_file.node,
                    source=log_file.source,
                    entity=str(row.get("entity", "") or log_file.node),
                    aligned_minute=timestamp,
                    template_id=template_id,
                    template=template,
                    anomaly_level=classify_template(template, severity, keyword_rules),
                    feature=explicit["feature"] if explicit else "frr_syslog_events",
                    dependency_family=(explicit["dependency_family"] if explicit
                                       else f"template:{template_id}"),
                    rule_name=explicit["name"] if explicit else "severity_or_keyword_fallback",
                    severity=severity,
                    program=str(row.get("program", "")).strip(),
                    message=message,
                )
            )
    return points


def minute_key(point: LogPoint) -> tuple[str, str, str, str, str, str, datetime]:
    return (
        point.city,
        point.node,
        point.source,
        point.entity,
        point.template_id,
        point.anomaly_level,
        point.aligned_minute,
    )


def build_minute_buckets(points: list[LogPoint]) -> dict[tuple[str, str, str, str, str, str, datetime], EventAccumulator]:
    buckets: dict[tuple[str, str, str, str, str, str, datetime], EventAccumulator] = {}
    for point in points:
        key = minute_key(point)
        bucket = buckets.get(key)
        if bucket is None:
            bucket = EventAccumulator(
                city=point.city,
                node=point.node,
                source=point.source,
                entity=point.entity,
                template_id=point.template_id,
                template=point.template,
                anomaly_level=point.anomaly_level,
                feature=point.feature,
                dependency_family=point.dependency_family,
                rule_name=point.rule_name,
                start_time=point.aligned_minute,
                end_time=point.aligned_minute,
                severity_counts={},
                program_counts={},
                first_message=point.message,
            )
            buckets[key] = bucket
        bucket.count += 1
        bucket.last_message = point.message
        if bucket.severity_counts is not None:
            bucket.severity_counts[point.severity or "unknown"] = bucket.severity_counts.get(point.severity or "unknown", 0) + 1
        if bucket.program_counts is not None:
            bucket.program_counts[point.program or "unknown"] = bucket.program_counts.get(point.program or "unknown", 0) + 1
    return buckets


def merge_adjacent_minute_events(minute_events: list[EventAccumulator]) -> list[EventAccumulator]:
    grouped: dict[tuple[str, str, str, str, str, str], list[EventAccumulator]] = {}
    for event in minute_events:
        grouped.setdefault(
            (event.city, event.node, event.source, event.entity, event.template_id, event.anomaly_level),
            [],
        ).append(event)

    merged: list[EventAccumulator] = []
    for events in grouped.values():
        events.sort(key=lambda item: item.start_time)
        current: EventAccumulator | None = None
        for event in events:
            if current is None:
                current = replace(
                    event,
                    severity_counts=dict(event.severity_counts or {}),
                    program_counts=dict(event.program_counts or {}),
                )
                continue
            delta_minutes = int((event.start_time - current.end_time).total_seconds() // 60)
            if delta_minutes == 1:
                current.end_time = event.end_time
                current.count += event.count
                current.last_message = event.last_message
                _add_counts(current.severity_counts, event.severity_counts)
                _add_counts(current.program_counts, event.program_counts)
            else:
                merged.append(current)
                current = replace(
                    event,
                    severity_counts=dict(event.severity_counts or {}),
                    program_counts=dict(event.program_counts or {}),
                )
        if current is not None:
            merged.append(current)
    merged.sort(key=lambda item: (item.start_time, item.city, item.entity, item.template_id))
    return merged


def _add_counts(target: dict[str, int] | None, source: dict[str, int] | None) -> None:
    if target is None or source is None:
        return
    for key, value in source.items():
        target[key] = target.get(key, 0) + value


def counts_text(counts: dict[str, int] | None) -> str:
    if not counts:
        return ""
    return ";".join(f"{key}:{counts[key]}" for key in sorted(counts))


def event_rows(events: list[EventAccumulator]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, event in enumerate(events, start=1):
        rows.append(
            {
                "event_id": f"LOG-E-{index:06d}",
                "city": event.city,
                "entity": f"{event.city}.{event.entity}",
                "raw_entity": event.entity,
                "source_node": event.node,
                "source_file": event.source,
                "template_id": event.template_id,
                "template": event.template,
                "anomaly_level": event.anomaly_level,
                "feature": event.feature,
                "dependency_family": event.dependency_family,
                "rule_name": event.rule_name,
                "start_time": event.start_time.strftime("%Y-%m-%d %H:%M:%S"),
                "end_time": event.end_time.strftime("%Y-%m-%d %H:%M:%S"),
                "duration_minutes": int((event.end_time - event.start_time).total_seconds() // 60) + 1,
                "count": event.count,
                "severity_counts": counts_text(event.severity_counts),
                "program_counts": counts_text(event.program_counts),
                "first_message": event.first_message,
                "last_message": event.last_message,
            }
        )
    return rows


def write_events_csv(events: list[EventAccumulator], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rows = event_rows(events)
    fieldnames = [
        "event_id",
        "city",
        "entity",
        "raw_entity",
        "source_node",
        "source_file",
        "template_id",
        "template",
        "anomaly_level",
        "feature",
        "dependency_family",
        "rule_name",
        "start_time",
        "end_time",
        "duration_minutes",
        "count",
        "severity_counts",
        "program_counts",
        "first_message",
        "last_message",
    ]
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _stable_id(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:24]


def standard_evidence_row(event: EventAccumulator, source_path: Path) -> dict[str, Any]:
    start = event.start_time.strftime("%Y-%m-%d %H:%M:%S")
    identity = _stable_id(VERSION, event.city, event.node, event.source,
                          event.entity, event.template_id, start)
    return {
        "evidence_id": identity,
        "episode_id": identity,
        "start_minute": start,
        "last_seen_minute": event.end_time.strftime("%Y-%m-%d %H:%M:%S"),
        "entity_id": f"{event.city}-{event.entity}",
        "modality": "log",
        "feature": event.feature,
        "anomaly_kind": "routing_log_event",
        "direction": None,
        "raw_score": event.count,
        "score_kind": "log_count",
        "reliability": None,
        "observed": True,
        "attributes": {
            "template_id": event.template_id,
            "template": event.template,
            "anomaly_level": event.anomaly_level,
            "rule_name": event.rule_name,
            "dependency_family": event.dependency_family,
            "dependency_id": _stable_id(event.city, event.node,
                                        event.dependency_family),
            "count": event.count,
            "severity_counts": dict(event.severity_counts or {}),
            "program_counts": dict(event.program_counts or {}),
            "first_message": event.first_message,
            "last_message": event.last_message,
            "source_node": event.node,
            "source_file": str(source_path),
            "detector_version": VERSION,
            "reliability_missing_reason": "not_calibrated",
        },
    }


def write_standard_outputs(
    anomaly_events: list[EventAccumulator], points: list[LogPoint],
    source_lookup: dict[tuple[str, str, str], Path], output_dir: Path,
) -> tuple[Path, Path, int]:
    output_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = output_dir / "evidence_events.jsonl"
    coverage_path = output_dir / "observation_coverage.jsonl"
    with evidence_path.open("w", encoding="utf-8") as handle:
        for event in anomaly_events:
            source = source_lookup[(event.city, event.node, event.source)]
            handle.write(json.dumps(standard_evidence_row(event, source),
                                    ensure_ascii=False, separators=(",", ":")) + "\n")
    counts: dict[tuple[str, str, str, str, datetime], int] = {}
    for point in points:
        key = (point.city, point.node, point.entity, point.source,
               point.aligned_minute)
        counts[key] = counts.get(key, 0) + 1
    with coverage_path.open("w", encoding="utf-8") as handle:
        for (city, node, entity, source, minute), count in sorted(
                counts.items(), key=lambda item: (item[0][4], *item[0][:4])):
            source_path = source_lookup[(city, node, source)]
            row = {
                "minute": minute.strftime("%Y-%m-%d %H:%M:%S"),
                "modality": "log",
                "entity_id": f"{city}-{entity}",
                "feature_or_source": source,
                "status": "observed",
                "expected": False,
                "observed_count": count,
                "source_ref": str(source_path),
            }
            handle.write(json.dumps(row, ensure_ascii=False,
                                    separators=(",", ":")) + "\n")
    return evidence_path, coverage_path, len(counts)


def write_template_review(points: list[LogPoint], output_path: Path) -> None:
    by_id: dict[str, dict[str, Any]] = {}
    for point in points:
        row = by_id.setdefault(point.template_id, {
            "template_id": point.template_id,
            "template": point.template,
            "observed_count": 0,
            "anomaly_level": point.anomaly_level,
            "feature": point.feature,
            "rule_name": point.rule_name,
            "dependency_family": point.dependency_family,
            "severity_counts": {},
            "program_counts": {},
        })
        row["observed_count"] += 1
        row["severity_counts"][point.severity or "unknown"] = (
            row["severity_counts"].get(point.severity or "unknown", 0) + 1)
        row["program_counts"][point.program or "unknown"] = (
            row["program_counts"].get(point.program or "unknown", 0) + 1)
    fields = ("template_id", "observed_count", "template", "anomaly_level",
              "feature", "rule_name", "dependency_family", "severity_counts",
              "program_counts")
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in sorted(by_id.values(), key=lambda item: (
                not item["template_id"].isdigit(),
                int(item["template_id"]) if item["template_id"].isdigit()
                else item["template_id"])):
            row["severity_counts"] = json.dumps(row["severity_counts"],
                                                ensure_ascii=False, sort_keys=True)
            row["program_counts"] = json.dumps(row["program_counts"],
                                               ensure_ascii=False, sort_keys=True)
            writer.writerow(row)


def write_minute_events_csv(minute_events: list[EventAccumulator], output_path: Path) -> None:
    ordered = sorted(minute_events, key=lambda item: (item.start_time, item.city, item.entity, item.template_id))
    write_events_csv(ordered, output_path)


def write_anomaly_events_csv(minute_events: list[EventAccumulator], output_path: Path) -> None:
    ordered = sorted(minute_events, key=lambda item: (item.start_time, item.city, item.entity, item.template_id))
    write_event_rows(
        output_path,
        (
            {
                "地区": event.city,
                "实体名称": event.entity,
                "数据类型": "日志",
                "名称": event.template,
                "异常类型": "关键词异常",
                "开始时间": event.start_time.strftime("%Y-%m-%d %H:%M:%S"),
                "结束时间": event.start_time.strftime("%Y-%m-%d %H:%M:%S"),
                "异常值": event.count,
            }
            for event in ordered
        ),
    )


def run_builder(
    data_root: Path,
    output_dir: Path,
    drain_model: Path,
    include_city: str | None = None,
    include_node: str | None = None,
    include_source: str | None = None,
    time_column: str = "event_time",
    message_column: str = "message",
    max_files: int | None = None,
    progress_every: int = 10,
    keywords_config: Path = DEFAULT_KEYWORDS_CONFIG,
) -> dict[str, Any]:
    log_files = discover_log_files(
        data_root,
        include_city=include_city,
        include_node=include_node,
        include_source=include_source,
        max_files=max_files,
    )
    print(f"[log-events] discovered log csv files={len(log_files)} under {data_root}", flush=True)
    if not log_files:
        raise SystemExit("No log csv files found.")
    miner = load_miner(drain_model)
    keyword_rules = load_keyword_rules(keywords_config)

    points: list[LogPoint] = []
    for ordinal, log_file in enumerate(log_files, start=1):
        if ordinal == 1 or ordinal == len(log_files) or ordinal % max(1, progress_every) == 0:
            print(
                f"[log-events] aligning {ordinal}/{len(log_files)}: "
                f"{log_file.city}/{log_file.node}/{log_file.source}",
                flush=True,
            )
        points.extend(read_log_points(log_file, miner, time_column, message_column, keyword_rules))

    minute_events = list(build_minute_buckets(points).values())
    all_events = merge_adjacent_minute_events(minute_events)
    anomaly_events = [
        event
        for event in all_events
        if event.anomaly_level in {"obvious_anomaly", "possible_anomaly"}
    ]
    anomaly_minute_events = [
        event
        for event in minute_events
        if event.anomaly_level in {"obvious_anomaly", "possible_anomaly"}
    ]

    all_file = output_dir / "log_events_all_templates.csv"
    anomaly_file = output_dir / "log_events_anomaly_templates.csv"
    all_minute_file = output_dir / "log_minute_events_all_templates.csv"
    anomaly_minute_file = output_dir / "log_minute_events_anomaly_templates.csv"
    write_events_csv(all_events, all_file)
    write_anomaly_events_csv(anomaly_minute_events, anomaly_file)
    write_minute_events_csv(minute_events, all_minute_file)
    write_anomaly_events_csv(anomaly_minute_events, anomaly_minute_file)
    source_lookup = {(log_file.city, log_file.node, log_file.source): log_file.path
                     for log_file in log_files}
    evidence_file, coverage_file, coverage_count = write_standard_outputs(
        anomaly_events, points, source_lookup, output_dir)
    template_review_file = output_dir / "template_review.csv"
    write_template_review(points, template_review_file)

    level_counts: dict[str, int] = {}
    for event in all_events:
        level_counts[event.anomaly_level] = level_counts.get(event.anomaly_level, 0) + 1
    summary = {
        "detector_version": VERSION,
        "log_file_count": len(log_files),
        "aligned_log_count": len(points),
        "minute_event_count": len(minute_events),
        "all_event_count": len(all_events),
        "anomaly_event_count": len(anomaly_minute_events),
        "merged_anomaly_event_count": len(anomaly_events),
        "all_minute_event_count": len(minute_events),
        "anomaly_minute_event_count": len(anomaly_minute_events),
        "standard_evidence_count": len(anomaly_events),
        "coverage_record_count": coverage_count,
        "event_count_by_level": level_counts,
        "all_event_file": str(all_file),
        "anomaly_event_file": str(anomaly_file),
        "all_minute_event_file": str(all_minute_file),
        "anomaly_minute_event_file": str(anomaly_minute_file),
        "evidence_file": str(evidence_file),
        "coverage_file": str(coverage_file),
        "template_review_file": str(template_review_file),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "log_event_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(
        f"[log-events] finished all_events={len(all_events)} anomaly_minutes={len(anomaly_minute_events)} "
        f"output={output_dir}",
        flush=True,
    )
    return summary


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build minute-aligned log anomaly events from parsed Drain templates.")
    parser.add_argument(
        "--data-root",
        type=Path,
        default=Path("data/updated/first_stage"),
    )
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/log_anomalies"))
    parser.add_argument(
        "--drain-model",
        type=Path,
        default=Path("outputs/log_anomalies/templates/drain_log_template_miner.pkl"),
    )
    parser.add_argument("--include-city", type=str, default=None)
    parser.add_argument("--include-node", type=str, default=None)
    parser.add_argument("--include-source", type=str, default=None)
    parser.add_argument("--time-column", type=str, default="event_time")
    parser.add_argument("--message-column", type=str, default="message")
    parser.add_argument("--max-files", type=int, default=None)
    parser.add_argument("--progress-every", type=int, default=10)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    summary = run_builder(
        data_root=args.data_root,
        output_dir=args.output_dir,
        drain_model=args.drain_model,
        include_city=args.include_city,
        include_node=args.include_node,
        include_source=args.include_source,
        time_column=args.time_column,
        message_column=args.message_column,
        max_files=args.max_files,
        progress_every=args.progress_every,
    )
    print(json.dumps(summary, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
