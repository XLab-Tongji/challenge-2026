"""One NORMAL/FAULT scan using evidence relations before post-interval RCA."""

from __future__ import annotations

from bisect import bisect_right
from collections import Counter, defaultdict, deque
from hashlib import sha256
from typing import Iterable

from .events import (Cluster, Event, _family_relation, _prepare, _source_group,
                     minute_number, minute_text)
from .missing import _missing_context, _scrape_sources
from .rca import rank_incident


def _relation(left: Event, right: Event, family: dict, minute: int) -> float:
    """Evidence relation only; no fault-type hypothesis is used online."""
    if left.ident == right.ident:
        return 1.0
    if left.start > minute or right.start > minute:
        return 0.0
    gap = max(0, left.start - min(right.end, minute),
              right.start - min(left.end, minute))
    if gap > 8:
        return 0.0
    if left.dependency == right.dependency:
        return 1.0
    if "observation_gap" in {left.family, right.family}:
        return family.get("missing_relation_same_entity", 0.72) if left.entity == right.entity else 0.0
    family_score = _family_relation(left, right, family)
    if family_score <= family.get("unknown_family_relation", 0.15):
        return 0.0
    if left.entity == right.entity:
        topology = 1.0
    elif left.region == right.region:
        topology = 0.85
    else:
        topology = 0.65 if family_score >= 0.7 else 0.35
    return min(1.0, 0.75 * family_score + 0.15 / (1 + gap / 3) + 0.10 * topology)


def _value(event: Event, minute: int, family: dict, runtime: dict) -> float:
    salience = family["family_salience"].get(event.family, 0.0)
    feature_weight = family.get("temporal_feature_weights", {}).get(event.raw["feature"], 1.0)
    base = event.quality * salience * feature_weight
    if event.start == minute:
        return base
    age = minute - event.start
    if base >= runtime["strong_ongoing_threshold"]:
        return base * 0.4
    return base * 0.4 / (1 + age / runtime["weak_decay_minutes"])


def _changed(previous: object, current: object) -> bool:
    if previous is None or current is None:
        return True
    if isinstance(previous, (int, float)) and isinstance(current, (int, float)):
        return abs(float(current) - float(previous)) > max(1e-6, 0.01 * max(abs(float(previous)), abs(float(current))))
    return previous != current


def _material_step(event: Event, runtime: dict) -> bool:
    """A large measured departure from baseline can maintain a stable fault state."""
    if event.modality != "metric":
        return False
    raw_value, baseline = event.attrs.get("raw_value"), event.attrs.get("baseline_value")
    if not (isinstance(raw_value, (int, float)) and isinstance(baseline, (int, float))):
        return False
    delta = raw_value - baseline
    direction = event.raw.get("direction")
    if direction == "up" and delta <= 0 or direction == "down" and delta >= 0:
        return False
    score = event.raw.get("raw_score")
    if not (isinstance(score, (int, float)) and score >= runtime["material_ratio_score_min"]
            and event.quality >= 0.55):
        return False
    if (event.raw["feature"].endswith("_ratio") or event.raw["feature"] == "disk_io_util") \
            and 0 <= raw_value <= 1 and 0 <= baseline <= 1:
        return abs(delta) >= runtime["material_ratio_change"]
    rule = runtime.get("material_absolute_steps", {}).get(event.raw["feature"])
    if rule is None or direction != "up":
        return False
    return delta >= rule["min_absolute"] and raw_value >= max(
        rule["min_absolute"], baseline * rule["min_fold"])


def _remember_anchor(active: dict, event: Event) -> None:
    """Keep one recent representative per independent source group."""
    group = _source_group(event)
    active["anchors"] = deque((item for item in active["anchors"]
                                if _source_group(item) != group),
                               maxlen=active["anchors"].maxlen)
    active["anchors"].append(event)


def _aggregate(items: list[tuple[Event, float]], runtime: dict) -> float:
    groups: dict[str, float] = {}
    modalities = set()
    for event, value in items:
        key = _source_group(event)
        groups[key] = max(groups.get(key, 0.0), value)
        modalities.add(event.modality)
    if not groups:
        return 0.0
    return min(1.0, max(groups.values())
               + min(runtime["max_independent_bonus"],
                     runtime["independent_bonus"] * (len(groups) - 1))
               + (runtime["cross_modality_bonus"] if len(modalities) > 1 else 0.0))


def _within_source_corroboration(items: list[tuple[Event, float]], minute: int,
                                 family: dict, runtime: dict) -> float:
    """Give a small bonus to distinct, related signs from one dependent source."""
    by_source: dict[str, list[Event]] = defaultdict(list)
    for event, _ in items:
        if event.quality >= runtime["corroboration_quality_min"]:
            by_source[_source_group(event)].append(event)
    for events in by_source.values():
        for index, left in enumerate(events):
            for right in events[index + 1:]:
                if (left.family != right.family and left.dependency != right.dependency
                        and left.entity == right.entity
                        and _relation(left, right, family, minute) >= runtime["association_threshold"]):
                    return runtime["within_source_corrob_bonus"]
    return 0.0


def _candidate_seed(members: list[Event], minute: int, family: dict, runtime: dict) -> bool:
    return any(event.start == minute and family.get("event_diagnosticity", {}).get(event.family) == "weak"
               and family["family_salience"].get(event.family, 0.0) >= runtime["candidate_seed_salience_min"]
               and event.quality >= runtime["candidate_seed_quality_min"] for event in members)


def _startup(window: list[Event], minute: int, family: dict,
             runtime: dict) -> tuple[float, list[Event]]:
    """Score coherent recent evidence, never the sum of unrelated anomalies."""
    candidates = [event for event in window if event.start <= minute
                  and event.end >= minute - runtime["candidate_window_minutes"] + 1]
    best_score, best_members = 0.0, []
    for seed in candidates:
        members = [event for event in candidates
                   if event.ident == seed.ident or _relation(event, seed, family, minute)
                   >= runtime["association_threshold"]]
        valued = [(event, _value(event, minute, family, runtime)) for event in members]
        score = min(1.0, _aggregate(valued, runtime)
                    + _within_source_corroboration(valued, minute, family, runtime))
        previous_raw: dict[str, object] = {}
        starts = set()
        for event in sorted(members, key=lambda item: (item.start, item.ident)):
            group = _source_group(event)
            raw_value = event.attrs.get("raw_value")
            if event.quality >= 0.5 and (group not in previous_raw
                                         or _changed(previous_raw[group], raw_value)
                                         or _material_step(event, runtime)):
                starts.add(event.start)
            previous_raw[group] = raw_value
        enough_repetition = len(starts) >= (2 if any(event.quality >= 0.7 for event in members) else 3)
        if enough_repetition and len({event.raw["episode_id"] for event in members}) >= 2:
            score = min(1.0, score + min(runtime["max_persistence_bonus"],
                                         runtime["repeated_observation_bonus"] * (len(starts) - 1)))
        if score > best_score:
            best_score, best_members = score, members
    return best_score, best_members


def _strong_seed(event: Event, minute: int, family: dict, runtime: dict) -> bool:
    role = family.get("event_diagnosticity", {}).get(event.family)
    if role != "strong":
        return False
    if _value(event, minute, family, runtime) >= runtime["strong_single_threshold"]:
        return True
    return (event.start == minute and event.raw.get("score_kind") == "local_mad_z"
            and isinstance(event.raw.get("raw_score"), (int, float))
            and event.raw["raw_score"] >= runtime["strong_local_mad_z"]
            and event.quality >= 0.7)


def _material_start(event: Event, rule: dict) -> bool:
    """Require a measured departure from baseline for a relaxed resource start."""
    if event.modality != "metric" or event.quality < rule["min_quality"]:
        return False
    score = event.raw.get("raw_score")
    raw = event.attrs.get("raw_value")
    baseline = event.attrs.get("baseline_value")
    if not all(isinstance(value, (int, float)) for value in (score, raw, baseline)):
        return False
    if score < rule["min_raw_score"] or raw - baseline < rule["min_absolute"]:
        return False
    return raw >= max(rule["min_absolute"], baseline * rule["min_fold"])


def _relaxed_start(members: list[Event], minute: int, score: float, runtime: dict) -> bool:
    """Admit clear CPU or disk IO evidence while retaining ordinary weak starts."""
    rules = runtime.get("relaxed_start_rules", {})
    for fault_type in ("resource_cpu_high", "resource_disk_io_pressure"):
        rule = rules.get(fault_type)
        if not rule or score < rule["min_start_score"]:
            continue
        direct = [event for event in members if event.raw["feature"] == rule["feature"]
                  and _material_start(event, rule)]
        by_entity: dict[str, list[Event]] = defaultdict(list)
        for event in direct:
            by_entity[event.entity].append(event)
        for entity, events in by_entity.items():
            if not any(event.start == minute for event in events):
                continue
            if len({event.start for event in events}) >= rule["min_minutes"]:
                return True
    return False


def _covered(events: dict[str, Event], minute: int, coverage: dict | None) -> bool:
    if coverage is None:
        return True
    intervals = coverage.get("entity_intervals")
    if intervals is None:
        return any(coverage.get((event.region, minute), 0) for event in events.values())
    for event in events.values():
        pair = intervals.get((event.entity, event.modality))
        if pair:
            starts, ends = pair
            index = bisect_right(starts, minute) - 1
            if index >= 0 and ends[index] >= minute:
                return True
    return False


def _incident(start: int, end: int, events: dict[str, Event], trace: list[dict],
              reason: str) -> tuple[dict, Cluster]:
    end = max(start + 1, end)
    evidence = {ident: event for ident, event in events.items()
                if event.start < end and event.end >= start}
    cluster_id = "cl-" + sha256(f"{start}:{end}:{sorted(evidence)}".encode()).hexdigest()[:16]
    cluster = Cluster(cluster_id, start, end - 1)
    cluster.events = evidence
    cluster.anchors = sorted(evidence.values(), key=lambda event: (event.start, event.ident))[-3:]
    ident = "inc-" + sha256(f"{start}:{end}:{cluster_id}".encode()).hexdigest()[:16]
    region = next(iter(evidence.values())).region if evidence else "unknown"
    row = {"incident_id": ident, "start": start, "end": end,
           "last_support": end - 1, "cluster_ids": {cluster_id},
           "region": region, "end_reason": reason, "trace": trace}
    return row, cluster


def infer_two_state(raw_events: Iterable[dict], family_config: dict, fault_config: dict,
                    runtime: dict, *, calibration: dict | None = None,
                    coverage: dict | None = None) -> dict:
    """Scan a single global fault state, then infer type and root per closed interval."""
    names, excluded, unknown = Counter(), Counter(), Counter()
    observed_events, missing_rows, unhealthy = [], [], set()
    for raw in raw_events:
        if raw.get("modality") == "metric" and raw.get("anomaly_kind") == "missing_value":
            missing_rows.append(raw)
            continue
        if raw.get("modality") == "metric" and (raw.get("attributes") or {}).get("raw_value") == 0:
            unhealthy.update((raw["entity_id"], source, minute_number(raw["start_minute"]))
                             for source in _scrape_sources(raw.get("feature", "")))
        event = _prepare(raw, family_config, calibration or {})
        if event is None:
            if raw.get("observed"):
                unknown[f"{raw.get('modality')}|{raw.get('feature')}|{raw.get('anomaly_kind')}|{raw.get('direction')}"] += 1
            else:
                excluded["unobserved"] += 1
            continue
        names[event.name] += 1
        if event.family in {"collection_context", "persistent_background"}:
            excluded[event.family] += 1
            continue
        observed_events.append(event)
    missing_events, missing_context = _missing_context(missing_rows, unhealthy, runtime)
    observed_events.extend(missing_events)
    names["metric.expected_missing"] += len(missing_events)
    by_minute: dict[int, list[Event]] = defaultdict(list)
    for event in observed_events:
        for minute in range(event.start, event.end + 1):
            by_minute[minute].append(event)
    if not by_minute:
        return {"incidents": [], "suspects": [], "clusters": [], "name_counts": dict(names),
                "excluded_counts": dict(excluded), "unknown_signatures": dict(unknown),
                "evidence_count": 0, "missing_context_events": missing_context,
                "missing_source_count": len(missing_rows), "decision_trace": []}
    mode, active, recent = "NORMAL", None, deque()
    closed, unconfirmed, cluster_rows = [], [], []
    last_closed_end = min(by_minute)
    candidate_points: list[tuple[int, float, list[Event]]] = []
    decision_trace: list[dict] = []
    source_runs: dict[str, tuple[int, int]] = {}
    covered_range = coverage.get("range") if coverage else None
    first_minute = minute_number(covered_range[0]) if covered_range else min(by_minute)
    last_minute = minute_number(covered_range[1]) if covered_range else max(by_minute)
    for minute in range(min(first_minute, min(by_minute)), max(last_minute, max(by_minute)) + 1):
        current = by_minute.get(minute, [])
        new_events = [event for event in current if event.start == minute]
        for group in {_source_group(event) for event in new_events}:
            previous = source_runs.get(group)
            source_runs[group] = (minute, previous[1] if previous and previous[0] == minute - 1 else minute)
        recent.extend(new_events)
        while recent and recent[0].start < minute - runtime["candidate_window_minutes"] + 1:
            recent.popleft()
        if mode == "NORMAL":
            start_score, members = _startup(list(recent), minute, family_config, runtime)
            strong = any(_strong_seed(event, minute, family_config, runtime) for event in members)
            ready = (strong or _relaxed_start(members, minute, start_score, runtime)
                     or (start_score >= runtime["start_threshold"]
                         and len({event.start for event in members}) >= 2))
            if not ready and (start_score >= runtime["weak_group_threshold"]
                              or start_score >= runtime["weak_candidate_threshold"]
                              and _candidate_seed(members, minute, family_config, runtime)):
                candidate_points.append((minute, start_score, members))
            if ready:
                start = max(last_closed_end, min(event.start for event in members))
                active = {"start": start, "last_support": minute, "accepted": {},
                          "anchors": deque(maxlen=runtime["anchor_group_limit"]), "trace": [],
                          "coactivity": {},
                          "no_support": 0, "recent_raw": {}}
                for event in members:
                    active["accepted"][event.ident] = event
                    _remember_anchor(active, event)
                    active["recent_raw"][_source_group(event)] = event.attrs.get("raw_value")
                mode = "FAULT"
                recent = deque(event for event in recent if event.ident not in active["accepted"])
                for event in recent:
                    active["coactivity"].setdefault(_source_group(event), {})[event.ident] = event
                active["trace"].append({"minute": minute_text(minute), "state": mode,
                                        "S_old": 0.0, "S_new": round(start_score, 4),
                                        "O": 0.0, "N": round(start_score, 4), "K": 0.0,
                                        "transition": "start", "accepted_event_ids": sorted(active["accepted"]),
                                        "candidate_start": minute_text(start)})
                decision_trace.append({**active["trace"][-1], "event_count": len(current)})
            else:
                decision_trace.append({"minute": minute_text(minute), "state": "NORMAL",
                                       "S_old": 0.0, "S_new": round(start_score, 4),
                                       "candidate_event_ids": sorted(event.ident for event in members),
                                       "event_count": len(current), "transition": "none"})
            continue
        assert active is not None
        old_items, unrelated = [], []
        for event in current:
            if event.ident in active["accepted"]:
                association = 1.0
            else:
                association = max((_relation(event, anchor, family_config, minute)
                                   for anchor in active["accepted"].values()
                                   if anchor.end >= minute - 8), default=0.0)
            if association >= runtime["association_threshold"]:
                freshness = 1.0
                source_group = _source_group(event)
                raw_value = event.attrs.get("raw_value")
                if (event.ident not in active["accepted"] and source_group in active["recent_raw"]
                        and not _changed(active["recent_raw"][source_group], raw_value)
                        and family_config["family_salience"].get(event.family, 0) < 0.65):
                    freshness = (runtime["material_plateau_hold_factor"]
                                 if _material_step(event, runtime) else 0.3)
                elif (event.ident not in active["accepted"] and source_group in active["recent_raw"]
                      and not _changed(active["recent_raw"][source_group], raw_value)):
                    freshness = 0.5
                old_items.append((event, _value(event, minute, family_config, runtime)
                                  * association * freshness))
                if event.ident not in active["accepted"]:
                    active["accepted"][event.ident] = event
                    _remember_anchor(active, event)
                    active["recent_raw"][source_group] = raw_value
            else:
                unrelated.append(event)
        old_score = _aggregate(old_items, runtime)
        if old_score >= runtime["old_support_threshold"]:
            active["last_support"] = minute
            active["no_support"] = 0
        else:
            active["no_support"] += 1
        recent = deque(event for event in recent if event.ident not in active["accepted"])
        new_score, new_members = _startup(list(recent), minute, family_config, runtime)
        strong_new = any(_strong_seed(event, minute, family_config, runtime) for event in new_members)
        new_ready = (strong_new or _relaxed_start(new_members, minute, new_score, runtime)
                     or (new_score >= runtime["start_threshold"]
                         and len({event.start for event in new_members}) >= 2))
        same_fault = new_ready and old_score >= runtime["same_fault_threshold"]
        coincident_added: list[str] = []
        for event in unrelated:
            if event.start == minute:
                active["coactivity"].setdefault(_source_group(event), {})[event.ident] = event
        if same_fault:
            for event in new_members:
                if event.ident not in active["accepted"]:
                    active["accepted"][event.ident] = event
                    _remember_anchor(active, event)
                    active["recent_raw"][_source_group(event)] = event.attrs.get("raw_value")
                    coincident_added.append(event.ident)
            recent = deque(event for event in recent if event.ident not in active["accepted"])
            unrelated = [event for event in unrelated if event.ident not in active["accepted"]]
        elif old_score >= runtime["coactivity_old_support_threshold"]:
            for group, bucket in list(active["coactivity"].items()):
                run = source_runs.get(group)
                if not run or run[0] < minute - runtime["candidate_window_minutes"]:
                    del active["coactivity"][group]
                    continue
                if (run[0] != minute or minute - run[1] + 1 < runtime["coactivity_confirm_minutes"]
                        or run[1] < active["start"] - runtime["coactivity_onset_slack_minutes"]):
                    continue
                eligible = [event for event in bucket.values()
                            if event.quality >= runtime["coactivity_min_quality"]
                            and event.quality * family_config.get("coactivity_weight", family_config["family_salience"]).get(
                                event.family, 0.0) >= runtime["coactivity_min_weighted_quality"]]
                if not eligible:
                    continue
                for event in eligible:
                    if event.ident not in active["accepted"]:
                        active["accepted"][event.ident] = event
                        _remember_anchor(active, event)
                        active["recent_raw"][_source_group(event)] = event.attrs.get("raw_value")
                        coincident_added.append(event.ident)
                del active["coactivity"][group]
            if coincident_added:
                recent = deque(event for event in recent if event.ident not in active["accepted"])
                unrelated = [event for event in unrelated if event.ident not in active["accepted"]]
        if new_score >= runtime["weak_group_threshold"] or (new_score >= runtime["weak_candidate_threshold"]
                and _candidate_seed(new_members, minute, family_config, runtime)):
            candidate_points.append((minute, new_score, new_members))
        observed = _covered(active["accepted"], minute, coverage)
        trace = {"minute": minute_text(minute), "state": mode,
                 "S_old": round(old_score, 4), "S_new": round(new_score, 4),
                 "O": round(old_score, 4), "N": round(new_score, 4), "K": 0.0,
                 "accepted_event_ids": [event.ident for event, _ in old_items],
                 "coincident_accepted_event_ids": sorted(set(coincident_added)),
                 "unassigned_event_ids": [event.ident for event in unrelated],
                 "coverage_observed": observed,
                 "no_support_minutes": active["no_support"]}
        active["trace"].append(trace)
        switch = (new_ready and not same_fault and old_score < runtime["same_fault_threshold"]
                  and (old_score < runtime["old_support_threshold"]
                       or new_score >= old_score + runtime["switch_strength_margin"]))
        recover = (old_score < runtime["old_support_threshold"]
                   and (active["no_support"] >= runtime["recovery_absolute_minutes"]
                        or observed and active["no_support"] >= runtime["recovery_observed_minutes"]))
        if switch or recover:
            end = active["last_support"] + 1
            if switch:
                end = min(end, min(event.start for event in new_members))
                end = max(active["start"] + 1, end)
                trace["transition"] = "switch"
            else:
                trace["transition"] = "recovered"
            row, cluster = _incident(active["start"], end, active["accepted"],
                                     active["trace"], trace["transition"])
            closed.append((row, cluster))
            last_closed_end = end
            if switch:
                selected = new_members
                if selected:
                    start = max(end, min(event.start for event in selected))
                    active = {"start": start, "last_support": minute, "accepted": {},
                              "anchors": deque(maxlen=runtime["anchor_group_limit"]), "trace": [],
                              "coactivity": {},
                              "no_support": 0, "recent_raw": {}}
                    for event in selected:
                        active["accepted"][event.ident] = event
                        _remember_anchor(active, event)
                        active["recent_raw"][_source_group(event)] = event.attrs.get("raw_value")
                    active["trace"].append({"minute": minute_text(minute), "state": "FAULT",
                                            "S_old": 0.0, "S_new": round(new_score, 4),
                                            "O": 0.0, "N": round(new_score, 4), "K": 0.0,
                                            "transition": "start_after_switch",
                                            "accepted_event_ids": sorted(active["accepted"])})
                    recent = deque(event for event in recent if event.ident not in active["accepted"])
                else:
                    active, mode = None, "NORMAL"
            else:
                active, mode = None, "NORMAL"
        elif same_fault:
            trace["transition"] = "same_fault"
        decision_trace.append({**trace, "state_after": mode, "event_count": len(current)})
    if active is not None:
        row, cluster = _incident(active["start"], active["last_support"] + 1,
                                 active["accepted"], active["trace"], "input_end")
        closed.append((row, cluster))
    candidate_groups: list[dict] = []
    for minute, score, members in candidate_points:
        if not members:
            continue
        if (candidate_groups and minute - candidate_groups[-1]["last"]
                <= runtime["candidate_window_minutes"]
                and any(_relation(event, anchor, family_config, minute)
                        >= runtime["association_threshold"]
                        for event in members for anchor in candidate_groups[-1]["anchors"][-3:])):
            group = candidate_groups[-1]
            group["last"] = minute
            group["end"] = max(group["end"], *(event.end + 1 for event in members))
            group["peak"] = max(group["peak"], score)
            group["events"].update((event.ident, event) for event in members)
            group["anchors"].extend(members)
        else:
            candidate_groups.append({"start": min(event.start for event in members),
                                     "last": minute, "end": max(event.end + 1 for event in members),
                                     "peak": score,
                                     "events": {event.ident: event for event in members},
                                     "anchors": members[:]})
    accepted_sets = [set(cluster.events) for _, cluster in closed]
    for group in candidate_groups:
        if any(set(group["events"]) <= accepted for accepted in accepted_sets):
            continue
        containing = next(((row, cluster) for row, cluster in closed
                           if row["start"] <= group["start"] and group["end"] <= row["end"]), None)
        if containing is not None:
            row, cluster = containing
            remainder = sorted(set(group["events"]) - set(cluster.events))
            row["coincident_unassigned_event_ids"] = sorted(
                set(row.get("coincident_unassigned_event_ids", [])) | set(remainder))
            continue
        row, cluster = _incident(group["start"], group["end"],
                                 group["events"], [{"minute": minute_text(group["last"]),
                                                    "state": "NORMAL", "S_old": 0.0,
                                                    "S_new": round(group["peak"], 4),
                                                    "O": 0.0, "N": round(group["peak"], 4),
                                                    "K": 0.0, "transition": "unconfirmed"}],
                                 "weak_unconfirmed")
        unconfirmed.append(row)
        closed.append((row, cluster))
    clusters = {cluster.ident: cluster for _, cluster in closed}
    formal = []
    for row, cluster in closed:
        interval_context = {event.ident: event
                            for minute in range(row["start"], row["end"])
                            for event in by_minute.get(minute, ())}
        row.update(rank_incident(row, clusters, fault_config, family_config,
                                 context_events=list(interval_context.values())))
        if row["end_reason"] == "weak_unconfirmed":
            pass
        elif row["fault_type"] is None:
            unconfirmed.append(row)
        else:
            formal.append(row)
        cluster.incident_id = row["incident_id"] if row in formal else None
        cluster_rows.append({"cluster_id": cluster.ident,
                             "first_minute": minute_text(cluster.start),
                             "last_related_minute": minute_text(cluster.last),
                             "event_ids": sorted(cluster.events),
                             "families": dict(Counter(event.family for event in cluster.events.values())),
                             "regions": sorted({event.region for event in cluster.events.values()}),
                             "entities": sorted({event.entity for event in cluster.events.values()}),
                             "incident_id": cluster.incident_id,
                             "status": "active" if cluster.incident_id else "candidate"})
    if any(left["end"] > right["start"] for left, right in zip(formal, formal[1:])):
        raise AssertionError("two-state intervals overlap")
    unique_suspects = {row["incident_id"]: row for row in unconfirmed}
    return {"incidents": formal, "suspects": list(unique_suspects.values()), "clusters": cluster_rows,
            "name_counts": dict(names), "excluded_counts": dict(excluded),
            "unknown_signatures": dict(unknown), "evidence_count": len(observed_events),
            "missing_context_events": missing_context, "missing_source_count": len(missing_rows),
            "decision_trace": decision_trace}
