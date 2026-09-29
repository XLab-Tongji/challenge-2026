"""Normalize detector events and represent related evidence."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import math
def minute_number(value: str) -> int:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp() // 60)



def minute_text(value: int) -> str:
    return datetime.fromtimestamp(value * 60, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")



def derive_name(raw: dict, config: dict) -> str | None:
    """Resolve a name in memory; source JSONL rows are never modified."""
    if not raw.get("observed") or raw.get("anomaly_kind") == "missing_value":
        return None
    attributes = raw.get("attributes") or {}
    for name, rule in config["event_name_rules"].items():
        if raw.get("modality") != rule["modality"]:
            continue
        if "feature" in rule and raw.get("feature") != rule["feature"]:
            continue
        if "feature_any" in rule and raw.get("feature") not in rule["feature_any"]:
            continue
        if "direction" in rule and raw.get("direction") != rule["direction"]:
            continue
        if "anomaly_kind" in rule and raw.get("anomaly_kind") != rule["anomaly_kind"]:
            continue
        if "attributes_raw_value_equals" in rule:
            observed, expected = attributes.get("raw_value"), rule["attributes_raw_value_equals"]
            if isinstance(observed, (int, float)) and isinstance(expected, (int, float)):
                if observed != expected:
                    continue
            elif str(observed) != str(expected):
                continue
        if "attributes_protocol" in rule and str(attributes.get("protocol")) != str(rule["attributes_protocol"]):
            continue
        if "attributes_template_id_any" in rule and str(attributes.get("template_id")) not in rule["attributes_template_id_any"]:
            continue
        return name
    return None



def region_hops(left: str, right: str, config: dict) -> int | None:
    if left == right:
        return 0
    adjacent: dict[str, set[str]] = defaultdict(set)
    for a, b in config["region_edges"]:
        adjacent[a].add(b)
        adjacent[b].add(a)
    queue = deque([(left, 0)])
    seen = {left}
    while queue:
        region, distance = queue.popleft()
        for neighbor in adjacent[region]:
            if neighbor == right:
                return distance + 1
            if neighbor not in seen:
                seen.add(neighbor)
                queue.append((neighbor, distance + 1))
    return None



def _role(entity: str) -> str:
    if entity.endswith("-fw"):
        return "fw"
    if "-br-" in entity:
        return "br"
    if "-cr-" in entity:
        return "cr"
    if "-service-vm-" in entity:
        return "service"
    return "traffic"



def _region(raw: dict) -> str:
    if raw["modality"] == "traffic_flow":
        return (raw.get("attributes") or {}).get("target_region") or raw["entity_id"].split("-")[0]
    return raw["entity_id"].split("-")[0]



def _quality(raw: dict, calibration: dict) -> float:
    if raw.get("score_kind") == "state_rule_indicator":
        return 1.0
    value = raw.get("raw_score")
    if not isinstance(value, (float, int)) or not math.isfinite(value):
        return 0.7
    key = f"{raw['modality']}|{raw['feature']}|{raw.get('score_kind')}"
    scale = calibration.get(key)
    if scale and scale["count"] >= 10:
        low, high = scale["q50"], scale["q90"]
        if high > low:
            result = min(1.0, 0.55 + 0.45 * max(0.0, (value - low) / (high - low)))
        else:
            result = 0.7
    elif raw.get("score_kind") in {"error_fraction", "timeout_fraction"}:
        result = min(1.0, max(0.55, float(value)))
    else:
        result = min(1.0, 0.55 + 0.16 * math.log1p(max(0.0, value)))
    reliability = raw.get("reliability")
    return result * reliability if isinstance(reliability, (float, int)) else result



@dataclass(slots=True)
class Event:
    raw: dict
    name: str
    family: str
    start: int
    end: int
    region: str
    quality: float
    dependency: str

    @property
    def ident(self) -> str:
        return self.raw["evidence_id"]

    @property
    def entity(self) -> str:
        return self.raw["entity_id"]

    @property
    def modality(self) -> str:
        return self.raw["modality"]

    @property
    def attrs(self) -> dict:
        return self.raw.get("attributes") or {}



def _prepare(raw: dict, config: dict, calibration: dict) -> Event | None:
    name = derive_name(raw, config)
    if name is None:
        return None
    family = config["event_name_to_family"][name]
    start, end = minute_number(raw["start_minute"]), minute_number(raw["last_seen_minute"])
    if end < start or end - start > 1440:
        raise ValueError(f"invalid evidence interval: {raw.get('evidence_id')}")
    return Event(raw, name, family, start, end, _region(raw), _quality(raw, calibration),
                 str((raw.get("attributes") or {}).get("dependency_id") or raw["episode_id"]))



def _condition(left: Event, right: Event, condition: str) -> bool:
    if condition == "same_entity":
        return left.entity == right.entity
    if condition == "same_router":
        if left.entity != right.entity:
            return False
        left_peer = (left.attrs.get("labels") or {}).get("peer") or left.attrs.get("peer")
        right_peer = (right.attrs.get("labels") or {}).get("peer") or right.attrs.get("peer")
        return not (left_peer and right_peer and left_peer != right_peer)
    if condition == "same_region":
        return left.region == right.region
    if condition == "target_region":
        probe = left if left.modality == "traffic_flow" else right if right.modality == "traffic_flow" else None
        other = right if probe is left else left
        return probe is not None and other.region == probe.region
    if condition == "same_flow":
        if left.modality != "traffic_flow" or right.modality != "traffic_flow":
            return False
        return (left.region == right.region and left.attrs.get("flow_type") == right.attrs.get("flow_type")
                and left.attrs.get("target_domain") == right.attrs.get("target_domain"))
    if condition == "flow_regions":
        probe = left if left.modality == "traffic_flow" else right if right.modality == "traffic_flow" else None
        flow = right if probe is left else left
        if probe is None or flow.family != "regional_return_absence":
            return False
        observed = {flow.attrs.get("region_a_inferred"), flow.attrs.get("region_b_inferred")}
        return None not in observed and observed == {probe.attrs.get("source_region"), probe.region}
    raise ValueError(f"unknown relation condition: {condition}")



def _family_relation(left: Event, right: Event, config: dict) -> float:
    if left.ident == right.ident or left.raw["episode_id"] == right.raw["episode_id"]:
        return 1.0
    if left.family == right.family:
        if left.modality == right.modality == "traffic_flow":
            return config["same_family_relation"] if _condition(left, right, "same_flow") else 0.0
        if left.family == "regional_return_absence":
            left_regions = {left.attrs.get("region_a_inferred"), left.attrs.get("region_b_inferred")}
            right_regions = {right.attrs.get("region_a_inferred"), right.attrs.get("region_b_inferred")}
            if None in left_regions or left_regions != right_regions:
                return 0.0
        if left.family.startswith("bgp_") and not _condition(left, right, "same_router"):
            return 0.0
        if left.entity == right.entity:
            return config["same_family_relation"]
    best = config["unknown_family_relation"]
    for rule in config["family_relations"]:
        if {left.family, right.family} != {rule["family_a"], rule["family_b"]}:
            continue
        if abs(left.start - right.start) > rule["lag_minutes"] + max(left.end-left.start, right.end-right.start):
            continue
        if _condition(left, right, rule["condition"]):
            best = max(best, rule["strength"])
    return best



def family_relation(left: dict, right: dict, config: dict) -> float:
    a, b = _prepare(left, config, {}), _prepare(right, config, {})
    return _family_relation(a, b, config) if a and b else 0.0



@dataclass
class Cluster:
    ident: str
    start: int
    last: int
    events: dict[str, Event] = field(default_factory=dict)
    anchors: list[Event] = field(default_factory=list)
    strengths: dict[int, float] = field(default_factory=dict)
    incident_id: str | None = None

    def add(self, event: Event, minute: int) -> None:
        self.events[event.ident] = event
        self.last = max(self.last, minute)
        if not any(anchor.ident == event.ident for anchor in self.anchors):
            self.anchors = [anchor for anchor in self.anchors if anchor.dependency != event.dependency]
            self.anchors.append(event)
            self.anchors = self.anchors[-3:]



def _source_group(event: Event) -> str:
    if event.modality == "metric":
        resource = ("cpu" if event.family == "compute_load" else
                    "disk" if event.family in {"disk_io_util_rise", "disk_activity_rise"} else
                    "interface" if event.family.startswith("interface_") else event.family)
        return f"metric|{event.entity}|{resource}"
    if event.modality == "traffic_flow":
        return f"traffic|{event.attrs.get('series_key') or event.dependency}|{event.family}"
    return f"{event.modality}|{event.dependency}"

