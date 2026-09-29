"""Evidence-guided length cap for already inferred fault intervals."""

from __future__ import annotations

from dataclasses import dataclass, replace

from .evidence_cluster_machine.events import Event


@dataclass(frozen=True)
class FaultInterval:
    start: int
    end: int
    fault_type: str | None
    root: str | None
    event_ids: frozenset[str]


def _diagnostic_events(interval: FaultInterval, events: dict[str, Event],
                       fault_priors: dict) -> list[tuple[Event, float]]:
    rule = fault_priors.get("fault_priors", {}).get(interval.fault_type, {})
    direct = rule.get("direct", {})
    effect = rule.get("effect", {})
    members = [events[ident] for ident in interval.event_ids if ident in events
               and events[ident].start < interval.end and events[ident].end >= interval.start]
    primary = [(event, direct[event.family] * event.quality) for event in members
               if event.family in direct and (interval.root is None or event.entity == interval.root)]
    if primary:
        if interval.fault_type == "route_bgp_session_down":
            # peer_up=0 measures the outage; low uptime in Established is its aftermath.
            state = [(event, weight) for event, weight in primary
                     if event.raw.get("feature") == "bgp_peer_up"]
            if state:
                return state
        return primary
    return [(event, effect[event.family] * event.quality) for event in members
            if event.family in effect]


def trim_to_max_duration(interval: FaultInterval, events: dict[str, Event],
                         fault_priors: dict, *, max_minutes: int = 30) -> FaultInterval:
    """Keep the compact diagnostic span or the strongest contiguous window."""
    if max_minutes < 1 or interval.end <= interval.start:
        raise ValueError("Fault duration and maximum duration must be positive")
    if interval.end - interval.start <= max_minutes:
        return interval

    strengths = [0.0] * (interval.end - interval.start)
    for event, weight in _diagnostic_events(interval, events, fault_priors):
        for minute in range(max(interval.start, event.start), min(interval.end, event.end + 1)):
            strengths[minute - interval.start] = max(strengths[minute - interval.start], weight)

    peak = max(strengths)
    if peak >= 0.2:
        threshold = max(0.2, peak * 0.5)
        supported = [index for index, strength in enumerate(strengths) if strength >= threshold]
        first, last = supported[0], supported[-1] + 1
        if last - first <= max_minutes:
            start = max(0, first - 1)
            end = min(len(strengths), last + 1)
            if end - start > max_minutes:
                start = max(0, min(start, end - max_minutes))
                end = start + max_minutes
            return replace(interval, start=interval.start + start, end=interval.start + end)

    if not any(strengths):
        members = [events[ident] for ident in interval.event_ids if ident in events]
        for event in members:
            for minute in range(max(interval.start, event.start), min(interval.end, event.end + 1)):
                index = minute - interval.start
                strengths[index] = max(strengths[index], event.quality)

    total = sum(strengths[:max_minutes])
    best_total, best_start = total, 0
    for index in range(max_minutes, len(strengths)):
        total += strengths[index] - strengths[index - max_minutes]
        if total > best_total + 1e-9:
            best_total, best_start = total, index - max_minutes + 1
    return replace(interval, start=interval.start + best_start,
                   end=interval.start + best_start + max_minutes)
