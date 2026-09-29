"""Evidence-based duration-only postprocessing checks."""

from baseline.netcluster.fault_detection.evidence_cluster_machine.events import Event
from baseline.netcluster.fault_detection.postprocess import FaultInterval, trim_to_max_duration


FAULTS = {"fault_priors": {
    "resource_cpu_high": {"direct": {"compute_load": 0.7}, "effect": {}},
    "link_loss": {"direct": {}, "effect": {"compute_load": 0.4}},
    "route_bgp_session_down": {"direct": {"bgp_session_loss": 0.92}, "effect": {}},
}}


def event(ident, start, end, *, family="compute_load", feature="cpu_usage",
          quality=1.0):
    raw = {"evidence_id": ident, "episode_id": ident, "entity_id": "beida-br-1",
           "modality": "metric", "feature": feature, "attributes": {}}
    return Event(raw, ident, family, start, end, "beida", quality, ident)


def interval(start, end, *, fault_type="resource_cpu_high", event_ids=()):
    return FaultInterval(start, end, fault_type, "beida-br-1", frozenset(event_ids))


def test_short_fault_is_unchanged():
    row = interval(0, 30, event_ids=("a",))
    assert trim_to_max_duration(row, {"a": event("a", 0, 29)}, FAULTS) is row


def test_weak_tails_trim_to_compact_direct_evidence():
    row = interval(0, 36, event_ids=("weak", "strong"))
    events = {"weak": event("weak", 0, 5, quality=0.2),
              "strong": event("strong", 20, 31)}
    trimmed = trim_to_max_duration(row, events, FAULTS)
    assert (trimmed.start, trimmed.end) == (19, 33)
    assert trimmed.event_ids == row.event_ids


def test_continuous_direct_evidence_selects_one_30_minute_window():
    row = interval(0, 44, event_ids=("direct",))
    trimmed = trim_to_max_duration(row, {"direct": event("direct", 1, 43)}, FAULTS)
    assert (trimmed.start, trimmed.end) == (1, 31)


def test_bgp_uptime_after_recovery_does_not_extend_outage():
    row = interval(0, 44, fault_type="route_bgp_session_down",
                   event_ids=("down", "uptime"))
    events = {"down": event("down", 1, 23, family="bgp_session_loss",
                            feature="bgp_peer_up"),
              "uptime": event("uptime", 24, 43, family="bgp_session_loss",
                              feature="bgp_peer_uptime_seconds")}
    trimmed = trim_to_max_duration(row, events, FAULTS)
    assert (trimmed.start, trimmed.end) == (0, 25)


def test_effect_only_fault_uses_effect_evidence():
    row = interval(0, 40, fault_type="link_loss", event_ids=("effect",))
    trimmed = trim_to_max_duration(row, {"effect": event("effect", 20, 34)}, FAULTS)
    assert (trimmed.start, trimmed.end) == (19, 36)


def test_disjoint_evidence_does_not_split_into_two_faults():
    row = interval(0, 45, event_ids=("first", "second"))
    events = {"first": event("first", 2, 12),
              "second": event("second", 20, 32)}
    trimmed = trim_to_max_duration(row, events, FAULTS)
    assert trimmed.end - trimmed.start == 30
    assert trimmed.event_ids == row.event_ids


def test_missing_evidence_uses_deterministic_earliest_window():
    row = interval(0, 40)
    trimmed = trim_to_max_duration(row, {}, FAULTS)
    assert (trimmed.start, trimmed.end) == (0, 30)
