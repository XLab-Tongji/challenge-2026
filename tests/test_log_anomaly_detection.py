"""Template review and standardized log evidence behavior."""

from datetime import datetime
import json
from pathlib import Path

from baseline.netcluster.anomaly_detector.log import detector


OBSERVED_TEMPLATES = {
    "1": "SPF Scheduled in <:*:> msec",
    "2": "SPF processing # Areas 1 SPF runtime 0 sec <:*:> usec Reason R+ R- <:*:>",
    "3": "SPF processing # Areas 1 SPF runtime 0 sec <:*:> usec Reason R+ R-",
    "4": "SPF processing # Areas 1 SPF runtime 0 sec <:*:> usec Reason N-",
    "5": "bgp update receive rcvd End-of-RIB for IPv6 Unicast from fd00 100 10 <:*:> in vrf default",
    "6": "sendmsg failed ifindex <:*:> Operation not permitted (1)",
    "7": "[EC 100663307] Could not send entire message",
    "8": "[EC 33554454] fd00 100 10 <:*:> [Error] bgp read packet error < EXCEPTION < PRODUCT CODE > RESET >",
}


def test_every_observed_template_has_an_explicit_review_rule():
    rules = detector.load_keyword_rules()
    expected = {
        "1": ("background", "ospf6_spf_scheduled"),
        "2": ("background", "ospf6_spf_processing"),
        "3": ("background", "ospf6_spf_processing"),
        "4": ("background", "ospf6_spf_processing"),
        "5": ("background", "bgp_end_of_rib"),
        "6": ("possible_anomaly", "ospf6_send_failure"),
        "7": ("obvious_anomaly", "ospf6_send_failure"),
        "8": ("obvious_anomaly", "bgp_session_reset"),
    }
    assert set(OBSERVED_TEMPLATES) == set(expected)
    for template_id, template in OBSERVED_TEMPLATES.items():
        rule = detector.match_template_rule(template, rules)
        assert rule is not None
        assert (rule["level"], rule["feature"]) == expected[template_id]
        assert detector.classify_template(template, "err", rules) == rule["level"]


def test_merged_log_episode_uses_standard_evidence_contract():
    event = detector.EventAccumulator(
        city="xian", node="br-1", source="frr_syslog_events", entity="br-1",
        template_id="8", template="bgp read packet error Connection reset by peer",
        anomaly_level="obvious_anomaly", feature="bgp_session_reset",
        dependency_family="bgp_session_reset", rule_name="bgp_session_reset",
        start_time=datetime(2026, 8, 19, 20, 48),
        end_time=datetime(2026, 8, 19, 20, 49), count=3,
        severity_counts={"err": 3}, program_counts={"bgpd": 3},
        first_message="Connection reset by peer", last_message="Connection reset by peer",
    )
    evidence = detector.standard_evidence_row(event, Path("logs/xian/br-1/frr_syslog_events.csv"))
    assert set(evidence) == {
        "evidence_id", "episode_id", "start_minute", "last_seen_minute",
        "entity_id", "modality", "feature", "anomaly_kind", "direction",
        "raw_score", "score_kind", "reliability", "observed", "attributes",
    }
    assert evidence["feature"] == "bgp_session_reset"
    assert evidence["start_minute"] == "2026-08-19 20:48:00"
    assert evidence["last_seen_minute"] == "2026-08-19 20:49:00"
    assert evidence["raw_score"] == 3
    assert evidence["score_kind"] == "log_count"
    assert evidence["reliability"] is None
    assert evidence["attributes"]["template_id"] == "8"
    assert json.dumps(evidence, ensure_ascii=False)


def test_log_coverage_marks_only_observed_minutes(tmp_path: Path):
    source = tmp_path / "xian" / "br-1" / "log" / "frr_syslog_events.csv"
    point = detector.LogPoint(
        city="xian", node="br-1", source="frr_syslog_events", entity="router-alias",
        aligned_minute=datetime(2026, 8, 19, 20, 48), template_id="8",
        template="bgp read packet error", anomaly_level="obvious_anomaly",
        feature="bgp_session_reset", dependency_family="bgp_session_reset",
        rule_name="bgp_session_reset", severity="err", program="bgpd",
        message="Connection reset by peer",
    )
    _, coverage_path, count = detector.write_standard_outputs(
        [], [point, point], {("xian", "br-1", "frr_syslog_events"): source},
        tmp_path / "results")
    rows = [json.loads(line) for line in coverage_path.read_text(encoding="utf-8").splitlines()]
    assert count == 1
    assert len(rows) == 1
    assert rows[0]["observed_count"] == 2
    assert rows[0]["expected"] is False
    assert rows[0]["source_ref"] == str(source)
