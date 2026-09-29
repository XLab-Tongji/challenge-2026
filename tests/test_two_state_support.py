"""Small detector-event fixture shared by current inference tests."""


def event(ident, minute, entity, feature, *, kind="metric_anomaly", direction="up",
          modality="metric", score=20.0, attributes=None, last=None):
    return {"evidence_id": ident, "episode_id": ident, "start_minute": f"2026-08-19 04:{minute:02d}:00",
            "last_seen_minute": f"2026-08-19 04:{last if last is not None else minute:02d}:00",
            "entity_id": entity, "modality": modality, "feature": feature,
            "anomaly_kind": kind, "direction": direction, "raw_score": score,
            "score_kind": "state_rule_indicator" if kind == "state_anomaly" else "local_mad_z",
            "reliability": None, "observed": True, "attributes": attributes or {}}
