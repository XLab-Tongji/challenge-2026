"""Rank fault types and observed root entities separately for each cluster."""

from __future__ import annotations

from collections import defaultdict

from aiops_challenge_2026.schema import VALID_NETWORK_ELEMENTS

from .events import Cluster, Event, _role


def _eligible(event: Event, fault_type: str) -> bool:
    if not fault_type.startswith("service_") or event.modality != "traffic_flow":
        return True
    flow = (event.attrs.get("flow_type") or "").lower()
    if fault_type.startswith("service_dns_"):
        return flow == "dns"
    if fault_type.startswith("service_web_"):
        return flow == "web"
    if fault_type.startswith("service_auth_"):
        return flow == "auth"
    return False


_TIER_ORDER = {"direct": 0, "observed_effect": 1, "regional_corrob": 2,
               "observation_point": 3, "regional_context": 4,
               "region_hypothesis": 5}


def rank_root_candidates(events: list[Event], fault_type: str, rule: dict, config: dict,
                         *, context_events: list[Event] = (), start: int | None = None,
                         end: int | None = None) -> list[dict]:
    """Rank type-compatible entities without treating an observation point as a verified root."""
    bindings: dict[str, dict[str, list[tuple[Event, float]]]] = defaultdict(lambda: defaultdict(list))
    roles = set(rule["applicable_entity_roles"])
    target_regions: set[str] = set()
    relevant = [event for event in events if _eligible(event, fault_type)
                and (event.family in rule["direct"] or event.family in rule["effect"])]
    for event in relevant:
        direct = rule["direct"].get(event.family, 0.0)
        effect = rule["effect"].get(event.family, 0.0)
        if event.modality in {"metric", "log"} and event.entity in VALID_NETWORK_ELEMENTS:
            if _role(event.entity) in roles:
                if direct:
                    bindings[event.entity]["direct"].append((event, direct))
                elif effect:
                    bindings[event.entity]["observed_effect"].append((event, effect))
        elif event.modality == "netflow" and effect and fault_type.startswith("link_"):
            if event.entity in VALID_NETWORK_ELEMENTS and _role(event.entity) in roles:
                bindings[event.entity]["observation_point"].append((event, effect))
        elif event.modality == "traffic_flow" and effect:
            region = event.attrs.get("target_region")
            if not isinstance(region, str) or not region:
                continue
            target_regions.add(region)
            if fault_type.startswith("service_"):
                candidate_roles = ("service-vm-1", "service-vm-2", "service-vm-3")
            elif fault_type.startswith("firewall_"):
                candidate_roles = ("fw",)
            elif fault_type.startswith("link_"):
                candidate_roles = ("br-1", "br-2", "cr-1", "cr-2")
            else:
                candidate_roles = ()
            for role in candidate_roles:
                name = f"{region}-{role}"
                if name in VALID_NETWORK_ELEMENTS and _role(name) in roles:
                    bindings[name]["region_hypothesis"].append((event, effect))
    accepted_ids = {event.ident for event in events}
    for event in context_events:
        if (event.ident in accepted_ids and
                (event.family in rule["direct"] or event.family in rule["effect"])):
            continue
        if (event.entity not in bindings
                or event.entity.split("-")[0] not in target_regions
                or start is not None and event.end < start
                or end is not None and event.start >= end):
            continue
        if event.modality in {"metric", "log"}:
            matched = max(rule["direct"].get(event.family, 0.0),
                          rule["effect"].get(event.family, 0.0))
            if not matched and not fault_type.startswith("service_"):
                continue
            tier = "regional_corrob" if matched else "regional_context"
            weight = 0.7 * matched if matched else 0.10
        elif event.modality == "netflow" and fault_type.startswith("link_"):
            matched = rule["effect"].get(event.family, 0.0)
            if not matched:
                continue
            tier, weight = "observation_point", matched
        else:
            continue
        if start is not None and end is not None:
            duration = max(3, end - start)
            weight *= max(0.5, 1.0 - abs(event.start - start) / duration)
        bindings[event.entity][tier].append((event, weight))
    ranked = []
    for root, tiers in bindings.items():
        tier = min(tiers, key=_TIER_ORDER.get)
        support = tiers[tier]
        by_dependency: dict[str, float] = {}
        for event, weight in support:
            by_dependency[event.dependency] = max(by_dependency.get(event.dependency, 0.0),
                                                  event.quality * weight)
        if not by_dependency:
            continue
        binding_factor = {"direct": 1.0, "observed_effect": 0.8,
                          "regional_corrob": 0.65, "observation_point": 0.55,
                          "regional_context": 0.35, "region_hypothesis": 0.3}[tier]
        score = min(1.0, (max(by_dependency.values()) +
                          min(0.12, 0.04 * (len(by_dependency) - 1))) * binding_factor)
        ranked.append({"root": root, "tier": tier, "score": round(score, 6),
                       "evidence_ids": sorted({event.ident for event, _ in support}),
                       "independent_groups": len(by_dependency)})
    ranked.sort(key=lambda row: (_TIER_ORDER[row["tier"]], -row["score"], row["root"]))
    return ranked[:5]


def _effect_matches_root(event: Event, root: str | None) -> bool:
    if root is None:
        return True
    region = root.split("-")[0]
    if event.modality == "traffic_flow":
        return event.region == region
    if event.modality == "netflow":
        return event.region == region  # observation point, not a verified path
    return event.entity == root


def _score(events: list[Event], fault_type: str, root: str | None, rule: dict, config: dict) -> dict:
    contributions: dict[tuple[str, str], float] = {}
    direct_groups: set[str] = set()
    modalities: set[str] = set()
    supporting: set[str] = set()
    for event in events:
        if not _eligible(event, fault_type):
            continue
        direct = rule["direct"].get(event.family, 0.0)
        effect = rule["effect"].get(event.family, 0.0)
        if root is not None and event.entity == root and event.modality in {"metric", "log"} and direct:
            weight = direct
            direct_groups.add(event.dependency)
        elif effect and _effect_matches_root(event, root):
            weight = effect
        else:
            continue
        key = (event.family, event.dependency)
        value = event.quality * weight
        if value > contributions.get(key, 0.0):
            contributions[key] = value
        modalities.add(event.modality)
        supporting.add(event.ident)
    if not contributions:
        return {"score": 0.0, "direct": False, "supporting_evidence_ids": []}
    by_family: dict[str, float] = defaultdict(float)
    for (family, _), value in contributions.items():
        by_family[family] = max(by_family[family], value)
    distinct_families = len(by_family)
    repeated = any(sum(1 for family, _ in contributions if family == name) >= 2 for name in by_family)
    score = min(1.0, max(by_family.values()) + min(0.18, 0.09 * (distinct_families - 1))
                + (0.08 if repeated else 0.0) + (0.08 if len(modalities) >= 2 else 0.0))
    if not direct_groups:
        score = min(score, config["effect_only_confidence_cap"])
    if (fault_type.startswith("resource_") or fault_type == "firewall_cpu_pressure") and direct_groups:
        direct_events = [e for e in events if e.dependency in direct_groups and e.entity == root]
        if len({e.start for e in direct_events}) == 1 and len(direct_groups) == 1 and distinct_families == 1:
            score = min(score, config["single_relative_resource_confidence_cap"])
    return {"score": round(score, 6), "direct": bool(direct_groups),
            "supporting_evidence_ids": sorted(supporting),
            "families": sorted(by_family), "independent_groups": len(contributions)}


def rank_incident(incident: dict, clusters: dict[str, Cluster], config: dict,
                  family_config: dict, *, context_events: list[Event] = ()) -> dict:
    """Choose the best diagnosed cluster; never sum scores across clusters."""
    all_rankings: list[dict] = []
    for cluster_id in sorted(incident["cluster_ids"]):
        cluster = clusters[cluster_id]
        events = [event for event in cluster.events.values()
                  if event.start < incident["end"] and event.end >= incident["start"]]
        if not events:
            continue
        family_rankings: list[dict] = []
        for fault_type, rule in config["fault_priors"].items():
            roots = sorted({event.entity for event in events
                            if event.modality in {"metric", "log"}
                            and event.family in rule["direct"]
                            and _role(event.entity) in rule["applicable_entity_roles"]})
            candidates = []
            for root in [None, *roots]:
                detail = _score(events, fault_type, root, rule, config)
                if detail["score"]:
                    candidates.append({"fault_type": fault_type, "root": root, **detail})
            if not candidates:
                continue
            candidates.sort(key=lambda row: (-row["score"], not row["direct"], row["root"] or ""))
            best = candidates[0]
            root_ranking = [row["root"] for row in candidates if row["root"] is not None and row["direct"]]
            family_rankings.append({**best, "root_candidates": root_ranking[:5]})
        family_rankings.sort(key=lambda row: (-row["score"], not row["direct"], row["fault_type"]))
        if family_rankings:
            all_rankings.append({"cluster_id": cluster_id, "ranking": family_rankings[:5],
                                 "best": family_rankings[0]})
    all_rankings.sort(key=lambda row: (-row["best"]["score"], not row["best"]["direct"], row["cluster_id"]))
    if not all_rankings or all_rankings[0]["best"]["score"] < 0.35:
        return {"fault_type": None, "score": 0.0, "root_cause_candidates": [],
                "selected_cluster_id": None, "cluster_rca": all_rankings[:5]}
    winning = all_rankings[0]
    best = winning["best"]
    winning_events = [event for event in clusters[winning["cluster_id"]].events.values()
                      if event.start < incident["end"] and event.end >= incident["start"]]
    root_details = rank_root_candidates(winning_events, best["fault_type"],
                                        config["fault_priors"][best["fault_type"]], config,
                                        context_events=context_events,
                                        start=incident["start"], end=incident["end"])
    root_names = [row["root"] for row in root_details]
    best["root_candidates"] = root_names
    if winning["ranking"]:
        winning["ranking"][0]["root_candidates"] = root_names
        winning["ranking"][0]["root_binding_details"] = root_details
    type_alternatives = [{"fault_type": row["fault_type"], "score": row["score"]}
                         for row in winning["ranking"]]
    type_margin = (round(type_alternatives[0]["score"] - type_alternatives[1]["score"], 6)
                   if len(type_alternatives) > 1 else None)
    return {"fault_type": best["fault_type"], "score": best["score"],
            "root_cause_candidates": root_names, "root_cause_details": root_details,
            "fault_type_alternatives": type_alternatives, "fault_type_margin": type_margin,
            "selected_cluster_id": winning["cluster_id"],
            "cluster_rca": all_rankings[:5],
            "uncertainty": "high" if (not root_details or _TIER_ORDER[root_details[0]["tier"]] >= 2
                                      or best["score"] < 0.6
                                      or type_margin is not None and type_margin <= 0.05) else "medium"}
