"""Run the public BiAn-style end-to-end baseline.

The detector only proposes time windows.  The RCA path then follows the public
BiAn stages: candidate evidence preprocessing, 7B-A candidate analysis, 7B-B
Stage-1 ranking, repeated Stage-2 synthesis with Rank-of-Ranks aggregation, and
taxonomy classification from evidence. ``--use-llm`` enables the full model
path; without it the command provides a lightweight validation path.
"""

from __future__ import annotations

import argparse
from datetime import timezone
import json
from pathlib import Path
import sys
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(HERE))

from anomaly_detector.five_sigma import detect
from aiops_challenge_2026.config import load_public_config
from classification.classifier import (
    classification_taxonomy,
    classify_with_llm,
    unknown_category,
)
from localization.ranking import (
    quick_validation_top5,
    rank_stage1,
    stage2_consensus,
    validate_stage1,
    validate_stage2,
)
from models.backend import JsonModelBackend, ModelConfig
from models.backend import OpenAICompatibleJsonBackend
from preprocessing.evidence import build_event_context, public_topology


def _config() -> dict[str, Any]:
    config = json.loads((HERE / "config" / "topology.json").read_text(encoding="utf-8"))
    network_elements = load_public_config("network_elements")
    taxonomy = load_public_config("fault_taxonomy")
    config.update(taxonomy)
    config["cities"] = network_elements["cities"]
    config["candidate_roles"] = network_elements["device_roles"]
    config["region_aliases"] = {city: city for city in network_elements["cities"]}
    return config


def _utc(value) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _device_analysis_validator(value: Any, nodes: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"device_analyses"}:
        raise ValueError("device analysis must contain only device_analyses")
    items = value["device_analyses"]
    if isinstance(items, dict):
        items = list(items.values())
    if not isinstance(items, list) or len(items) != len(nodes):
        raise ValueError("device analysis must cover every public candidate")
    by_node = {}
    for item in items:
        required = {"node_id", "anomaly_score", "evidence_summary"}
        if not isinstance(item, dict) or not required <= set(item):
            raise ValueError("invalid device analysis item")
        node = item["node_id"]
        score = item["anomaly_score"]
        if node not in nodes or node in by_node or not isinstance(score, (int, float)) or not 0 <= score <= 1:
            raise ValueError("invalid device analysis node or score")
        if not isinstance(item["evidence_summary"], str):
            raise ValueError("invalid device analysis evidence summary")
        by_node[node] = {"node_id": node, "anomaly_score": float(score), "evidence_summary": item["evidence_summary"]}
    if set(by_node) != set(nodes):
        raise ValueError("device analysis node set differs from candidates")
    return {"device_analyses": [by_node[node] for node in nodes]}


def _quick_validation_stage1(context: dict[str, Any]) -> list[dict[str, Any]]:
    """Create a shortlist for the no-model workflow check."""
    return rank_stage1(context["candidates"], {}, {"min_candidates": 5, "max_candidates": 12, "top_p": 0.85, "weights": {"model_anomaly_score": 0.0, "deterministic_feature_score": 1.0}})[1]


def _topology_for_nodes(topology: dict[str, Any], nodes: list[str]) -> dict[str, Any]:
    """Keep each batched model request bounded while retaining public edges."""
    allowed = set(nodes)
    return {
        "directed": topology.get("directed", False),
        "nodes": [item for item in topology.get("nodes", []) if item.get("node_id") in allowed],
        "edges": [item for item in topology.get("edges", []) if item.get("source") in allowed and item.get("target") in allowed],
    }


def _llm_event(
    event: dict[str, Any],
    context: dict[str, Any],
    config: dict[str, Any],
    backend: JsonModelBackend,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    nodes = [item["node_id"] for item in context["candidates"]]
    compact_candidates = context["candidates"]
    batch_size = config["model"].get("batch_size", 8)
    analyses_items = []
    for batch_index in range(0, len(compact_candidates), batch_size):
        batch = compact_candidates[batch_index : batch_index + batch_size]
        batch_nodes = [item["node_id"] for item in batch]
        analyses = backend.generate_json(
            role="7B-A",
            prompt_name="7b_a_device_analysis",
            payload={"batch_index": batch_index // batch_size + 1, "candidates": batch},
            validator=lambda value, expected=batch_nodes: _device_analysis_validator(value, expected),
            max_new_tokens=config["model"]["device_max_new_tokens"],
        )
        analyses_items.extend(analyses["device_analyses"])
    analysis_by_node = {item["node_id"]: item for item in analyses_items}
    model_scores = {}
    for batch_index in range(0, len(nodes), batch_size):
        batch_nodes = nodes[batch_index : batch_index + batch_size]
        stage1_raw = backend.generate_json(
            role="7B-B",
            prompt_name="7b_b_stage1",
            payload={
                "batch_index": batch_index // batch_size + 1,
                "candidate_evidence": [item for item in compact_candidates if item["node_id"] in batch_nodes],
                "device_analyses": [analysis_by_node[node] for node in batch_nodes],
                "topology": _topology_for_nodes(context["topology"], batch_nodes),
            },
            validator=lambda value, expected=batch_nodes: validate_stage1(value, expected),
            max_new_tokens=config["model"]["stage1_max_new_tokens"],
        )
        model_scores.update(stage1_raw["scores"])
    shortlist = rank_stage1(
        context["candidates"],
        analysis_by_node,
        config["stage1"],
        model_scores=model_scores,
    )[1]
    shortlist_nodes = [item["node_id"] for item in shortlist]
    shortlist_timeline = [item for item in context["timeline"] if item.get("node_id") in set(shortlist_nodes)]
    shortlist_topology = _topology_for_nodes(context["topology"], shortlist_nodes)

    rounds = []
    for round_index in range(1, config["stage2"]["rounds"] + 1):
        stage2_raw = backend.generate_json(
            role="7B-B",
            prompt_name="7b_b_stage2",
            payload={
                "round": round_index,
                "candidates": shortlist,
                "topology": shortlist_topology,
                "timeline": shortlist_timeline,
            },
            validator=lambda value, allowed=shortlist_nodes: validate_stage2(value, allowed),
            max_new_tokens=config["model"]["stage2_max_new_tokens"],
        )
        rounds.append(stage2_raw["candidates"])
    top5, _ = stage2_consensus(rounds, shortlist, config["stage2"]["weights"])

    category, _ = classify_with_llm(
        backend,
        top5=top5,
        context=context,
        taxonomy=classification_taxonomy(config),
        rounds=config["classification"]["rounds"],
        max_new_tokens=config["model"]["classification_max_new_tokens"],
    )
    return top5, category


def run(
    data_root: Path,
    output: Path,
    model: str | None,
    use_llm: bool,
    prediction_prefix: str,
    max_events: int | None = None,
    backend_type: str = "local",
    env_file: Path = Path(".env"),
) -> int:
    config = _config()
    events = detect(data_root, config["region_aliases"])
    if max_events is not None:
        events = events[:max_events]
    backend = None
    if use_llm:
        model_config = ModelConfig(**config["model"])
        if backend_type == "openai":
            backend = OpenAICompatibleJsonBackend.from_env(
                model,
                model_config,
                HERE / "prompts",
                env_file=env_file,
            )
        else:
            if not model:
                model = "deepseek-ai/DeepSeek-R1-Distill-Qwen-7B"
            backend = JsonModelBackend(
                model,
                model_config,
                HERE / "prompts",
            )
    records = []
    for index, event in enumerate(events, 1):
        context = build_event_context(event, config)
        if backend is not None:
            try:
                top5, category = _llm_event(event, context, config, backend)
            except Exception as exc:
                reason = " ".join(str(exc).splitlines())[:500]
                raise RuntimeError(
                    f"BiAn LLM inference failed for event {index}: "
                    f"{type(exc).__name__}: {reason}"
                ) from None
        else:
            shortlist = _quick_validation_stage1(context)
            top5 = quick_validation_top5(shortlist)
            category = unknown_category()
        start = event["start"].astimezone(timezone.utc)
        end = event["end"].astimezone(timezone.utc)
        records.append({
            "prediction_id": f"{prediction_prefix}{index:06d}",
            "start_time": _utc(start),
            "end_time": _utc(end),
            "root_cause_top5": top5,
            "fault_category": category,
        })
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(json.dumps({"events": len(records), "output": str(output), "mode": "bian_llm" if use_llm else "quick_validation"}, ensure_ascii=False))
    return 0


def resolve_env_file(path: Path) -> Path:
    """Resolve relative env files from the repository root."""
    return path if path.is_absolute() else REPO / path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("outputs/predictions.jsonl"))
    parser.add_argument("--model")
    parser.add_argument("--backend", choices=("local", "openai"), default="local")
    parser.add_argument("--env-file", type=Path, default=Path(".env"))
    parser.add_argument("--use-llm", action="store_true")
    parser.add_argument("--prediction-prefix", default="pred_")
    parser.add_argument("--max-events", type=int)
    args = parser.parse_args()
    try:
        return run(
            args.data_root,
            args.output,
            args.model,
            args.use_llm,
            args.prediction_prefix,
            args.max_events,
            args.backend,
            resolve_env_file(args.env_file),
        )
    except Exception as exc:
        print(f"Baseline failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
