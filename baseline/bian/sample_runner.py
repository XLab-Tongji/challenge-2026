"""Run the Baseline over all public sample cases without invoking evaluation."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


REPO = Path(__file__).resolve().parents[2]
CASES = ("case_001", "case_002", "case_003")


def resolve_env_file(path: Path) -> Path:
    """Resolve relative env files from the repository root."""
    return path if path.is_absolute() else REPO / path


def _read_jsonl(path: Path, *, allow_unknown_category: bool = False) -> list[dict]:
    sys.path.insert(0, str(REPO))
    from aiops_challenge_2026.config import load_public_config
    from aiops_challenge_2026.schema import validate_prediction

    network = load_public_config("network_elements")
    taxonomy = load_public_config("fault_taxonomy")
    valid_ids = {
        f"{city}-{role}"
        for city in network["cities"]
        for role in network["device_roles"]
    }
    valid_categories = {
        (category["major_category"], category["sub_category"])
        for category in taxonomy["fault_categories"]
    }
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        raw = json.loads(line)
        category = raw.get("fault_category") if isinstance(raw, dict) else None
        is_quick_unknown = allow_unknown_category and category == {
            "major_category": "unknown",
            "sub_category": "unknown",
        }
        record = validate_prediction(
            raw,
            allow_invalid_category=is_quick_unknown,
        )
        if any(
            cause["network_element_id"] not in valid_ids
            for cause in record["root_cause_top5"]
        ):
            raise ValueError("prediction contains an unknown network_element_id")
        category = record["fault_category"]
        pair = (category["major_category"], category["sub_category"])
        if pair not in valid_categories and not is_quick_unknown:
            raise ValueError("prediction contains a category outside the public taxonomy")
        records.append(
            {key: value for key, value in record.items() if not key.startswith("_")}
        )
    return records


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Baseline inference for the three public sample cases"
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--use-llm", action="store_true")
    parser.add_argument(
        "--model"
    )
    parser.add_argument("--backend", choices=("local", "openai"), default="local")
    parser.add_argument("--env-file", type=Path, default=Path(".env"))
    args = parser.parse_args()

    if args.output.exists():
        raise SystemExit("output path already exists")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    env_file = resolve_env_file(args.env_file)
    with tempfile.TemporaryDirectory(prefix="aiops_baseline_") as temporary:
        run_dir = Path(temporary)
        for case_name in CASES:
            case_output = run_dir / f"{case_name}.jsonl"
            command = [
                sys.executable,
                str(REPO / "baseline" / "bian" / "run.py"),
                "--data-root",
                str(REPO / "sample" / case_name),
                "--output",
                str(case_output),
                "--prediction-prefix",
                f"{case_name}_",
            ]
            if args.use_llm:
                command.extend(["--use-llm", "--backend", args.backend, "--env-file", str(env_file)])
                if args.model:
                    command.extend(["--model", args.model])
            try:
                subprocess.run(command, cwd=REPO, check=True)
            except subprocess.CalledProcessError as exc:
                raise SystemExit(
                    f"{case_name}: Baseline inference failed with exit code "
                    f"{exc.returncode}"
                ) from None
            records = _read_jsonl(
                case_output,
                allow_unknown_category=not args.use_llm,
            )
            if len(records) != 1:
                raise RuntimeError(
                    f"{case_name}: expected one prediction, got {len(records)}"
                )

        case_paths = [run_dir / f"{case_name}.jsonl" for case_name in CASES]
        combined = b"".join(path.read_bytes() for path in case_paths)
        staged_output = run_dir / "combined.jsonl"
        staged_output.write_bytes(combined)
        records = _read_jsonl(
            staged_output,
            allow_unknown_category=not args.use_llm,
        )
        if len(records) != 3 or len({item["prediction_id"] for item in records}) != 3:
            raise RuntimeError("combined prediction must contain three unique events")
        output_staging = args.output.with_name(f".{args.output.name}.tmp")
        output_staging.write_bytes(combined)
        os.replace(output_staging, args.output)
    print(json.dumps({"events": 3, "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
