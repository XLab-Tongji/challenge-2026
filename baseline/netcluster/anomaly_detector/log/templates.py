from __future__ import annotations

import argparse
import csv
import hashlib
import pickle
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


@dataclass(frozen=True)
class LogFile:
    city: str
    node: str
    source: str
    path: Path


@dataclass
class TemplateStats:
    template_id: str
    template: str
    count: int = 0
    examples: list[str] = field(default_factory=list)
    source_files: set[str] = field(default_factory=set)


def discover_log_files(
    data_root: Path,
    include_city: str | None = None,
    include_node: str | None = None,
    include_source: str | None = None,
    max_files: int | None = None,
) -> list[LogFile]:
    files: list[LogFile] = []

    def add_candidate(path: Path, city: str, node: str) -> bool:
        source = path.stem
        if include_city and city != include_city:
            return False
        if include_node and node != include_node:
            return False
        if include_source and source != include_source:
            return False
        files.append(LogFile(city, node, source, path))
        return max_files is not None and len(files) >= max_files

    for path in sorted(data_root.glob("*/*/log/*.csv")):
        city, node = path.relative_to(data_root).parts[:2]
        if add_candidate(path, city, node):
            return files
    if files:
        return files

    city = data_root.name
    for path in sorted(data_root.glob("*/log/*.csv")):
        node = path.relative_to(data_root).parts[0]
        if add_candidate(path, city, node):
            return files
    return files


def build_template_miner(config_path: Path | None) -> TemplateMiner:
    config = TemplateMinerConfig()
    if config_path and config_path.exists():
        try:
            config.load(str(config_path))
        except UnicodeDecodeError:
            print(f"[log-template] could not decode Drain config, using built-in defaults: {config_path}", flush=True)
            _set_default_drain_config(config)
    else:
        _set_default_drain_config(config)
    config.profiling_enabled = False
    return TemplateMiner(config=config)


def _set_default_drain_config(config: TemplateMinerConfig) -> None:
        config.drain_sim_th = 0.3
        config.drain_depth = 6
        config.drain_max_children = 100
        config.drain_max_clusters = 4096


def iter_log_messages(
    path: Path,
    message_column: str,
    max_rows: int | None = None,
) -> tuple[int, int, list[str]]:
    messages: list[str] = []
    total_rows = 0
    skipped_rows = 0
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            return 0, 0, []
        for row in reader:
            total_rows += 1
            if max_rows is not None and len(messages) >= max_rows:
                break
            message = row.get(message_column)
            if message is None and "message" in row:
                message = row.get("message")
            if message is None:
                skipped_rows += 1
                continue
            message = _ANSI_RE.sub("", str(message).strip())
            if not message:
                skipped_rows += 1
                continue
            messages.append(message)
    return total_rows, skipped_rows, messages


def update_template_stats(
    stats_by_id: dict[str, TemplateStats],
    result: dict[str, Any],
    message: str,
    source_label: str,
    max_examples: int,
) -> None:
    template_id = str(result.get("cluster_id") or result.get("cluster_id_str") or "")
    template = str(result.get("template_mined") or result.get("template") or message)
    if not template_id:
        template_id = hashlib.sha256(template.encode("utf-8")).hexdigest()[:16]
    stats = stats_by_id.setdefault(template_id, TemplateStats(template_id=template_id, template=template))
    stats.template = template
    stats.count += 1
    stats.source_files.add(source_label)
    if len(stats.examples) < max_examples:
        stats.examples.append(message)


def write_template_csv(stats_by_id: dict[str, TemplateStats], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rows = sorted(stats_by_id.values(), key=lambda item: (-item.count, item.template_id))
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "template_id",
                "count",
                "template",
                "example_message",
                "source_file_count",
                "source_files",
            ],
        )
        writer.writeheader()
        for item in rows:
            writer.writerow(
                {
                    "template_id": item.template_id,
                    "count": item.count,
                    "template": item.template,
                    "example_message": item.examples[0] if item.examples else "",
                    "source_file_count": len(item.source_files),
                    "source_files": ";".join(sorted(item.source_files)),
                }
            )


def save_miner(miner: TemplateMiner, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as handle:
        pickle.dump(miner, handle)


def run_parser(
    data_root: Path,
    output_dir: Path,
    config_path: Path | None,
    include_city: str | None = None,
    include_node: str | None = None,
    include_source: str | None = None,
    message_column: str = "message",
    max_files: int | None = None,
    max_rows_per_file: int | None = None,
    progress_every: int = 10,
) -> dict[str, Any]:
    log_files = discover_log_files(
        data_root,
        include_city=include_city,
        include_node=include_node,
        include_source=include_source,
        max_files=max_files,
    )
    print(f"[log-template] discovered log csv files={len(log_files)} under {data_root}", flush=True)
    if not log_files:
        raise SystemExit("No log csv files found.")

    miner = build_template_miner(config_path)
    stats_by_id: dict[str, TemplateStats] = {}
    total_rows = 0
    skipped_rows = 0
    parsed_messages = 0

    for ordinal, log_file in enumerate(log_files, start=1):
        if ordinal == 1 or ordinal == len(log_files) or ordinal % max(1, progress_every) == 0:
            print(
                f"[log-template] parsing {ordinal}/{len(log_files)}: "
                f"{log_file.city}/{log_file.node}/{log_file.source}",
                flush=True,
            )
        rows, skipped, messages = iter_log_messages(
            log_file.path,
            message_column=message_column,
            max_rows=max_rows_per_file,
        )
        total_rows += rows
        skipped_rows += skipped
        source_label = f"{log_file.city}/{log_file.node}/{log_file.source}"
        for message in messages:
            result = miner.add_log_message(message)
            update_template_stats(stats_by_id, result, message, source_label, max_examples=3)
        parsed_messages += len(messages)

    template_file = output_dir / "log_templates.csv"
    model_file = output_dir / "drain_log_template_miner.pkl"
    write_template_csv(stats_by_id, template_file)
    save_miner(miner, model_file)
    summary = {
        "log_file_count": len(log_files),
        "total_rows": total_rows,
        "parsed_messages": parsed_messages,
        "skipped_rows": skipped_rows,
        "template_count": len(stats_by_id),
        "template_file": str(template_file),
        "drain_model_file": str(model_file),
    }
    print(
        f"[log-template] finished files={summary['log_file_count']} messages={parsed_messages} "
        f"templates={summary['template_count']} output={template_file}",
        flush=True,
    )
    return summary


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Parse updated challenge logs with Drain and export log templates.")
    parser.add_argument(
        "--data-root",
        type=Path,
        default=Path("data/updated/first_stage"),
        help="Root containing <city>/<node>/log/*.csv.",
    )
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/log_anomalies/templates"))
    parser.add_argument(
        "--drain-config",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "config" / "drain3.ini",
    )
    parser.add_argument("--include-city", type=str, default=None)
    parser.add_argument("--include-node", type=str, default=None)
    parser.add_argument("--include-source", type=str, default=None)
    parser.add_argument("--message-column", type=str, default="message")
    parser.add_argument("--max-files", type=int, default=None)
    parser.add_argument("--max-rows-per-file", type=int, default=None)
    parser.add_argument("--progress-every", type=int, default=10)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    summary = run_parser(
        data_root=args.data_root,
        output_dir=args.output_dir,
        config_path=args.drain_config,
        include_city=args.include_city,
        include_node=args.include_node,
        include_source=args.include_source,
        message_column=args.message_column,
        max_files=args.max_files,
        max_rows_per_file=args.max_rows_per_file,
        progress_every=args.progress_every,
    )
    print(summary, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
