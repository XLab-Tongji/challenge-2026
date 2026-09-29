"""Move per-router NetFlow 5-tuple files from scripts/data into first_stage."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path


DEFAULT_SOURCE_ROOT = Path("./data/updated/first_stage")
DEFAULT_TARGET_ROOT = Path("../data/updated/first_stage")


def discover_netflow_files(source_root: Path) -> list[Path]:
    """Return NetFlow files in the mirrored <region>/<router>/netflow layout."""
    return sorted(source_root.glob("*/*/netflow/netflow_5tuple.csv"))


def target_path(source_path: Path, source_root: Path, target_root: Path) -> Path:
    relative_path = source_path.relative_to(source_root)
    if len(relative_path.parts) != 4:
        raise ValueError(f"unexpected NetFlow path: {source_path}")
    region, router, directory, filename = relative_path.parts
    if directory != "netflow" or filename != "netflow_5tuple.csv":
        raise ValueError(f"unexpected NetFlow path: {source_path}")
    return target_root / region / router / directory / filename


def move_netflow_files(
    source_root: Path,
    target_root: Path,
    apply: bool,
    overwrite: bool,
) -> tuple[int, int]:
    moved = 0
    skipped = 0
    for source_path in discover_netflow_files(source_root):
        destination = target_path(source_path, source_root, target_root)
        if destination.exists() and not overwrite:
            print(f"skip existing target: {destination}")
            skipped += 1
            continue

        print(f"move: {source_path} -> {destination}")
        if apply:
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                destination.unlink()
            shutil.move(str(source_path), str(destination))
            moved += 1
    return moved, skipped


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Move router netflow_5tuple.csv files from scripts/data to first_stage."
    )
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--target-root", type=Path, default=DEFAULT_TARGET_ROOT)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Perform the move. Without this option, only print the planned operations.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace an existing target file. Requires --apply to make changes.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    source_root: Path = args.source_root
    target_root: Path = args.target_root
    if not source_root.is_dir():
        raise SystemExit(f"source root does not exist: {source_root}")

    files = discover_netflow_files(source_root)
    print(f"discovered NetFlow files: {len(files)}")
    if not args.apply:
        print("dry run: pass --apply to move files")
    moved, skipped = move_netflow_files(source_root, target_root, args.apply, args.overwrite)
    print(f"completed: moved={moved}, skipped_existing={skipped}, dry_run={not args.apply}")


if __name__ == "__main__":
    main()
