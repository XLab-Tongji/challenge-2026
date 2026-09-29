#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
from typing import Any

from submit import CONTEST, JUDGE_SERVER, TICKET, check_status


def _first_value(*values: str | None) -> str | None:
    for value in values:
        if value:
            return value
    return None


def _print_status(status: dict[str, Any], *, raw: bool = False) -> None:
    if raw:
        print(json.dumps(status, ensure_ascii=False, indent=2))
        return

    submission_id = status.get("submission_id")
    judge_time = status.get("judge_time")
    evaluation_error = status.get("error")

    if not judge_time:
        print("Submission %s is still in queue." % submission_id)
        return
    if evaluation_error:
        print("Submission %s failed: %s" % (submission_id, evaluation_error))
        return

    print("Submission %s score: %s" % (submission_id, status.get("score")))
    for label, key in (
        ("Anomaly detection (AD)", "ad_score"),
        ("Root-cause localization (RCA)", "rca_score"),
        ("Major-category classification", "major_score"),
        ("Minor-category classification", "minor_score"),
    ):
        value = status.get(key)
        if value is not None:
            print("  %s: %s" % (label, value))


def main() -> int:
    parser = argparse.ArgumentParser(description="Check AIOps challenge submission score")
    parser.add_argument(
        "submission_id",
        nargs="?",
        help="Submission ID returned by submit.py. Can also be set by AIOPS_SUBMISSION_ID.",
    )
    parser.add_argument("-s", "--server", help="Judge server URL")
    parser.add_argument("-c", "--contest", help="Contest ID")
    parser.add_argument("-k", "--ticket", help="Team ticket")
    parser.add_argument("--raw", action="store_true", help="Print raw JSON response")
    args = parser.parse_args()

    submission_id = _first_value(args.submission_id, os.getenv("AIOPS_SUBMISSION_ID"))
    server = _first_value(args.server, os.getenv("AIOPS_JUDGE_SERVER"), JUDGE_SERVER)
    contest = _first_value(args.contest, os.getenv("AIOPS_CONTEST"), CONTEST)
    ticket = _first_value(args.ticket, os.getenv("AIOPS_TICKET"), TICKET)

    if not submission_id:
        parser.error("submission_id is required; pass it as an argument or set AIOPS_SUBMISSION_ID")

    status = check_status(
        submission_id,
        judge_server=server,
        contest=contest,
        ticket=ticket,
    )
    if not status:
        print("Failed to check submission status.")
        return 1
    _print_status(status, raw=args.raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
