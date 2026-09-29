import json
import argparse
from urllib import request, error


# 提交答案服务域名或 IP
JUDGE_SERVER = "https://judge.aiops.cn"
# 比赛 ID，可通过比赛页面 URL 获取
CONTEST = "2087843807868489822"
# 团队 ID，需要在参加比赛并组队后能获得，具体在比赛详情页-> 团队 -> 团队ID，为一串数字标识。
TICKET = "2097868617176584202"


def submit(data, judge_server=None, contest=None, ticket=None):
    judge_server = judge_server or JUDGE_SERVER
    contest = contest or CONTEST
    ticket = ticket or TICKET

    if not judge_server or not contest or not ticket:
        missing = [
            "judge_server" if not judge_server else "",
            "contest" if not contest else "",
            "ticket" if not ticket else "",
        ]
        missing = [item for item in missing if item]
        print("Required fields must be provided: %s" % ", ".join(missing))
        return None

    req_data = json.dumps({"data": data}).encode("utf-8")
    req = request.Request(
        judge_server,
        data=req_data,
        headers={
            "ticket": ticket,
            "contest": contest,
            "Content-Type": "application/json",
        },
    )

    try:
        with request.urlopen(req) as response:
            response_body = json.loads(response.read().decode("utf-8"))
            submission_id = response_body["submission_id"]
            remaining_attempts_today = response_body.get(
                "remaining_attempts_today", -1
            )
            return submission_id, remaining_attempts_today
    except error.HTTPError as exc:
        message = exc.reason
        response_body = exc.read().decode("utf-8")
        if response_body:
            try:
                message = json.loads(response_body)["detail"]
            except (KeyError, json.JSONDecodeError):
                pass
        print("[Error %s] %s" % (exc.code, message))
    except error.URLError as exc:
        print(exc.reason)
        return None


def check_status(submission_id, judge_server=None, contest=None, ticket=None):
    judge_server = judge_server or JUDGE_SERVER
    contest = contest or CONTEST
    ticket = ticket or TICKET

    if not judge_server or not contest or not ticket or not submission_id:
        missing = [
            "judge_server" if not judge_server else "",
            "contest" if not contest else "",
            "ticket" if not ticket else "",
            "submission_id" if not submission_id else "",
        ]
        missing = [item for item in missing if item]
        print("Required fields must be provided: %s" % ", ".join(missing))
        return None

    req = request.Request(
        judge_server + "/status",
        headers={
            "ticket": ticket,
            "contest": contest,
            "submission": submission_id,
            "Content-Type": "application/json",
        },
    )

    try:
        with request.urlopen(req) as response:
            return json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        message = exc.reason
        response_body = exc.read().decode("utf-8")
        if response_body:
            try:
                message = json.loads(response_body)["detail"]
            except (KeyError, json.JSONDecodeError):
                pass
        print("[Error %s] %s" % (exc.code, message))
    except error.URLError as exc:
        print(exc.reason)
        return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Submit to judge server")
    parser.add_argument(
        "result_path",
        nargs="?",
        default="predictions.jsonl",
        help="Path to the submission JSONL file, default is predictions.jsonl",
    )
    parser.add_argument("-s", "--server", help="Judge server URL")
    parser.add_argument("-c", "--contest", help="Contest ID")
    parser.add_argument("-k", "--ticket", help="Submission ticket")
    parser.add_argument(
        "-i",
        "--submission_id",
        help="Submission ID, specified if you want to check the submission status",
        default=None,
    )
    args = parser.parse_args()

    if args.submission_id:
        status = check_status(
            args.submission_id,
            judge_server=args.server,
            contest=args.contest,
            ticket=args.ticket,
        )
        if status:
            submission_id = status.get("submission_id")
            score = status.get("score")
            judge_time = status.get("judge_time")
            evaluation_error = status.get("error")
            if not judge_time:
                print("Submission %s is still in queue." % submission_id)
            elif evaluation_error:
                print("Submission %s failed: %s" % (submission_id, evaluation_error))
            else:
                print("Submission %s score: %s" % (submission_id, score))
            raise SystemExit(0)
        print("Failed to check submission status.")
        raise SystemExit(1)

    try:
        with open(args.result_path, "r", encoding="utf-8") as file:
            data = [json.loads(line.strip()) for line in file if line.strip()]
    except Exception as exc:
        print(exc)
        raise SystemExit(1)

    return_data = submit(
        data,
        judge_server=args.server,
        contest=args.contest,
        ticket=args.ticket,
    )
    if return_data:
        submission_id, remaining_attempts_today = return_data
        print("Success! Your submission ID is %s." % submission_id)
        if remaining_attempts_today >= 0:
            print(
                "You have %d evaluation attempt(s) remaining today."
                % remaining_attempts_today
            )
        raise SystemExit(0)
    raise SystemExit(1)
