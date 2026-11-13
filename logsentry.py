#!/usr/bin/env python3
"""Analyze an authorized web access log for repeated failed login requests."""

import argparse
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import sys

LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<date>[^]]+)\] '
    r'"(?P<request>[^\"]*)" (?P<status>\d{3}) \S+'
)
AUTH_PATH = re.compile(r"(?:login|signin|auth|session)", re.IGNORECASE)
DATE_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def parse_line(line: str):
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None
    try:
        timestamp = datetime.strptime(match["date"], DATE_FORMAT).astimezone(timezone.utc)
        status = int(match["status"])
    except ValueError:
        return None
    request_parts = match["request"].split()
    path = request_parts[1].split("?", 1)[0] if len(request_parts) >= 2 else ""
    return {"ip": match["ip"], "timestamp": timestamp, "status": status, "path": path}


def analyze(path: Path, threshold: int, window_minutes: int):
    parsed = 0
    failures = defaultdict(list)
    with path.open(encoding="utf-8", errors="replace") as log_file:
        for line in log_file:
            record = parse_line(line)
            if record is None:
                continue
            parsed += 1
            if record["status"] in (401, 403) and AUTH_PATH.search(record["path"]):
                failures[record["ip"]].append(record)

    window = timedelta(minutes=window_minutes)
    alerts = []
    total_failures = sum(map(len, failures.values()))
    for ip, records in failures.items():
        records.sort(key=lambda item: item["timestamp"])
        left = 0
        peak_start, peak_end, peak_count = None, None, 0
        for right, record in enumerate(records):
            while record["timestamp"] - records[left]["timestamp"] > window:
                left += 1
            count = right - left + 1
            if count > peak_count:
                peak_start, peak_end, peak_count = records[left], record, count
        if peak_count >= threshold:
            sample_paths = sorted({r["path"] for r in records})[:5]
            alerts.append({
                "source_ip": ip,
                "failures_in_window": peak_count,
                "window_start": peak_start["timestamp"].isoformat(),
                "window_end": peak_end["timestamp"].isoformat(),
                "paths": sample_paths,
            })

    alerts.sort(key=lambda item: (-item["failures_in_window"], item["source_ip"]))
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_file": path.name,
        "settings": {"threshold": threshold, "window_minutes": window_minutes},
        "summary": {
            "parsed_lines": parsed,
            "authentication_failures": total_failures,
            "flagged_sources": len(alerts),
        },
        "alerts": alerts,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("logfile", type=Path, help="authorized access log to analyze")
    parser.add_argument("--threshold", type=int, default=5, help="failures needed to flag a source (default: 5)")
    parser.add_argument("--window-minutes", type=int, default=10, help="rolling time window (default: 10)")
    parser.add_argument("--output", type=Path, help="write JSON report to this path instead of stdout")
    args = parser.parse_args()
    if args.threshold < 1 or args.window_minutes < 1:
        parser.error("--threshold and --window-minutes must be positive")
    if not args.logfile.is_file():
        parser.error(f"input file does not exist: {args.logfile}")

    report = analyze(args.logfile, args.threshold, args.window_minutes)
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        sys.stdout.write(rendered)


if __name__ == "__main__":
    main()
