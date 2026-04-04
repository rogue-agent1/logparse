#!/usr/bin/env python3
"""logparse - log file analyzer (patterns, frequency, timeline, filter, stats)."""

import argparse, sys, re, os, time, json
from collections import Counter, defaultdict
from datetime import datetime

# Common log timestamp patterns
TS_PATTERNS = [
    (re.compile(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})'), "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"),
    (re.compile(r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})'), "%d/%b/%Y:%H:%M:%S", None),
    (re.compile(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'), "%b %d %H:%M:%S", None),
]

LOG_LEVELS = re.compile(r'\b(FATAL|ERROR|WARN(?:ING)?|INFO|DEBUG|TRACE|CRITICAL|NOTICE)\b', re.I)
IP_PATTERN = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
HTTP_STATUS = re.compile(r'\b([1-5]\d{2})\b')

def extract_ts(line):
    for pat, fmt1, fmt2 in TS_PATTERNS:
        m = pat.search(line)
        if m:
            raw = m.group(1)
            for fmt in [fmt1, fmt2]:
                if fmt:
                    try:
                        return datetime.strptime(raw, fmt)
                    except ValueError:
                        pass
    return None

def read_lines(args):
    if hasattr(args, 'file') and args.file:
        with open(args.file, errors='replace') as f:
            return f.readlines()
    if not sys.stdin.isatty():
        return sys.stdin.readlines()
    print("Error: provide file or pipe via stdin", file=sys.stderr)
    sys.exit(1)

def cmd_stats(args):
    lines = read_lines(args)
    total = len(lines)
    levels = Counter()
    ips = Counter()
    statuses = Counter()
    timestamps = []

    for line in lines:
        m = LOG_LEVELS.search(line)
        if m:
            levels[m.group(1).upper()] += 1
        for ip in IP_PATTERN.findall(line):
            ips[ip] += 1
        for s in HTTP_STATUS.findall(line):
            statuses[s] += 1
        ts = extract_ts(line)
        if ts:
            timestamps.append(ts)

    size = sum(len(l) for l in lines)
    print(f"\n  Log Statistics")
    print("  " + "─" * 40)
    print(f"  Lines:       {total:,}")
    print(f"  Size:        {size/1024:.1f} KB")

    if timestamps:
        span = timestamps[-1] - timestamps[0]
        print(f"  Time span:   {timestamps[0]} → {timestamps[-1]}")
        print(f"  Duration:    {span}")
        if span.total_seconds() > 0:
            rate = total / (span.total_seconds() / 60)
            print(f"  Rate:        {rate:.1f} lines/min")

    if levels:
        print(f"\n  Log Levels:")
        mx = max(levels.values())
        for lev in ["FATAL", "CRITICAL", "ERROR", "WARNING", "WARN", "NOTICE", "INFO", "DEBUG", "TRACE"]:
            if lev in levels:
                cnt = levels[lev]
                bar = "█" * int(cnt * 25 / mx)
                print(f"    {lev:<10} {cnt:>6}  {bar}")

    if ips:
        print(f"\n  Top IPs:")
        for ip, cnt in ips.most_common(10):
            print(f"    {ip:<16} {cnt:>6}")

    if statuses:
        print(f"\n  HTTP Status Codes:")
        for s, cnt in statuses.most_common(10):
            print(f"    {s}  {cnt:>6}")
    print()

def cmd_filter(args):
    lines = read_lines(args)
    pattern = re.compile(args.pattern, re.I if args.ignore_case else 0) if args.pattern else None
    level = args.level.upper() if args.level else None
    count = 0

    for line in lines:
        show = True
        if pattern and not pattern.search(line):
            show = False
        if level:
            m = LOG_LEVELS.search(line)
            if not m or m.group(1).upper() != level:
                show = False
        if args.invert:
            show = not show
        if show:
            count += 1
            if args.count_only:
                continue
            sys.stdout.write(line)

    if args.count_only:
        print(f"  {count} matching lines")

def cmd_timeline(args):
    lines = read_lines(args)
    by_minute = Counter()
    by_hour = Counter()
    levels_by_hour = defaultdict(Counter)

    for line in lines:
        ts = extract_ts(line)
        if ts:
            minute = ts.strftime("%H:%M")
            hour = ts.strftime("%H:00")
            by_minute[minute] += 1
            by_hour[hour] += 1
            m = LOG_LEVELS.search(line)
            if m:
                levels_by_hour[hour][m.group(1).upper()] += 1

    if not by_hour:
        print("  No timestamps found")
        return

    print(f"\n  Timeline (by hour)")
    print("  " + "─" * 55)
    mx = max(by_hour.values())
    for hour in sorted(by_hour):
        cnt = by_hour[hour]
        bar = "█" * int(cnt * 30 / mx)
        errs = levels_by_hour[hour].get("ERROR", 0) + levels_by_hour[hour].get("FATAL", 0) + levels_by_hour[hour].get("CRITICAL", 0)
        err_str = f"  ⚠ {errs} errors" if errs else ""
        print(f"  {hour}  {bar} {cnt}{err_str}")

    # Busiest minutes
    print(f"\n  Busiest minutes:")
    for minute, cnt in by_minute.most_common(5):
        print(f"    {minute}  {cnt} lines")
    print()

def cmd_top(args):
    """Find most frequent log messages (deduped by removing numbers/timestamps)."""
    lines = read_lines(args)
    patterns = Counter()

    for line in lines:
        # Normalize: remove timestamps, numbers, IPs, hashes
        normalized = line.strip()
        normalized = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.\d]*', '<TS>', normalized)
        normalized = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '<IP>', normalized)
        normalized = re.sub(r'\b[0-9a-f]{8,}\b', '<HEX>', normalized, flags=re.I)
        normalized = re.sub(r'\b\d+\b', '<N>', normalized)
        if normalized:
            patterns[normalized] += 1

    n = args.num
    print(f"\n  Top {n} Log Patterns")
    print("  " + "─" * 60)
    for pat, cnt in patterns.most_common(n):
        display = pat[:80] + "..." if len(pat) > 80 else pat
        print(f"  {cnt:>6}  {display}")
    print()

def main():
    p = argparse.ArgumentParser(description="Log file analyzer")
    sp = p.add_subparsers(dest="cmd")

    s = sp.add_parser("stats", help="Log statistics")
    s.add_argument("file", nargs="?")
    s.set_defaults(func=cmd_stats)

    f = sp.add_parser("filter", help="Filter log lines")
    f.add_argument("file", nargs="?")
    f.add_argument("-p", "--pattern", help="Regex pattern")
    f.add_argument("-l", "--level", help="Log level")
    f.add_argument("-i", "--ignore-case", action="store_true")
    f.add_argument("-v", "--invert", action="store_true")
    f.add_argument("-c", "--count-only", action="store_true")
    f.set_defaults(func=cmd_filter)

    t = sp.add_parser("timeline", help="Activity timeline")
    t.add_argument("file", nargs="?")
    t.set_defaults(func=cmd_timeline)

    top = sp.add_parser("top", help="Top log patterns")
    top.add_argument("file", nargs="?")
    top.add_argument("-n", "--num", type=int, default=15)
    top.set_defaults(func=cmd_top)

    args = p.parse_args()
    if not args.cmd:
        p.print_help()
        sys.exit(1)
    args.func(args)

if __name__ == "__main__":
    main()
