"""agent-retry-audit: offline retry-discipline audit for agent traces.

Reads a JSONL trace of tool calls and reports how each distinct call was
retried: storms (too many attempts), missing backoff (gaps not growing),
and fast retries (gap below a floor). Purely analytical: it never runs the
agent, never calls a model, and cannot change how anything retries.

Trace: one JSON object per line, one per tool call:
  {"tool": "web.fetch", "args": {"url": "..."}, "ts": 12.5, "ok": false}
  - tool required, non-empty string
  - args optional; any JSON value. Two calls are "the same call" when tool
    and args are identical after key-order canonicalization.
  - ts   optional finite number (seconds); needed for backoff findings
  - ok   optional boolean; informational only

Defaults: >3 attempts of the same call is a storm (error), gaps that fail
to strictly increase across 3+ attempts is missing backoff (warning), any
gap under 1.0s is a fast retry (warning).
"""

import json
import math
import sys

MAX_BYTES = 1 << 20          # 1 MiB trace cap
MAX_RECORDS = 10_000
MAX_DEPTH = 64

ERROR = "error"
WARNING = "warning"

DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_MIN_GAP = 1.0


class InvalidInput(Exception):
    """Raised when the trace cannot be parsed within the safety caps."""


def _check_depth(node, depth=0):
    if depth > MAX_DEPTH:
        raise InvalidInput(f"JSON nesting deeper than {MAX_DEPTH}")
    if isinstance(node, dict):
        for v in node.values():
            _check_depth(v, depth + 1)
    elif isinstance(node, list):
        for v in node:
            _check_depth(v, depth + 1)


def load_trace(text):
    """Parse JSONL trace text, enforcing size, count and depth caps."""
    if len(text.encode("utf-8", "replace")) > MAX_BYTES:
        raise InvalidInput(f"trace larger than {MAX_BYTES} bytes")
    records = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        if len(records) >= MAX_RECORDS:
            raise InvalidInput(f"more than {MAX_RECORDS} records")
        try:
            rec = json.loads(line)
        except (json.JSONDecodeError, RecursionError) as e:
            raise InvalidInput(f"line {lineno}: invalid JSON: {e}")
        _check_depth(rec)
        if not isinstance(rec, dict):
            raise InvalidInput(f"line {lineno}: record is not an object")
        tool = rec.get("tool")
        if not isinstance(tool, str) or not tool:
            raise InvalidInput(f"line {lineno}: missing non-empty string tool")
        ts = rec.get("ts")
        if ts is not None and (not isinstance(ts, (int, float))
                               or isinstance(ts, bool) or not math.isfinite(ts)):
            raise InvalidInput(f"line {lineno}: ts must be a finite number")
        records.append((lineno, rec))
    return records


def _signature(rec):
    args = rec.get("args")
    return rec["tool"] + "\x00" + json.dumps(args, sort_keys=True,
                                             separators=(",", ":"))


def audit_trace(records, max_attempts=DEFAULT_MAX_ATTEMPTS,
                min_gap=DEFAULT_MIN_GAP):
    """Return deterministically ordered findings for parsed records.

    Each finding is {severity, code, message}. `max_attempts` must be >= 1;
    `min_gap` must be >= 0.
    """
    if not (isinstance(max_attempts, int) and max_attempts >= 1):
        raise InvalidInput("max_attempts must be a positive integer")
    if not _finite(min_gap) or min_gap < 0:
        raise InvalidInput("min_gap must be a non-negative finite number")

    attempts = {}  # signature -> list of (lineno, ts or None)
    for lineno, rec in records:
        attempts.setdefault(_signature(rec), []).append((lineno, rec.get("ts")))

    findings = []

    def add(sev, code, msg):
        findings.append({"severity": sev, "code": code, "message": msg})

    for sig in sorted(attempts):
        tries = attempts[sig]
        tool = sig.split("\x00", 1)[0]
        n = len(tries)
        if n == 1:
            continue
        lines = ", ".join(str(ln) for ln, _ in tries)
        if n > max_attempts:
            add(ERROR, "retry-storm",
                f"{tool!r} attempted {n} times (lines {lines}), over the {max_attempts}-attempt limit")
        else:
            add(WARNING, "retry",
                f"{tool!r} attempted {n} times (lines {lines})")

        timed = [(ln, ts) for ln, ts in tries if ts is not None]
        if len(timed) >= 2 and len(timed) == n:
            gaps = [round(timed[i + 1][1] - timed[i][1], 9) for i in range(len(timed) - 1)]
            for i, gap in enumerate(gaps):
                if gap < min_gap:
                    add(WARNING, "fast-retry",
                        f"{tool!r} attempt {i + 2} came {gap:g}s after attempt {i + 1} "
                        f"(line {timed[i + 1][0]}), under the {min_gap:g}s floor")
            if n >= 3 and not all(gaps[i + 1] > gaps[i] for i in range(len(gaps) - 1)):
                add(WARNING, "no-backoff",
                    f"{tool!r} gaps between attempts ({', '.join(f'{g:g}s' for g in gaps)}) "
                    "do not strictly increase")

    order = {ERROR: 0, WARNING: 1}
    findings.sort(key=lambda f: (order[f["severity"]], f["code"], f["message"]))
    return findings


def _finite(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def has_errors(findings):
    return any(f["severity"] == ERROR for f in findings)


def main(argv):
    if len(argv) < 2 or len(argv) > 4:
        print("usage: retry_audit.py TRACE.jsonl [max_attempts] [min_gap_seconds]",
              file=sys.stderr)
        return 2
    try:
        max_attempts = int(argv[2]) if len(argv) >= 3 else DEFAULT_MAX_ATTEMPTS
        min_gap = float(argv[3]) if len(argv) == 4 else DEFAULT_MIN_GAP
    except ValueError:
        print("invalid input: max_attempts must be an integer, min_gap a number",
              file=sys.stderr)
        return 2
    try:
        with open(argv[1], "rb") as fh:
            raw = fh.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise InvalidInput(f"trace larger than {MAX_BYTES} bytes")
        records = load_trace(raw.decode("utf-8"))
        findings = audit_trace(records, max_attempts, min_gap)
    except (OSError, UnicodeDecodeError, InvalidInput) as e:
        print(f"invalid input: {e}", file=sys.stderr)
        return 2
    if not findings:
        print("no retry findings")
    for f in findings:
        print(f"{f['severity']}: {f['code']}: {f['message']}")
    return 1 if has_errors(findings) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
