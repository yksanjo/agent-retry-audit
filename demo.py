"""Synthetic demo: audit one disciplined trace and one sloppy trace.

All traces here are made up. No model calls, no network, nothing executes.
"""
import json
import retry_audit

disciplined = [
    {"tool": "web.fetch", "args": {"url": "https://example.com/a"}, "ts": 0, "ok": False},
    {"tool": "web.fetch", "args": {"url": "https://example.com/a"}, "ts": 2, "ok": False},
    {"tool": "web.fetch", "args": {"url": "https://example.com/a"}, "ts": 6, "ok": True},
    {"tool": "web.search", "args": {"q": "agent budgets"}, "ts": 8, "ok": True},
]

sloppy = [
    {"tool": "web.fetch", "args": {"url": "https://example.com/b"}, "ts": 0, "ok": False},
    {"tool": "web.fetch", "args": {"url": "https://example.com/b"}, "ts": 0.2, "ok": False},
    {"tool": "web.fetch", "args": {"url": "https://example.com/b"}, "ts": 0.5, "ok": False},
    {"tool": "web.fetch", "args": {"url": "https://example.com/b"}, "ts": 0.6, "ok": False},
    {"tool": "web.fetch", "args": {"url": "https://example.com/b"}, "ts": 0.7, "ok": False},
]

for label, calls in [("disciplined", disciplined), ("sloppy", sloppy)]:
    recs = retry_audit.load_trace("\n".join(json.dumps(c) for c in calls))
    findings = retry_audit.audit_trace(recs)
    print(f"--- {label} trace ({len(calls)} calls) ---")
    if not findings:
        print("no retry findings")
    for f in findings:
        print(f"{f['severity']}: {f['code']}: {f['message']}")
    print()
