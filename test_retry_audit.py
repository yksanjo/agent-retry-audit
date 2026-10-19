import itertools
import json
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import retry_audit


def trace(calls):
    return retry_audit.load_trace("\n".join(json.dumps(c) for c in calls))


def codes(findings):
    return [f["code"] for f in findings]


class AuditTests(unittest.TestCase):
    def test_single_calls_clean(self):
        recs = trace([{"tool": "a"}, {"tool": "b"}])
        self.assertEqual(retry_audit.audit_trace(recs), [])

    def test_same_tool_different_args_not_retry(self):
        recs = trace([{"tool": "a", "args": {"x": 1}}, {"tool": "a", "args": {"x": 2}}])
        self.assertEqual(retry_audit.audit_trace(recs), [])

    def test_args_key_order_irrelevant(self):
        recs = trace([
            {"tool": "a", "args": {"x": 1, "y": 2}},
            {"tool": "a", "args": {"y": 2, "x": 1}},
        ])
        self.assertEqual(codes(retry_audit.audit_trace(recs)), ["retry"])

    def test_two_attempts_is_warning(self):
        recs = trace([{"tool": "a"}, {"tool": "a"}])
        f = retry_audit.audit_trace(recs)
        self.assertEqual(codes(f), ["retry"])
        self.assertEqual(f[0]["severity"], retry_audit.WARNING)

    def test_storm_over_limit(self):
        recs = trace([{"tool": "a"}] * 4)
        f = retry_audit.audit_trace(recs)
        self.assertEqual(codes(f), ["retry-storm"])
        self.assertTrue(retry_audit.has_errors(f))

    def test_storm_threshold_configurable(self):
        recs = trace([{"tool": "a"}] * 3)
        self.assertEqual(codes(retry_audit.audit_trace(recs, max_attempts=2)),
                         ["retry-storm"])

    def test_increasing_gaps_no_backoff_finding(self):
        recs = trace([
            {"tool": "a", "ts": 0},
            {"tool": "a", "ts": 1},
            {"tool": "a", "ts": 3},
            {"tool": "a", "ts": 7},
        ])
        self.assertNotIn("no-backoff", codes(retry_audit.audit_trace(recs)))

    def test_flat_gaps_flagged(self):
        recs = trace([{"tool": "a", "ts": 0}, {"tool": "a", "ts": 2}, {"tool": "a", "ts": 4}])
        self.assertIn("no-backoff", codes(retry_audit.audit_trace(recs)))

    def test_shrinking_gaps_flagged(self):
        recs = trace([{"tool": "a", "ts": 0}, {"tool": "a", "ts": 10}, {"tool": "a", "ts": 12}])
        self.assertIn("no-backoff", codes(retry_audit.audit_trace(recs)))

    def test_fast_retry(self):
        recs = trace([{"tool": "a", "ts": 0}, {"tool": "a", "ts": 0.5}])
        f = retry_audit.audit_trace(recs)
        self.assertIn("fast-retry", codes(f))
        f = retry_audit.audit_trace(recs, min_gap=0.1)
        self.assertNotIn("fast-retry", codes(f))

    def test_missing_ts_skips_timing_findings(self):
        recs = trace([{"tool": "a"}] * 4)
        c = codes(retry_audit.audit_trace(recs))
        self.assertNotIn("fast-retry", c)
        self.assertNotIn("no-backoff", c)

    def test_partial_ts_skips_timing(self):
        recs = trace([{"tool": "a", "ts": 0}, {"tool": "a"}, {"tool": "a", "ts": 5}])
        c = codes(retry_audit.audit_trace(recs))
        self.assertNotIn("fast-retry", c)
        self.assertNotIn("no-backoff", c)

    def test_deterministic(self):
        recs = trace([{"tool": "b"}] * 4 + [{"tool": "a"}] * 2)
        f1 = codes(retry_audit.audit_trace(recs))
        f2 = codes(retry_audit.audit_trace(recs))
        self.assertEqual(f1, f2)


class InputTests(unittest.TestCase):
    def test_missing_tool_rejected(self):
        with self.assertRaises(retry_audit.InvalidInput):
            retry_audit.load_trace('{"args": {}}')

    def test_bad_ts_rejected(self):
        with self.assertRaises(retry_audit.InvalidInput):
            retry_audit.load_trace('{"tool": "a", "ts": "soon"}')

    def test_bad_config_rejected(self):
        recs = trace([{"tool": "a"}])
        with self.assertRaises(retry_audit.InvalidInput):
            retry_audit.audit_trace(recs, max_attempts=0)
        with self.assertRaises(retry_audit.InvalidInput):
            retry_audit.audit_trace(recs, min_gap=-1)

    def test_caps(self):
        with self.assertRaises(retry_audit.InvalidInput):
            retry_audit.load_trace("{bad")
        with self.assertRaises(retry_audit.InvalidInput):
            retry_audit.load_trace("[1]")
        big = "\n".join('{"tool": "a"}' for _ in range(retry_audit.MAX_RECORDS + 1))
        with self.assertRaises(retry_audit.InvalidInput):
            retry_audit.load_trace(big)


class OracleTests(unittest.TestCase):
    """Exhaustive oracle: every trace of length 0..7 over three signatures
    (a, b, a-with-args) with a fixed timestamp ladder, checked against an
    independent recount written with plain loops."""

    SIGS = ({"tool": "a"}, {"tool": "b"}, {"tool": "a", "args": {"x": 1}})

    def test_all_small_traces(self):
        checked = 0
        for length in range(8):
            for combo in itertools.product(self.SIGS, repeat=length):
                calls = [dict(c, ts=float(i)) for i, c in enumerate(combo)]
                recs = trace(calls)
                got = retry_audit.audit_trace(recs)
                # Independent oracle.
                positions = {}
                for i, c in enumerate(calls):
                    key = c["tool"] + "|" + json.dumps(c.get("args"), sort_keys=True)
                    positions.setdefault(key, []).append(float(i))
                want = []
                for sig, tries in positions.items():
                    n = len(tries)
                    if n >= 2:
                        want.append("retry-storm" if n > 3 else "retry")
                    gaps = [tries[i + 1] - tries[i] for i in range(n - 1)]
                    if any(g < 1.0 for g in gaps):
                        want.append("fast-retry")
                    if n >= 3 and not all(gaps[i + 1] > gaps[i] for i in range(len(gaps) - 1)):
                        want.append("no-backoff")
                self.assertEqual(Counter(codes(got)), Counter(want),
                                 f"mismatch on {combo}")
                checked += 1
        self.assertEqual(checked, sum(3 ** k for k in range(8)))


class CliTests(unittest.TestCase):
    def run_cli(self, text, *extra):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as fh:
            fh.write(text)
            path = fh.name
        return subprocess.run(
            [sys.executable, str(Path(__file__).parent / "retry_audit.py"), path, *extra],
            capture_output=True, text=True)

    def test_cli_clean_exit_0(self):
        r = self.run_cli('{"tool": "a"}\n')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("no retry findings", r.stdout)

    def test_cli_storm_exit_1(self):
        r = self.run_cli('{"tool": "a"}\n' * 4)
        self.assertEqual(r.returncode, 1)
        self.assertIn("retry-storm", r.stdout)

    def test_cli_warning_only_exit_0(self):
        r = self.run_cli('{"tool": "a"}\n{"tool": "a"}\n')
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_cli_invalid_exit_2(self):
        r = self.run_cli("{bad")
        self.assertEqual(r.returncode, 2)

    def test_cli_exact_1mib_boundary(self):
        rec = {"tool": "a", "pad": ""}
        rec["pad"] = "x" * (retry_audit.MAX_BYTES - len(json.dumps(rec)) - 1)
        text = json.dumps(rec) + "\n"
        self.assertEqual(len(text.encode()), retry_audit.MAX_BYTES)
        r = self.run_cli(text)
        self.assertEqual(r.returncode, 0, r.stderr)
        rec["pad"] += "x"
        r = self.run_cli(json.dumps(rec) + "\n")
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
