# agent-retry-audit

Offline retry-discipline audit for agent traces.

When an agent hits a flaky tool, how it retries matters: hammering a failing endpoint makes things worse, and retrying with no growing delay is a design smell. This tool reads a recorded trace and reports how each distinct call was retried. It never runs the agent, never calls a model, and cannot change how anything retries.

## Trace format

One JSON object per line, one per tool call:

```jsonl
{"tool": "web.fetch", "args": {"url": "https://example.com"}, "ts": 12.5, "ok": false}
```

- `tool` - required, non-empty string.
- `args` - optional, any JSON value. Two calls count as the same call when `tool` and `args` match after key-order canonicalization.
- `ts` - optional finite number (seconds); needed for backoff findings.
- `ok` - optional boolean; carried for context, not judged.

## What it reports

Defaults: over 3 attempts of the same call is a storm, gaps that fail to strictly increase across 3+ attempts is missing backoff, any gap under 1.0s is a fast retry.

| Code | Severity | Meaning |
| --- | --- | --- |
| `retry-storm` | error | same call attempted more than `max_attempts` times |
| `retry` | warning | same call attempted 2+ times, within the limit |
| `no-backoff` | warning | 3+ attempts and the gaps do not strictly increase |
| `fast-retry` | warning | an attempt arrived under `min_gap` after the previous one |

Findings are sorted deterministically (severity, code, message), so the same trace always produces the same report.

## Use

```sh
python3 retry_audit.py trace.jsonl                  # defaults: 3 attempts, 1.0s floor
python3 retry_audit.py trace.jsonl 5 2.0            # custom: 5 attempts, 2.0s floor
python3 demo.py                                     # synthetic demo
python3 -m unittest test_retry_audit                # 23 tests
```

Exit codes: `0` no errors (warnings may still print), `1` a storm was found, `2` invalid input.

## Safety caps

The CLI refuses traces over 1 MiB, records nested deeper than 64 levels, and traces with more than 10,000 records - all as exit 2, never a crash.

## Tests

23 tests, including an exhaustive independent oracle: every trace of length 0..7 over three call signatures on a fixed timestamp ladder (3,280 traces) is checked against a separately written plain-loop recount, plus the exact 1 MiB accept/reject boundary.

## Limits

- **Audit, not enforcement.** Nothing here delays, blocks or schedules a retry. It tells you how the recorded retries behaved.
- **Sameness is syntactic.** Calls match on identical tool and args after key ordering. A retry with a cosmetically changed argument (a fresh timestamp, a bumped nonce) is a different call to this tool.
- **Timing needs timestamps.** Without `ts` on every attempt of a call, backoff and fast-retry findings are skipped for that call - no guessing.
- **Strictly-increasing is a smell test, not a policy.** Constant gaps (fixed-interval retry) and shrinking gaps both flag. Whether exponential, jittered or fixed backoff is right is your design call.
- **`ok` is not judged.** A trace full of failed attempts with no retries is a different problem than a retry storm; this tool does not score failures, only repetition.
- **Trusted-input API.** The caps live in the CLI and `load_trace`; calling `audit_trace` directly with hand-built records bypasses them.

## License

MIT - see [LICENSE](LICENSE).
