# Checklist — reasoning tokens in the meter (Task C, 2026-10-23)

Task: OpenRouter's usage carries completion_tokens_details.reasoning_tokens
(seen on Opus, 2026-10-23). TokenMeter records it when present (0 otherwise),
format_tokens shows it, and the trace's llm_requests carries it. Tests with a
fake usage object. Closes open problem 16.

- [x] the meter keeps a reasoning total -> `../itdr_agent/usage.py::self.reasoning_tokens = 0`
- [x] the meter reads completion_tokens_details.reasoning_tokens, 0 when absent -> `../itdr_agent/usage.py::def _reasoning_tokens`
- [x] the snapshot exposes reasoning_tokens -> `../itdr_agent/usage.py::"reasoning_tokens": self.reasoning_tokens`
- [x] format_tokens shows reasoning when it is non-zero -> `../itdr_agent/usage.py::if reasoning:`
- [x] the trace llm_requests entry carries reasoning_tokens -> `../itdr_agent/trace.py::"reasoning_tokens":`
- [x] a fake-usage test proves the meter counts it -> `../tests/test_token_meter.py::def test_meter_counts_reasoning_tokens`
- [x] a trace test proves a request carries it -> `../tests/test_trace.py::def test_trace_records_reasoning_tokens`
- [x] PROGRESS.md records the task and closes open problem 16 -> `../PROGRESS.md::reasoning-tokens`
- [x] the red and green commits are recorded in PROGRESS.md -> `../PROGRESS.md::reasoning-tokens: red`
- [x] full suite green and check_progress exits 0
