# Checklist — per-call reply log (`RunTrace.llm_replies`)

Task (2026-10-23, Joe's "Next task for Pi"): log every model reply — stage,
finish reason, and the first 300 characters — in the run trace, on every
attempt, success or failure, through a small hook. No fixture or prompt
changes. Backfilled after the finish-check rule landed mid-session.

- [x] `RunTrace` keeps `llm_replies` and appends via `record_llm_reply` -> `../itdr_agent/trace.py::record_llm_reply` `../itdr_agent/trace.py::llm_replies`
- [x] `llm_replies` is written into the run JSON -> `../itdr_agent/trace.py::"llm_replies": self.llm_replies`
- [x] both OpenRouter wrappers call the optional `on_reply` hook on every attempt -> `../itdr_agent/__main__.py::self.on_reply` `../itdr_agent/__main__.py::hook("investigation"`
- [x] the orchestrator wires both agents' LLMs to the trace -> `../itdr_agent/orchestrator.py::_wire_llm_reply_hook`
- [x] wrapper tests: success = one entry, retry = two, adjudicator stage, 300-char cap, end-to-end run JSON -> `../tests/test_bad_reply.py::test_a_successful_call_records_one_llm_reply`
- [x] trace tests: `llm_replies` in `to_dict` and the written run JSON -> `../tests/test_trace.py::test_llm_replies_are_written_into_the_run_json`
- [x] full suite green at the time (635 passed)
