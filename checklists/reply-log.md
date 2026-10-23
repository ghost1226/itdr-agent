# Checklist — reply log (every model call in the run trace)

Task (2026-10-23, Joe's "Next task for Pi"): log every model reply — stage,
finish reason, and the first 300 characters — in the run trace, on every
attempt, success or failure, through a small hook. No fixture or prompt
changes. Written before the code; the implementation landed as red `ad052db`
→ green `d278a4d`, so this checklist verifies that work.

- [x] `RunTrace` keeps `llm_replies` and appends via `record_llm_reply` -> `../itdr_agent/trace.py::record_llm_reply` `../itdr_agent/trace.py::self.llm_replies`
- [x] `llm_replies` is written into the run JSON by `to_dict` -> `../itdr_agent/trace.py::"llm_replies": self.llm_replies`
- [x] both OpenRouter wrappers call the optional `on_reply` hook on every attempt, success or failure -> `../itdr_agent/__main__.py::hook("investigation"` `../itdr_agent/__main__.py::hook("adjudication"`
- [x] the orchestrator sets each wrapper's `on_reply` to the trace's method -> `../itdr_agent/orchestrator.py::_wire_llm_reply_hook`
- [x] tests: one call records one entry, a two-attempt call records two, the run JSON contains `llm_replies` -> `../tests/test_bad_reply.py::test_a_successful_call_records_one_llm_reply` `../tests/test_trace.py::test_llm_replies_are_written_into_the_run_json`
- [x] the PROGRESS.md What's Done entry names the reply-log task -> `../PROGRESS.md::Every model reply logged in the run trace`
- [x] the red and green commits are recorded in PROGRESS.md -> `../PROGRESS.md::ad052db` `../PROGRESS.md::d278a4d`
- [x] full suite green and `python scripts/check_progress.py` exits 0
