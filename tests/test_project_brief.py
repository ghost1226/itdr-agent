"""The workflow Mermaid diagram in PROJECT_BRIEF.md (Task B, 2026-10-23).

Section 5 is the flow section. The diagram must follow the brief's order and
name every stage, so a reader gets the machine and the human loop in one
picture. Offline: this only reads a tracked markdown file.
"""

from __future__ import annotations

import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
BRIEF = PROJECT_ROOT / "PROJECT_BRIEF.md"

# Every stage of the workflow, in the brief's order.
STAGES = [
    "alert",
    "pre-fetch",
    "investigator tool loop",
    "dossier",
    "adjudicator",
    "guards",
    "confidence",
    "thin evidence",
    "mitre evidence",
    "analyst question",
    "containment review",
    "approve",
    "edit",
    "reject",
    "audit log",
]


def _diagram() -> str:
    text = BRIEF.read_text(encoding="utf-8")
    blocks = re.findall(r"```mermaid\n(.*?)```", text, flags=re.DOTALL)
    assert blocks, "PROJECT_BRIEF.md has no ```mermaid block"
    return "\n".join(blocks).lower()


def test_the_brief_has_a_mermaid_workflow_block():
    assert "flowchart" in _diagram(), "the mermaid block is not a flowchart"


def test_the_diagram_names_every_stage():
    diagram = _diagram()
    missing = [stage for stage in STAGES if stage not in diagram]
    assert not missing, f"workflow diagram is missing: {missing}"


def test_the_diagram_keeps_the_brief_order():
    diagram = _diagram()
    positions = [diagram.index(stage) for stage in STAGES]
    assert positions == sorted(positions), "workflow stages are out of the brief's order"
