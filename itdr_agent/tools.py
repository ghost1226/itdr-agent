"""Checkpoint 4 — Tool registry for the Investigator agent.

Tools wrap the simulated Graph layer. Tool output is untrusted data: it is
serialized and wrapped in ``<microsoft_graph_data>`` tags before it ever
reaches the LLM, so a malicious record cannot smuggle instructions.
"""

from __future__ import annotations

import json
from typing import Any

from . import sim_api

TOOL_SPECS: dict[str, dict[str, Any]] = {
    "get_user_profile": {
        "description": "Fetch the Entra ID profile for a user principal name.",
        "parameters": {"upn": "string"},
    },
    "get_sign_in_history": {
        "description": "Fetch recent sign-in events for a user.",
        "parameters": {"upn": "string", "hours": "integer"},
    },
    "get_device_trust": {
        "description": "Fetch device compliance/trust details for a device id.",
        "parameters": {"device_id": "string"},
    },
    "get_directory_audits": {
        "description": "Fetch directory audit events touching a user.",
        "parameters": {"upn": "string", "hours": "integer"},
    },
    "get_risky_user_report": {
        "description": "Fetch the risky-user report for a user.",
        "parameters": {"upn": "string"},
    },
}


def call_tool(name: str, arguments: dict[str, Any]) -> Any:
    """Execute a registered tool against the simulated Graph layer."""
    if name not in TOOL_SPECS:
        raise KeyError(f"Unknown tool: {name!r}")
    return getattr(sim_api, name)(**arguments)


def wrap_tool_output(name: str, payload: Any) -> str:
    """Serialize tool output as clearly-delimited, untrusted data.

    ``<`` and ``>`` are escaped so a record containing the closing tag
    cannot break out of the data block. The body remains valid JSON.
    """
    body = json.dumps(payload, sort_keys=True, default=str)
    body = body.replace("<", "\\u003c").replace(">", "\\u003e")
    return (
        f'<microsoft_graph_data tool="{name}" untrusted="true">\n'
        f"{body}\n"
        f"</microsoft_graph_data>"
    )
