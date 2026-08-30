from __future__ import annotations

from .version import DISPLAY_VERSION
from .workspace_frontend_v11 import WORKSPACE_HTML_V11


# V4 keeps the hardened V3 authorization/checkpoint controls and changes only the
# release label plus the admitted execution capability description. Endpoints stay
# stable so users do not need a new operational workflow for the new release line.
html = WORKSPACE_HTML_V11
html = html.replace("workflowV3", "workflowV4")
html = html.replace("workflow-v3", "workflow-v4")
html = html.replace("Workflow V3", "Workflow V4")
html = html.replace("Prepare V3", "Prepare V4")
html = html.replace("V3 prepared", "V4 prepared")
html = html.replace("Prepare V4 first", "Prepare V4 first")
html = html.replace("V3 admission blocked", "V4 admission blocked")
html = html.replace("V3 start failed", "V4 start failed")
html = html.replace(
    "Manual low-risk workflows may use deterministic validation branches and persistent approval checkpoints. Scheduling, arbitrary conditions, branch joins and new capabilities remain blocked.",
    "Manual low-risk workflows may use deterministic validation branches, persistent approval checkpoints, and one bounded two-lane parallel DAG (Research → Presentation per lane) with a verified join. Scheduling, event triggers, arbitrary conditions, nested parallelism and new capabilities remain blocked.",
)
html = html.replace(
    "Compiling the diagram contract into a bounded V3 state machine.",
    "Compiling the diagram contract into the bounded V4 state machine.",
)
html = html.replace(
    "V3 requires a fresh admission and fingerprint.",
    "V4 requires a fresh admission and fingerprint.",
)
html = html.replace("status.textContent='V3: '+text", f"status.textContent='{DISPLAY_VERSION} · V4: '+text")
html = html.replace(">V3: not prepared<", f">{DISPLAY_VERSION} · V4: not prepared<")

WORKSPACE_HTML_V12 = html
