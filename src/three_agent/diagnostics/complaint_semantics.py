from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .complaint_intake import normalize_text

COMPLAINT_SEMANTICS_SCHEMA = "workspace-complaint-semantics/v1"

# These catalogs translate what the customer says into diagnostic observations.
# Causal language is kept in a separate catalog so it never becomes a fact merely
# because the customer used a technical word.
_SYMPTOM_ALIASES: Mapping[str, tuple[str, ...]] = {
    "perceived_unresponsiveness": (
        "may bi do", "may do", "bi do", "treo", "freeze", "freezes", "frozen",
        "not responding", "unresponsive", "フリーズ",
    ),
    "unexpected_restart": (
        "tu khoi dong lai", "tu reset", "khoi dong lai", "random restart",
        "random reboot", "restart", "reboot", "勝手に再起動", "再起動",
    ),
    "display_blackout": (
        "man hinh den", "black screen", "screen black", "no display", "画面 真っ暗",
    ),
    "blue_screen_observed": (
        "man hinh xanh", "blue screen", "bsod", "ブルースクリーン",
    ),
    "expected_network_access_unavailable": (
        "mat mang", "khong vao mang", "khong co mang", "no internet", "no network",
        "internet broken", "ネット 繋がらない",
    ),
    "application_unresponsive": (
        "app bi do", "phan mem bi do", "app not responding", "application not responding",
        "アプリ 応答なし",
    ),
}

_CUSTOMER_HYPOTHESIS_ALIASES: Mapping[str, tuple[str, ...]] = {
    "gpu_failure": (
        "gpu hong", "gpu bi loi", "card man hinh hong", "gpu broken", "gpu dead",
        "graphics card broken",
    ),
    "ram_failure": (
        "ram hong", "ram bi loi", "ram broken", "bad ram",
    ),
    "storage_failure": (
        "ssd hong", "o cung hong", "disk hong", "ssd broken", "disk failure",
    ),
    "power_supply_failure": (
        "nguon hong", "psu hong", "power supply broken", "bad psu",
    ),
    "windows_update_regression": (
        "windows update lam hong", "update lam hong", "windows update broke",
        "update broke", "update caused",
    ),
    "malware_infection": (
        "bi virus", "chac bi virus", "virus roi", "infected by virus", "malware infected",
    ),
    "overheating": (
        "do qua nong", "vi qua nong", "overheating", "too hot",
    ),
}

_ROUTING_TERMS: Mapping[str, tuple[str, ...]] = {
    "perceived_unresponsiveness": ("system event", "application event", "freeze"),
    "unexpected_restart": ("system event", "reboot", "restart", "shutdown", "bsod"),
    "display_blackout": ("system event", "display"),
    "blue_screen_observed": ("system event", "bsod", "reboot"),
    "expected_network_access_unavailable": ("network", "internet"),
    "application_unresponsive": ("application event", "app crash"),
}

_HYPOTHESIS_ROUTING_TERMS: Mapping[str, tuple[str, ...]] = {
    "gpu_failure": ("display", "system event"),
    "ram_failure": ("system event", "bsod"),
    "storage_failure": ("system event",),
    "power_supply_failure": ("system event", "shutdown", "reboot"),
    "windows_update_regression": ("system event", "reboot"),
    "malware_infection": ("security event",),
    "overheating": ("system event", "shutdown"),
}


def _matched_ids(text: str, catalog: Mapping[str, tuple[str, ...]]) -> tuple[str, ...]:
    matched: list[str] = []
    for concept, aliases in catalog.items():
        if any(normalize_text(alias) in text for alias in aliases):
            matched.append(concept)
    return tuple(sorted(matched))


@dataclass(frozen=True)
class ComplaintSemantics:
    raw_text: str
    normalized_text: str
    canonical_symptoms: tuple[str, ...]
    customer_hypotheses: tuple[str, ...]
    schema_version: str = COMPLAINT_SEMANTICS_SCHEMA

    def routing_query(self) -> str:
        """Augment routing terms without upgrading customer hypotheses into facts."""
        terms: list[str] = [self.raw_text]
        for symptom in self.canonical_symptoms:
            terms.extend(_ROUTING_TERMS.get(symptom, ()))
        for hypothesis in self.customer_hypotheses:
            terms.extend(_HYPOTHESIS_ROUTING_TERMS.get(hypothesis, ()))
        return " ".join(dict.fromkeys(term for term in terms if term))


def normalize_complaint_semantics(value: str) -> ComplaintSemantics:
    raw = str(value).strip()
    if not raw:
        raise ValueError("complaint text is required")
    normalized = normalize_text(raw)
    return ComplaintSemantics(
        raw_text=raw,
        normalized_text=normalized,
        canonical_symptoms=_matched_ids(normalized, _SYMPTOM_ALIASES),
        customer_hypotheses=_matched_ids(normalized, _CUSTOMER_HYPOTHESIS_ALIASES),
    )
