from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .complaint_intake import normalize_text

COMPLAINT_SEMANTICS_SCHEMA = "workspace-complaint-semantics/v1"

# User wording is evidence about experience, not proof of a technical cause.
_SYMPTOM_ALIASES: Mapping[str, tuple[str, ...]] = {
    "perceived_unresponsiveness": (
        "may bi do", "may do", "bi do", "treo", "freeze", "freezes", "frozen",
        "not responding", "unresponsive", "dung hinh", "フリーズ", "固まる",
        "パソコンが固まる",
    ),
    "unexpected_restart": (
        "tu khoi dong lai", "tu reset", "khoi dong lai", "tu bat lai tu dau",
        "bat lai tu dau", "random restart", "random reboot", "restart", "reboot",
        "勝手に再起動", "再起動",
    ),
    "display_blackout": (
        "man hinh den", "man hinh khong len", "black screen", "screen black",
        "no display", "画面 真っ暗", "画面が真っ暗", "真っ暗",
    ),
    "blue_screen_observed": (
        "man hinh xanh", "xanh man hinh", "blue screen", "bsod", "ブルースクリーン",
    ),
    "expected_network_access_unavailable": (
        "mat mang", "khong vao mang", "khong vao duoc mang", "khong co mang",
        "internet tu nhien bi mat", "no internet", "no network", "internet broken",
        "ネット 繋がらない", "ネットが繋がらない",
    ),
    "application_unresponsive": (
        "app bi do", "app bi treo", "phan mem bi do", "phan mem bi treo",
        "excel bi do", "app not responding", "application not responding",
        "chrome is not responding", "アプリ 応答なし", "アプリが応答しない",
    ),
}

_CUSTOMER_HYPOTHESIS_ALIASES: Mapping[str, tuple[str, ...]] = {
    "gpu_failure": (
        "gpu hong", "gpu bi loi", "card man hinh hong", "gpu broken", "gpu dead",
        "gpu is dead", "graphics card broken", "graphics card is broken",
        "gpuが壊れ", "gpuが故障", "gpu 故障",
    ),
    "ram_failure": (
        "ram hong", "ram bi loi", "ram broken", "bad ram", "ram is broken",
        "ramが壊れ", "ramが故障", "ram 故障",
    ),
    "storage_failure": (
        "ssd hong", "o cung hong", "disk hong", "ssd broken", "disk failure",
        "ssd is broken", "ssdが壊れ", "ssdが故障", "disk is failing",
    ),
    "power_supply_failure": (
        "nguon hong", "psu hong", "power supply broken", "power supply is broken",
        "bad psu", "電源ユニットが壊れ", "電源ユニットが故障", "psu is broken",
    ),
    "windows_update_regression": (
        "windows update lam hong", "update lam hong", "windows update broke",
        "update broke", "update caused", "windows update caused",
        "windows updateで壊れ", "updateで壊れ",
    ),
    "malware_infection": (
        "bi virus", "chac bi virus", "virus roi", "infected by virus",
        "infected by malware", "malware infected", "malware infection",
        "ウイルスに感染", "マルウェアに感染",
    ),
    "overheating": (
        "do qua nong", "vi qua nong", "overheating", "too hot", "qua nong",
        "熱暴走", "過熱", "オーバーヒート",
    ),
}

# Routing terms intentionally describe evidence channels/subsystems, not conclusions.
_ROUTING_TERMS: Mapping[str, tuple[str, ...]] = {
    "perceived_unresponsiveness": ("performance", "cpu", "memory", "system event", "application event", "freeze"),
    "unexpected_restart": ("operating system", "system event", "reboot", "restart", "shutdown", "bsod"),
    "display_blackout": ("operating system", "system event", "display"),
    "blue_screen_observed": ("operating system", "system event", "bsod", "reboot"),
    "expected_network_access_unavailable": ("network adapter", "ip address", "gateway", "dns", "internet"),
    "application_unresponsive": ("performance", "application event", "app crash"),
}

_HYPOTHESIS_ROUTING_TERMS: Mapping[str, tuple[str, ...]] = {
    "gpu_failure": ("display", "system event"),
    "ram_failure": ("memory", "system event", "bsod"),
    "storage_failure": ("storage", "system event"),
    "power_supply_failure": ("system event", "shutdown", "reboot"),
    "windows_update_regression": ("operating system", "system event", "reboot"),
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
