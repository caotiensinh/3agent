from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .complaint_intake import normalize_text

COMPLAINT_SEMANTICS_SCHEMA = "workspace-complaint-semantics/v1"

# User wording is evidence about experience, not proof of a technical cause.
_SYMPTOM_ALIASES: Mapping[str, tuple[str, ...]] = {
    "perceived_unresponsiveness": (
        "may bi do", "may do", "bi do", "treo", "freeze", "freezes", "frozen",
        "not responding", "unresponsive", "dung hinh", "lag cung", "pc bi dung",
        "may khong phan hoi", "computer hangs", "system stopped responding", "pc hangs",
        "フリーズ", "固まる", "パソコンが固まる", "pcが応答しなく", "固まったまま動かない",
    ),
    "unexpected_restart": (
        "tu khoi dong lai", "tu reset", "khoi dong lai", "tu bat lai tu dau",
        "bat lai tu dau", "random restart", "random reboot", "restart", "reboot",
        "勝手に再起動", "再起動",
    ),
    "display_blackout": (
        "man hinh den", "man hinh khong len", "man hinh toi den", "black screen",
        "screen black", "no display", "display went black", "monitor is black",
        "screen just went black", "画面 真っ暗", "画面が真っ暗", "真っ暗",
        "画面が消え", "ディスプレイが真っ黒",
    ),
    "blue_screen_observed": (
        "man hinh xanh", "xanh man hinh", "blue screen", "bsod", "ブルースクリーン",
        "青い画面",
    ),
    "expected_network_access_unavailable": (
        "mat mang", "khong vao mang", "khong vao duoc mang", "khong co mang",
        "khong co internet", "khong ket noi internet", "internet tu nhien bi mat",
        "no internet", "no network", "internet broken", "cannot connect to the internet",
        "ネット 繋がらない", "ネットが繋がらない", "ネットに接続できない", "ネットに接続できません",
    ),
    "hostname_resolution_unavailable": (
        "hostname khong resolve", "khong resolve duoc hostname", "khong phan giai duoc hostname",
        "ten may khong phan giai", "ten server khong phan giai", "cannot resolve hostname",
        "hostname not resolving", "hostname does not resolve", "ip works but hostname does not",
        "vao duoc bang ip nhung khong vao duoc bang ten", "bang ip vao duoc nhung ten khong vao duoc",
        "ホスト名を解決できない", "名前解決できない", "ipでは繋がるがホスト名では繋がらない",
    ),
    "vpn_internal_resource_unavailable": (
        "vpn vao duoc nhung", "vpn da vao duoc nhung", "vpn ket noi duoc nhung",
        "vpn connected but", "connected to vpn but", "vpn works but",
        "vpn接続できるが", "vpn接続済みだが", "vpnは繋がるが",
    ),
    "audio_output_unavailable": (
        "khong co tieng", "mat tieng", "khong nghe thay tieng", "khong co am thanh",
        "no sound", "no audio", "cannot hear audio", "sound is missing",
        "音が出ない", "音が聞こえない", "音声が出ない",
    ),
    "application_unresponsive": (
        "app bi do", "app bi treo", "phan mem bi do", "phan mem bi treo",
        "ung dung khong phan hoi", "excel bi do", "excel khong phan hoi",
        "chrome bi treo", "app not responding", "app is not responding",
        "application not responding", "chrome is not responding", "アプリ 応答なし",
        "アプリが応答しない", "ソフトが固ま",
    ),
}

_CUSTOMER_HYPOTHESIS_ALIASES: Mapping[str, tuple[str, ...]] = {
    "gpu_failure": (
        "gpu hong", "gpu bi hong", "gpu bi loi", "card man hinh hong", "card do hoa bi loi",
        "gpu broken", "gpu dead", "gpu is dead", "gpu may be failing",
        "graphics card broken", "graphics card is broken", "graphics card may be failing",
        "gpuが壊れ", "gpuが故障", "gpu 故障", "グラフィックボードが故障",
    ),
    "ram_failure": (
        "ram hong", "ram bi loi", "ram loi", "ram broken", "bad ram", "faulty ram",
        "ram is broken", "ramが壊れ", "ramが故障", "ram 故障",
    ),
    "storage_failure": (
        "ssd hong", "ssd sap hong", "ssd co ve sap hong", "o cung hong", "disk hong",
        "ssd broken", "disk failure", "ssd is broken", "ssd may be failing",
        "ssdが壊れ", "ssdが故障", "disk is failing", "ディスクが故障",
    ),
    "power_supply_failure": (
        "nguon hong", "nguon may tinh co the bi loi", "psu hong", "power supply broken",
        "power supply is broken", "bad psu", "psu is failing", "電源ユニットが壊れ",
        "電源ユニットが故障", "psu is broken",
    ),
    "router_failure": (
        "router hong", "router bi hong", "router chet", "router bi loi", "router broken",
        "router is broken", "router dead", "router is dead", "router may be failing",
        "ルーターが壊れ", "ルーターが故障", "router 故障",
    ),
    "dns_failure": (
        "dns chet", "dns hong", "dns bi hong", "dns bi loi", "dns server chet",
        "dns broken", "dns is broken", "dns server down", "dns server is down",
        "dnsが壊れ", "dnsが故障", "dnsサーバーが落ちている",
    ),
    "switch_failure": (
        "switch hong", "switch bi hong", "switch chet", "switch bi loi", "switch broken",
        "switch is broken", "switch dead", "switch is dead", "switch may be failing",
        "スイッチが壊れ", "スイッチが故障", "switch 故障",
    ),
    "camera_failure": (
        "camera hong", "camera bi hong", "camera chet", "camera bi loi", "camera broken",
        "camera is broken", "camera dead", "camera is dead", "camera may be failing",
        "カメラが壊れ", "カメラが故障", "camera 故障",
    ),
    "windows_update_regression": (
        "windows update lam hong", "update lam hong", "windows update broke",
        "update broke", "update caused", "windows update caused",
        "windows update co the gay ra", "windows updateで壊れ", "updateで壊れ",
    ),
    "malware_infection": (
        "bi virus", "chac bi virus", "virus roi", "nhiem malware", "bi nhiem malware",
        "infected by virus", "infected by malware", "malware infected", "malware infection",
        "ウイルスに感染", "マルウェアに感染",
    ),
    "overheating": (
        "do qua nong", "vi qua nong", "overheating", "too hot", "qua nong",
        "熱暴走", "過熱", "オーバーヒート",
    ),
}

# Explicit causal denials suppress only customer hypotheses. They never suppress an
# observed symptom such as "khong phan hoi" / "not responding".
_HYPOTHESIS_NEGATION_PREFIXES = (
    "khong phai",
    "khong nghi la",
    "khong nghi",
    "khong do",
    "not caused by",
    "probably not",
    "is not",
    "isn't",
    "not",
)
_HYPOTHESIS_NEGATION_SUFFIXES = (
    "ではない",
    "じゃない",
    "でない",
    "ではありません",
    "じゃありません",
)

# Routing terms intentionally describe evidence channels/subsystems, not conclusions.
_ROUTING_TERMS: Mapping[str, tuple[str, ...]] = {
    "perceived_unresponsiveness": ("performance", "cpu", "memory", "system event", "application event", "freeze"),
    "unexpected_restart": ("operating system", "system event", "reboot", "restart", "shutdown", "bsod"),
    "display_blackout": ("operating system", "system event", "display"),
    "blue_screen_observed": ("operating system", "system event", "bsod", "reboot"),
    "expected_network_access_unavailable": ("network adapter", "ip address", "gateway", "dns", "internet"),
    "hostname_resolution_unavailable": ("dns", "name resolution", "ip address", "gateway"),
    "vpn_internal_resource_unavailable": ("vpn route", "route", "gateway"),
    "audio_output_unavailable": ("audio device", "no sound", "speaker", "microphone"),
    "application_unresponsive": ("performance", "application event", "app crash"),
}

_HYPOTHESIS_ROUTING_TERMS: Mapping[str, tuple[str, ...]] = {
    "gpu_failure": ("display", "system event"),
    "ram_failure": ("memory", "system event", "bsod"),
    "storage_failure": ("storage", "system event"),
    "power_supply_failure": ("system event", "shutdown", "reboot"),
    "router_failure": ("network adapter", "ip address", "gateway", "route", "dns"),
    "dns_failure": ("dns", "name resolution", "ip address", "gateway"),
    "switch_failure": ("network adapter", "ip address", "gateway"),
    "camera_failure": ("reachability", "ping"),
    "windows_update_regression": ("operating system", "system event", "reboot"),
    "malware_infection": ("security event",),
    "overheating": ("system event", "shutdown"),
}


def _normalized_negation_terms() -> tuple[tuple[str, ...], tuple[str, ...]]:
    return (
        tuple(normalize_text(prefix) for prefix in _HYPOTHESIS_NEGATION_PREFIXES),
        tuple(normalize_text(suffix) for suffix in _HYPOTHESIS_NEGATION_SUFFIXES),
    )


def _match_is_denied(text: str, index: int, normalized_alias: str) -> bool:
    normalized_prefixes, normalized_suffixes = _normalized_negation_terms()
    before = text[max(0, index - 32):index].rstrip()
    after = text[index + len(normalized_alias):index + len(normalized_alias) + 24].lstrip()
    return any(before.endswith(prefix) for prefix in normalized_prefixes) or any(
        after.startswith(suffix) for suffix in normalized_suffixes
    )


def _alias_has_non_denied_match(text: str, alias: str) -> bool:
    normalized_alias = normalize_text(alias)
    start = 0
    while True:
        index = text.find(normalized_alias, start)
        if index < 0:
            return False
        if not _match_is_denied(text, index, normalized_alias):
            return True
        start = index + max(1, len(normalized_alias))


def _alias_has_denied_match(text: str, alias: str) -> bool:
    normalized_alias = normalize_text(alias)
    start = 0
    while True:
        index = text.find(normalized_alias, start)
        if index < 0:
            return False
        if _match_is_denied(text, index, normalized_alias):
            return True
        start = index + max(1, len(normalized_alias))


def _matched_ids(
    text: str,
    catalog: Mapping[str, tuple[str, ...]],
    *,
    suppress_explicit_denials: bool = False,
) -> tuple[str, ...]:
    matched: list[str] = []
    for concept, aliases in catalog.items():
        if suppress_explicit_denials:
            found = any(_alias_has_non_denied_match(text, alias) for alias in aliases)
        else:
            found = any(normalize_text(alias) in text for alias in aliases)
        if found:
            matched.append(concept)
    return tuple(sorted(matched))


def _matched_denied_ids(
    text: str,
    catalog: Mapping[str, tuple[str, ...]],
) -> tuple[str, ...]:
    return tuple(
        sorted(
            concept
            for concept, aliases in catalog.items()
            if any(_alias_has_denied_match(text, alias) for alias in aliases)
        )
    )


@dataclass(frozen=True)
class ComplaintSemantics:
    raw_text: str
    normalized_text: str
    canonical_symptoms: tuple[str, ...]
    customer_hypotheses: tuple[str, ...]
    denied_customer_hypotheses: tuple[str, ...] = ()
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
        customer_hypotheses=_matched_ids(
            normalized,
            _CUSTOMER_HYPOTHESIS_ALIASES,
            suppress_explicit_denials=True,
        ),
        denied_customer_hypotheses=_matched_denied_ids(
            normalized,
            _CUSTOMER_HYPOTHESIS_ALIASES,
        ),
    )
