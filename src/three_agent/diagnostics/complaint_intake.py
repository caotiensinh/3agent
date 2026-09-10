from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

DIAGNOSTIC_ROUTE_SCHEMA = "workspace-diagnostic-route/v1"
COMPLAINT_INTAKE_SCHEMA = "workspace-complaint-intake/v1"

_ROUTE_ID_RE = re.compile(r"^IT-\d{4}$")
_TOOL_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_DOMAIN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")

_SCOPE_VALUES = {
    "unknown",
    "one_user_or_device",
    "room_or_area",
    "site",
    "multiple_sites",
    "organization",
}


def normalize_text(value: str) -> str:
    """Normalize user wording for deterministic matching without claiming semantics."""
    normalized = unicodedata.normalize("NFKD", str(value).lower()).replace("đ", "d")
    folded = "".join(ch for ch in normalized if not unicodedata.combining(ch))
    return " ".join(folded.split())


def detect_language_hint(value: str) -> str:
    """Return a coarse UI-language hint only; this is not linguistic identification."""
    text = str(value)
    if re.search(r"[ぁ-ゟ゠-ヿ一-龯]", text):
        return "ja"
    if re.search(r"[ăâđêôơưĂÂĐÊÔƠƯà-ỹÀ-Ỹ]", text):
        return "vi"
    if re.search(r"[A-Za-z]", text):
        return "en"
    return "unknown"


@dataclass(frozen=True)
class DomainProfile:
    id: str
    label: str
    aliases: tuple[str, ...]
    entity_hints: tuple[str, ...] = ()

    def validate(self) -> "DomainProfile":
        if not _DOMAIN_ID_RE.fullmatch(self.id):
            raise ValueError(f"invalid domain id: {self.id!r}")
        if not self.label.strip():
            raise ValueError("domain label is required")
        if not self.aliases or any(not item.strip() for item in self.aliases):
            raise ValueError("domain aliases must be non-empty")
        return self


DOMAIN_PROFILES: tuple[DomainProfile, ...] = (
    DomainProfile("identity_auth", "Identity, authentication and MFA", ("cannot login", "can't login", "login fail", "password", "account locked", "mfa", "otp", "dang nhap", "quen mat khau", "tai khoan bi khoa", "ログイン", "パスワード"), ("login", "identity")),
    DomainProfile("windows_endpoint", "Windows boot, profile, update and crash", ("windows won't start", "windows not boot", "blue screen", "bsod", "reboot", "restart", "update failed", "profile error", "khong vao windows", "man hinh xanh", "khoi dong lai", "Windows 起動", "ブルースクリーン"), ("windows", "boot")),
    DomainProfile("endpoint_performance", "Endpoint performance and storage", ("computer slow", "pc slow", "machine slow", "everything slow", "hang", "freeze", "disk 100", "cpu 100", "may cham", "may bi cham", "bi do", "パソコン 遅い", "フリーズ"), ("slow", "performance")),
    DomainProfile("hardware_power", "Hardware, power, battery and thermal", ("won't turn on", "no power", "battery", "overheat", "fan loud", "ssd", "ram", "khong len nguon", "pin", "qua nong", "電源 入らない", "バッテリー"), ("power", "hardware")),
    DomainProfile("dock_display", "Dock, USB-C, display and peripherals", ("dock", "usb c", "usb-c", "second monitor", "external monitor", "no display", "screen not detected", "man hinh phu", "khong nhan man hinh", "ドック", "外部モニター"), ("display", "dock")),
    DomainProfile("printing", "Printing and scanning", ("cannot print", "can't print", "printer offline", "print queue", "scanner", "scan to email", "khong in duoc", "may in", "khong scan duoc", "印刷できない", "プリンター"), ("printer", "scanner")),
    DomainProfile("lan_wifi", "LAN, Wi-Fi, DHCP and DNS", ("internet broken", "no internet", "wifi not working", "wi-fi not working", "network slow", "no network", "dns", "dhcp", "mat mang", "mang cham", "wifi loi", "khong vao mang", "ネット 繋がらない", "Wi-Fi"), ("network", "wifi")),
    DomainProfile("vpn_remote", "VPN and remote access", ("vpn", "remote access", "remote desktop", "rdp", "cannot connect from home", "khong vao vpn", "khong remote duoc", "VPN 接続", "リモート"), ("vpn", "remote")),
    DomainProfile("mail_exchange", "Outlook, email and Exchange", ("outlook", "email not sending", "email not received", "mailbox", "mail slow", "khong gui mail", "khong nhan mail", "mail loi", "メール", "Outlook"), ("mail", "outlook")),
    DomainProfile("meeting_collaboration", "Teams, Zoom and conferencing", ("teams no sound", "zoom no sound", "teams camera", "meeting no audio", "screen share", "teams mic", "khong nghe teams", "teams khong co tieng", "会議 音", "Teams"), ("teams", "audio")),
    DomainProfile("cloud_files", "OneDrive, SharePoint and cloud files", ("onedrive", "sharepoint", "sync error", "sync conflict", "cloud file", "khong dong bo", "onedrive loi", "同期できない", "SharePoint"), ("onedrive", "sharepoint")),
    DomainProfile("file_share_gpo", "SMB, mapped drives, permissions and GPO", ("shared folder", "file share", "mapped drive", "network drive", "access denied", "gpo", "group policy", "thu muc chia se", "o mang", "khong vao folder", "共有フォルダ", "ネットワークドライブ"), ("share", "permission")),
    DomainProfile("business_apps", "Software, browser and business applications", ("app not working", "software error", "browser error", "activation", "install failed", "phan mem loi", "khong mo duoc phan mem", "アプリ エラー", "ソフト 起動しない"), ("application", "browser")),
    DomainProfile("security", "Security, phishing, EDR and policy", ("phishing", "virus", "malware", "edr", "antivirus", "blocked by security", "suspicious connection", "unknown ip connection", "tu ket noi den ip la", "ket noi den ip la", "bi chan", "bao mat", "virus", "フィッシング", "ウイルス"), ("security", "malware")),
    DomainProfile("mobile_mdm", "Mobile, MDM and BYOD", ("iphone work mail", "android work mail", "mdm", "company portal", "mobile enrollment", "dien thoai cong ty", "iphone khong vao mail", "モバイル", "MDM"), ("mobile", "mdm")),
    DomainProfile("server_backup", "Server, virtualization, storage and backup", ("server down", "server slow", "vm down", "backup failed", "restore failed", "storage full", "server loi", "backup loi", "サーバー", "バックアップ"), ("server", "backup")),
    DomainProfile("voip", "VoIP, phones and headsets", ("phone no audio", "one way audio", "softphone", "voip", "headset", "call drop", "dien thoai khong co tieng", "電話 音", "VoIP"), ("voip", "phone")),
    DomainProfile("service_ops", "User lifecycle and service operations", ("new employee", "new starter", "offboarding", "leaver", "access request", "permission request", "nhan vien moi", "cap quyen", "新入社員", "アカウント作成"), ("lifecycle", "access")),
    DomainProfile("saas", "Cloud, SaaS, licensing and service health", ("saas down", "cloud service down", "license missing", "license error", "subscription", "dich vu cloud loi", "thieu license", "SaaS", "ライセンス"), ("saas", "license")),
    DomainProfile("network_infra", "Switch, VLAN, PoE and physical network", ("switch", "vlan", "poe", "port down", "uplink", "crc", "network closet", "cong switch", "mat poe", "スイッチ", "PoE"), ("switch", "poe")),
    DomainProfile("intune_autopilot", "Intune and Autopilot provisioning", ("intune", "autopilot", "enrollment", "esp stuck", "company portal enrollment", "dang ky intune", "Intune", "Autopilot"), ("intune", "enrollment")),
    DomainProfile("macos", "macOS, Jamf and FileVault", ("macbook", "macos", "jamf", "filevault", "secure token", "mac khong dang nhap", "Mac", "FileVault"), ("mac", "filevault")),
    DomainProfile("facilities", "UPS, power and server-room environment", ("ups", "server room hot", "cooling", "power outage", "pdu", "temperature alarm", "mat dien phong server", "ups loi", "UPS", "サーバールーム 温度"), ("ups", "power")),
    DomainProfile("room_av", "Meeting-room A/V and wireless presentation", ("projector", "meeting room screen", "hdmi", "wireless display", "miracast", "room camera", "may chieu", "phong hop", "会議室", "プロジェクター"), ("display", "meeting_room")),
    DomainProfile("auth_vdi", "FIDO2, smart cards and VDI", ("security key", "fido2", "smart card", "citrix", "vdi", "virtual desktop", "khoa bao mat", "Citrix", "セキュリティキー"), ("security_key", "vdi")),
    DomainProfile("warehouse", "Barcode, label and specialized peripherals", ("barcode", "scanner gun", "zebra", "label printer", "com port", "serial device", "may quet ma vach", "may in tem", "バーコード", "ラベルプリンター"), ("barcode", "label_printer")),
    DomainProfile("ad_core", "Active Directory, DNS, DHCP and Group Policy core", ("active directory", "domain controller", "ad replication", "sysvol", "kerberos", "group policy", "domain login", "ad loi", "domain controller", "Active Directory", "ドメインコントローラー"), ("active_directory", "dns")),
    DomainProfile("office_productivity", "Microsoft Office desktop productivity", ("excel", "word", "powerpoint", "onenote", "office crash", "excel slow", "excel not responding", "excel bi do", "word loi", "Excel", "Word"), ("office", "excel")),
    DomainProfile("erp_database", "ERP, SQL, database and ODBC", ("erp", "sql", "database", "odbc", "dsn", "query timeout", "erp cham", "database loi", "ERP", "SQL"), ("database", "erp")),
    DomainProfile("cctv_access", "CCTV, NVR/VMS and access control", ("camera offline", "camera disappeared", "nvr", "vms", "rtsp", "access control", "badge", "camera mat", "camera khong xem duoc", "カメラ オフライン", "NVR"), ("camera", "nvr")),
    DomainProfile("pki_smtp", "Certificates, PKI, TLS and SMTP relay", ("certificate expired", "tls error", "smtp relay", "scan to email", "cert error", "chung chi het han", "smtp loi", "証明書", "SMTP"), ("certificate", "smtp")),
    DomainProfile("wan_remote", "Remote sites, WAN, ISP and SD-WAN", ("branch office offline", "site offline", "wan down", "isp", "sd-wan", "remote site slow", "chi nhanh mat mang", "wan loi", "拠点 ネットワーク", "WAN"), ("wan", "site")),
)
DOMAIN_PROFILE_BY_ID = {profile.id: profile.validate() for profile in DOMAIN_PROFILES}


_ENTITY_ALIASES: Mapping[str, tuple[str, ...]] = {
    "login": ("login", "log in", "dang nhap", "ログイン"),
    "identity": ("account", "password", "mfa", "otp", "tai khoan", "mat khau", "アカウント"),
    "windows": ("windows", "bsod", "blue screen"),
    "boot": ("boot", "startup", "khoi dong", "起動"),
    "slow": ("slow", "cham", "遅い"),
    "performance": ("freeze", "hang", "100%", "lag"),
    "power": ("power", "battery", "ups", "nguon", "pin", "電源"),
    "hardware": ("ram", "ssd", "fan", "hardware"),
    "display": ("monitor", "screen", "display", "man hinh", "モニター"),
    "dock": ("dock", "usb-c", "usb c"),
    "printer": ("printer", "print", "may in", "印刷", "プリンター"),
    "scanner": ("scanner", "scan", "may scan", "スキャナー"),
    "network": ("network", "internet", "mang", "ネット", "ネットワーク"),
    "wifi": ("wifi", "wi-fi", "wireless", "無線"),
    "vpn": ("vpn",),
    "remote": ("remote", "rdp", "リモート"),
    "mail": ("mail", "email", "メール"),
    "outlook": ("outlook",),
    "teams": ("teams", "zoom"),
    "audio": ("sound", "audio", "mic", "microphone", "tieng", "音", "マイク"),
    "onedrive": ("onedrive",),
    "sharepoint": ("sharepoint",),
    "share": ("shared folder", "file share", "network drive", "mapped drive", "thu muc chia se", "共有フォルダ"),
    "permission": ("access denied", "permission", "quyen", "アクセス拒否"),
    "application": ("app", "application", "software", "phan mem", "アプリ"),
    "browser": ("browser", "chrome", "edge", "ブラウザ"),
    "security": ("security", "edr", "antivirus", "bao mat", "suspicious connection", "unknown ip connection", "tu ket noi den ip la", "ket noi den ip la", "セキュリティ"),
    "malware": ("virus", "malware", "phishing", "ウイルス"),
    "mobile": ("iphone", "android", "mobile", "dien thoai", "スマホ"),
    "mdm": ("mdm", "company portal", "intune"),
    "server": ("server", "vm", "サーバー"),
    "backup": ("backup", "restore", "バックアップ"),
    "voip": ("voip", "softphone"),
    "phone": ("phone", "headset", "call", "dien thoai", "電話"),
    "lifecycle": ("new employee", "offboarding", "leaver", "nhan vien moi", "新入社員"),
    "access": ("access request", "permission request", "cap quyen"),
    "saas": ("saas", "cloud service", "cloud"),
    "license": ("license", "licence", "subscription", "ライセンス"),
    "switch": ("switch", "vlan", "uplink", "スイッチ"),
    "poe": ("poe",),
    "intune": ("intune", "autopilot"),
    "enrollment": ("enrollment", "enroll", "esp"),
    "mac": ("mac", "macbook", "macos"),
    "filevault": ("filevault", "secure token"),
    "ups": ("ups", "pdu", "cooling", "server room"),
    "meeting_room": ("meeting room", "conference room", "phong hop", "会議室"),
    "security_key": ("fido2", "security key", "smart card", "セキュリティキー"),
    "vdi": ("vdi", "citrix", "virtual desktop"),
    "barcode": ("barcode", "scanner gun", "ma vach", "バーコード"),
    "label_printer": ("zebra", "label printer", "may in tem", "ラベルプリンター"),
    "active_directory": ("active directory", "domain controller", "sysvol", "kerberos"),
    "dns": ("dns", "dhcp", "group policy", "gpo"),
    "office": ("microsoft office", "office", "word", "powerpoint", "onenote"),
    "excel": ("excel",),
    "database": ("database", "sql", "odbc", "dsn"),
    "erp": ("erp",),
    "camera": ("camera", "cctv", "rtsp", "カメラ"),
    "nvr": ("nvr", "vms",),
    "certificate": ("certificate", "cert", "tls", "pki", "証明書"),
    "smtp": ("smtp", "relay", "scan to email"),
    "wan": ("wan", "isp", "sd-wan"),
    "site": ("branch office", "remote site", "chi nhanh", "拠点"),
}


def extract_entities(value: str) -> tuple[str, ...]:
    text = normalize_text(value)
    found: list[str] = []
    for entity, aliases in _ENTITY_ALIASES.items():
        if any(normalize_text(alias) in text for alias in aliases):
            found.append(entity)
    return tuple(sorted(set(found)))


def extract_explicit_scope_facts(value: str) -> Mapping[str, Any]:
    """Extract only explicit blast-radius statements so the planner does not re-ask answered scope facts."""
    text = normalize_text(value)

    def contains_any(phrases: tuple[str, ...]) -> bool:
        return any(normalize_text(phrase) in text for phrase in phrases)

    if contains_any(
        (
            "ca cong ty",
            "toan cong ty",
            "ca to chuc",
            "toan to chuc",
            "whole company",
            "entire company",
            "whole organization",
            "entire organization",
            "全社",
            "会社全体",
            "組織全体",
        )
    ):
        return {"scope.others_affected": True, "scope.organization_affected": True}
    if contains_any(
        (
            "hai chi nhanh",
            "2 chi nhanh",
            "nhieu chi nhanh",
            "cac chi nhanh",
            "two branches",
            "multiple branches",
            "multiple sites",
            "several sites",
            "複数拠点",
            "2拠点",
        )
    ):
        return {"scope.others_affected": True, "scope.multiple_sites": True}
    if contains_any(
        (
            "ca van phong",
            "toan van phong",
            "ca chi nhanh",
            "toan chi nhanh",
            "whole office",
            "entire office",
            "whole site",
            "entire site",
            "オフィス全体",
            "拠点全体",
        )
    ):
        return {"scope.others_affected": True, "scope.site_affected": True}
    if contains_any(
        (
            "ca phong",
            "toan phong",
            "ca tang",
            "toan tang",
            "ca khu vuc",
            "toan khu vuc",
            "moi nguoi trong phong",
            "tat ca trong phong",
            "whole room",
            "entire room",
            "whole floor",
            "everyone in the room",
            "部屋全体",
            "フロア全体",
            "同じ部屋の全員",
        )
    ):
        return {"scope.others_affected": True, "scope.same_area": True}
    if contains_any(
        (
            "chi may toi",
            "chi may nay",
            "chi minh toi",
            "chi toi bi",
            "moi may toi",
            "only my pc",
            "only my computer",
            "only me",
            "just my pc",
            "自分だけ",
            "このpcだけ",
            "この端末だけ",
        )
    ):
        return {"scope.others_affected": False}
    return {}


def extract_explicit_context_facts(value: str) -> Mapping[str, Any]:
    """Preserve explicit context already stated by the user without inferring a cause."""
    raw = str(value).strip()
    text = normalize_text(raw)
    change_markers = (
        "reboot",
        "restart",
        "update",
        "cap nhat",
        "doi mat khau",
        "password change",
        "chuyen cho",
        "moved desk",
        "thay day",
        "cable change",
        "thay thiet bi",
        "hardware change",
        "再起動",
        "更新",
        "パスワード変更",
        "ケーブル交換",
        "機器交換",
    )
    temporal_markers = (
        "sau khi",
        "ngay sau",
        "sau luc",
        "after ",
        "right after",
        "since ",
        "直後",
        "後に",
        "以降",
    )
    if any(normalize_text(marker) in text for marker in temporal_markers) and any(
        normalize_text(marker) in text for marker in change_markers
    ):
        return {"timeline.recent_change": raw}
    return {}


@dataclass(frozen=True)
class DomainCandidate:
    domain_id: str
    score: int
    matched_aliases: tuple[str, ...]
    matched_entities: tuple[str, ...]


@dataclass(frozen=True)
class ComplaintSession:
    raw_text: str
    normalized_text: str
    language_hint: str
    entities: tuple[str, ...]
    candidates: tuple[DomainCandidate, ...]
    facts: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = COMPLAINT_INTAKE_SCHEMA


@dataclass(frozen=True)
class DiagnosticRoute:
    route_id: str
    domain_id: str
    symptom_aliases: tuple[str, ...]
    required_facts: tuple[str, ...]
    clarification_question_ids: tuple[str, ...]
    evidence_tool_ids: tuple[str, ...]
    stop_conditions: tuple[str, ...]
    physical_verification_possible: bool = False
    remediation_tool_ids: tuple[str, ...] = ()
    schema_version: str = DIAGNOSTIC_ROUTE_SCHEMA

    def validate(self) -> "DiagnosticRoute":
        if self.schema_version != DIAGNOSTIC_ROUTE_SCHEMA:
            raise ValueError(f"unsupported route schema: {self.schema_version}")
        if not _ROUTE_ID_RE.fullmatch(self.route_id):
            raise ValueError(f"invalid route id: {self.route_id!r}")
        if self.domain_id not in DOMAIN_PROFILE_BY_ID:
            raise ValueError(f"unknown domain: {self.domain_id}")
        if not self.symptom_aliases or any(not item.strip() for item in self.symptom_aliases):
            raise ValueError("symptom aliases are required")
        if len(set(self.symptom_aliases)) != len(self.symptom_aliases):
            raise ValueError("symptom aliases must be unique")
        for field_name, items in (
            ("required_facts", self.required_facts),
            ("clarification_question_ids", self.clarification_question_ids),
            ("evidence_tool_ids", self.evidence_tool_ids),
            ("stop_conditions", self.stop_conditions),
            ("remediation_tool_ids", self.remediation_tool_ids),
        ):
            if len(set(items)) != len(items):
                raise ValueError(f"{field_name} must not contain duplicates")
            if any(not str(item).strip() for item in items):
                raise ValueError(f"{field_name} must not contain blank values")
        for tool_id in self.evidence_tool_ids:
            if not _TOOL_ID_RE.fullmatch(tool_id):
                raise ValueError(f"invalid evidence tool id: {tool_id!r}")
            if tool_id.startswith("remediate."):
                raise ValueError("remediation tools cannot be listed as diagnostic evidence tools")
        for tool_id in self.remediation_tool_ids:
            if not _TOOL_ID_RE.fullmatch(tool_id):
                raise ValueError(f"invalid remediation tool id: {tool_id!r}")
        if type(self.physical_verification_possible) is not bool:
            raise ValueError("physical_verification_possible must be boolean")
        return self


def rank_domain_candidates(value: str, *, max_candidates: int = 5) -> tuple[DomainCandidate, ...]:
    if not 1 <= int(max_candidates) <= len(DOMAIN_PROFILES):
        raise ValueError("max_candidates is out of bounds")
    text = normalize_text(value)
    entities = set(extract_entities(value))
    scored: list[DomainCandidate] = []
    for profile in DOMAIN_PROFILES:
        matched_aliases: list[str] = []
        score = 0
        for alias in profile.aliases:
            normalized_alias = normalize_text(alias)
            if normalized_alias and normalized_alias in text:
                matched_aliases.append(alias)
                score += 2 + min(4, len(normalized_alias.split()))
        matched_entities = tuple(sorted(entities.intersection(profile.entity_hints)))
        score += len(matched_entities) * 2
        if score:
            scored.append(
                DomainCandidate(
                    domain_id=profile.id,
                    score=score,
                    matched_aliases=tuple(matched_aliases),
                    matched_entities=matched_entities,
                )
            )
    scored.sort(key=lambda item: (-item.score, item.domain_id))
    return tuple(scored[: int(max_candidates)])


def build_complaint_session(value: str, *, max_candidates: int = 5) -> ComplaintSession:
    raw = str(value).strip()
    if not raw:
        raise ValueError("complaint text is required")
    facts = dict(extract_explicit_scope_facts(raw))
    facts.update(extract_explicit_context_facts(raw))
    return ComplaintSession(
        raw_text=raw,
        normalized_text=normalize_text(raw),
        language_hint=detect_language_hint(raw),
        entities=extract_entities(raw),
        candidates=rank_domain_candidates(raw, max_candidates=max_candidates),
        facts=facts,
    )


@dataclass(frozen=True)
class ScopeAssessment:
    scope: str
    confidence: float
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.scope not in _SCOPE_VALUES:
            raise ValueError(f"unknown scope: {self.scope}")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("confidence must be within 0..1")


def classify_scope(facts: Mapping[str, Any]) -> ScopeAssessment:
    organization_affected = facts.get("scope.organization_affected")
    multiple_sites = facts.get("scope.multiple_sites")
    site_affected = facts.get("scope.site_affected")
    same_area = facts.get("scope.same_area")
    others_affected = facts.get("scope.others_affected")
    affected_count = facts.get("scope.affected_count")

    if organization_affected is True:
        return ScopeAssessment("organization", 0.98, ("ORGANIZATION_WIDE_REPORTED",))
    if multiple_sites is True:
        return ScopeAssessment("multiple_sites", 0.95, ("MULTIPLE_SITES_REPORTED",))
    if site_affected is True:
        return ScopeAssessment("site", 0.9, ("SITE_WIDE_REPORTED",))
    if same_area is True and others_affected is True:
        return ScopeAssessment("room_or_area", 0.85, ("MULTIPLE_USERS_SAME_AREA",))
    if others_affected is False:
        return ScopeAssessment("one_user_or_device", 0.85, ("NO_OTHER_USERS_REPORTED",))
    if isinstance(affected_count, int) and not isinstance(affected_count, bool):
        if affected_count <= 1:
            return ScopeAssessment("one_user_or_device", 0.8, ("AFFECTED_COUNT_ONE",))
        if affected_count >= 2:
            return ScopeAssessment("room_or_area", 0.55, ("MULTIPLE_AFFECTED_SCOPE_NOT_LOCALIZED",))
    return ScopeAssessment("unknown", 0.0, ("SCOPE_EVIDENCE_MISSING",))


@dataclass(frozen=True)
class ClarificationQuestion:
    id: str
    fact_key: str
    answer_kind: str
    priority: int
    prompts: Mapping[str, str]
    applicable_domains: tuple[str, ...] = ()

    def prompt(self, language_hint: str) -> str:
        return self.prompts.get(language_hint) or self.prompts.get("en") or next(iter(self.prompts.values()))


QUESTION_CATALOG: tuple[ClarificationQuestion, ...] = (
    ClarificationQuestion(
        "scope.others_affected",
        "scope.others_affected",
        "yes_no",
        100,
        {
            "vi": "Chỉ bạn bị hay những người khác cũng đang gặp cùng lỗi này?",
            "ja": "この問題はあなたの端末だけですか、それとも周りの人も同じ問題が出ていますか？",
            "en": "Is this only affecting you, or are other people seeing the same problem?",
        },
    ),
    ClarificationQuestion(
        "context.what_is_affected",
        "context.affected_object",
        "free_text",
        96,
        {
            "vi": "Cụ thể cái gì đang không hoạt động: máy tính, mạng, máy in, camera hay một chương trình nào đó?",
            "ja": "具体的に動かないのは、PC、ネットワーク、プリンター、カメラ、それとも特定のアプリですか？",
            "en": "What exactly is not working: the computer, network, printer, camera, or a specific application?",
        },
    ),
    ClarificationQuestion(
        "scope.same_area",
        "scope.same_area",
        "yes_no",
        90,
        {
            "vi": "Những người bị lỗi có ở cùng phòng hoặc cùng khu vực với bạn không?",
            "ja": "同じ問題の人は、同じ部屋や同じエリアにいますか？",
            "en": "Are the affected people in the same room or area?",
        },
    ),
    ClarificationQuestion(
        "context.location",
        "context.location",
        "free_text",
        80,
        {
            "vi": "Bạn đang ở văn phòng, ở nhà hay một chi nhánh khác?",
            "ja": "今いる場所はオフィス、自宅、それとも別拠点ですか？",
            "en": "Are you at the office, at home, or at another site?",
        },
        ("vpn_remote", "wan_remote", "lan_wifi"),
    ),
    ClarificationQuestion(
        "timeline.last_known_good",
        "timeline.last_known_good",
        "free_text",
        76,
        {
            "vi": "Lần gần nhất nó hoạt động bình thường là khi nào?",
            "ja": "最後に正常に動いていたのはいつですか？",
            "en": "When was the last time it worked normally?",
        },
    ),
    ClarificationQuestion(
        "timeline.recent_change",
        "timeline.recent_change",
        "free_text",
        74,
        {
            "vi": "Ngay trước khi lỗi xuất hiện có update, restart, đổi mật khẩu, chuyển chỗ hoặc thay dây/thiết bị gì không?",
            "ja": "問題が出る直前に、更新、再起動、パスワード変更、移動、ケーブルや機器の交換はありましたか？",
            "en": "Just before this started, was there an update, restart, password change, move, cable change, or hardware change?",
        },
    ),
    ClarificationQuestion(
        "pattern.intermittent",
        "pattern.intermittent",
        "yes_no",
        68,
        {
            "vi": "Lỗi này xảy ra liên tục hay lúc được lúc không?",
            "ja": "この問題は常に起きますか、それとも時々だけですか？",
            "en": "Does the problem happen all the time, or only intermittently?",
        },
    ),
    ClarificationQuestion(
        "alternate.other_device",
        "alternate.other_device_works",
        "yes_no",
        64,
        {
            "vi": "Nếu dùng một máy hoặc điện thoại khác ở cùng chỗ thì có hoạt động bình thường không?",
            "ja": "同じ場所で別のPCやスマートフォンを使うと正常に動きますか？",
            "en": "Does another computer or phone work normally from the same location?",
        },
        ("lan_wifi", "vpn_remote", "saas", "mail_exchange", "cloud_files", "wan_remote"),
    ),
    ClarificationQuestion(
        "physical.power_link",
        "physical.power_link_visible",
        "yes_no",
        62,
        {
            "vi": "Thiết bị có đang sáng đèn nguồn hoặc đèn mạng như bình thường không? Chưa cần rút dây hay reset.",
            "ja": "機器の電源ランプやネットワークランプは通常どおり点灯していますか？まだケーブルを抜いたりリセットしたりしないでください。",
            "en": "Are the device power or network-link lights on as usual? Do not unplug or reset anything yet.",
        },
        ("hardware_power", "network_infra", "cctv_access", "facilities", "warehouse", "room_av"),
    ),
    ClarificationQuestion(
        "identity.other_device_login",
        "identity.other_device_login_works",
        "yes_no",
        62,
        {
            "vi": "Bạn thử cùng tài khoản đó trên một máy khác thì có đăng nhập được không?",
            "ja": "同じアカウントで別の端末にログインできますか？",
            "en": "Can you sign in with the same account on another device?",
        },
        ("identity_auth", "ad_core", "saas"),
    ),
    ClarificationQuestion(
        "error.exact_message",
        "error.exact_message",
        "free_text",
        58,
        {
            "vi": "Nếu có thông báo lỗi, bạn hãy gửi nguyên văn nội dung hoặc ảnh màn hình của nó.",
            "ja": "エラーメッセージがある場合は、その全文または画面の画像を送ってください。",
            "en": "If there is an error message, please send the exact text or a screenshot of it.",
        },
    ),
)
QUESTION_BY_ID = {question.id: question for question in QUESTION_CATALOG}


def next_best_questions(
    session: ComplaintSession,
    *,
    facts: Mapping[str, Any] | None = None,
    max_questions: int = 3,
) -> tuple[ClarificationQuestion, ...]:
    if not 1 <= int(max_questions) <= 3:
        raise ValueError("max_questions must be within 1..3")
    known = dict(session.facts)
    if facts:
        known.update(facts)
    top_domains = {candidate.domain_id for candidate in session.candidates[:3]}
    entities_known = bool(session.entities or known.get("context.affected_object"))

    ranked: list[tuple[int, str, ClarificationQuestion]] = []
    for question in QUESTION_CATALOG:
        if question.fact_key in known:
            continue
        if question.id == "context.what_is_affected" and entities_known:
            continue
        score = question.priority
        if question.applicable_domains:
            overlap = top_domains.intersection(question.applicable_domains)
            if not overlap:
                continue
            score += 20 * len(overlap)
        if question.id == "scope.same_area" and known.get("scope.others_affected") is not True:
            continue
        if question.id == "scope.same_area" and (
            known.get("scope.organization_affected") is True
            or known.get("scope.site_affected") is True
            or known.get("scope.multiple_sites") is True
        ):
            continue
        if question.id == "context.what_is_affected" and not top_domains and not entities_known:
            score += 40
        if question.id == "scope.others_affected" and top_domains:
            score += 1
        ranked.append((-score, question.id, question))
    ranked.sort(key=lambda item: (item[0], item[1]))
    return tuple(item[2] for item in ranked[: int(max_questions)])


@dataclass(frozen=True)
class NormalizedAnswer:
    question_id: str
    fact_key: str
    understood: bool
    value: Any
    raw_text: str


_TRUE_WORDS = {"yes", "y", "true", "co", "dung", "có", "はい", "そうです"}
_FALSE_WORDS = {"no", "n", "false", "khong", "không", "いいえ", "違います"}


def normalize_answer(question_id: str, answer: Any) -> NormalizedAnswer:
    try:
        question = QUESTION_BY_ID[question_id]
    except KeyError as exc:
        raise ValueError(f"unknown clarification question: {question_id}") from exc
    raw = str(answer).strip()
    if not raw:
        return NormalizedAnswer(question.id, question.fact_key, False, None, raw)
    if question.answer_kind == "yes_no":
        folded = normalize_text(raw)
        true_words = {normalize_text(item) for item in _TRUE_WORDS}
        false_words = {normalize_text(item) for item in _FALSE_WORDS}
        if folded in true_words:
            return NormalizedAnswer(question.id, question.fact_key, True, True, raw)
        if folded in false_words:
            return NormalizedAnswer(question.id, question.fact_key, True, False, raw)
        return NormalizedAnswer(question.id, question.fact_key, False, None, raw)
    return NormalizedAnswer(question.id, question.fact_key, True, raw, raw)


@dataclass(frozen=True)
class HypothesisEvidence:
    hypothesis_id: str
    prior_weight: float = 0.0
    supporting_evidence: tuple[str, ...] = ()
    contradicting_evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class RankedHypothesis:
    hypothesis_id: str
    score: float
    supporting_evidence: tuple[str, ...]
    contradicting_evidence: tuple[str, ...]


def rank_hypotheses(hypotheses: Iterable[HypothesisEvidence]) -> tuple[RankedHypothesis, ...]:
    ranked: list[RankedHypothesis] = []
    for item in hypotheses:
        if not item.hypothesis_id.strip():
            raise ValueError("hypothesis id is required")
        score = float(item.prior_weight) + (2.0 * len(item.supporting_evidence)) - (3.0 * len(item.contradicting_evidence))
        ranked.append(
            RankedHypothesis(
                hypothesis_id=item.hypothesis_id,
                score=score,
                supporting_evidence=item.supporting_evidence,
                contradicting_evidence=item.contradicting_evidence,
            )
        )
    ranked.sort(key=lambda item: (-item.score, item.hypothesis_id))
    return tuple(ranked)


@dataclass(frozen=True)
class PhysicalBoundaryAssessment:
    physical_evidence_required: bool
    reason_code: str


def evaluate_physical_boundary(
    *,
    telemetry_available: bool,
    direct_power_evidence: bool,
    physical_fault_plausible: bool,
) -> PhysicalBoundaryAssessment:
    for value in (telemetry_available, direct_power_evidence, physical_fault_plausible):
        if type(value) is not bool:
            raise ValueError("physical-boundary inputs must be boolean")
    if physical_fault_plausible and not direct_power_evidence and not telemetry_available:
        return PhysicalBoundaryAssessment(True, "PHYSICAL_EVIDENCE_REQUIRED")
    if physical_fault_plausible and not direct_power_evidence:
        return PhysicalBoundaryAssessment(True, "PHYSICAL_STATE_NOT_PROVEN")
    return PhysicalBoundaryAssessment(False, "PHYSICAL_BOUNDARY_SATISFIED")


@dataclass(frozen=True)
class EvidenceSufficiency:
    sufficient: bool
    reason_codes: tuple[str, ...]


def evaluate_evidence_sufficiency(
    *,
    candidate_count: int,
    scope: ScopeAssessment,
    machine_evidence_count: int,
    unresolved_required_facts: int = 0,
    physical_boundary_pending: bool = False,
    confidence: float = 0.0,
) -> EvidenceSufficiency:
    if candidate_count < 0 or machine_evidence_count < 0 or unresolved_required_facts < 0:
        raise ValueError("evidence counters must be non-negative")
    if not 0.0 <= float(confidence) <= 1.0:
        raise ValueError("confidence must be within 0..1")
    reasons: list[str] = []
    if physical_boundary_pending:
        reasons.append("PHYSICAL_EVIDENCE_REQUIRED")
    if candidate_count != 1:
        reasons.append("AMBIGUOUS_ROUTE")
    if scope.scope == "unknown":
        reasons.append("SCOPE_UNKNOWN")
    if machine_evidence_count < 1:
        reasons.append("MACHINE_EVIDENCE_REQUIRED")
    if unresolved_required_facts:
        reasons.append("REQUIRED_FACTS_MISSING")
    if float(confidence) < 0.6:
        reasons.append("LOW_CONFIDENCE")
    return EvidenceSufficiency(not reasons, tuple(reasons) if reasons else ("EVIDENCE_SUFFICIENT",))


__all__ = [
    "COMPLAINT_INTAKE_SCHEMA",
    "DIAGNOSTIC_ROUTE_SCHEMA",
    "DOMAIN_PROFILES",
    "DOMAIN_PROFILE_BY_ID",
    "QUESTION_CATALOG",
    "QUESTION_BY_ID",
    "ClarificationQuestion",
    "ComplaintSession",
    "DiagnosticRoute",
    "DomainCandidate",
    "DomainProfile",
    "EvidenceSufficiency",
    "HypothesisEvidence",
    "NormalizedAnswer",
    "PhysicalBoundaryAssessment",
    "RankedHypothesis",
    "ScopeAssessment",
    "build_complaint_session",
    "classify_scope",
    "detect_language_hint",
    "evaluate_evidence_sufficiency",
    "evaluate_physical_boundary",
    "extract_entities",
    "extract_explicit_context_facts",
    "extract_explicit_scope_facts",
    "next_best_questions",
    "normalize_answer",
    "normalize_text",
    "rank_domain_candidates",
    "rank_hypotheses",
]
