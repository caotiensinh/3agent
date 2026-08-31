from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import signal
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from .contracts import AssetInventoryRecord, MonitoringContractError, sha256_fingerprint
from .runtime_config import MonitoringRuntimeConfig

CAPTURE_SCHEMA = "workspace-security-monitoring/incident-capture-v1"
APPROVAL_SCHEMA = "workspace-security-monitoring/incident-capture-approval-v1"
RECEIPT_SCHEMA = "workspace-security-monitoring/incident-capture-receipt-v1"
CAPTURE_CONFIRMATION = "AUTHORIZE_PCAP"
_INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,31}$", re.ASCII)
_PURPOSE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+/-]{2,95}$", re.ASCII)
_REQUEST_KEYS = {
    "interface",
    "asset_ids",
    "ports",
    "duration_seconds",
    "max_bytes",
    "retention_ttl_seconds",
    "purpose",
}


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _parse_iso(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitoringContractError(f"{field} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise MonitoringContractError(f"{field} must include timezone")
    return parsed.astimezone(timezone.utc)


def _bool_env(raw: str | None, field: str) -> bool:
    value = str(raw or "0").strip().lower()
    if value in {"0", "false", "no", "off", ""}:
        return False
    if value in {"1", "true", "yes", "on"}:
        return True
    raise MonitoringContractError(f"{field} must be an explicit boolean")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _safe_root(path: Path, field: str, *, require_existing: bool) -> Path:
    value = Path(path)
    if not value.is_absolute() or value.is_symlink():
        raise MonitoringContractError(f"{field} must be an absolute non-symlink path")
    if require_existing and (not value.is_dir() or value.is_symlink()):
        raise MonitoringContractError(f"{field} must already exist as a safe directory")
    return value


@dataclass(frozen=True)
class IncidentCapturePolicy:
    enabled: bool = False
    approved_interfaces: tuple[str, ...] = ()
    approval_root: Path = Path("/var/lib/workspace-monitor/pcap-approvals")
    capture_root: Path = Path("/var/lib/workspace-monitor/pcap")
    tcpdump_path: Path = Path("/usr/bin/tcpdump")
    max_duration_seconds: int = 300
    max_capture_bytes: int = 64 * 1024 * 1024
    max_retention_ttl_seconds: int = 24 * 60 * 60
    approval_valid_seconds: int = 10 * 60
    max_targets: int = 8
    max_ports: int = 16
    snaplen: int = 2048

    @classmethod
    def from_environment(cls, env: Mapping[str, str] | None = None) -> "IncidentCapturePolicy":
        source = os.environ if env is None else env
        interfaces = tuple(
            part.strip()
            for part in str(source.get("WORKSPACE_SECURITY_PCAP_INTERFACES") or "").split(",")
            if part.strip()
        )
        policy = cls(
            enabled=_bool_env(source.get("WORKSPACE_SECURITY_PCAP_ENABLED"), "WORKSPACE_SECURITY_PCAP_ENABLED"),
            approved_interfaces=interfaces,
            approval_root=Path(
                source.get("WORKSPACE_SECURITY_PCAP_APPROVAL_ROOT")
                or "/var/lib/workspace-monitor/pcap-approvals"
            ),
            capture_root=Path(
                source.get("WORKSPACE_SECURITY_PCAP_ROOT")
                or "/var/lib/workspace-monitor/pcap"
            ),
            tcpdump_path=Path(source.get("WORKSPACE_SECURITY_TCPDUMP_PATH") or "/usr/bin/tcpdump"),
        )
        return policy.validate()

    def validate(self) -> "IncidentCapturePolicy":
        interfaces = tuple(dict.fromkeys(self.approved_interfaces))
        if any(not _INTERFACE_RE.fullmatch(value) for value in interfaces):
            raise MonitoringContractError("capture interface allowlist contains invalid name")
        object.__setattr__(self, "approved_interfaces", interfaces)
        if not 1 <= self.max_duration_seconds <= 900:
            raise MonitoringContractError("capture max duration must be within 1..900 seconds")
        if not 256 * 1024 <= self.max_capture_bytes <= 256 * 1024 * 1024:
            raise MonitoringContractError("capture max bytes must be within 256KiB..256MiB")
        if not 60 <= self.max_retention_ttl_seconds <= 7 * 24 * 60 * 60:
            raise MonitoringContractError("capture max retention TTL must be within 60s..7d")
        if not 60 <= self.approval_valid_seconds <= 3600:
            raise MonitoringContractError("capture approval validity must be within 60..3600 seconds")
        if not 1 <= self.max_targets <= 32 or not 0 <= self.max_ports <= 64:
            raise MonitoringContractError("capture target/port bounds are invalid")
        if not 96 <= self.snaplen <= 8192:
            raise MonitoringContractError("capture snaplen must be within 96..8192 bytes")
        if self.enabled:
            if not interfaces:
                raise MonitoringContractError("enabled incident capture requires approved interfaces")
            _safe_root(self.approval_root, "capture approval root", require_existing=True)
            _safe_root(self.capture_root, "capture root", require_existing=True)
            tool = Path(self.tcpdump_path)
            if not tool.is_absolute() or tool.is_symlink():
                raise MonitoringContractError("tcpdump path must be absolute and non-symlink")
        return self

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(
            {
                "enabled": self.enabled,
                "approved_interfaces": list(self.approved_interfaces),
                "approval_root": str(self.approval_root),
                "capture_root": str(self.capture_root),
                "tcpdump_path": str(self.tcpdump_path),
                "max_duration_seconds": self.max_duration_seconds,
                "max_capture_bytes": self.max_capture_bytes,
                "max_retention_ttl_seconds": self.max_retention_ttl_seconds,
                "approval_valid_seconds": self.approval_valid_seconds,
                "max_targets": self.max_targets,
                "max_ports": self.max_ports,
                "snaplen": self.snaplen,
            }
        )


@dataclass(frozen=True)
class IncidentCaptureRequest:
    request_id: str
    interface: str
    asset_ids: tuple[str, ...]
    ports: tuple[int, ...]
    duration_seconds: int
    max_bytes: int
    retention_ttl_seconds: int
    purpose: str
    requested_at: str
    schema_version: str = CAPTURE_SCHEMA

    @property
    def fingerprint(self) -> str:
        payload = asdict(self)
        payload["asset_ids"] = list(self.asset_ids)
        payload["ports"] = list(self.ports)
        return sha256_fingerprint(payload)


@dataclass(frozen=True)
class CapturePlan:
    request: IncidentCaptureRequest
    filter_tokens: tuple[str, ...]
    filter_sha256: str
    inventory_fingerprint: str
    max_packets: int

    @property
    def filter_expression(self) -> str:
        return " ".join(self.filter_tokens)


@dataclass(frozen=True)
class IncidentCaptureApproval:
    approval_id: str
    request: IncidentCaptureRequest
    request_fingerprint: str
    filter_sha256: str
    inventory_fingerprint: str
    policy_fingerprint: str
    approved_by_sha256: str
    approved_at: str
    approval_expires_at: str
    schema_version: str = APPROVAL_SCHEMA

    def public_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "approval_id": self.approval_id,
            "request_id": self.request.request_id,
            "request_fingerprint": self.request_fingerprint,
            "filter_sha256": self.filter_sha256,
            "approved_at": self.approved_at,
            "approval_expires_at": self.approval_expires_at,
            "capture_execution_separate": True,
        }


@dataclass(frozen=True)
class IncidentCaptureReceipt:
    capture_id: str
    approval_id: str
    request_fingerprint: str
    filter_sha256: str
    pcap_sha256: str
    captured_bytes: int
    started_at: str
    completed_at: str
    retention_expires_at: str
    stop_reason: str
    evidence_ref: str
    schema_version: str = RECEIPT_SCHEMA


def _inventory_map(config: MonitoringRuntimeConfig) -> dict[str, AssetInventoryRecord]:
    return {asset.asset_id: asset.validate() for asset in config.assets if asset.enabled}


def prepare_capture_request(
    payload: Mapping[str, Any],
    *,
    policy: IncidentCapturePolicy,
    config: MonitoringRuntimeConfig,
    now: datetime | None = None,
) -> IncidentCaptureRequest:
    policy.validate()
    if not policy.enabled:
        raise PermissionError("INCIDENT_CAPTURE_DISABLED")
    unknown = set(payload) - _REQUEST_KEYS
    if unknown:
        raise MonitoringContractError("incident capture request contains unknown fields")
    interface = str(payload.get("interface") or "").strip()
    if interface not in policy.approved_interfaces:
        raise PermissionError("CAPTURE_INTERFACE_NOT_APPROVED")
    raw_assets = payload.get("asset_ids")
    if not isinstance(raw_assets, list):
        raise MonitoringContractError("capture asset_ids must be an array")
    asset_ids = tuple(dict.fromkeys(str(value or "").strip() for value in raw_assets if str(value or "").strip()))
    if not 1 <= len(asset_ids) <= policy.max_targets:
        raise MonitoringContractError("capture target count exceeds policy")
    inventory = _inventory_map(config)
    if any(asset_id not in inventory for asset_id in asset_ids):
        raise PermissionError("CAPTURE_TARGET_NOT_IN_APPROVED_INVENTORY")
    # Hostname targets are rejected so tcpdump never performs DNS resolution and
    # the compiled filter is bound to exact literal addresses.
    for asset_id in asset_ids:
        try:
            ipaddress.ip_address(inventory[asset_id].management_host)
        except ValueError as exc:
            raise MonitoringContractError("incident capture requires literal-IP inventory targets") from exc

    raw_ports = payload.get("ports") or []
    if not isinstance(raw_ports, list):
        raise MonitoringContractError("capture ports must be an array")
    try:
        ports = tuple(dict.fromkeys(int(value) for value in raw_ports))
    except (TypeError, ValueError) as exc:
        raise MonitoringContractError("capture ports must be integers") from exc
    if len(ports) > policy.max_ports or any(port < 1 or port > 65535 for port in ports):
        raise MonitoringContractError("capture port set exceeds policy")

    try:
        duration = int(payload.get("duration_seconds"))
        max_bytes = int(payload.get("max_bytes"))
        ttl = int(payload.get("retention_ttl_seconds"))
    except (TypeError, ValueError) as exc:
        raise MonitoringContractError("capture duration/max_bytes/TTL must be integers") from exc
    if not 1 <= duration <= policy.max_duration_seconds:
        raise MonitoringContractError("capture duration exceeds policy")
    if not 256 * 1024 <= max_bytes <= policy.max_capture_bytes:
        raise MonitoringContractError("capture byte budget exceeds policy")
    if not 60 <= ttl <= policy.max_retention_ttl_seconds:
        raise MonitoringContractError("capture retention TTL exceeds policy")
    purpose = str(payload.get("purpose") or "").strip()
    if not _PURPOSE_RE.fullmatch(purpose):
        raise MonitoringContractError("capture purpose must be a compact incident/change identifier")

    requested = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    identity_payload = {
        "interface": interface,
        "asset_ids": list(asset_ids),
        "ports": list(ports),
        "duration_seconds": duration,
        "max_bytes": max_bytes,
        "retention_ttl_seconds": ttl,
        "purpose": purpose,
        "requested_at": _iso(requested),
    }
    request_id = "pcap-" + sha256_fingerprint(identity_payload).split(":", 1)[1][:24]
    return IncidentCaptureRequest(
        request_id=request_id,
        interface=interface,
        asset_ids=asset_ids,
        ports=ports,
        duration_seconds=duration,
        max_bytes=max_bytes,
        retention_ttl_seconds=ttl,
        purpose=purpose,
        requested_at=_iso(requested),
    )


def compile_capture_plan(
    request: IncidentCaptureRequest,
    *,
    policy: IncidentCapturePolicy,
    config: MonitoringRuntimeConfig,
) -> CapturePlan:
    policy.validate()
    if not policy.enabled or request.interface not in policy.approved_interfaces:
        raise PermissionError("INCIDENT_CAPTURE_NOT_AUTHORIZED_BY_POLICY")
    inventory = _inventory_map(config)
    selected: list[AssetInventoryRecord] = []
    for asset_id in request.asset_ids:
        asset = inventory.get(asset_id)
        if asset is None:
            raise PermissionError("CAPTURE_TARGET_NOT_IN_APPROVED_INVENTORY")
        try:
            ipaddress.ip_address(asset.management_host)
        except ValueError as exc:
            raise MonitoringContractError("incident capture requires literal-IP inventory targets") from exc
        selected.append(asset)

    host_tokens: list[str] = ["("]
    for index, asset in enumerate(selected):
        if index:
            host_tokens.append("or")
        host_tokens.extend(("host", asset.management_host))
    host_tokens.append(")")
    tokens = host_tokens
    if request.ports:
        tokens.extend(("and", "("))
        for index, port in enumerate(request.ports):
            if index:
                tokens.append("or")
            tokens.extend(("port", str(port)))
        tokens.append(")")
    expression = " ".join(tokens)
    filter_sha = "sha256:" + hashlib.sha256(expression.encode("ascii")).hexdigest()
    inventory_fingerprint = sha256_fingerprint([asset.fingerprint for asset in selected])
    # Classic pcap: 24-byte file header + <=16-byte packet record header + snaplen.
    # -c enforces this packet-count bound without a monitor thread or packet library.
    max_packets = max(1, (request.max_bytes - 24) // (policy.snaplen + 16))
    return CapturePlan(
        request=request,
        filter_tokens=tuple(tokens),
        filter_sha256=filter_sha,
        inventory_fingerprint=inventory_fingerprint,
        max_packets=max_packets,
    )


def approve_capture_request(
    payload: Mapping[str, Any],
    *,
    approver_user_id: str,
    policy: IncidentCapturePolicy,
    config: MonitoringRuntimeConfig,
    now: datetime | None = None,
) -> IncidentCaptureApproval:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    request = prepare_capture_request(payload, policy=policy, config=config, now=current)
    plan = compile_capture_plan(request, policy=policy, config=config)
    approver_hash = "sha256:" + hashlib.sha256(
        ("workspace-pcap-approver-v1:" + str(approver_user_id)).encode("utf-8")
    ).hexdigest()
    approval_id = "approval-" + request.request_id.removeprefix("pcap-")
    return IncidentCaptureApproval(
        approval_id=approval_id,
        request=request,
        request_fingerprint=request.fingerprint,
        filter_sha256=plan.filter_sha256,
        inventory_fingerprint=plan.inventory_fingerprint,
        policy_fingerprint=policy.fingerprint,
        approved_by_sha256=approver_hash,
        approved_at=_iso(current),
        approval_expires_at=_iso(current + timedelta(seconds=policy.approval_valid_seconds)),
    )


def _approval_payload(approval: IncidentCaptureApproval) -> dict[str, Any]:
    payload = asdict(approval)
    payload["request"]["asset_ids"] = list(approval.request.asset_ids)
    payload["request"]["ports"] = list(approval.request.ports)
    return payload


def persist_capture_approval(
    approval: IncidentCaptureApproval,
    *,
    policy: IncidentCapturePolicy,
) -> Path:
    policy.validate()
    root = _safe_root(policy.approval_root, "capture approval root", require_existing=True)
    final = root / f"{approval.approval_id}.json"
    temp = root / f".{approval.approval_id}.{os.getpid()}.tmp"
    if final.exists() or final.is_symlink() or temp.exists() or temp.is_symlink():
        raise MonitoringContractError("capture approval already exists or temp path is unsafe")
    encoded = (json.dumps(_approval_payload(approval), sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, final)
    except Exception:
        try:
            temp.unlink()
        except OSError:
            pass
        raise
    return final


def _request_from_payload(raw: Mapping[str, Any]) -> IncidentCaptureRequest:
    expected = {
        "request_id",
        "interface",
        "asset_ids",
        "ports",
        "duration_seconds",
        "max_bytes",
        "retention_ttl_seconds",
        "purpose",
        "requested_at",
        "schema_version",
    }
    if set(raw) != expected or raw.get("schema_version") != CAPTURE_SCHEMA:
        raise MonitoringContractError("capture approval contains invalid request shape")
    return IncidentCaptureRequest(
        request_id=str(raw["request_id"]),
        interface=str(raw["interface"]),
        asset_ids=tuple(str(value) for value in raw["asset_ids"]),
        ports=tuple(int(value) for value in raw["ports"]),
        duration_seconds=int(raw["duration_seconds"]),
        max_bytes=int(raw["max_bytes"]),
        retention_ttl_seconds=int(raw["retention_ttl_seconds"]),
        purpose=str(raw["purpose"]),
        requested_at=str(raw["requested_at"]),
    )


def load_capture_approval(path: Path) -> IncidentCaptureApproval:
    approval_path = Path(path)
    if not approval_path.is_file() or approval_path.is_symlink():
        raise MonitoringContractError("capture approval file is missing or unsafe")
    payload = json.loads(approval_path.read_text(encoding="utf-8"))
    expected = {
        "approval_id",
        "request",
        "request_fingerprint",
        "filter_sha256",
        "inventory_fingerprint",
        "policy_fingerprint",
        "approved_by_sha256",
        "approved_at",
        "approval_expires_at",
        "schema_version",
    }
    if not isinstance(payload, dict) or set(payload) != expected or payload.get("schema_version") != APPROVAL_SCHEMA:
        raise MonitoringContractError("capture approval shape/schema is invalid")
    request_raw = payload.get("request")
    if not isinstance(request_raw, dict):
        raise MonitoringContractError("capture approval request is invalid")
    request = _request_from_payload(request_raw)
    approval = IncidentCaptureApproval(
        approval_id=str(payload["approval_id"]),
        request=request,
        request_fingerprint=str(payload["request_fingerprint"]),
        filter_sha256=str(payload["filter_sha256"]),
        inventory_fingerprint=str(payload["inventory_fingerprint"]),
        policy_fingerprint=str(payload["policy_fingerprint"]),
        approved_by_sha256=str(payload["approved_by_sha256"]),
        approved_at=str(payload["approved_at"]),
        approval_expires_at=str(payload["approval_expires_at"]),
    )
    if approval.request_fingerprint != request.fingerprint:
        raise MonitoringContractError("capture approval request fingerprint mismatch")
    for digest in (
        approval.filter_sha256,
        approval.inventory_fingerprint,
        approval.policy_fingerprint,
        approval.approved_by_sha256,
    ):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise MonitoringContractError("capture approval contains invalid fingerprint")
    return approval


def verify_capture_approval(
    approval: IncidentCaptureApproval,
    *,
    policy: IncidentCapturePolicy,
    config: MonitoringRuntimeConfig,
    now: datetime | None = None,
) -> CapturePlan:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if current > _parse_iso(approval.approval_expires_at, "approval_expires_at"):
        raise PermissionError("CAPTURE_APPROVAL_EXPIRED")
    if approval.policy_fingerprint != policy.fingerprint:
        raise PermissionError("CAPTURE_POLICY_CHANGED_SINCE_APPROVAL")
    plan = compile_capture_plan(approval.request, policy=policy, config=config)
    if plan.filter_sha256 != approval.filter_sha256:
        raise PermissionError("CAPTURE_FILTER_CHANGED_SINCE_APPROVAL")
    if plan.inventory_fingerprint != approval.inventory_fingerprint:
        raise PermissionError("CAPTURE_INVENTORY_CHANGED_SINCE_APPROVAL")
    if approval.request_fingerprint != approval.request.fingerprint:
        raise PermissionError("CAPTURE_REQUEST_CHANGED_SINCE_APPROVAL")
    return plan


def capture_argv(plan: CapturePlan, *, policy: IncidentCapturePolicy, output_path: Path) -> tuple[str, ...]:
    policy.validate()
    if os.name != "posix":
        raise RuntimeError("INCIDENT_CAPTURE_POSIX_ONLY")
    tool = Path(policy.tcpdump_path)
    if not tool.is_file() or tool.is_symlink():
        raise RuntimeError("TCPDUMP_UNAVAILABLE")
    if output_path.is_symlink():
        raise MonitoringContractError("capture output symlink denied")
    return (
        str(tool),
        "-n",
        "-U",
        "-s",
        str(policy.snaplen),
        "-c",
        str(plan.max_packets),
        "-i",
        plan.request.interface,
        "-w",
        str(output_path),
        *plan.filter_tokens,
    )


def execute_capture_approval(
    approval_path: Path,
    *,
    confirmation: str,
    policy: IncidentCapturePolicy,
    config: MonitoringRuntimeConfig,
    now: datetime | None = None,
    popen_factory: Any = subprocess.Popen,
) -> IncidentCaptureReceipt:
    if confirmation != CAPTURE_CONFIRMATION:
        raise PermissionError("CAPTURE_CONFIRMATION_REQUIRED")
    policy.validate()
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    root = _safe_root(policy.approval_root, "capture approval root", require_existing=True)
    source = Path(approval_path)
    if source.parent.resolve() != root.resolve() or source.name.startswith("."):
        raise PermissionError("CAPTURE_APPROVAL_OUTSIDE_ROOT")
    approval = load_capture_approval(source)
    plan = verify_capture_approval(approval, policy=policy, config=config, now=current)

    capture_root = _safe_root(policy.capture_root, "capture root", require_existing=True)
    final = capture_root / f"{approval.request.request_id}.pcap"
    temp = capture_root / f".{approval.request.request_id}.{os.getpid()}.pcap.tmp"
    receipt_path = capture_root / f"{approval.request.request_id}.receipt.json"
    if any(path.exists() or path.is_symlink() for path in (final, temp, receipt_path)):
        raise MonitoringContractError("capture output already exists or path is unsafe")
    argv = capture_argv(plan, policy=policy, output_path=temp)

    # Claim approval atomically. A failed/partial attempt cannot replay the same
    # administrative approval; a new capture requires a fresh approval receipt.
    claimed = root / f".{approval.approval_id}.claimed"
    if claimed.exists() or claimed.is_symlink():
        raise PermissionError("CAPTURE_APPROVAL_ALREADY_CLAIMED")
    os.replace(source, claimed)
    started = datetime.now(timezone.utc)
    stop_reason = "packet_budget"
    process = None
    try:
        process = popen_factory(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            start_new_session=True,
        )
        try:
            return_code = process.wait(timeout=approval.request.duration_seconds)
            if return_code != 0:
                raise RuntimeError("CAPTURE_TOOL_FAILED")
        except subprocess.TimeoutExpired:
            stop_reason = "duration_budget"
            process.send_signal(signal.SIGINT)
            try:
                return_code = process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                return_code = process.wait(timeout=2)
            if return_code not in {0, -signal.SIGINT}:
                raise RuntimeError("CAPTURE_TOOL_FAILED_AFTER_TIMEOUT")

        if not temp.is_file() or temp.is_symlink():
            raise RuntimeError("CAPTURE_OUTPUT_MISSING")
        size = temp.stat().st_size
        if not 24 <= size <= approval.request.max_bytes:
            raise RuntimeError("CAPTURE_OUTPUT_BYTE_BOUND_VIOLATED")
        digest = _sha256_file(temp)
        os.chmod(temp, 0o600)
        os.replace(temp, final)
        completed = datetime.now(timezone.utc)
        retention_expires = completed + timedelta(seconds=approval.request.retention_ttl_seconds)
        receipt = IncidentCaptureReceipt(
            capture_id=approval.request.request_id,
            approval_id=approval.approval_id,
            request_fingerprint=approval.request_fingerprint,
            filter_sha256=approval.filter_sha256,
            pcap_sha256=digest,
            captured_bytes=size,
            started_at=_iso(started),
            completed_at=_iso(completed),
            retention_expires_at=_iso(retention_expires),
            stop_reason=stop_reason,
            evidence_ref=f"pcap:{approval.request.request_id}",
        )
        encoded = (json.dumps(asdict(receipt), sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        descriptor = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        return receipt
    finally:
        if temp.exists() and not temp.is_symlink():
            try:
                temp.unlink()
            except OSError:
                pass
        if claimed.exists() and not claimed.is_symlink():
            # Claimed approvals contain admin authorization metadata and are no longer
            # executable. Keep only a hash-bound capture receipt after execution.
            try:
                claimed.unlink()
            except OSError:
                pass


def cleanup_expired_captures(
    *,
    policy: IncidentCapturePolicy,
    now: datetime | None = None,
    max_deletes: int = 16,
) -> tuple[str, ...]:
    if not 1 <= int(max_deletes) <= 128:
        raise MonitoringContractError("capture cleanup delete bound must be within 1..128")
    root = _safe_root(policy.capture_root, "capture root", require_existing=True)
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    deleted: list[str] = []
    for receipt_path in sorted(root.glob("pcap-*.receipt.json")):
        if len(deleted) >= max_deletes:
            break
        if not receipt_path.is_file() or receipt_path.is_symlink():
            continue
        try:
            payload = json.loads(receipt_path.read_text(encoding="utf-8"))
            capture_id = str(payload.get("capture_id") or "")
            if payload.get("schema_version") != RECEIPT_SCHEMA or not re.fullmatch(r"pcap-[0-9a-f]{24}", capture_id):
                continue
            expires = _parse_iso(str(payload.get("retention_expires_at") or ""), "retention_expires_at")
        except (json.JSONDecodeError, MonitoringContractError):
            continue
        if expires > current:
            continue
        pcap = root / f"{capture_id}.pcap"
        if pcap.exists():
            if not pcap.is_file() or pcap.is_symlink():
                continue
            pcap.unlink()
        receipt_path.unlink()
        deleted.append(capture_id)
    return tuple(deleted)
