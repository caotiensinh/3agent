from __future__ import annotations

import asyncio
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

from .contracts import MonitoringContractError, SecretReference


@dataclass(frozen=True)
class SnmpV3Credential:
    username: str
    auth_key: str
    priv_key: str
    auth_protocol: str = "sha256"
    priv_protocol: str = "aes128"

    def validate(self) -> "SnmpV3Credential":
        if not self.username or len(self.username) > 64:
            raise MonitoringContractError("SNMPv3 username is invalid")
        if not 8 <= len(self.auth_key.encode("utf-8")) <= 32:
            raise MonitoringContractError("SNMPv3 auth key must be 8..32 octets")
        if not 8 <= len(self.priv_key.encode("utf-8")) <= 32:
            raise MonitoringContractError("SNMPv3 privacy key must be 8..32 octets")
        if self.auth_protocol not in {"sha224", "sha256", "sha384", "sha512"}:
            raise MonitoringContractError("SNMPv3 auth protocol must use SHA-2")
        if self.priv_protocol not in {"aes128", "aes192", "aes256"}:
            raise MonitoringContractError("SNMPv3 privacy protocol must use AES")
        return self


class FileSecretResolver:
    """Resolve `secret-ref:<id>` from a POSIX permission-protected directory.

    ver.0.0.1 deliberately supports this file-secret backend only where POSIX mode
    bits are authoritative. Windows ACLs are a different security model; pretending
    that ``st_mode`` proves equivalent protection would weaken the credential
    boundary. Non-POSIX hosts therefore fail closed before any secret file is read.
    """

    def __init__(self, root: str | Path):
        self.root = Path(root)
        if not self.root.is_absolute():
            raise MonitoringContractError("secret directory must be absolute")

    @staticmethod
    def _require_supported_permission_model() -> None:
        if os.name != "posix":
            raise MonitoringContractError("SNMP_FILE_SECRET_BACKEND_REQUIRES_POSIX_PERMISSIONS")

    def resolve_snmpv3(self, ref: SecretReference) -> SnmpV3Credential:
        self._require_supported_permission_model()
        ref.validate()
        suffix = ref.handle.removeprefix("secret-ref:")
        path = self.root / f"{suffix}.json"
        try:
            root_resolved = self.root.resolve(strict=True)
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise MonitoringContractError("SNMP_SECRET_NOT_FOUND") from exc
        if resolved.parent != root_resolved:
            raise MonitoringContractError("SNMP_SECRET_PATH_OUTSIDE_ROOT")
        if path.is_symlink():
            raise MonitoringContractError("SNMP_SECRET_SYMLINK_DENIED")
        st = resolved.stat()
        if not stat.S_ISREG(st.st_mode):
            raise MonitoringContractError("SNMP_SECRET_NOT_REGULAR_FILE")
        mode = stat.S_IMODE(st.st_mode)
        if mode & 0o007:
            raise MonitoringContractError("SNMP_SECRET_WORLD_ACCESS_DENIED")
        if mode & 0o020:
            raise MonitoringContractError("SNMP_SECRET_GROUP_WRITE_DENIED")
        if mode & 0o002:
            raise MonitoringContractError("SNMP_SECRET_WORLD_WRITE_DENIED")
        if resolved.stat().st_size > 4096:
            raise MonitoringContractError("SNMP_SECRET_FILE_TOO_LARGE")
        payload = json.loads(resolved.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise MonitoringContractError("SNMP_SECRET_INVALID")
        allowed = {"username", "auth_key", "priv_key", "auth_protocol", "priv_protocol"}
        unknown = set(payload) - allowed
        if unknown:
            raise MonitoringContractError(f"SNMP secret has unknown fields: {sorted(unknown)}")
        return SnmpV3Credential(
            username=str(payload.get("username") or ""),
            auth_key=str(payload.get("auth_key") or ""),
            priv_key=str(payload.get("priv_key") or ""),
            auth_protocol=str(payload.get("auth_protocol") or "sha256").lower(),
            priv_protocol=str(payload.get("priv_protocol") or "aes128").lower(),
        ).validate()


# Numeric OIDs avoid MIB loading and its extra memory/IO cost.
_COLUMN_OIDS = {
    "interface": "1.3.6.1.2.1.31.1.1.1.1",       # ifName
    "rx_bytes": "1.3.6.1.2.1.31.1.1.1.6",        # ifHCInOctets
    "tx_bytes": "1.3.6.1.2.1.31.1.1.1.10",       # ifHCOutOctets
    "speed_mbps": "1.3.6.1.2.1.31.1.1.1.15",     # ifHighSpeed
    "rx_discards": "1.3.6.1.2.1.2.2.1.13",       # ifInDiscards
    "rx_errors": "1.3.6.1.2.1.2.2.1.14",         # ifInErrors
    "tx_discards": "1.3.6.1.2.1.2.2.1.19",       # ifOutDiscards
    "tx_errors": "1.3.6.1.2.1.2.2.1.20",         # ifOutErrors
}


async def _pysnmp_walk_columns(
    *,
    target_host: str,
    credential: SnmpV3Credential,
    timeout_seconds: float,
    max_rows: int,
    max_calls: int,
) -> Sequence[dict[str, Any]]:
    try:
        from pysnmp.hlapi.v3arch.asyncio import (
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            UsmUserData,
            USM_AUTH_HMAC128_SHA224,
            USM_AUTH_HMAC192_SHA256,
            USM_AUTH_HMAC256_SHA384,
            USM_AUTH_HMAC384_SHA512,
            USM_PRIV_CFB128_AES,
            USM_PRIV_CFB192_AES,
            USM_PRIV_CFB256_AES,
            walk_cmd,
        )
    except ImportError as exc:
        raise RuntimeError("PYSNMP_MONITORING_EXTRA_NOT_INSTALLED") from exc

    auth_protocols = {
        "sha224": USM_AUTH_HMAC128_SHA224,
        "sha256": USM_AUTH_HMAC192_SHA256,
        "sha384": USM_AUTH_HMAC256_SHA384,
        "sha512": USM_AUTH_HMAC384_SHA512,
    }
    priv_protocols = {
        "aes128": USM_PRIV_CFB128_AES,
        "aes192": USM_PRIV_CFB192_AES,
        "aes256": USM_PRIV_CFB256_AES,
    }
    engine = SnmpEngine()
    auth = UsmUserData(
        credential.username,
        authKey=credential.auth_key,
        privKey=credential.priv_key,
        authProtocol=auth_protocols[credential.auth_protocol],
        privProtocol=priv_protocols[credential.priv_protocol],
    )
    target = await UdpTransportTarget.create(
        (target_host, 161),
        timeout=max(0.1, float(timeout_seconds)),
        retries=0,
    )
    by_index: dict[str, dict[str, Any]] = {}
    try:
        for key, base_oid in _COLUMN_OIDS.items():
            generator = walk_cmd(
                engine,
                auth,
                target,
                ContextData(),
                ObjectType(ObjectIdentity(base_oid)),
                lookupMib=False,
                lexicographicMode=False,
                maxRows=max_rows,
                maxCalls=max_calls,
            )
            async for error_indication, error_status, _error_index, var_binds in generator:
                if error_indication:
                    raise OSError("SNMPV3_ENGINE_ERROR")
                if error_status:
                    raise OSError("SNMPV3_PDU_ERROR")
                for var_bind in var_binds:
                    oid_obj, value_obj = var_bind
                    oid = str(oid_obj)
                    prefix = base_oid + "."
                    if not oid.startswith(prefix):
                        continue
                    index = oid[len(prefix):]
                    row = by_index.setdefault(index, {})
                    if key == "interface":
                        row[key] = str(value_obj)
                    else:
                        try:
                            row[key] = int(value_obj)
                        except (TypeError, ValueError):
                            continue
    finally:
        engine.close_dispatcher()

    rows: list[dict[str, Any]] = []
    for index in sorted(by_index, key=lambda value: tuple(int(p) if p.isdigit() else 0 for p in value.split("."))):
        row = by_index[index]
        if "interface" not in row:
            row["interface"] = "if" + index.replace(".", "_")
        if "speed_mbps" in row:
            row["speed_bps"] = int(row.pop("speed_mbps")) * 1_000_000
        rows.append(row)
    return rows


class PySnmpV3Backend:
    """Optional pure-Python SNMPv3 authPriv backend; never invokes an external CLI."""

    def __init__(
        self,
        resolver: FileSecretResolver,
        *,
        query: Callable[..., Sequence[dict[str, Any]]] | None = None,
        max_rows: int = 256,
        max_calls: int = 64,
    ):
        if not 1 <= max_rows <= 2048:
            raise ValueError("max_rows must be within 1..2048")
        if not 1 <= max_calls <= 256:
            raise ValueError("max_calls must be within 1..256")
        self.resolver = resolver
        self.query = query
        self.max_rows = max_rows
        self.max_calls = max_calls

    def read_interface_counters(
        self,
        *,
        target_host: str,
        credential_ref: SecretReference,
        timeout_seconds: float,
    ) -> Sequence[dict]:
        credential = self.resolver.resolve_snmpv3(credential_ref)
        if self.query is not None:
            return self.query(
                target_host=target_host,
                credential=credential,
                timeout_seconds=timeout_seconds,
                max_rows=self.max_rows,
                max_calls=self.max_calls,
            )
        return asyncio.run(
            _pysnmp_walk_columns(
                target_host=target_host,
                credential=credential,
                timeout_seconds=timeout_seconds,
                max_rows=self.max_rows,
                max_calls=self.max_calls,
            )
        )
