from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Iterable, Mapping

from .ai_analyst import LocalAIAnalyst
from .capability_registry import SecurityCapabilityRegistry, SecurityOperationAuthorization
from .collectors import CollectorResult
from .contracts import AssetInventoryRecord, MonitoringContractError, sha256_fingerprint
from .correlation_graph import CorrelationEvent
from .dispatch import DefaultCollectorDispatcher
from .dns_behavior import SUPPORTED_DNS_SOURCES, extract_dns_behavior_features
from .flow_analysis import MAX_FLOW_ANALYSIS_EVENTS, FlowEvidenceAnalysis, analyze_flow_evidence
from .network_triage import NetworkIncidentTriage
from .operation_binding import (
    FLOW_ANALYSIS_HANDLER_ID,
    SecurityOperationBindingRegistry,
    SecurityOperationHandlerUnbound,
    reviewed_runtime_handler_exists,
)
from .operation_plan import (
    SecurityOperationPlan,
    SecurityOperationPlanCompiler,
    SecurityOperationPlanError,
    SecurityOperationStep,
)
from .passive_sensors import PassiveJsonlSensorAdapter
from .plan import CollectorWorkItem
from .policy import MonitoringPolicyEngine
from .reporting import DeterministicReport

SECURITY_INVOCATION_RECEIPT_SCHEMA = "workspace-security-operation-invocation-receipt/v1"
FLOW_ANALYSIS_INVOCATION_RECEIPT_SCHEMA = "workspace-security-flow-analysis-invocation-receipt/v1"
FLOW_ANALYSIS_OUTPUT_KIND = "flow_evidence_analysis"
MAX_DNS_INVOCATION_BYTES = 256 * 1024
MAX_ANALYST_TRIAGE_RECORDS = 16

_COMPACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,255}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_FLOW_ANALYSIS_KEY = ("network.flow.analyze", "analyze_flow_evidence")
_HANDLER_OUTPUT_KINDS = {
    "monitoring.dispatch.snmpv3_read": "collector_result",
    "monitoring.dispatch.local_net_read": "collector_result",
    "monitoring.passive_jsonl.read_batch": "passive_sensor_batch",
    "analysis.dns_behavior.extract_features": "dns_behavior_features",
    FLOW_ANALYSIS_HANDLER_ID: FLOW_ANALYSIS_OUTPUT_KIND,
    "analysis.local_ai_analyst.analyze": "ai_analysis_result",
}


class SecurityOperationInvocationError(ValueError):
    """A typed invocation request or its plan lineage is invalid."""


class SecurityOperationInvocationDenied(PermissionError):
    """Invocation failed closed before a reviewed runtime handler was called."""

    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _compact(value: str, field_name: str, *, max_len: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or not _COMPACT_RE.fullmatch(text) or "://" in text:
        raise SecurityOperationInvocationError(f"{field_name} must be a compact identifier")
    return text


def _iso(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SecurityOperationInvocationError(f"{field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise SecurityOperationInvocationError(f"{field_name} must include timezone")
    return text


def _sha_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CollectorInvocationRequest:
    """Typed request for an inventory-bound monitoring collector.

    No target host, port, credential or backend capability is accepted from the
    request. Those values are derived from reviewed plan + trusted inventory.
    """

    asset_id: str
    run_id: str
    observed_at: str

    def validate(self) -> "CollectorInvocationRequest":
        object.__setattr__(self, "asset_id", _compact(self.asset_id, "asset_id", max_len=128))
        object.__setattr__(self, "run_id", _compact(self.run_id, "run_id", max_len=128))
        object.__setattr__(self, "observed_at", _iso(self.observed_at, "observed_at"))
        return self

    @property
    def fingerprint(self) -> str:
        self.validate()
        return sha256_fingerprint(asdict(self))


@dataclass(frozen=True)
class PassiveTelemetryInvocationRequest:
    """Select only a preconfigured passive source; paths never cross this boundary."""

    asset_id: str
    source_id: str
    evaluated_at: str

    def validate(self) -> "PassiveTelemetryInvocationRequest":
        object.__setattr__(self, "asset_id", _compact(self.asset_id, "asset_id", max_len=128))
        object.__setattr__(self, "source_id", _compact(self.source_id, "source_id", max_len=128))
        object.__setattr__(self, "evaluated_at", _iso(self.evaluated_at, "evaluated_at"))
        return self

    @property
    def fingerprint(self) -> str:
        self.validate()
        return sha256_fingerprint(asdict(self))


@dataclass(frozen=True)
class DNSAnalysisInvocationRequest:
    """Bounded untrusted DNS evidence for the pure local feature extractor."""

    event_id: str
    source_type: str
    raw_line: str

    def validate(self) -> "DNSAnalysisInvocationRequest":
        object.__setattr__(self, "event_id", _compact(self.event_id, "event_id", max_len=128))
        source_type = str(self.source_type or "").strip()
        if source_type not in SUPPORTED_DNS_SOURCES:
            raise SecurityOperationInvocationError("unsupported DNS invocation source_type")
        object.__setattr__(self, "source_type", source_type)
        if not isinstance(self.raw_line, str):
            raise SecurityOperationInvocationError("DNS invocation raw_line must be text")
        size = len(self.raw_line.encode("utf-8", errors="strict"))
        if size < 2 or size > MAX_DNS_INVOCATION_BYTES:
            raise SecurityOperationInvocationError("DNS invocation evidence exceeds bounded size")
        return self

    @property
    def fingerprint(self) -> str:
        self.validate()
        return sha256_fingerprint(
            {
                "event_id": self.event_id,
                "source_type": self.source_type,
                "raw_line_sha256": _sha_text(self.raw_line),
            }
        )


@dataclass(frozen=True)
class FlowAnalysisInvocationRequest:
    """Typed normalized evidence only; no path, target, credential or runtime selector."""

    events: tuple[CorrelationEvent, ...]

    def validate(self) -> "FlowAnalysisInvocationRequest":
        rows = tuple(self.events)
        if not rows or len(rows) > MAX_FLOW_ANALYSIS_EVENTS:
            raise SecurityOperationInvocationError("flow analysis invocation event count is out of bounds")
        for item in rows:
            if not isinstance(item, CorrelationEvent):
                raise SecurityOperationInvocationError("flow analysis invocation requires CorrelationEvent")
            try:
                item.validate()
            except MonitoringContractError as exc:
                raise SecurityOperationInvocationError("flow analysis invocation contains invalid evidence") from exc
        object.__setattr__(self, "events", rows)
        return self

    @property
    def fingerprint(self) -> str:
        self.validate()
        rows = sorted(self.events, key=lambda item: (item.observed, item.event.event_id))
        return sha256_fingerprint(
            {
                "events": [
                    {
                        "event": asdict(item.event),
                        "context": item.context.public_dict(),
                        "stage": item.stage,
                    }
                    for item in rows
                ]
            }
        )


@dataclass(frozen=True)
class AnalystInvocationRequest:
    """Typed deterministic report/triage input for the already-configured local analyst."""

    report: DeterministicReport
    enabled: bool = True
    network_triage: tuple[NetworkIncidentTriage, ...] = ()

    def validate(self) -> "AnalystInvocationRequest":
        if not isinstance(self.report, DeterministicReport):
            raise SecurityOperationInvocationError("analyst invocation requires DeterministicReport")
        if not isinstance(self.enabled, bool):
            raise SecurityOperationInvocationError("analyst enabled must be boolean")
        triage = tuple(self.network_triage)
        if len(triage) > MAX_ANALYST_TRIAGE_RECORDS:
            raise SecurityOperationInvocationError("analyst triage input exceeds v0.5 bound")
        if any(not isinstance(item, NetworkIncidentTriage) for item in triage):
            raise SecurityOperationInvocationError("analyst triage input type is invalid")
        object.__setattr__(self, "network_triage", triage)
        return self

    @property
    def fingerprint(self) -> str:
        self.validate()
        report_payload = asdict(self.report)
        triage_payload = [item.public_dict() for item in self.network_triage]
        return sha256_fingerprint(
            {
                "report": report_payload,
                "enabled": self.enabled,
                "network_triage": triage_payload,
            }
        )


SecurityTypedInvocationRequest = (
    CollectorInvocationRequest
    | PassiveTelemetryInvocationRequest
    | DNSAnalysisInvocationRequest
    | FlowAnalysisInvocationRequest
    | AnalystInvocationRequest
)


@dataclass(frozen=True)
class SecurityInvocationReceipt:
    invocation_id: str
    plan_fingerprint: str
    step_id: str
    capability_id: str
    operation_id: str
    handler_id: str
    handler_kind: str
    input_fingerprint: str
    authority_domain: str
    authority_fingerprint: str
    authority_reason_code: str
    registry_fingerprint: str
    binding_fingerprint: str
    output_kind: str
    status: str = "completed"
    schema_version: str = SECURITY_INVOCATION_RECEIPT_SCHEMA

    def validate(self) -> "SecurityInvocationReceipt":
        if not re.fullmatch(r"invoke-[0-9a-f]{24}", self.invocation_id):
            raise SecurityOperationInvocationError("invocation_id must derive from invocation identity")
        for value in (
            self.plan_fingerprint,
            self.input_fingerprint,
            self.authority_fingerprint,
            self.registry_fingerprint,
            self.binding_fingerprint,
        ):
            if not _SHA256_RE.fullmatch(str(value or "")):
                raise SecurityOperationInvocationError("invocation fingerprints must be SHA-256")
        if not re.fullmatch(r"step:[0-9a-f]{24}", self.step_id):
            raise SecurityOperationInvocationError("receipt step_id is invalid")
        if self.authority_domain not in {"internal", "monitoring"}:
            raise SecurityOperationInvocationError("v0.5 receipt authority domain is unsupported")
        if self.output_kind not in set(_HANDLER_OUTPUT_KINDS.values()):
            raise SecurityOperationInvocationError("receipt output_kind is unsupported")
        if self.status != "completed":
            raise SecurityOperationInvocationError("v0.5 emits completed receipts only")
        expected = "invoke-" + sha256_fingerprint(self._identity_payload()).split(":", 1)[1][:24]
        if self.invocation_id != expected:
            raise SecurityOperationInvocationError("invocation_id does not match receipt identity")
        return self

    def _identity_payload(self) -> dict[str, object]:
        return {
            "plan_fingerprint": self.plan_fingerprint,
            "step_id": self.step_id,
            "capability_id": self.capability_id,
            "operation_id": self.operation_id,
            "handler_id": self.handler_id,
            "handler_kind": self.handler_kind,
            "input_fingerprint": self.input_fingerprint,
            "authority_domain": self.authority_domain,
            "authority_fingerprint": self.authority_fingerprint,
            "authority_reason_code": self.authority_reason_code,
            "registry_fingerprint": self.registry_fingerprint,
            "binding_fingerprint": self.binding_fingerprint,
            "output_kind": self.output_kind,
            "status": self.status,
            "schema_version": self.schema_version,
        }

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {"invocation_id": self.invocation_id, **self._identity_payload()}


@dataclass(frozen=True)
class FlowAnalysisInvocationReceipt:
    invocation_id: str
    plan_fingerprint: str
    step_id: str
    capability_id: str
    operation_id: str
    handler_id: str
    handler_kind: str
    input_fingerprint: str
    output_fingerprint: str
    authority_domain: str
    authority_fingerprint: str
    authority_reason_code: str
    registry_fingerprint: str
    binding_fingerprint: str
    output_kind: str
    status: str = "completed"
    schema_version: str = FLOW_ANALYSIS_INVOCATION_RECEIPT_SCHEMA

    def validate(self) -> "FlowAnalysisInvocationReceipt":
        if not re.fullmatch(r"invoke-[0-9a-f]{24}", self.invocation_id):
            raise SecurityOperationInvocationError("flow analysis invocation_id is invalid")
        for value in (
            self.plan_fingerprint,
            self.input_fingerprint,
            self.output_fingerprint,
            self.authority_fingerprint,
            self.registry_fingerprint,
            self.binding_fingerprint,
        ):
            if not _SHA256_RE.fullmatch(str(value or "")):
                raise SecurityOperationInvocationError("flow analysis receipt fingerprints must be SHA-256")
        if not re.fullmatch(r"step:[0-9a-f]{24}", self.step_id):
            raise SecurityOperationInvocationError("flow analysis receipt step_id is invalid")
        if (self.capability_id, self.operation_id) != _FLOW_ANALYSIS_KEY:
            raise SecurityOperationInvocationError("flow analysis receipt operation scope mismatch")
        if self.handler_id != FLOW_ANALYSIS_HANDLER_ID or self.handler_kind != "pure_function":
            raise SecurityOperationInvocationError("flow analysis receipt handler is not reviewed")
        if self.output_kind != FLOW_ANALYSIS_OUTPUT_KIND:
            raise SecurityOperationInvocationError("flow analysis receipt output_kind is invalid")
        if self.authority_domain != "internal":
            raise SecurityOperationInvocationError("flow analysis receipt must remain internal-domain")
        if self.authority_reason_code != "SECURITY_INTERNAL_OPERATION_AUTHORIZED":
            raise SecurityOperationInvocationError("flow analysis receipt requires internal authority")
        if self.status != "completed":
            raise SecurityOperationInvocationError("flow analysis emits completed receipts only")
        expected = "invoke-" + sha256_fingerprint(self._identity_payload()).split(":", 1)[1][:24]
        if self.invocation_id != expected:
            raise SecurityOperationInvocationError("flow analysis invocation_id does not match receipt identity")
        return self

    def _identity_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "plan_fingerprint": self.plan_fingerprint,
            "step_id": self.step_id,
            "capability_id": self.capability_id,
            "operation_id": self.operation_id,
            "handler_id": self.handler_id,
            "handler_kind": self.handler_kind,
            "input_fingerprint": self.input_fingerprint,
            "output_fingerprint": self.output_fingerprint,
            "authority_domain": self.authority_domain,
            "authority_fingerprint": self.authority_fingerprint,
            "authority_reason_code": self.authority_reason_code,
            "registry_fingerprint": self.registry_fingerprint,
            "binding_fingerprint": self.binding_fingerprint,
            "output_kind": self.output_kind,
            "status": self.status,
        }

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {"invocation_id": self.invocation_id, **self._identity_payload()}


@dataclass(frozen=True)
class SecurityInvocationResult:
    receipt: SecurityInvocationReceipt | FlowAnalysisInvocationReceipt
    output: Any


class SecurityOperationInvoker:
    """Typed, fail-closed invocation gate for reviewed Guardian operations.

    The invoker does not accept shell commands, argv, executable names, target hosts,
    ports, credentials, Python import paths, model-selected callables or file paths.
    Monitoring authority is re-evaluated against trusted inventory immediately before
    the canonical handler runs. Internal operations remain compute-only.
    """

    def __init__(
        self,
        *,
        registry: SecurityCapabilityRegistry | None = None,
        binding_registry: SecurityOperationBindingRegistry | None = None,
        monitoring_engine: MonitoringPolicyEngine | None = None,
        dispatcher: DefaultCollectorDispatcher | None = None,
        assets: Iterable[AssetInventoryRecord] = (),
        passive_adapters: Mapping[str, PassiveJsonlSensorAdapter] | None = None,
        passive_source_assets: Mapping[str, str] | None = None,
        analyst: LocalAIAnalyst | None = None,
    ) -> None:
        self.registry = registry or SecurityCapabilityRegistry()
        self.binding_registry = binding_registry or SecurityOperationBindingRegistry(self.registry)
        if self.binding_registry.registry.fingerprint != self.registry.fingerprint:
            raise SecurityOperationInvocationError("INVOCATION_BINDING_REGISTRY_MISMATCH")
        self.compiler = SecurityOperationPlanCompiler(self.registry)

        if dispatcher is not None and not isinstance(dispatcher, DefaultCollectorDispatcher):
            raise SecurityOperationInvocationError("dispatcher must be DefaultCollectorDispatcher")
        if monitoring_engine is not None and not isinstance(monitoring_engine, MonitoringPolicyEngine):
            raise SecurityOperationInvocationError("monitoring_engine must be MonitoringPolicyEngine")
        if dispatcher is not None:
            if monitoring_engine is None:
                monitoring_engine = dispatcher.policy_engine
            elif dispatcher.policy_engine.policy.fingerprint != monitoring_engine.policy.fingerprint:
                raise SecurityOperationInvocationError("dispatcher and invocation monitoring policy differ")
        self.monitoring_engine = monitoring_engine
        self.dispatcher = dispatcher

        inventory: dict[str, AssetInventoryRecord] = {}
        for raw in assets:
            asset = raw.validate()
            if asset.asset_id in inventory:
                raise SecurityOperationInvocationError("duplicate trusted asset_id")
            inventory[asset.asset_id] = asset
        self.assets = inventory

        adapters: dict[str, PassiveJsonlSensorAdapter] = {}
        for key, adapter in dict(passive_adapters or {}).items():
            source_id = _compact(key, "passive_source_id", max_len=128)
            if not isinstance(adapter, PassiveJsonlSensorAdapter):
                raise SecurityOperationInvocationError("passive adapter must be PassiveJsonlSensorAdapter")
            config = adapter.config.validate()
            if config.source_id != source_id:
                raise SecurityOperationInvocationError("passive adapter key/source_id mismatch")
            adapters[source_id] = adapter
        source_assets = {
            _compact(source, "passive_source_id", max_len=128): _compact(asset_id, "asset_id", max_len=128)
            for source, asset_id in dict(passive_source_assets or {}).items()
        }
        if set(source_assets) != set(adapters):
            raise SecurityOperationInvocationError("every passive adapter requires one explicit asset binding")
        if any(asset_id not in inventory for asset_id in source_assets.values()):
            raise SecurityOperationInvocationError("passive source references unknown trusted asset")
        self.passive_adapters = adapters
        self.passive_source_assets = source_assets

        if analyst is not None and not isinstance(analyst, LocalAIAnalyst):
            raise SecurityOperationInvocationError("analyst must be LocalAIAnalyst")
        self.analyst = analyst

    def invoke(
        self,
        plan: SecurityOperationPlan,
        *,
        step_id: str,
        request: SecurityTypedInvocationRequest,
    ) -> SecurityInvocationResult:
        self._require_plan_integrity(plan)
        plan.validate()
        if plan.status != "planned":
            raise SecurityOperationInvocationDenied("INVOCATION_REQUIRES_PLANNED_OPERATION")
        if plan.registry_fingerprint != self.registry.fingerprint:
            raise SecurityOperationInvocationDenied("INVOCATION_REGISTRY_FINGERPRINT_MISMATCH")
        wanted = str(step_id or "").strip()
        matching = [step for step in plan.steps if step.step_id == wanted]
        if len(matching) != 1:
            raise SecurityOperationInvocationDenied("INVOCATION_STEP_NOT_IN_PLAN")
        step = matching[0].validate()

        try:
            binding = self.binding_registry.require_bound(step.capability_id, step.operation_id)
        except SecurityOperationHandlerUnbound:
            raise
        if binding.handler_id is None or binding.handler_kind is None:
            raise SecurityOperationInvocationDenied("INVOCATION_BOUND_HANDLER_METADATA_MISSING")
        if not reviewed_runtime_handler_exists(binding.handler_id):
            raise SecurityOperationInvocationDenied("INVOCATION_REVIEWED_HANDLER_UNAVAILABLE")
        if binding.handler_id not in _HANDLER_OUTPUT_KINDS:
            raise SecurityOperationInvocationDenied("INVOCATION_HANDLER_NOT_ADMITTED_V05")

        validated_request = self._validate_request_for_handler(binding.handler_id, request)
        authorization = self._authorize(step, binding.handler_id, validated_request)
        self._validate_authorization(step, authorization)
        output = self._call_handler(binding.handler_id, step, validated_request)
        input_fingerprint = validated_request.fingerprint
        if binding.handler_id == FLOW_ANALYSIS_HANDLER_ID:
            if not isinstance(output, FlowEvidenceAnalysis):
                raise SecurityOperationInvocationError("flow analysis reviewed handler returned unexpected type")
            receipt = self._flow_receipt(
                plan=plan,
                step=step,
                input_fingerprint=input_fingerprint,
                output_fingerprint=output.fingerprint,
                authority=authorization,
            )
        else:
            receipt = self._receipt(
                plan=plan,
                step=step,
                handler_id=binding.handler_id,
                handler_kind=binding.handler_kind,
                input_fingerprint=input_fingerprint,
                authorization=authorization,
            )
        return SecurityInvocationResult(receipt=receipt, output=output)

    def _require_plan_integrity(self, plan: SecurityOperationPlan) -> None:
        for step in plan.steps:
            expected_step_id = self.compiler._step_id(
                plan.request_sha256,
                step.sequence,
                step.capability_id,
                step.operation_id,
            )
            if step.step_id != expected_step_id:
                raise SecurityOperationPlanError("INVOCATION_PLAN_STEP_ID_TAMPERED")
        expected = self.compiler._plan_fingerprint(
            request_sha256=plan.request_sha256,
            route_status=plan.route_status,
            status=plan.status,
            steps=plan.steps,
            registry_fingerprint=plan.registry_fingerprint,
            reason_codes=plan.reason_codes,
        )
        if plan.plan_fingerprint != expected:
            raise SecurityOperationPlanError("INVOCATION_PLAN_FINGERPRINT_TAMPERED")

    def _validate_request_for_handler(
        self,
        handler_id: str,
        request: SecurityTypedInvocationRequest,
    ) -> SecurityTypedInvocationRequest:
        if handler_id in {"monitoring.dispatch.snmpv3_read", "monitoring.dispatch.local_net_read"}:
            if not isinstance(request, CollectorInvocationRequest):
                raise SecurityOperationInvocationDenied("INVOCATION_REQUEST_TYPE_MISMATCH")
            return request.validate()
        if handler_id == "monitoring.passive_jsonl.read_batch":
            if not isinstance(request, PassiveTelemetryInvocationRequest):
                raise SecurityOperationInvocationDenied("INVOCATION_REQUEST_TYPE_MISMATCH")
            return request.validate()
        if handler_id == "analysis.dns_behavior.extract_features":
            if not isinstance(request, DNSAnalysisInvocationRequest):
                raise SecurityOperationInvocationDenied("INVOCATION_REQUEST_TYPE_MISMATCH")
            return request.validate()
        if handler_id == FLOW_ANALYSIS_HANDLER_ID:
            if not isinstance(request, FlowAnalysisInvocationRequest):
                raise SecurityOperationInvocationDenied("INVOCATION_REQUEST_TYPE_MISMATCH")
            return request.validate()
        if handler_id == "analysis.local_ai_analyst.analyze":
            if not isinstance(request, AnalystInvocationRequest):
                raise SecurityOperationInvocationDenied("INVOCATION_REQUEST_TYPE_MISMATCH")
            return request.validate()
        raise SecurityOperationInvocationDenied("INVOCATION_HANDLER_NOT_ADMITTED_V05")

    def _trusted_asset(self, asset_id: str) -> AssetInventoryRecord:
        asset = self.assets.get(asset_id)
        if asset is None:
            raise SecurityOperationInvocationDenied("INVOCATION_ASSET_NOT_IN_TRUSTED_INVENTORY")
        asset.validate()
        if not asset.enabled:
            raise SecurityOperationInvocationDenied("INVOCATION_ASSET_DISABLED")
        return asset

    def _authorize(
        self,
        step: SecurityOperationStep,
        handler_id: str,
        request: SecurityTypedInvocationRequest,
    ) -> SecurityOperationAuthorization:
        if step.authority_domain == "internal":
            if handler_id == FLOW_ANALYSIS_HANDLER_ID:
                expected_scope = (
                    _FLOW_ANALYSIS_KEY[0],
                    _FLOW_ANALYSIS_KEY[1],
                    "network.flow",
                    "L1",
                    "internal",
                    None,
                    "compute",
                    "ready_internal",
                )
                actual_scope = (
                    step.capability_id,
                    step.operation_id,
                    step.taxonomy_id,
                    step.authority_level,
                    step.authority_domain,
                    step.backend_capability,
                    step.effect,
                    step.preflight_state,
                )
                if actual_scope != expected_scope:
                    raise SecurityOperationInvocationDenied("INVOCATION_FLOW_ANALYSIS_SCOPE_MISMATCH")
            return self.compiler.authorize_internal_step(step)
        if step.authority_domain != "monitoring":
            raise SecurityOperationInvocationDenied("INVOCATION_TASK_DOMAIN_NOT_ADMITTED_V05")
        if self.monitoring_engine is None:
            raise SecurityOperationInvocationDenied("INVOCATION_MONITORING_ENGINE_REQUIRED")

        if isinstance(request, CollectorInvocationRequest):
            asset = self._trusted_asset(request.asset_id)
            expected_backend = {
                "monitoring.dispatch.snmpv3_read": "snmpv3_read",
                "monitoring.dispatch.local_net_read": "local_net_read",
            }.get(handler_id)
            if step.backend_capability != expected_backend:
                raise SecurityOperationInvocationDenied("INVOCATION_HANDLER_BACKEND_MISMATCH")
            credential = asset.credential_ref if expected_backend == "snmpv3_read" else None
            return self.compiler.require_monitoring_step_authority(
                self.monitoring_engine,
                asset,
                step,
                target_host=asset.management_host,
                credential_ref=credential,
            )

        if isinstance(request, PassiveTelemetryInvocationRequest):
            asset = self._trusted_asset(request.asset_id)
            if step.backend_capability != "fixed_readonly_adapter":
                raise SecurityOperationInvocationDenied("INVOCATION_HANDLER_BACKEND_MISMATCH")
            if request.source_id not in self.passive_adapters:
                raise SecurityOperationInvocationDenied("INVOCATION_PASSIVE_SOURCE_NOT_CONFIGURED")
            if self.passive_source_assets.get(request.source_id) != asset.asset_id:
                raise SecurityOperationInvocationDenied("INVOCATION_PASSIVE_SOURCE_ASSET_MISMATCH")
            return self.compiler.require_monitoring_step_authority(
                self.monitoring_engine,
                asset,
                step,
                target_host=asset.management_host,
            )

        raise SecurityOperationInvocationDenied("INVOCATION_MONITORING_REQUEST_TYPE_MISMATCH")

    @staticmethod
    def _validate_authorization(
        step: SecurityOperationStep,
        authorization: SecurityOperationAuthorization,
    ) -> None:
        if not isinstance(authorization, SecurityOperationAuthorization) or not authorization.allowed:
            raise SecurityOperationInvocationDenied("INVOCATION_AUTHORITY_NOT_ALLOWED")
        expected_backend = step.backend_capability if step.backend_capability is not None else "internal_compute"
        expected = (
            step.capability_id,
            step.operation_id,
            step.taxonomy_id,
            step.authority_level,
            step.authority_domain,
            expected_backend,
            step.effect,
        )
        actual = (
            authorization.capability_id,
            authorization.operation_id,
            authorization.taxonomy_id,
            authorization.authority_level,
            authorization.authority_domain,
            authorization.backend_capability,
            authorization.effect,
        )
        if actual != expected:
            raise SecurityOperationInvocationDenied("INVOCATION_AUTHORITY_SCOPE_MISMATCH")
        if not _SHA256_RE.fullmatch(str(authorization.authority_fingerprint or "")):
            raise SecurityOperationInvocationDenied("INVOCATION_AUTHORITY_FINGERPRINT_INVALID")

    def _call_handler(
        self,
        handler_id: str,
        step: SecurityOperationStep,
        request: SecurityTypedInvocationRequest,
    ) -> Any:
        if handler_id in {"monitoring.dispatch.snmpv3_read", "monitoring.dispatch.local_net_read"}:
            if self.dispatcher is None or not isinstance(request, CollectorInvocationRequest):
                raise SecurityOperationInvocationDenied("INVOCATION_TYPED_DISPATCHER_REQUIRED")
            asset = self._trusted_asset(request.asset_id)
            backend = step.backend_capability
            if backend not in {"snmpv3_read", "local_net_read"}:
                raise SecurityOperationInvocationDenied("INVOCATION_HANDLER_BACKEND_MISMATCH")
            payload = [asset.asset_id, backend, asset.management_host]
            work_item = CollectorWorkItem(
                work_id="work-" + sha256_fingerprint(payload).split(":", 1)[1][:24],
                asset_id=asset.asset_id,
                capability=backend,
                target_host=asset.management_host,
                credential_ref=asset.credential_ref if backend == "snmpv3_read" else None,
            )
            result = self.dispatcher(work_item, asset, request.run_id, request.observed_at)
            if not isinstance(result, CollectorResult):
                raise SecurityOperationInvocationError("reviewed dispatcher returned unexpected type")
            return result

        if handler_id == "monitoring.passive_jsonl.read_batch":
            if not isinstance(request, PassiveTelemetryInvocationRequest):
                raise SecurityOperationInvocationDenied("INVOCATION_REQUEST_TYPE_MISMATCH")
            adapter = self.passive_adapters.get(request.source_id)
            if adapter is None:
                raise SecurityOperationInvocationDenied("INVOCATION_PASSIVE_SOURCE_NOT_CONFIGURED")
            return adapter.read_batch(evaluated_at=request.evaluated_at)

        if handler_id == "analysis.dns_behavior.extract_features":
            if not isinstance(request, DNSAnalysisInvocationRequest):
                raise SecurityOperationInvocationDenied("INVOCATION_REQUEST_TYPE_MISMATCH")
            return extract_dns_behavior_features(
                event_id=request.event_id,
                source_type=request.source_type,
                raw_line=request.raw_line,
            )

        if handler_id == FLOW_ANALYSIS_HANDLER_ID:
            if not isinstance(request, FlowAnalysisInvocationRequest):
                raise SecurityOperationInvocationDenied("INVOCATION_REQUEST_TYPE_MISMATCH")
            result = analyze_flow_evidence(request.events)
            if not isinstance(result, FlowEvidenceAnalysis):
                raise SecurityOperationInvocationError("flow analysis reviewed handler returned unexpected type")
            return result

        if handler_id == "analysis.local_ai_analyst.analyze":
            if self.analyst is None or not isinstance(request, AnalystInvocationRequest):
                raise SecurityOperationInvocationDenied("INVOCATION_LOCAL_ANALYST_REQUIRED")
            return self.analyst.analyze(
                request.report,
                enabled=request.enabled,
                network_triage=request.network_triage,
            )

        raise SecurityOperationInvocationDenied("INVOCATION_HANDLER_NOT_ADMITTED_V05")

    def _receipt(
        self,
        *,
        plan: SecurityOperationPlan,
        step: SecurityOperationStep,
        handler_id: str,
        handler_kind: str,
        input_fingerprint: str,
        authorization: SecurityOperationAuthorization,
    ) -> SecurityInvocationReceipt:
        payload = {
            "plan_fingerprint": plan.plan_fingerprint,
            "step_id": step.step_id,
            "capability_id": step.capability_id,
            "operation_id": step.operation_id,
            "handler_id": handler_id,
            "handler_kind": handler_kind,
            "input_fingerprint": input_fingerprint,
            "authority_domain": step.authority_domain,
            "authority_fingerprint": authorization.authority_fingerprint,
            "authority_reason_code": authorization.reason_code,
            "registry_fingerprint": self.registry.fingerprint,
            "binding_fingerprint": self.binding_registry.fingerprint,
            "output_kind": _HANDLER_OUTPUT_KINDS[handler_id],
            "status": "completed",
            "schema_version": SECURITY_INVOCATION_RECEIPT_SCHEMA,
        }
        invocation_id = "invoke-" + sha256_fingerprint(payload).split(":", 1)[1][:24]
        return SecurityInvocationReceipt(
            invocation_id=invocation_id,
            **{k: v for k, v in payload.items() if k != "schema_version"},
        ).validate()

    def _flow_receipt(
        self,
        *,
        plan: SecurityOperationPlan,
        step: SecurityOperationStep,
        input_fingerprint: str,
        output_fingerprint: str,
        authority: SecurityOperationAuthorization,
    ) -> FlowAnalysisInvocationReceipt:
        payload = {
            "schema_version": FLOW_ANALYSIS_INVOCATION_RECEIPT_SCHEMA,
            "plan_fingerprint": plan.plan_fingerprint,
            "step_id": step.step_id,
            "capability_id": step.capability_id,
            "operation_id": step.operation_id,
            "handler_id": FLOW_ANALYSIS_HANDLER_ID,
            "handler_kind": "pure_function",
            "input_fingerprint": input_fingerprint,
            "output_fingerprint": output_fingerprint,
            "authority_domain": "internal",
            "authority_fingerprint": authority.authority_fingerprint,
            "authority_reason_code": authority.reason_code,
            "registry_fingerprint": self.registry.fingerprint,
            "binding_fingerprint": self.binding_registry.fingerprint,
            "output_kind": FLOW_ANALYSIS_OUTPUT_KIND,
            "status": "completed",
        }
        invocation_id = "invoke-" + sha256_fingerprint(payload).split(":", 1)[1][:24]
        return FlowAnalysisInvocationReceipt(
            invocation_id=invocation_id,
            **{key: value for key, value in payload.items() if key != "schema_version"},
        ).validate()

    @property
    def runtime_fingerprint(self) -> str:
        payload = {
            "registry_fingerprint": self.registry.fingerprint,
            "binding_fingerprint": self.binding_registry.fingerprint,
            "monitoring_policy_fingerprint": (
                self.monitoring_engine.policy.fingerprint if self.monitoring_engine is not None else None
            ),
            "asset_fingerprints": {
                asset_id: asset.fingerprint for asset_id, asset in sorted(self.assets.items())
            },
            "passive_source_assets": dict(sorted(self.passive_source_assets.items())),
            "handler_availability": {
                handler_id: reviewed_runtime_handler_exists(handler_id)
                for handler_id in sorted(_HANDLER_OUTPUT_KINDS)
            },
        }
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return _sha_text(canonical)
