from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import timezone
from typing import Iterable

from .contracts import MonitoringContractError, sha256_fingerprint
from .correlation_graph import CorrelationEvent, STAGE_DNS, STAGE_FLOW
from .dns_behavior import DNSBehaviorFeatures

RULE_RARE_DNS = "RARE_DNS_QUERY_V1"
RULE_RARE_PEER = "RARE_DESTINATION_PEER_V1"
RULE_RARE_SERVICE = "RARE_DESTINATION_SERVICE_V1"
RULE_DNS_ENTROPY = "HIGH_ENTROPY_DNS_V1"
RULE_DNS_CARDINALITY = "DNS_QUERY_CARDINALITY_BURST_V1"
RULE_DNS_NXDOMAIN = "DNS_NXDOMAIN_RATIO_BURST_V1"
_SCOPE_ENTITY_RE = re.compile(r"^entity:[a-z]+:sha256:[0-9a-f]{64}$")
_SCOPE_ASSET_RE = re.compile(r"^asset:[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,127}$")


@dataclass(frozen=True)
class BehaviorBaselineConfig:
    history_bucket_seconds: int = 3600
    min_history_events: int = 20
    min_history_buckets: int = 6
    rare_max_occurrences: int = 1
    min_entropy_query_length: int = 20
    min_shannon_entropy: float = 3.5
    min_normalized_entropy: float = 0.72
    min_current_dns_events: int = 10
    dns_cardinality_threshold: int = 20
    nxdomain_ratio_threshold: float = 0.5
    max_events: int = 10000
    max_dns_features: int = 10000
    max_assessments: int = 2000

    def validate(self) -> "BehaviorBaselineConfig":
        if not 60 <= int(self.history_bucket_seconds) <= 86400:
            raise MonitoringContractError("history bucket must be within 60..86400 seconds")
        if not 3 <= int(self.min_history_events) <= 10000:
            raise MonitoringContractError("min_history_events must be within 3..10000")
        if not 2 <= int(self.min_history_buckets) <= 1000:
            raise MonitoringContractError("min_history_buckets must be within 2..1000")
        if not 0 <= int(self.rare_max_occurrences) <= 1000:
            raise MonitoringContractError("rare_max_occurrences must be within 0..1000")
        if not 5 <= int(self.min_entropy_query_length) <= 253:
            raise MonitoringContractError("minimum entropy query length is invalid")
        if not 0.0 <= float(self.min_shannon_entropy) <= 8.0:
            raise MonitoringContractError("Shannon entropy threshold is invalid")
        if not 0.0 <= float(self.min_normalized_entropy) <= 1.0:
            raise MonitoringContractError("normalized entropy threshold is invalid")
        if not 2 <= int(self.min_current_dns_events) <= 1000:
            raise MonitoringContractError("min_current_dns_events must be within 2..1000")
        if not 2 <= int(self.dns_cardinality_threshold) <= 10000:
            raise MonitoringContractError("DNS cardinality threshold is invalid")
        if not 0.05 <= float(self.nxdomain_ratio_threshold) <= 1.0:
            raise MonitoringContractError("NXDOMAIN ratio threshold is invalid")
        if not 1 <= int(self.max_events) <= 50000:
            raise MonitoringContractError("behavior max_events must be within 1..50000")
        if not 1 <= int(self.max_dns_features) <= 50000:
            raise MonitoringContractError("behavior max_dns_features must be within 1..50000")
        if not 1 <= int(self.max_assessments) <= 10000:
            raise MonitoringContractError("behavior max_assessments must be within 1..10000")
        return self


@dataclass(frozen=True, order=True)
class BehaviorAssessment:
    assessment_id: str
    rule_id: str
    status: str
    severity: str
    event_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    entity_refs: tuple[str, ...]
    scope_entity_ref: str | None = None
    baseline_occurrences: int | None = None
    baseline_buckets: int | None = None
    metric_name: str | None = None
    metric_value: float | None = None
    threshold: float | None = None
    authority: str = "advisory"
    schema_version: str = "workspace-security-monitoring/behavior-assessment-v1"

    def validate(self) -> "BehaviorAssessment":
        if self.status not in {"normal", "signal", "data_gap"}:
            raise MonitoringContractError("unsupported behavior assessment status")
        if self.severity not in {"info", "low", "medium", "high"}:
            raise MonitoringContractError("unsupported behavior assessment severity")
        if self.authority != "advisory":
            raise MonitoringContractError("behavior assessment authority must remain advisory")
        if not self.event_ids or len(self.event_ids) > 256:
            raise MonitoringContractError("behavior assessment event refs are outside bounds")
        if len(self.evidence_refs) > 256 or len(self.entity_refs) > 64:
            raise MonitoringContractError("behavior assessment reference bound exceeded")
        if self.scope_entity_ref is not None:
            scope = str(self.scope_entity_ref)
            if not (_SCOPE_ENTITY_RE.fullmatch(scope) or _SCOPE_ASSET_RE.fullmatch(scope)):
                raise MonitoringContractError("behavior assessment scope must be an opaque entity or approved asset ref")
            if scope not in self.entity_refs:
                raise MonitoringContractError("behavior assessment scope must be present in entity_refs")
        if self.baseline_occurrences is not None and self.baseline_occurrences < 0:
            raise MonitoringContractError("baseline occurrences must be non-negative")
        if self.baseline_buckets is not None and self.baseline_buckets < 0:
            raise MonitoringContractError("baseline buckets must be non-negative")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "assessment_id": self.assessment_id,
            "rule_id": self.rule_id,
            "status": self.status,
            "severity": self.severity,
            "event_ids": list(self.event_ids),
            "evidence_refs": list(self.evidence_refs),
            "entity_refs": list(self.entity_refs),
            "scope_entity_ref": self.scope_entity_ref,
            "baseline_occurrences": self.baseline_occurrences,
            "baseline_buckets": self.baseline_buckets,
            "metric_name": self.metric_name,
            "metric_value": self.metric_value,
            "threshold": self.threshold,
            "authority": self.authority,
        }


def _identity(item: CorrelationEvent) -> tuple[object, ...]:
    item.validate()
    return (
        item.event.event_id,
        item.event.source_id,
        item.event.source_type,
        item.event.observed_at,
        item.event.category,
        item.event.severity,
        item.event.message_sha256,
        item.event.parser_version,
        item.event.evidence_ref,
        tuple(item.context.references),
    )


def _dedupe_events(events: Iterable[CorrelationEvent], *, limit: int) -> tuple[CorrelationEvent, ...]:
    unique: dict[str, CorrelationEvent] = {}
    for raw in events:
        item = raw.validate()
        previous = unique.get(item.event.event_id)
        if previous is not None:
            if _identity(previous) != _identity(item):
                raise MonitoringContractError("behavior duplicate event_id has conflicting context")
            continue
        unique[item.event.event_id] = item
        if len(unique) > limit:
            raise MonitoringContractError("behavior event bound exceeded")
    return tuple(sorted(unique.values(), key=lambda item: (item.observed, item.event.event_id)))


def _initiators(item: CorrelationEvent) -> tuple[str, ...]:
    assets = item.context.refs_for_role("asset")
    return assets if assets else item.context.refs_for_role("source_ip")


def _targets(item: CorrelationEvent) -> tuple[tuple[str, str, str], ...]:
    result: list[tuple[str, str, str]] = []
    if item.stage == STAGE_DNS:
        result.extend((RULE_RARE_DNS, "dns_query", ref) for ref in item.context.refs_for_role("dns_query"))
    if item.stage == STAGE_FLOW:
        result.extend((RULE_RARE_PEER, "destination_ip", ref) for ref in item.context.refs_for_role("destination_ip"))
        result.extend((RULE_RARE_SERVICE, "service", ref) for ref in item.context.refs_for_role("service"))
    return tuple(result)


def _bucket(item: CorrelationEvent, seconds: int) -> int:
    timestamp = item.observed.astimezone(timezone.utc).timestamp()
    return int(timestamp // seconds)


def _assessment(
    *,
    rule_id: str,
    status: str,
    severity: str,
    event_ids: Iterable[str],
    evidence_refs: Iterable[str],
    entity_refs: Iterable[str],
    scope_entity_ref: str | None = None,
    baseline_occurrences: int | None = None,
    baseline_buckets: int | None = None,
    metric_name: str | None = None,
    metric_value: float | None = None,
    threshold: float | None = None,
) -> BehaviorAssessment:
    all_events = tuple(sorted(set(event_ids)))
    all_evidence = tuple(sorted(set(ref for ref in evidence_refs if ref)))
    all_entities = tuple(sorted(set(entity_refs)))
    if not all_events:
        raise MonitoringContractError("behavior assessment requires at least one event reference")
    identity = {
        "rule_id": rule_id,
        "status": status,
        "severity": severity,
        "event_ids": list(all_events),
        "evidence_refs": list(all_evidence),
        "entity_refs": list(all_entities),
        "scope_entity_ref": scope_entity_ref,
        "baseline_occurrences": baseline_occurrences,
        "baseline_buckets": baseline_buckets,
        "metric_name": metric_name,
        "metric_value": metric_value,
        "threshold": threshold,
        "authority": "advisory",
    }
    assessment_id = "behavior-" + sha256_fingerprint(identity).split(":", 1)[1][:24]
    return BehaviorAssessment(
        assessment_id=assessment_id,
        rule_id=rule_id,
        status=status,
        severity=severity,
        event_ids=all_events[:256],
        evidence_refs=all_evidence[:256],
        entity_refs=all_entities[:64],
        scope_entity_ref=scope_entity_ref,
        baseline_occurrences=baseline_occurrences,
        baseline_buckets=baseline_buckets,
        metric_name=metric_name,
        metric_value=metric_value,
        threshold=threshold,
    ).validate()


class DeterministicBehaviorAnalyzer:
    """Pure metadata analyzer for rarity and bounded DNS behavior signals."""

    def __init__(self, config: BehaviorBaselineConfig | None = None):
        self.config = (config or BehaviorBaselineConfig()).validate()

    def analyze(
        self,
        *,
        current_events: Iterable[CorrelationEvent],
        history_events: Iterable[CorrelationEvent],
        current_dns_features: Iterable[DNSBehaviorFeatures] = (),
    ) -> tuple[BehaviorAssessment, ...]:
        current = _dedupe_events(current_events, limit=self.config.max_events)
        history = _dedupe_events(history_events, limit=self.config.max_events)

        current_by_id = {item.event.event_id: item for item in current}
        feature_by_event: dict[str, DNSBehaviorFeatures] = {}
        for raw in current_dns_features:
            feature = raw.validate()
            previous = feature_by_event.get(feature.event_id)
            if previous is not None and previous != feature:
                raise MonitoringContractError("conflicting DNS behavior feature replay")
            feature_by_event[feature.event_id] = feature
            if len(feature_by_event) > self.config.max_dns_features:
                raise MonitoringContractError("DNS behavior feature bound exceeded")
        for event_id, feature in feature_by_event.items():
            item = current_by_id.get(event_id)
            if item is None or item.stage != STAGE_DNS:
                raise MonitoringContractError("DNS behavior feature must bind a current DNS event")
            if feature.query_entity_ref not in item.context.refs_for_role("dns_query"):
                raise MonitoringContractError("DNS behavior feature query ref mismatches event context")

        history_counts: Counter[tuple[str, str, str]] = Counter()
        baseline_events: Counter[tuple[str, str]] = Counter()
        baseline_buckets: dict[tuple[str, str], set[int]] = defaultdict(set)
        for item in history:
            initiators = _initiators(item)
            targets = _targets(item)
            target_roles = {role for _rule_id, role, _target in targets}
            for initiator in initiators:
                for role in target_roles:
                    key = (initiator, role)
                    baseline_events[key] += 1
                    baseline_buckets[key].add(_bucket(item, self.config.history_bucket_seconds))
                for _rule_id, role, target in targets:
                    history_counts[(initiator, role, target)] += 1

        assessments: list[BehaviorAssessment] = []
        for item in current:
            initiators = _initiators(item)
            for rule_id, role, target in _targets(item):
                for initiator in initiators:
                    baseline_key = (initiator, role)
                    history_event_count = baseline_events[baseline_key]
                    bucket_count = len(baseline_buckets[baseline_key])
                    warm = (
                        history_event_count >= self.config.min_history_events
                        and bucket_count >= self.config.min_history_buckets
                    )
                    occurrences = history_counts[(initiator, role, target)]
                    if not warm:
                        status, severity = "data_gap", "info"
                    elif occurrences <= self.config.rare_max_occurrences:
                        status, severity = "signal", "low"
                    else:
                        status, severity = "normal", "info"
                    assessments.append(
                        _assessment(
                            rule_id=rule_id,
                            status=status,
                            severity=severity,
                            event_ids=(item.event.event_id,),
                            evidence_refs=(item.event.evidence_ref or "",),
                            entity_refs=(initiator, target),
                            scope_entity_ref=initiator,
                            baseline_occurrences=occurrences,
                            baseline_buckets=bucket_count,
                            metric_name="historical_occurrences",
                            metric_value=float(occurrences),
                            threshold=float(self.config.rare_max_occurrences),
                        )
                    )

        dns_by_initiator: dict[str, list[tuple[CorrelationEvent, DNSBehaviorFeatures]]] = defaultdict(list)
        for event_id, feature in feature_by_event.items():
            item = current_by_id[event_id]
            initiators = _initiators(item)
            for initiator in initiators:
                dns_by_initiator[initiator].append((item, feature))
            if (
                feature.query_length >= self.config.min_entropy_query_length
                and feature.shannon_entropy >= self.config.min_shannon_entropy
                and feature.normalized_entropy >= self.config.min_normalized_entropy
            ):
                if initiators:
                    for initiator in initiators:
                        assessments.append(
                            _assessment(
                                rule_id=RULE_DNS_ENTROPY,
                                status="signal",
                                severity="medium",
                                event_ids=(event_id,),
                                evidence_refs=(item.event.evidence_ref or "",),
                                entity_refs=(initiator, feature.query_entity_ref),
                                scope_entity_ref=initiator,
                                metric_name="shannon_entropy",
                                metric_value=feature.shannon_entropy,
                                threshold=self.config.min_shannon_entropy,
                            )
                        )
                else:
                    assessments.append(
                        _assessment(
                            rule_id=RULE_DNS_ENTROPY,
                            status="signal",
                            severity="medium",
                            event_ids=(event_id,),
                            evidence_refs=(item.event.evidence_ref or "",),
                            entity_refs=(feature.query_entity_ref,),
                            metric_name="shannon_entropy",
                            metric_value=feature.shannon_entropy,
                            threshold=self.config.min_shannon_entropy,
                        )
                    )

        for initiator, entries in dns_by_initiator.items():
            if len(entries) < self.config.min_current_dns_events:
                continue
            event_ids = tuple(item.event.event_id for item, _ in entries)
            evidence = tuple(item.event.evidence_ref or "" for item, _ in entries)
            query_refs = {feature.query_entity_ref for _, feature in entries}
            if len(query_refs) >= self.config.dns_cardinality_threshold:
                assessments.append(
                    _assessment(
                        rule_id=RULE_DNS_CARDINALITY,
                        status="signal",
                        severity="medium",
                        event_ids=event_ids,
                        evidence_refs=evidence,
                        entity_refs=(initiator, *sorted(query_refs)),
                        scope_entity_ref=initiator,
                        metric_name="distinct_dns_queries",
                        metric_value=float(len(query_refs)),
                        threshold=float(self.config.dns_cardinality_threshold),
                    )
                )
            nxdomain = sum(1 for _, feature in entries if feature.is_nxdomain)
            ratio = nxdomain / len(entries)
            if ratio >= self.config.nxdomain_ratio_threshold:
                assessments.append(
                    _assessment(
                        rule_id=RULE_DNS_NXDOMAIN,
                        status="signal",
                        severity="medium",
                        event_ids=event_ids,
                        evidence_refs=evidence,
                        entity_refs=(initiator,),
                        scope_entity_ref=initiator,
                        metric_name="nxdomain_ratio",
                        metric_value=round(ratio, 6),
                        threshold=self.config.nxdomain_ratio_threshold,
                    )
                )

        deduped = {assessment.assessment_id: assessment for assessment in assessments}
        if len(deduped) > self.config.max_assessments:
            raise MonitoringContractError("behavior assessment bound exceeded")
        return tuple(sorted(deduped.values()))
