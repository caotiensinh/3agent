from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .runtime_invocation import RuntimeInvocationBundle
from .runtime_plan_compiler import CompiledRuntimePlan

RUNTIME_READONLY_QUERY_PROFILE_SCHEMA = "workspace-runtime-readonly-query-profile/v1"
RUNTIME_QUERY_PARAMETER_SET_SCHEMA = "workspace-runtime-query-parameter-set/v1"
RUNTIME_READONLY_QUERY_BUNDLE_SCHEMA = "workspace-runtime-readonly-query-bundle/v1"
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#@+\-=]{0,127}$")
_PARAM_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_NAMED_PLACEHOLDER_RE = re.compile(r":([A-Za-z_][A-Za-z0-9_]*)")
_FORBIDDEN_SQL_RE = re.compile(
    r"(?i)\b(INSERT|UPDATE|DELETE|REPLACE|CREATE|ALTER|DROP|ATTACH|DETACH|PRAGMA|"
    r"VACUUM|REINDEX|ANALYZE|BEGIN|COMMIT|ROLLBACK|SAVEPOINT|RELEASE|LOAD_EXTENSION)\b"
)
_MAX_SQL_CHARS = 16_384
_MAX_PARAMETERS = 32
_MAX_PARAMETER_TEXT = 2_048


class RuntimeReadonlyQueryError(ValueError):
    """Reviewed query semantics are invalid or drift from typed invocation binding."""


def _canonical(payload: Any) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _sha(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _identifier(value: object, field: str) -> str:
    text = str(value or "").strip()
    if not text or not _ID_RE.fullmatch(text) or "://" in text:
        raise RuntimeReadonlyQueryError(f"QUERY_{field.upper()}_INVALID")
    return text


def _parameter_name(value: object) -> str:
    text = str(value or "").strip()
    if not _PARAM_RE.fullmatch(text):
        raise RuntimeReadonlyQueryError("QUERY_PARAMETER_NAME_INVALID")
    return text


def _parameter_value(value: object) -> str | int | float | bool | None:
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise RuntimeReadonlyQueryError("QUERY_PARAMETER_VALUE_INVALID")
        return value
    if isinstance(value, str):
        if len(value) > _MAX_PARAMETER_TEXT or "\x00" in value:
            raise RuntimeReadonlyQueryError("QUERY_PARAMETER_VALUE_INVALID")
        return value
    raise RuntimeReadonlyQueryError("QUERY_PARAMETER_VALUE_TYPE_INVALID")


def _review_sql(sql: object, parameter_names: Iterable[str]) -> tuple[str, tuple[str, ...], str]:
    if not isinstance(sql, str):
        raise RuntimeReadonlyQueryError("QUERY_SQL_TYPE_INVALID")
    normalized = sql.strip()
    if normalized.endswith(";"):
        normalized = normalized[:-1].rstrip()
    if (
        not normalized
        or len(normalized) > _MAX_SQL_CHARS
        or "\x00" in normalized
        or ";" in normalized
    ):
        raise RuntimeReadonlyQueryError("QUERY_SQL_SHAPE_INVALID")
    if not re.match(r"(?is)^\s*(SELECT|WITH)\b", normalized):
        raise RuntimeReadonlyQueryError("QUERY_SQL_READONLY_REQUIRED")
    if _FORBIDDEN_SQL_RE.search(normalized):
        raise RuntimeReadonlyQueryError("QUERY_SQL_FORBIDDEN_TOKEN")
    if "?" in normalized or re.search(r"[@$][A-Za-z_]", normalized):
        raise RuntimeReadonlyQueryError("QUERY_SQL_NAMED_PARAMETERS_REQUIRED")

    names = tuple(_parameter_name(item) for item in parameter_names)
    if len(names) > _MAX_PARAMETERS or len(set(names)) != len(names):
        raise RuntimeReadonlyQueryError("QUERY_PARAMETER_NAMES_INVALID")
    placeholders = tuple(dict.fromkeys(_NAMED_PLACEHOLDER_RE.findall(normalized)))
    if set(placeholders) != set(names):
        raise RuntimeReadonlyQueryError("QUERY_SQL_PARAMETER_BINDING_MISMATCH")
    sql_sha = "sha256:" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return normalized, names, sql_sha


@dataclass(frozen=True)
class ReviewedReadonlyQueryProfile:
    profile_id: str
    sql_sha256: str
    parameter_names: tuple[str, ...]
    _sql: str
    schema_version: str = RUNTIME_READONLY_QUERY_PROFILE_SCHEMA

    @classmethod
    def compile(
        cls,
        profile_id: str,
        sql: str,
        *,
        parameter_names: Iterable[str] = (),
    ) -> "ReviewedReadonlyQueryProfile":
        profile = _identifier(profile_id, "profile_id")
        normalized, names, sql_sha = _review_sql(sql, parameter_names)
        return cls(
            profile_id=profile,
            sql_sha256=sql_sha,
            parameter_names=names,
            _sql=normalized,
        ).validate()

    @property
    def sql(self) -> str:
        return self._sql

    @property
    def fingerprint(self) -> str:
        return _sha(self.metadata())

    def validate(self) -> "ReviewedReadonlyQueryProfile":
        if self.schema_version != RUNTIME_READONLY_QUERY_PROFILE_SCHEMA:
            raise RuntimeReadonlyQueryError("QUERY_PROFILE_SCHEMA_UNSUPPORTED")
        profile = _identifier(self.profile_id, "profile_id")
        normalized, names, actual_sha = _review_sql(self._sql, self.parameter_names)
        if profile != self.profile_id or normalized != self._sql or names != self.parameter_names:
            raise RuntimeReadonlyQueryError("QUERY_PROFILE_NORMALIZATION_DRIFT")
        if actual_sha != self.sql_sha256:
            raise RuntimeReadonlyQueryError("QUERY_PROFILE_SQL_DIGEST_MISMATCH")
        return self

    def metadata(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "profile_id": self.profile_id,
            "sql_sha256": self.sql_sha256,
            "parameter_names": list(self.parameter_names),
        }


@dataclass(frozen=True)
class ReviewedQueryParameterSet:
    ref_id: str
    values_sha256: str
    _values: tuple[tuple[str, str | int | float | bool | None], ...]
    schema_version: str = RUNTIME_QUERY_PARAMETER_SET_SCHEMA

    @classmethod
    def compile(
        cls,
        ref_id: str,
        values: Mapping[str, object],
    ) -> "ReviewedQueryParameterSet":
        ref = _identifier(ref_id, "parameters_ref")
        if not isinstance(values, Mapping):
            raise RuntimeReadonlyQueryError("QUERY_PARAMETER_SET_MAPPING_REQUIRED")
        rows: list[tuple[str, str | int | float | bool | None]] = []
        seen: set[str] = set()
        for raw_key in values:
            if not isinstance(raw_key, str):
                raise RuntimeReadonlyQueryError("QUERY_PARAMETER_NAME_INVALID")
            key = _parameter_name(raw_key)
            if key in seen:
                raise RuntimeReadonlyQueryError("QUERY_PARAMETER_NAME_DUPLICATE")
            seen.add(key)
            rows.append((key, _parameter_value(values[raw_key])))
        if len(rows) > _MAX_PARAMETERS:
            raise RuntimeReadonlyQueryError("QUERY_PARAMETER_SET_TOO_LARGE")
        normalized = tuple(sorted(rows, key=lambda item: item[0]))
        digest = _sha({"values": [[key, value] for key, value in normalized]})
        return cls(ref, digest, normalized).validate()

    @property
    def values(self) -> dict[str, str | int | float | bool | None]:
        return dict(self._values)

    @property
    def fingerprint(self) -> str:
        return _sha(self.metadata())

    def validate(self) -> "ReviewedQueryParameterSet":
        if self.schema_version != RUNTIME_QUERY_PARAMETER_SET_SCHEMA:
            raise RuntimeReadonlyQueryError("QUERY_PARAMETER_SET_SCHEMA_UNSUPPORTED")
        ref = _identifier(self.ref_id, "parameters_ref")
        rows = tuple(
            sorted(
                ((_parameter_name(key), _parameter_value(value)) for key, value in self._values),
                key=lambda item: item[0],
            )
        )
        if ref != self.ref_id or rows != self._values or len(rows) > _MAX_PARAMETERS:
            raise RuntimeReadonlyQueryError("QUERY_PARAMETER_SET_INVALID")
        expected = _sha({"values": [[key, value] for key, value in rows]})
        if expected != self.values_sha256:
            raise RuntimeReadonlyQueryError("QUERY_PARAMETER_SET_DIGEST_MISMATCH")
        return self

    def metadata(self) -> dict[str, str]:
        return {
            "schema_version": self.schema_version,
            "ref_id": self.ref_id,
            "values_sha256": self.values_sha256,
        }


@dataclass(frozen=True)
class RuntimeReadonlyQueryBundle:
    task_id: str
    plan_id: str
    plan_fingerprint: str
    compiled_plan_fingerprint: str
    invocation_bundle_fingerprint: str
    profiles: tuple[ReviewedReadonlyQueryProfile, ...]
    parameter_sets: tuple[ReviewedQueryParameterSet, ...]
    schema_version: str = RUNTIME_READONLY_QUERY_BUNDLE_SCHEMA

    @classmethod
    def compile(
        cls,
        *,
        compiled_plan: CompiledRuntimePlan,
        invocation_bundle: RuntimeInvocationBundle,
        profiles: Iterable[ReviewedReadonlyQueryProfile],
        parameter_sets: Iterable[ReviewedQueryParameterSet] = (),
    ) -> "RuntimeReadonlyQueryBundle":
        invocation_bundle.validate(compiled_plan)
        bundle = cls(
            task_id=compiled_plan.plan.task_id,
            plan_id=compiled_plan.plan.plan_id,
            plan_fingerprint=compiled_plan.plan.fingerprint,
            compiled_plan_fingerprint=compiled_plan.fingerprint,
            invocation_bundle_fingerprint=invocation_bundle.fingerprint,
            profiles=tuple(profiles),
            parameter_sets=tuple(parameter_sets),
        )
        return bundle.validate(
            compiled_plan=compiled_plan,
            invocation_bundle=invocation_bundle,
        )

    @property
    def fingerprint(self) -> str:
        return _sha(self.metadata())

    def profile(self, profile_id: str) -> ReviewedReadonlyQueryProfile:
        key = str(profile_id).strip()
        for profile in self.profiles:
            if profile.profile_id == key:
                return profile
        raise RuntimeReadonlyQueryError("QUERY_PROFILE_NOT_IN_BUNDLE")

    def parameter_set(self, ref_id: str) -> ReviewedQueryParameterSet:
        key = str(ref_id).strip()
        for item in self.parameter_sets:
            if item.ref_id == key:
                return item
        raise RuntimeReadonlyQueryError("QUERY_PARAMETER_SET_NOT_IN_BUNDLE")

    def validate(
        self,
        *,
        compiled_plan: CompiledRuntimePlan,
        invocation_bundle: RuntimeInvocationBundle,
    ) -> "RuntimeReadonlyQueryBundle":
        invocation_bundle.validate(compiled_plan)
        checks = (
            (self.schema_version == RUNTIME_READONLY_QUERY_BUNDLE_SCHEMA, "QUERY_BUNDLE_SCHEMA_UNSUPPORTED"),
            (self.task_id == compiled_plan.plan.task_id, "QUERY_BUNDLE_TASK_MISMATCH"),
            (self.plan_id == compiled_plan.plan.plan_id, "QUERY_BUNDLE_PLAN_ID_MISMATCH"),
            (self.plan_fingerprint == compiled_plan.plan.fingerprint, "QUERY_BUNDLE_PLAN_CHANGED"),
            (self.compiled_plan_fingerprint == compiled_plan.fingerprint, "QUERY_BUNDLE_COMPILED_PLAN_CHANGED"),
            (self.invocation_bundle_fingerprint == invocation_bundle.fingerprint, "QUERY_BUNDLE_INVOCATION_CHANGED"),
        )
        for valid, code in checks:
            if not valid:
                raise RuntimeReadonlyQueryError(code)

        profile_ids = [profile.profile_id for profile in self.profiles]
        parameter_ids = [item.ref_id for item in self.parameter_sets]
        if len(profile_ids) != len(set(profile_ids)):
            raise RuntimeReadonlyQueryError("QUERY_BUNDLE_DUPLICATE_PROFILE")
        if len(parameter_ids) != len(set(parameter_ids)):
            raise RuntimeReadonlyQueryError("QUERY_BUNDLE_DUPLICATE_PARAMETER_SET")
        for profile in self.profiles:
            profile.validate()
        for item in self.parameter_sets:
            item.validate()

        query_nodes = [
            node for node in compiled_plan.plan.nodes if node.capability == "query_db_readonly"
        ]
        expected_profiles: set[str] = set()
        expected_parameter_sets: set[str] = set()
        for node in query_nodes:
            spec = invocation_bundle.for_node(node.node_id)
            if spec.capability != "query_db_readonly" or spec.operation != "query":
                raise RuntimeReadonlyQueryError("QUERY_BUNDLE_INVOCATION_INVALID")
            args = spec.argument_map()
            query_ref = str(args["query_ref"])
            expected_profiles.add(query_ref)
            profile = self.profile(query_ref)
            parameters_ref = args.get("parameters_ref")
            if profile.parameter_names:
                if parameters_ref is None:
                    raise RuntimeReadonlyQueryError("QUERY_PARAMETERS_REF_REQUIRED")
                ref = str(parameters_ref)
                expected_parameter_sets.add(ref)
                params = self.parameter_set(ref)
                if set(params.values) != set(profile.parameter_names):
                    raise RuntimeReadonlyQueryError("QUERY_PARAMETER_KEYS_MISMATCH")
            elif parameters_ref is not None:
                raise RuntimeReadonlyQueryError("QUERY_PARAMETERS_REF_UNEXPECTED")

        if set(profile_ids) != expected_profiles:
            raise RuntimeReadonlyQueryError("QUERY_BUNDLE_PROFILE_COVERAGE_MISMATCH")
        if set(parameter_ids) != expected_parameter_sets:
            raise RuntimeReadonlyQueryError("QUERY_BUNDLE_PARAMETER_COVERAGE_MISMATCH")
        return self

    def metadata(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "plan_id": self.plan_id,
            "plan_fingerprint": self.plan_fingerprint,
            "compiled_plan_fingerprint": self.compiled_plan_fingerprint,
            "invocation_bundle_fingerprint": self.invocation_bundle_fingerprint,
            "profiles": [
                profile.metadata()
                for profile in sorted(self.profiles, key=lambda item: item.profile_id)
            ],
            "parameter_sets": [
                item.metadata()
                for item in sorted(self.parameter_sets, key=lambda value: value.ref_id)
            ],
        }
