from __future__ import annotations

import ast
import hashlib
import math
import operator
import re
from dataclasses import dataclass
from typing import Protocol

from .inference_scope import current_capability_authority
from .resource_events import ResourceEventRecorder
from .runtime_capability_boundary import require_runtime_capability
from .runtime_execution_plan import ExecutionNode

RUNTIME_REVIEWED_CALCULATOR_SCHEMA = "workspace-runtime-reviewed-calculator/v1"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVIDENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#@+\-=]{0,255}$")
_MAX_EXPRESSION_CHARS = 2048
_MAX_AST_NODES = 128
_MAX_AST_DEPTH = 32
_MAX_INT_BITS = 4096
_MAX_ABS_FLOAT = 1e100
_MAX_EXPONENT = 12


class ReviewedCalculatorError(RuntimeError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


class CalculatorEvidenceSink(Protocol):
    def persist_calculation(
        self,
        *,
        task_id: str,
        node_id: str,
        expression_sha256: str,
        result: int | float,
        result_sha256: str,
    ) -> tuple[str, ...]: ...


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _validate_refs(values: tuple[str, ...]) -> tuple[str, ...]:
    refs: list[str] = []
    for value in values:
        ref = str(value).strip()
        if not ref or not _EVIDENCE_RE.fullmatch(ref) or "://" in ref:
            raise ReviewedCalculatorError("CALCULATOR_EVIDENCE_REF_INVALID")
        if ref not in refs:
            refs.append(ref)
        if len(refs) > 32:
            raise ReviewedCalculatorError("CALCULATOR_EVIDENCE_REF_LIMIT_EXCEEDED")
    return tuple(refs)


def _result_text(value: int | float) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ReviewedCalculatorError("CALCULATOR_RESULT_TYPE_INVALID")
    if isinstance(value, int):
        if value.bit_length() > _MAX_INT_BITS:
            raise ReviewedCalculatorError("CALCULATOR_RESULT_MAGNITUDE_EXCEEDED")
        return str(value)
    if not math.isfinite(value) or abs(value) > _MAX_ABS_FLOAT:
        raise ReviewedCalculatorError("CALCULATOR_RESULT_MAGNITUDE_EXCEEDED")
    return repr(value)


def _validate_ast(tree: ast.AST) -> None:
    nodes = list(ast.walk(tree))
    if len(nodes) > _MAX_AST_NODES:
        raise ReviewedCalculatorError("CALCULATOR_AST_NODE_LIMIT_EXCEEDED")

    allowed = (
        ast.Expression,
        ast.BinOp,
        ast.UnaryOp,
        ast.Constant,
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.Div,
        ast.FloorDiv,
        ast.Mod,
        ast.Pow,
        ast.UAdd,
        ast.USub,
    )
    for node in nodes:
        if not isinstance(node, allowed):
            raise ReviewedCalculatorError("CALCULATOR_AST_NODE_FORBIDDEN")
        if isinstance(node, ast.Constant):
            value = node.value
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ReviewedCalculatorError("CALCULATOR_LITERAL_TYPE_INVALID")
            _result_text(value)

    def depth(node: ast.AST, level: int = 1) -> None:
        if level > _MAX_AST_DEPTH:
            raise ReviewedCalculatorError("CALCULATOR_AST_DEPTH_EXCEEDED")
        for child in ast.iter_child_nodes(node):
            depth(child, level + 1)

    depth(tree)


_BINOPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
}


def _evaluate(node: ast.AST) -> int | float:
    if isinstance(node, ast.Expression):
        return _evaluate(node.body)
    if isinstance(node, ast.Constant):
        value = node.value
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ReviewedCalculatorError("CALCULATOR_LITERAL_TYPE_INVALID")
        _result_text(value)
        return value
    if isinstance(node, ast.UnaryOp):
        value = _evaluate(node.operand)
        result = value if isinstance(node.op, ast.UAdd) else -value
        _result_text(result)
        return result
    if isinstance(node, ast.BinOp):
        left = _evaluate(node.left)
        right = _evaluate(node.right)
        try:
            if isinstance(node.op, ast.Pow):
                if isinstance(right, bool) or not isinstance(right, int) or abs(right) > _MAX_EXPONENT:
                    raise ReviewedCalculatorError("CALCULATOR_EXPONENT_LIMIT_EXCEEDED")
                if right < 0 and left == 0:
                    raise ReviewedCalculatorError("CALCULATOR_DIVISION_BY_ZERO")
                result = operator.pow(left, right)
            else:
                operation = _BINOPS.get(type(node.op))
                if operation is None:
                    raise ReviewedCalculatorError("CALCULATOR_OPERATOR_FORBIDDEN")
                result = operation(left, right)
        except ZeroDivisionError as exc:
            raise ReviewedCalculatorError("CALCULATOR_DIVISION_BY_ZERO") from exc
        except OverflowError as exc:
            raise ReviewedCalculatorError("CALCULATOR_RESULT_MAGNITUDE_EXCEEDED") from exc
        _result_text(result)
        return result
    raise ReviewedCalculatorError("CALCULATOR_AST_NODE_FORBIDDEN")


@dataclass(frozen=True)
class ReviewedCalculationResult:
    expression_sha256: str
    result: int | float
    result_sha256: str
    evidence_refs: tuple[str, ...]
    schema_version: str = RUNTIME_REVIEWED_CALCULATOR_SCHEMA

    def validate(self) -> "ReviewedCalculationResult":
        if not _SHA256_RE.fullmatch(str(self.expression_sha256)):
            raise ReviewedCalculatorError("CALCULATOR_EXPRESSION_DIGEST_INVALID")
        text = _result_text(self.result)
        if _sha256(text.encode("utf-8")) != self.result_sha256:
            raise ReviewedCalculatorError("CALCULATOR_RESULT_DIGEST_MISMATCH")
        _validate_refs(tuple(self.evidence_refs))
        return self


class ReviewedCalculatorBoundary:
    """Deterministic arithmetic boundary with no eval/name/call authority."""

    def __init__(
        self,
        *,
        evidence_sink: CalculatorEvidenceSink | None = None,
        recorder: ResourceEventRecorder | None = None,
    ):
        if evidence_sink is not None and not callable(
            getattr(evidence_sink, "persist_calculation", None)
        ):
            raise ReviewedCalculatorError("CALCULATOR_EVIDENCE_SINK_INVALID")
        self.evidence_sink = evidence_sink
        self.recorder = recorder

    def evaluate(
        self,
        *,
        task_id: str,
        node: ExecutionNode,
        expression: str,
    ) -> ReviewedCalculationResult:
        if (
            node.capability != "calculator"
            or node.effect != "compute"
            or node.resource_kind != "compute"
        ):
            raise ReviewedCalculatorError("CALCULATOR_NODE_UNSUPPORTED")
        if node.resource_ref != "deterministic_math":
            raise ReviewedCalculatorError("CALCULATOR_RESOURCE_UNSUPPORTED")
        if not isinstance(expression, str):
            raise ReviewedCalculatorError("CALCULATOR_EXPRESSION_TYPE_INVALID")
        normalized = expression.strip()
        if (
            not normalized
            or len(normalized) > _MAX_EXPRESSION_CHARS
            or "\x00" in normalized
        ):
            raise ReviewedCalculatorError("CALCULATOR_EXPRESSION_INVALID")

        authority = current_capability_authority()
        if authority is None:
            raise ReviewedCalculatorError("CALCULATOR_NODE_AUTHORITY_REQUIRED")
        if authority.network_scope not in {"deny", "internal_only"} or authority.write_scope != "none":
            raise ReviewedCalculatorError("CALCULATOR_SCOPE_NOT_ISOLATED")

        require_runtime_capability(
            node.capability,
            task_id=task_id,
            resource_kind=node.resource_kind,
            resource_ref=node.resource_ref,
            effect=node.effect,
            recorder=self.recorder,
            actor_id="runtime_node",
            action="reviewed_calculator",
        )

        try:
            tree = ast.parse(normalized, mode="eval")
        except (SyntaxError, ValueError, MemoryError) as exc:
            raise ReviewedCalculatorError("CALCULATOR_EXPRESSION_PARSE_INVALID") from exc
        _validate_ast(tree)
        result = _evaluate(tree)
        result_text = _result_text(result)
        expression_sha = _sha256(normalized.encode("utf-8"))
        result_sha = _sha256(result_text.encode("utf-8"))
        refs: tuple[str, ...] = ()
        if self.evidence_sink is not None:
            refs = _validate_refs(
                tuple(
                    self.evidence_sink.persist_calculation(
                        task_id=task_id,
                        node_id=node.node_id,
                        expression_sha256=expression_sha,
                        result=result,
                        result_sha256=result_sha,
                    )
                )
            )
        return ReviewedCalculationResult(
            expression_sha256=expression_sha,
            result=result,
            result_sha256=result_sha,
            evidence_refs=refs,
        ).validate()
