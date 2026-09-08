import pytest

from three_agent.security_monitoring.evidence_lineage import EvidenceLineageError, EvidenceLineageReceipt


def _sha(char: str) -> str:
    return "sha256:" + (char * 64)


def _receipt(*, evidence_batch: str | None = None) -> EvidenceLineageReceipt:
    return EvidenceLineageReceipt(
        task_ref_sha256=_sha("1"),
        policy_fingerprint=_sha("2"),
        evidence_batch_fingerprint=evidence_batch or _sha("3"),
        evidence_ids=("evidence:" + ("a" * 24), "evidence:" + ("b" * 24)),
        evidence_count=2,
    )


def test_receipt_fingerprint_is_deterministic_sha256() -> None:
    first = _receipt()
    second = _receipt()

    assert first.fingerprint == second.fingerprint
    assert first.fingerprint.startswith("sha256:")
    assert len(first.fingerprint) == 71


def test_receipt_fingerprint_changes_when_public_receipt_changes() -> None:
    first = _receipt()
    second = _receipt(evidence_batch=_sha("4"))

    assert first.fingerprint != second.fingerprint


def test_receipt_fingerprint_validates_before_hashing() -> None:
    invalid = EvidenceLineageReceipt(
        task_ref_sha256="not-a-sha",
        policy_fingerprint=_sha("2"),
        evidence_batch_fingerprint=_sha("3"),
        evidence_ids=("evidence:" + ("a" * 24),),
        evidence_count=1,
    )

    with pytest.raises(EvidenceLineageError):
        _ = invalid.fingerprint
