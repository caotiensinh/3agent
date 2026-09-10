# WorkSpace Chat Attachment Pipeline V22

## Status

This document is the durable integration record for the chat continuity and local business-document parsing work originally developed on PR #180.

The implementation is intentionally reconciled onto the current `main` architecture instead of restoring the old V19 gateway. `chat_gateway_v21` remains the rollback/security boundary; V22 composes the missing chat-memory and document-processing behavior on top of it.

## Integrated scope

- bounded same-conversation continuity: up to 12 completed messages / 18,000 characters
- current user request and current system policy always take precedence over prior turns
- explicit missing-reference behavior remains fail-closed
- same-owner, same-conversation attachment-reference memory using opaque upload IDs only
- local text extraction for PDF, DOCX, PPTX, XLSX, CSV/TSV, JSON/JSONL, XML, YAML/YML, LOG/INI/CFG/CONF
- bounded OOXML, PDF and spreadsheet parsing
- scanned/image-only PDF reports that OCR is not configured
- image files remain metadata-only unless a separately configured local vision model exists
- query-aware excerpts over the complete extracted document, bounded to the direct-chat attachment context budget
- attachment content remains untrusted user data and never gains instruction/tool/network authority
- V21 Security Analyst read-only context is preserved in the V22 prompt
- V17/V21 rollback layers are not rewritten; the new UI composition is isolated in `workspace_frontend_v18.py`

## Security boundary

V22 does not grant Internet, shell, credential, firewall, remediation, packet-capture execution, or arbitrary network authority. Attachment bytes are parsed locally and are never executed. Reused attachment IDs are revalidated through the existing owner validation path before use.

## Validation state model

Use only these states:

- `PASS`: test completed successfully on the exact integration head.
- `FAIL`: test completed and demonstrated a defect.
- `TEST_DEFERRED`: test could not reach a reliable conclusion in the available environment; this is not PASS.
- `ACCEPTANCE_PENDING`: production/field validation remains to be performed; this is not PASS.

## Historical evidence from PR #180

The earlier reconciled head `ee8438ad1a89c6cacc5b64eefe3360e1e23f5f17` completed all six workflows successfully before later feature commits were added.

The later PR #180 head `b231f037a78a493885cef796597e84860831c6c4` had the following exact-head state before this V22 reconciliation:

- harness-ci: PASS
- installer-ci: PASS
- portable-deploy-ci: PASS
- CIC real-source evidence: PASS
- LANL publisher access contract: PASS
- Windows contract and Python 3.11 clean install: PASS
- Windows Python 3.12 initial attempt: FAIL in a concurrency-sensitive Workflow V4 test
- Windows Python 3.12 retry: bootstrap and exact source-lineage PASS; final idempotent redeploy conclusion was not reliably captured before the repository advanced substantially

Therefore the old Windows Python 3.12 result is recorded as `TEST_DEFERRED`, not PASS.

## V22 merge rule

The current V22 integration must run the repository CI available on its exact head. Any deterministic code/test failure must be fixed before merge. Environment-specific acceptance that cannot be concluded may be recorded as `TEST_DEFERRED` or `ACCEPTANCE_PENDING` and followed up after merge, so implemented code is not stranded on a long-lived feature branch.

## Deferred acceptance checklist

- [ ] Re-run Windows Python 3.12 clean install + exact lineage + idempotent redeploy on the final V22/main code line if the CI environment can complete it reliably.
- [ ] Run real workstation chat acceptance with PDF, DOCX, PPTX and XLSX uploads.
- [ ] Run same-conversation attachment follow-up after process restart and confirm owner isolation.
- [ ] Validate scanned/image-only PDF diagnostic on a field workstation; OCR remains intentionally out of scope until a local OCR/vision policy is approved.
- [ ] Confirm CPU/RAM/latency bounds with representative enterprise documents near configured limits.

Until checked, these items are `ACCEPTANCE_PENDING`; they do not invalidate the already integrated code but must not be reported as production PASS.
