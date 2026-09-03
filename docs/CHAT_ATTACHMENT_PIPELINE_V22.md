# WorkSpace Chat Attachment Pipeline V22

## Status

This document is the durable integration record for the chat continuity and local business-document parsing work originally developed on PR #180.

The implementation is reconciled onto the current `main` architecture instead of restoring the old V19 gateway. `chat_gateway_v21` remains the rollback/security boundary; V22 composes the missing chat-memory and document-processing behavior on top of it.

## Product wiring

The production path is intentionally end-to-end rather than a collection of disconnected modules:

1. `workspace_frontend_v18.py` is served by the V22-composed V17 HTTP entrypoint.
2. The frontend uploads local files through `/api/upload`.
3. The account-scoped upload route stores the authenticated owner identity and calls `KnowledgeGatewayV2`.
4. `KnowledgeGatewayV2` parses supported business documents locally, stores bounded extracted text, and returns `document_count`, `image_count`, and parser warnings to the UI.
5. The frontend submits `/api/chat` with `conversation_id` and validated `upload_ids`.
6. The HTTP route revalidates every upload against the authenticated owner before the V22 chat service receives it.
7. V22 builds bounded query-aware attachment context and bounded conversation continuity, preserving V21 Security Analyst read-only context.
8. Same-conversation attachment follow-ups may reuse only opaque upload IDs and must pass the same owner-validation path again.
9. The default package entrypoints `workspace-chat` and `three-agent-chat` point to V22. Explicit V21 rollback entrypoints remain available as `workspace-chat-v21` and `three-agent-chat-v21`.

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

## Automated product acceptance

`tests/test_chat_memory_attachments_v22.py` includes an HTTP product-integration test that opens the real V22-composed HTTP handler on an ephemeral localhost port and proves:

- the served `/` page is V18 and exposes business-document upload types;
- `/api/upload` reaches the real `KnowledgeGatewayV2` parser;
- the upload response returns parser counts/warnings;
- `/api/chat` revalidates the uploaded artifact under the same authenticated owner identity;
- `conversation_id` and `upload_ids` cross the HTTP boundary together;
- the parsed attachment text is retrievable for the chat request.

The expensive model response is stubbed in this test; HTTP routing, owner validation, local parsing, persistence, bounded retrieval and frontend serving are not stubbed.

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
- [ ] Run same-conversation attachment follow-up after process restart and confirm owner isolation on a field workstation.
- [ ] Validate scanned/image-only PDF diagnostic on a field workstation; OCR remains intentionally out of scope until a local OCR/vision policy is approved.
- [ ] Confirm CPU/RAM/latency bounds with representative enterprise documents near configured limits.

Until checked, these items are `ACCEPTANCE_PENDING`; they do not invalidate integrated code but must not be reported as production PASS.
