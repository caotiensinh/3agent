# WorkSpace V19 Attachment Processing Pipeline

## Purpose

V19 makes chat attachments part of the actual local reasoning path instead of a UI-only upload feature.

## Current-turn pipeline

```text
Browser file selection
  -> POST /api/upload
  -> owner-scoped KnowledgeGatewayV2
  -> type/size/archive validation
  -> local document extraction
  -> original bytes + extracted text manifest
  -> upload_id
  -> POST /api/chat with upload_ids
  -> owner validation
  -> query-aware excerpt selection
  -> UNTRUSTED_LOCAL_ATTACHMENT_DATA prompt boundary
  -> local LLM / admitted workflow
```

The current frontend shows upload, local processing, and relevant-content retrieval states before model dispatch.

## Follow-up attachment memory

Attachments are associated with a user turn through `ConversationAttachmentMemory`:

```text
conversation_id + job_id + upload_id
```

Only opaque references are stored in SQLite. Raw file bytes and extracted document text remain in KnowledgeGateway storage.

A later turn that references a prior file/document can resolve the most recent attachment-bearing turns in the same conversation. Before reuse, WorkSpace verifies:

1. the conversation belongs to the current owner;
2. the upload still exists;
3. the upload manifest owner matches the current sender.

An unrelated later message does not silently inherit old attachments.

## Supported semantic document extraction

- TXT, Markdown, HTML
- PDF with extractable text
- DOCX
- PPTX text
- XLSX
- CSV / TSV
- JSON / JSONL
- XML
- YAML / YML
- LOG / INI / CFG / CONF
- ZIP containing admitted formats, subject to archive safety limits

## Long documents

V19 does not rely on the legacy first-12k-character prefix for direct chat. Extracted documents are chunked with bounded overlap, scored against the current user request, and a bounded set of relevant excerpts is selected. If no query terms discriminate chunks, WorkSpace samples beginning, middle, and end coverage.

## Images and scanned PDFs

PNG/JPG/JPEG/WEBP are validated and stored, but semantic image understanding is not enabled by this change. Image-only/scanned PDFs are not claimed as read. WorkSpace emits parser diagnostics instead of silently pretending the content was analyzed.

A separate local vision/OCR capability is required for semantic processing of images and scanned documents.

## Security boundaries

- Attachments never execute.
- Archive extraction is bounded and path-safe.
- Attachment text is untrusted data, not instruction authority.
- Current system policy and current user request take precedence.
- No new Internet authority is granted.
- V18 remains the auth/RBAC/Security Monitoring/Workflow V4/DLP rollback boundary; V19 replaces only conversation/file processing behavior and the current frontend layer.
