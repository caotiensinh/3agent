# Attachment Full-Understanding Contract

Status: mandatory acceptance gate for WorkSpace local chat.

## 1. User-uploaded file contract

When a user attaches a supported file, WorkSpace MUST NOT claim that it has read or understood the file until the complete supported contents have passed the local understanding pipeline.

`complete` means all supported content units within the accepted file have been processed:

- text documents: all accepted text, without silent truncation;
- PDF: every accepted page is accounted for; machine text and required visual/scan understanding are both covered;
- DOCX: paragraphs, tables, and supported embedded visuals are accounted for;
- PPTX: every accepted slide, table, text object, and supported embedded visual is accounted for;
- XLSX: every accepted sheet/cell range and supported embedded visual is accounted for;
- native images: the complete accepted image is analyzed by the local Vision boundary;
- ZIP: every accepted member is accounted for. Unsupported, nested, encrypted, skipped, truncated, or failed members make the archive incomplete.

The ingestion layer MUST emit an explicit coverage state:

- `complete`: every accepted unit was processed successfully;
- `partial`: at least one unit was skipped, truncated, unreadable, or unavailable;
- `rejected`: the file cannot safely enter the understanding pipeline.

The answer layer MUST NOT silently promote `partial` to `complete`.

If coverage is `partial`, WorkSpace may explain the limitation, but it MUST NOT make a whole-file claim such as "I read the entire file" or "I understood everything in the attachment".

If the user's request requires whole-file understanding, `partial` is a hard answer gate: WorkSpace must state what could not be processed rather than inventing or extrapolating the missing content.

## 2. Full-read does not mean prompt flooding

The full file does not need to be injected verbatim into one LLM prompt.

For large accepted files WorkSpace SHOULD:

1. parse and persist every supported content unit locally;
2. create deterministic chunk/locator metadata for the entire file;
3. analyze every required visual locally;
4. build a coverage manifest proving that every accepted unit is accounted for;
5. use hierarchical summarization and/or query-aware retrieval to fit the final reasoning context;
6. retain locators so the final answer can be traced back to the original file.

Token/context optimization is allowed only after full-ingestion coverage is established. It must never be used as a reason to silently skip unseen file content while claiming whole-file understanding.

## 3. Long pasted-text compaction

A long user-authored paste SHOULD be automatically persisted as a local UTF-8 `.txt` attachment once it crosses the configured inline threshold.

Required behavior:

- preserve the original pasted text byte-for-byte after UTF-8 normalization chosen by the chat boundary;
- compute and retain integrity metadata (at minimum SHA-256, size, owner, and upload/message lineage);
- use a compact reference in conversation history instead of duplicating the full text inline;
- keep the `.txt` file local under the same owner/conversation security boundary as normal uploads;
- feed the generated `.txt` through the same full-understanding coverage gate as a normal text attachment;
- preserve the original user-visible intent and response language.

## 4. Authority preservation for auto-generated paste files

A `.txt` file created automatically from the CURRENT user message is NOT an ordinary attachment with lower instruction authority.

It MUST be tagged with an origin equivalent to:

`origin = current_user_paste`

The prompt compiler/chat service MUST treat its contents as a continuation of `CURRENT_USER_REQUEST`, below system/developer policy but above ordinary attachment data.

Ordinary uploaded documents remain untrusted attachment evidence. Their embedded instructions are data unless the current user request explicitly asks to follow them.

This distinction is mandatory to prevent long-paste compaction from changing request semantics.

## 5. No-silent-truncation gate

Any safety/resource bound that prevents complete processing MUST be visible in the coverage manifest. Examples include:

- page limits;
- extracted-character limits;
- sheet/row/column limits;
- visual-asset limits;
- ZIP member/size/ratio limits;
- unavailable local Vision model;
- parser failures;
- encrypted or unsupported content.

A limit may reject the file or mark it `partial`; it MUST NOT silently return `complete`.

## 6. Acceptance tests

The feature is not accepted until automated tests prove all of the following:

1. a multi-page/multi-section file reports `complete` only after every supported unit is accounted for;
2. a deliberately truncated or skipped unit produces `partial`/`rejected`, never `complete`;
3. a scanned PDF requires Vision coverage for every accepted scanned page before whole-file readiness;
4. Office embedded-image failures prevent whole-file readiness;
5. a long pasted message is stored as `.txt` and conversation history contains only a compact reference;
6. the generated paste file preserves exact content/integrity metadata;
7. instructions inside an auto-generated current-user paste retain CURRENT USER REQUEST authority;
8. instructions inside a normal uploaded document remain untrusted attachment data;
9. same-owner/same-conversation attachment continuity remains enforced;
10. no cloud Vision or external file-understanding endpoint is introduced.

## 7. Completion rule

WorkSpace may advertise `full_attachment_understanding=true` only when the implementation and exact-head CI satisfy this contract. Until then the capability must be described as bounded/partial multimodal understanding.
