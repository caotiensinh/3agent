# WorkSpace Skill Supply-Chain Policy V1

## Hard rule

Runtime MUST NOT search the Internet for, download, install, import, or execute a newly discovered skill. Internet/GitHub projects are research inputs only.

A runtime capability request is resolved only from `skills/registry.json` entries with `status=approved`. Missing capability returns `missing_skill` and creates an offline/admin skill-intake task.

## Admission lifecycle

`discovered -> quarantined -> audited -> curated_internal_adapter -> tested -> approved -> monitored -> disabled/revoked`

No transition may skip quarantine and audit.

## Audit checklist

For each upstream candidate record:
- exact project/repository/tag/commit and license
- package/dependency lock and SBOM
- security policy and recent advisories/CVEs
- outbound network, telemetry and model auto-download behavior
- plugin/dynamic import surface
- subprocess/shell/native executable use
- install/build hooks
- arbitrary URL fetches
- unsafe deserialization, eval/exec, unsafe YAML/XML entities
- PDF/HTML/Office active content and macro/script behavior
- archive traversal, symlink, nested archive and decompression-bomb behavior
- temp-file permissions and environment/secret access
- parser CPU/RAM/disk denial-of-service surface
- native/shared-library surface
- prompt-injection/data-authority boundary
- reproducible/pinned artifact hashes where feasible

An audit cannot prove absence of a backdoor. Approval means the reviewed pinned version and the WorkSpace adapter satisfy the defined threat model and permission boundary.

## Permissions

Approved skills declare network (`none|loopback|allowlist`), subprocess (`none|allowlist`), filesystem scope, GPU access, resource limits and supported content types. The broker chooses the smallest approved capability set deterministically.

## Current upstream research posture (2026-09-02)

- **Apache Tika basic parsers**: promising design reference because upstream separates basic Java-only parsers from extended/native/REST parsers. Still quarantined until a pinned adapter/dependency review is complete.
- **Tesseract OCR**: promising local OCR candidate under Apache-2.0; still quarantined until binary/language-model packaging and sandbox review are complete.
- **pypdf**: useful pure-Python PDF parsing reference with an active security policy, but recent resource-exhaustion advisories justify strict time/memory/page budgets and pinning.
- **Docling**: feature-rich, but multiple 2026 advisories include unsafe archive/XML/path/URI/HTML/file-read issues. Use design ideas only; backend-by-backend review required.
- **Microsoft MarkItDown**: plugins are disabled by default upstream, but optional converters can use cloud/network services and plugin enablement expands code execution trust. Do not adopt the all-extras/plugin surface.
- **OCRmyPDF**: upstream documentation warns it is not designed as a malicious public-PDF service and it relies on external tools such as Ghostscript. Keep quarantined for untrusted enterprise uploads.

## Missing-skill intake

When no approved skill satisfies a capability:
1. return explicit `missing_skill` without silently degrading;
2. capture required capability/file type without user document contents;
3. research candidates offline from runtime;
4. audit and curate a narrow internal adapter;
5. test adversarial fixtures and resource limits;
6. administrator approves a pinned version/hash;
7. only then publish it into the approved registry.
