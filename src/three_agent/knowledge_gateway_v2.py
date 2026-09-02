from __future__ import annotations

import hashlib
import json
import re
import uuid
import zipfile
from io import BytesIO
from pathlib import Path

from .document_extractors import DOCUMENT_EXTENSIONS, DocumentExtractionError, extract_document
from .knowledge_gateway import (
    HTML_EXTENSIONS,
    IMAGE_EXTENSIONS,
    MAX_UPLOAD_BYTES,
    MAX_ZIP_ENTRIES,
    MAX_ZIP_MEMBER_BYTES,
    MAX_ZIP_RATIO,
    MAX_ZIP_TOTAL_BYTES,
    TEXT_EXTENSIONS,
    KnowledgeGateway,
    UploadRecord,
    UploadSecurityError,
    _decode_text,
    _html_text,
    _image_metadata,
    _safe_name,
    _zip_member_name,
)
from .web_research import ResearchSource

EXTENDED_UPLOAD_EXTENSIONS = (
    TEXT_EXTENSIONS | HTML_EXTENSIONS | IMAGE_EXTENSIONS | DOCUMENT_EXTENSIONS | {".zip"}
)

_ATTACHMENT_CHUNK_CHARS = 2_400
_ATTACHMENT_CHUNK_OVERLAP = 240
_ATTACHMENT_MAX_DOCUMENTS = 8
_ATTACHMENT_MAX_EXCERPTS_PER_DOCUMENT = 3
_QUERY_STOP_WORDS = {
    "the", "and", "for", "with", "that", "this", "from", "what", "which", "file",
    "hãy", "cho", "tôi", "của", "và", "trong", "này", "đó", "với", "được", "là", "có",
    "この", "その", "これ", "それ", "ファイル", "について", "してください",
}


class KnowledgeGatewayV2(KnowledgeGateway):
    """KnowledgeGateway with bounded local extraction for common business files."""

    def _persist_documents(
        self,
        name: str,
        extension: str,
        data: bytes,
        documents: list[dict],
        images: list[dict],
        warnings: list[str],
        sender: str,
    ) -> UploadRecord:
        upload_id = uuid.uuid4().hex[:16]
        folder = self._folder(upload_id)
        folder.mkdir(parents=True, exist_ok=False)
        self._chmod(folder, 0o700)
        original = folder / f"original{extension}"
        original.write_bytes(data)
        self._chmod(original, 0o600)

        extracted_dir = folder / "extracted"
        extracted_dir.mkdir(exist_ok=True)
        self._chmod(extracted_dir, 0o700)
        manifest_documents: list[dict] = []
        for index, item in enumerate(documents, 1):
            path = extracted_dir / f"doc-{index:03d}.txt"
            text = str(item.get("text") or "")
            path.write_text(text, encoding="utf-8")
            self._chmod(path, 0o600)
            manifest_documents.append(
                {
                    "name": str(item.get("name") or name),
                    "kind": str(item.get("kind") or "document"),
                    "text_file": path.name,
                    "chars": len(text),
                }
            )

        digest = hashlib.sha256(data).hexdigest()
        manifest = {
            "schema_version": 2,
            "upload_id": upload_id,
            "name": name,
            "size": len(data),
            "sha256": f"sha256:{digest}",
            "sender": str(sender or "")[:120],
            "documents": manifest_documents,
            "images": images,
            "warnings": warnings,
        }
        manifest_path = folder / "manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        self._chmod(manifest_path, 0o600)
        return UploadRecord(
            upload_id=upload_id,
            name=name,
            size=len(data),
            sha256=f"sha256:{digest}",
            kind="zip" if extension == ".zip" else "document",
            document_count=len(manifest_documents),
            image_count=len(images),
            warnings=tuple(warnings),
        )

    def ingest_upload(self, filename: str, data: bytes, *, content_type: str = "", sender: str = "") -> UploadRecord:
        name = _safe_name(filename)
        extension = Path(name).suffix.casefold()
        if extension not in EXTENDED_UPLOAD_EXTENSIONS:
            allowed = ", ".join(sorted(ext.lstrip(".") for ext in EXTENDED_UPLOAD_EXTENSIONS))
            raise UploadSecurityError(f"Unsupported upload type. Allowed: {allowed}")
        if extension not in DOCUMENT_EXTENSIONS:
            return super().ingest_upload(name, data, content_type=content_type, sender=sender)
        if not data:
            raise UploadSecurityError("Upload is empty")
        if len(data) > MAX_UPLOAD_BYTES:
            raise UploadSecurityError("Upload exceeds 16 MiB per-file limit")
        try:
            text, kind, warnings = extract_document(name, data)
        except DocumentExtractionError as exc:
            raise UploadSecurityError(str(exc)) from exc
        return self._persist_documents(
            name,
            extension,
            data,
            [{"name": name, "kind": kind, "text": text}],
            [],
            warnings,
            sender,
        )

    def _inspect_zip(self, data: bytes) -> tuple[list[dict], list[dict], list[str]]:
        if not zipfile.is_zipfile(BytesIO(data)):
            raise UploadSecurityError("Invalid ZIP upload")
        documents: list[dict] = []
        images: list[dict] = []
        warnings: list[str] = []
        total_uncompressed = 0
        with zipfile.ZipFile(BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ZIP_ENTRIES:
                raise UploadSecurityError(f"ZIP contains more than {MAX_ZIP_ENTRIES} entries")
            for info in infos:
                if info.is_dir():
                    continue
                member_name = _zip_member_name(info)
                if info.flag_bits & 0x1:
                    raise UploadSecurityError("Encrypted ZIP members are not permitted")
                if info.file_size > MAX_ZIP_MEMBER_BYTES:
                    raise UploadSecurityError(f"ZIP member exceeds 8 MiB: {member_name}")
                total_uncompressed += info.file_size
                if total_uncompressed > MAX_ZIP_TOTAL_BYTES:
                    raise UploadSecurityError("ZIP uncompressed content exceeds 32 MiB")
                if info.compress_size == 0 and info.file_size > 0:
                    raise UploadSecurityError(f"Suspicious ZIP compression ratio: {member_name}")
                if info.compress_size and info.file_size / info.compress_size > MAX_ZIP_RATIO:
                    raise UploadSecurityError(f"ZIP compression ratio exceeds safety limit: {member_name}")
                extension = Path(member_name).suffix.casefold()
                if extension == ".zip":
                    warnings.append(f"Nested ZIP skipped: {member_name}")
                    continue
                if extension not in TEXT_EXTENSIONS | HTML_EXTENSIONS | IMAGE_EXTENSIONS | DOCUMENT_EXTENSIONS:
                    warnings.append(f"Unsupported ZIP member skipped: {member_name}")
                    continue
                member = archive.read(info)
                if extension in TEXT_EXTENSIONS:
                    text = _decode_text(member)
                    if text:
                        documents.append({"name": member_name, "kind": "text", "text": text})
                elif extension in HTML_EXTENSIONS:
                    text = _html_text(member)
                    if text:
                        documents.append({"name": member_name, "kind": "html", "text": text})
                elif extension in IMAGE_EXTENSIONS:
                    width, height, image_format = _image_metadata(member, extension)
                    images.append({"name": member_name, "kind": "image", "width": width, "height": height, "format": image_format})
                else:
                    try:
                        text, kind, member_warnings = extract_document(member_name, member)
                        documents.append({"name": member_name, "kind": kind, "text": text})
                        warnings.extend(f"{member_name}: {warning}" for warning in member_warnings)
                    except DocumentExtractionError as exc:
                        warnings.append(f"Document skipped: {member_name}: {exc}")
        if images:
            warnings.append("ZIP images are metadata-only; local semantic vision is not configured.")
        return documents, images, warnings

    @staticmethod
    def _query_terms(query: str) -> set[str]:
        terms = {
            token.casefold()
            for token in re.findall(r"[^\W_]{2,}", str(query or ""), flags=re.UNICODE)
        }
        return {term for term in terms if term not in _QUERY_STOP_WORDS}

    @staticmethod
    def _chunks(text: str) -> list[tuple[int, str]]:
        body = str(text or "").strip()
        if not body:
            return []
        if len(body) <= _ATTACHMENT_CHUNK_CHARS:
            return [(0, body)]
        step = _ATTACHMENT_CHUNK_CHARS - _ATTACHMENT_CHUNK_OVERLAP
        return [
            (offset, body[offset : offset + _ATTACHMENT_CHUNK_CHARS])
            for offset in range(0, len(body), step)
            if body[offset : offset + _ATTACHMENT_CHUNK_CHARS].strip()
        ]

    @classmethod
    def _select_excerpts(cls, text: str, query: str) -> list[tuple[int, str]]:
        chunks = cls._chunks(text)
        if len(chunks) <= _ATTACHMENT_MAX_EXCERPTS_PER_DOCUMENT:
            return chunks
        terms = cls._query_terms(query)
        normalized_query = " ".join(str(query or "").casefold().split())
        scored: list[tuple[int, int, int, str]] = []
        for chunk_index, (offset, chunk) in enumerate(chunks):
            normalized = chunk.casefold()
            term_hits = sum(normalized.count(term) for term in terms)
            phrase_hit = 1 if len(normalized_query) >= 6 and normalized_query in normalized else 0
            score = phrase_hit * 1000 + term_hits
            scored.append((score, -chunk_index, offset, chunk))

        if any(score > 0 for score, _, _, _ in scored):
            selected = sorted(scored, reverse=True)[:_ATTACHMENT_MAX_EXCERPTS_PER_DOCUMENT]
            return sorted(((offset, chunk) for _, _, offset, chunk in selected), key=lambda item: item[0])

        sample_indexes = {0, len(chunks) // 2, len(chunks) - 1}
        return [chunks[index] for index in sorted(sample_indexes)]

    def build_attachment_context(
        self,
        upload_ids: list[str],
        query: str,
        *,
        max_chars: int = 24_000,
    ) -> tuple[str, list[str]]:
        """Build bounded query-aware local context from the complete extracted documents.

        This deliberately does not execute file content. Each excerpt is passed
        through the normal ResearchSource untrusted-payload sanitizer before it is
        returned to the chat prompt.
        """

        budget = max(1_000, min(64_000, int(max_chars)))
        blocks: list[str] = []
        diagnostics: list[str] = []
        used = 0
        document_number = 0
        for upload_id in self.validate_upload_ids(upload_ids):
            folder = self._folder(upload_id)
            manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
            for warning in manifest.get("warnings", []):
                diagnostics.append(f"upload_warning upload_id={upload_id} {str(warning)[:300]}")
            for image in manifest.get("images", []):
                diagnostics.append(
                    "image_not_semantically_parsed "
                    f"upload_id={upload_id} name={str(image.get('name') or '')[:120]}"
                )
            for item in manifest.get("documents", []):
                if document_number >= _ATTACHMENT_MAX_DOCUMENTS:
                    diagnostics.append("attachment_document_limit_reached")
                    return "\n\n".join(blocks), diagnostics
                text_file = str(item.get("text_file") or "")
                candidate = (folder / "extracted" / text_file).resolve()
                extracted_root = (folder / "extracted").resolve()
                if not candidate.is_relative_to(extracted_root) or not candidate.is_file():
                    diagnostics.append(f"upload_extracted_file_missing upload_id={upload_id}")
                    continue
                full_text = candidate.read_text(encoding="utf-8").strip()
                if not full_text:
                    continue
                document_number += 1
                name = str(item.get("name") or manifest.get("name") or upload_id)
                excerpts = self._select_excerpts(full_text, query)
                for excerpt_index, (offset, excerpt) in enumerate(excerpts, 1):
                    source = ResearchSource(
                        source_id="",
                        title=name,
                        url=f"upload://{upload_id}/{_safe_name(Path(name).name)}",
                        search_snippet="User-provided local attachment excerpt.",
                        extracted_text=excerpt,
                        fetch_status="ok",
                    )
                    header = (
                        f"[LOCAL ATTACHMENT {document_number}: {source.title} | "
                        f"excerpt {excerpt_index} | char {offset}]\n"
                    )
                    remaining = budget - used
                    if remaining <= len(header) + 80:
                        diagnostics.append("attachment_context_budget_reached")
                        return "\n\n".join(blocks), diagnostics
                    body = source.extracted_text[: remaining - len(header)]
                    block = header + body
                    blocks.append(block)
                    used += len(block) + 2
        return "\n\n".join(blocks), diagnostics
