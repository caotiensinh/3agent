from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
import zipfile
from dataclasses import asdict, dataclass
from io import BytesIO
from pathlib import Path
from typing import Iterable

from PIL import Image

from .web_research import ResearchSource, VisibleTextParser, WebResearchClient

MAX_UPLOAD_BYTES = 16 * 1024 * 1024
MAX_UPLOADS_PER_TASK = 8
MAX_ZIP_ENTRIES = 64
MAX_ZIP_MEMBER_BYTES = 8 * 1024 * 1024
MAX_ZIP_TOTAL_BYTES = 32 * 1024 * 1024
MAX_ZIP_RATIO = 200
MAX_EXTRACTED_CHARS = 200_000
MAX_SOURCE_CHARS = 12_000
MAX_COMBINED_SOURCES = 12

TEXT_EXTENSIONS = {".txt", ".md", ".markdown"}
HTML_EXTENSIONS = {".html", ".htm"}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}
UPLOAD_EXTENSIONS = TEXT_EXTENSIONS | HTML_EXTENSIONS | IMAGE_EXTENSIONS | {".zip"}

_UPLOAD_ID_RE = re.compile(r"^[a-f0-9]{16}$")
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._()\-\u0080-\uffff]+")


class UploadSecurityError(ValueError):
    pass


@dataclass(frozen=True)
class UploadRecord:
    upload_id: str
    name: str
    size: int
    sha256: str
    kind: str
    document_count: int
    image_count: int
    warnings: tuple[str, ...] = ()

    def public_dict(self) -> dict:
        return asdict(self)


def _safe_name(value: str) -> str:
    raw = str(value or "").replace("\\", "/")
    name = raw.rsplit("/", 1)[-1].strip()
    name = _SAFE_NAME_RE.sub("_", name).strip("._")
    if not name:
        raise UploadSecurityError("Upload filename is empty or unsafe")
    return name[:160]


def _decode_text(data: bytes) -> str:
    if b"\x00" in data:
        raise UploadSecurityError("Text upload contains NUL bytes")
    for encoding in ("utf-8-sig", "utf-8", "cp932"):
        try:
            text = data.decode(encoding)
            return "\n".join(line.rstrip() for line in text.splitlines()).strip()[:MAX_EXTRACTED_CHARS]
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")[:MAX_EXTRACTED_CHARS].strip()


def _html_text(data: bytes) -> str:
    parser = VisibleTextParser()
    parser.feed(data.decode("utf-8", errors="replace"))
    return parser.text[:MAX_EXTRACTED_CHARS]


def _image_metadata(data: bytes, extension: str) -> tuple[int, int, str]:
    Image.MAX_IMAGE_PIXELS = 40_000_000
    try:
        with Image.open(BytesIO(data)) as image:
            width, height = image.size
            image_format = str(image.format or "").upper()
            if width <= 0 or height <= 0 or width * height > 40_000_000:
                raise UploadSecurityError("Image dimensions exceed the configured safety limit")
            image.verify()
    except UploadSecurityError:
        raise
    except Exception as exc:
        raise UploadSecurityError(f"Invalid image upload: {type(exc).__name__}: {exc}") from exc

    expected = {
        ".png": {"PNG"},
        ".jpg": {"JPEG"},
        ".jpeg": {"JPEG"},
        ".webp": {"WEBP"},
    }[extension]
    if image_format not in expected:
        raise UploadSecurityError(
            f"Image content does not match filename extension ({extension} vs {image_format or 'unknown'})"
        )
    return width, height, image_format


def _zip_member_name(info: zipfile.ZipInfo) -> str:
    name = info.filename.replace("\\", "/")
    parts = [part for part in name.split("/") if part not in {"", "."}]
    if not parts or any(part == ".." for part in parts) or name.startswith("/"):
        raise UploadSecurityError(f"Unsafe ZIP member path: {info.filename!r}")
    return "/".join(parts)


class KnowledgeGateway:
    """Controlled gateway for public-web research plus user-provided files.

    Uploads never execute. ZIP members are inspected in-memory and are never
    extracted using their original paths. Only allowlisted document/image types
    are admitted. Images are stored and metadata-validated, but their semantic
    content is not converted into research evidence without a configured vision
    path.
    """

    def __init__(self, artifact_root: Path, web: WebResearchClient):
        self.root = Path(artifact_root) / "uploads"
        self.root.mkdir(parents=True, exist_ok=True)
        self.web = web

    @staticmethod
    def _chmod(path: Path, mode: int) -> None:
        try:
            os.chmod(path, mode)
        except OSError:
            pass

    def _folder(self, upload_id: str) -> Path:
        if not _UPLOAD_ID_RE.fullmatch(upload_id):
            raise UploadSecurityError("Invalid upload_id")
        path = (self.root / upload_id).resolve()
        root = self.root.resolve()
        if not path.is_relative_to(root):
            raise UploadSecurityError("Upload path escaped upload root")
        return path

    def ingest_upload(
        self,
        filename: str,
        data: bytes,
        *,
        content_type: str = "",
        sender: str = "",
    ) -> UploadRecord:
        del content_type
        name = _safe_name(filename)
        extension = Path(name).suffix.casefold()
        if extension not in UPLOAD_EXTENSIONS:
            raise UploadSecurityError(
                "Unsupported upload type. Allowed: txt, md, html, zip, png, jpg, jpeg, webp"
            )
        if not data:
            raise UploadSecurityError("Upload is empty")
        if len(data) > MAX_UPLOAD_BYTES:
            raise UploadSecurityError("Upload exceeds 16 MiB per-file limit")

        # Validate and parse entirely in memory first. Rejected uploads leave no
        # original bytes behind in the persistent upload area.
        documents: list[dict] = []
        images: list[dict] = []
        warnings: list[str] = []
        if extension in TEXT_EXTENSIONS:
            text = _decode_text(data)
            if not text:
                raise UploadSecurityError("No readable text found in uploaded document")
            documents.append({"name": name, "kind": "text", "text": text})
        elif extension in HTML_EXTENSIONS:
            text = _html_text(data)
            if not text:
                raise UploadSecurityError("No readable visible text found in uploaded HTML")
            documents.append({"name": name, "kind": "html", "text": text})
        elif extension in IMAGE_EXTENSIONS:
            width, height, image_format = _image_metadata(data, extension)
            images.append(
                {
                    "name": name,
                    "kind": "image",
                    "width": width,
                    "height": height,
                    "format": image_format,
                }
            )
            warnings.append(
                "Image stored safely; semantic image understanding is disabled until a local vision model is configured."
            )
        else:
            documents, images, zip_warnings = self._inspect_zip(data)
            warnings.extend(zip_warnings)
            if not documents and not images:
                raise UploadSecurityError("ZIP contains no supported readable document or image")

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
        for index, item in enumerate(documents, start=1):
            path = extracted_dir / f"doc-{index:03d}.txt"
            path.write_text(str(item["text"]), encoding="utf-8")
            self._chmod(path, 0o600)
            manifest_documents.append(
                {
                    "name": item["name"],
                    "kind": item["kind"],
                    "text_file": path.name,
                    "chars": len(str(item["text"])),
                }
            )

        digest = hashlib.sha256(data).hexdigest()
        manifest = {
            "schema_version": 1,
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
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        self._chmod(manifest_path, 0o600)

        return UploadRecord(
            upload_id=upload_id,
            name=name,
            size=len(data),
            sha256=f"sha256:{digest}",
            kind="zip" if extension == ".zip" else ("image" if extension in IMAGE_EXTENSIONS else "document"),
            document_count=len(manifest_documents),
            image_count=len(images),
            warnings=tuple(warnings),
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
                if extension not in TEXT_EXTENSIONS | HTML_EXTENSIONS | IMAGE_EXTENSIONS:
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
                else:
                    width, height, image_format = _image_metadata(member, extension)
                    images.append(
                        {
                            "name": member_name,
                            "kind": "image",
                            "width": width,
                            "height": height,
                            "format": image_format,
                        }
                    )
        if images:
            warnings.append(
                "ZIP images were stored/validated as metadata only; semantic image understanding is disabled."
            )
        return documents, images, warnings

    def validate_upload_ids(self, upload_ids: Iterable[str]) -> list[str]:
        valid: list[str] = []
        for raw in upload_ids:
            value = str(raw or "").strip()
            if not value or value in valid:
                continue
            folder = self._folder(value)
            if not (folder / "manifest.json").is_file():
                raise UploadSecurityError(f"Unknown upload_id: {value}")
            valid.append(value)
            if len(valid) > MAX_UPLOADS_PER_TASK:
                raise UploadSecurityError(f"At most {MAX_UPLOADS_PER_TASK} uploads may be attached to one task")
        return valid

    def load_upload_sources(
        self,
        upload_ids: Iterable[str],
        *,
        max_sources: int = 8,
    ) -> tuple[list[ResearchSource], list[str]]:
        sources: list[ResearchSource] = []
        diagnostics: list[str] = []
        for upload_id in self.validate_upload_ids(upload_ids):
            folder = self._folder(upload_id)
            manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
            for item in manifest.get("documents", []):
                if len(sources) >= max_sources:
                    diagnostics.append("upload_source_limit_reached")
                    return sources, diagnostics
                text_file = str(item.get("text_file") or "")
                candidate = (folder / "extracted" / text_file).resolve()
                extracted_root = (folder / "extracted").resolve()
                if not candidate.is_relative_to(extracted_root) or not candidate.is_file():
                    diagnostics.append(f"upload_extracted_file_missing upload_id={upload_id}")
                    continue
                text = candidate.read_text(encoding="utf-8")[:MAX_SOURCE_CHARS].strip()
                if not text:
                    continue
                name = str(item.get("name") or manifest.get("name") or upload_id)
                sources.append(
                    ResearchSource(
                        source_id="",
                        title=name,
                        url=f"upload://{upload_id}/{_safe_name(Path(name).name)}",
                        search_snippet="User-provided upload admitted by KnowledgeGateway.",
                        extracted_text=text,
                        fetch_status="ok",
                    )
                )
            for image in manifest.get("images", []):
                diagnostics.append(
                    "image_not_semantically_parsed "
                    f"upload_id={upload_id} name={str(image.get('name') or '')[:120]}"
                )
        return sources, diagnostics

    @staticmethod
    def _reindex(sources: Iterable[ResearchSource]) -> list[ResearchSource]:
        indexed: list[ResearchSource] = []
        for index, source in enumerate(sources, start=1):
            indexed.append(
                ResearchSource(
                    source_id=f"S{index}",
                    title=source.title,
                    url=source.url,
                    search_snippet=source.search_snippet,
                    extracted_text=source.extracted_text,
                    fetch_status=source.fetch_status,
                    error=source.error,
                )
            )
        return indexed

    def collect(
        self,
        agent_id: str,
        task_id: str,
        queries: Iterable[str],
        *,
        upload_ids: Iterable[str] = (),
    ) -> tuple[list[ResearchSource], list[str]]:
        upload_sources, diagnostics = self.load_upload_sources(upload_ids, max_sources=8)
        remaining = max(0, MAX_COMBINED_SOURCES - len(upload_sources))
        web_sources: list[ResearchSource] = []
        if remaining:
            search_results, search_diagnostics = self.web.search_many(
                agent_id,
                task_id,
                queries,
                max_unique_results=min(8, remaining),
            )
            diagnostics.extend(search_diagnostics)
            web_sources = self.web.fetch_sources(
                agent_id,
                task_id,
                search_results,
                max_sources=min(6, remaining),
            )
        combined = (upload_sources + web_sources)[:MAX_COMBINED_SOURCES]
        return self._reindex(combined), diagnostics


# Extended business-document ingestion and bounded attachment retrieval.
from .document_extractors import (
    DOCUMENT_EXTENSIONS,
    DocumentExtractionError,
    extract_document,
)

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
