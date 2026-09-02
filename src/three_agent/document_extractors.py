from __future__ import annotations

import csv
import json
import zipfile
from io import BytesIO, StringIO
from pathlib import Path

from defusedxml import ElementTree as SafeElementTree
from docx import Document
from openpyxl import load_workbook
from pptx import Presentation
from pypdf import PdfReader

MAX_EXTRACTED_CHARS = 200_000
MAX_OOXML_ENTRIES = 512
MAX_OOXML_TOTAL_BYTES = 96 * 1024 * 1024
MAX_OOXML_RATIO = 200
MAX_PDF_PAGES = 300
MAX_SHEETS = 32
MAX_ROWS_PER_SHEET = 5_000
MAX_COLS_PER_SHEET = 128

PLAIN_DOCUMENT_EXTENSIONS = {
    ".csv", ".tsv", ".json", ".jsonl", ".xml", ".yaml", ".yml",
    ".log", ".ini", ".cfg", ".conf",
}
RICH_DOCUMENT_EXTENSIONS = {".pdf", ".docx", ".pptx", ".xlsx"}
DOCUMENT_EXTENSIONS = PLAIN_DOCUMENT_EXTENSIONS | RICH_DOCUMENT_EXTENSIONS


class DocumentExtractionError(ValueError):
    pass


def _bounded(text: str) -> str:
    return str(text or "").strip()[:MAX_EXTRACTED_CHARS]


def _decode(data: bytes) -> str:
    if b"\x00" in data:
        raise DocumentExtractionError("Text document contains NUL bytes")
    for encoding in ("utf-8-sig", "utf-8", "cp932"):
        try:
            return _bounded(data.decode(encoding))
        except UnicodeDecodeError:
            pass
    return _bounded(data.decode("utf-8", errors="replace"))


def _guard_ooxml(data: bytes) -> None:
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_OOXML_ENTRIES:
                raise DocumentExtractionError("Office document contains too many package entries")
            total = 0
            for info in infos:
                if info.flag_bits & 0x1:
                    raise DocumentExtractionError("Encrypted Office documents are not supported")
                total += max(0, info.file_size)
                if total > MAX_OOXML_TOTAL_BYTES:
                    raise DocumentExtractionError("Office document expands beyond the safety limit")
                if info.compress_size and info.file_size / info.compress_size > MAX_OOXML_RATIO:
                    raise DocumentExtractionError("Office document compression ratio exceeds the safety limit")
    except DocumentExtractionError:
        raise
    except (zipfile.BadZipFile, OSError) as exc:
        raise DocumentExtractionError("Invalid Office Open XML document") from exc


def _extract_pdf(data: bytes) -> tuple[str, list[str]]:
    try:
        reader = PdfReader(BytesIO(data), strict=False)
        if reader.is_encrypted:
            try:
                if reader.decrypt("") == 0:
                    raise DocumentExtractionError("Encrypted PDF is not supported")
            except Exception as exc:
                if isinstance(exc, DocumentExtractionError):
                    raise
                raise DocumentExtractionError("Encrypted PDF is not supported") from exc
        chunks: list[str] = []
        total_chars = 0
        for index, page in enumerate(reader.pages[:MAX_PDF_PAGES], 1):
            text = str(page.extract_text() or "").strip()
            if text:
                block = f"[PDF page {index}]\n{text}"
                chunks.append(block)
                total_chars += len(block)
            if total_chars >= MAX_EXTRACTED_CHARS:
                break
        rendered = _bounded("\n\n".join(chunks))
    except DocumentExtractionError:
        raise
    except Exception as exc:
        raise DocumentExtractionError(f"PDF parsing failed: {type(exc).__name__}") from exc
    if not rendered:
        raise DocumentExtractionError(
            "PDF contains no extractable text. Scanned/image-only PDF OCR is not configured."
        )
    warnings = []
    if len(reader.pages) > MAX_PDF_PAGES:
        warnings.append(f"PDF truncated after {MAX_PDF_PAGES} pages for bounded local processing.")
    return rendered, warnings


def _extract_docx(data: bytes) -> tuple[str, list[str]]:
    _guard_ooxml(data)
    try:
        doc = Document(BytesIO(data))
        rows: list[str] = []
        for p in doc.paragraphs:
            text = p.text.strip()
            if text:
                rows.append(text)
        for t_index, table in enumerate(doc.tables, 1):
            rows.append(f"[Table {t_index}]")
            for row in table.rows:
                cells = [" ".join(cell.text.split()) for cell in row.cells]
                rows.append(" | ".join(cells))
        return _bounded("\n".join(rows)), []
    except Exception as exc:
        raise DocumentExtractionError(f"DOCX parsing failed: {type(exc).__name__}") from exc


def _extract_pptx(data: bytes) -> tuple[str, list[str]]:
    _guard_ooxml(data)
    try:
        deck = Presentation(BytesIO(data))
        rows: list[str] = []
        total_chars = 0
        for index, slide in enumerate(deck.slides, 1):
            texts: list[str] = []
            for shape in slide.shapes:
                text = str(getattr(shape, "text", "") or "").strip()
                if text:
                    texts.append(text)
            if texts:
                block = f"[Slide {index}]\n" + "\n".join(texts)
                rows.append(block)
                total_chars += len(block)
            if total_chars >= MAX_EXTRACTED_CHARS:
                break
        return _bounded("\n\n".join(rows)), []
    except Exception as exc:
        raise DocumentExtractionError(f"PPTX parsing failed: {type(exc).__name__}") from exc


def _extract_xlsx(data: bytes) -> tuple[str, list[str]]:
    _guard_ooxml(data)
    try:
        workbook = load_workbook(BytesIO(data), read_only=True, data_only=True)
        rows: list[str] = []
        warnings: list[str] = []
        total_chars = 0
        try:
            for sheet_index, sheet in enumerate(workbook.worksheets[:MAX_SHEETS], 1):
                heading = f"[Sheet {sheet_index}: {sheet.title}]"
                rows.append(heading)
                total_chars += len(heading)
                for row_index, values in enumerate(
                    sheet.iter_rows(max_col=MAX_COLS_PER_SHEET, values_only=True), 1
                ):
                    if row_index > MAX_ROWS_PER_SHEET:
                        warnings.append(
                            f"Sheet {sheet.title} truncated after {MAX_ROWS_PER_SHEET} rows."
                        )
                        break
                    rendered = ["" if value is None else str(value) for value in values]
                    while rendered and not rendered[-1]:
                        rendered.pop()
                    if rendered:
                        line = "\t".join(rendered)
                        rows.append(line)
                        total_chars += len(line)
                    if total_chars >= MAX_EXTRACTED_CHARS:
                        warnings.append("XLSX text truncated at the global extraction limit.")
                        return _bounded("\n".join(rows)), warnings
            if len(workbook.worksheets) > MAX_SHEETS:
                warnings.append(f"Workbook truncated after {MAX_SHEETS} sheets.")
            return _bounded("\n".join(rows)), warnings
        finally:
            workbook.close()
    except Exception as exc:
        raise DocumentExtractionError(f"XLSX parsing failed: {type(exc).__name__}") from exc


def _extract_csv(data: bytes, delimiter: str | None = None) -> tuple[str, list[str]]:
    text = _decode(data)
    try:
        if delimiter is None:
            try:
                delimiter = csv.Sniffer().sniff(text[:8192], delimiters=",\t;|").delimiter
            except csv.Error:
                delimiter = ","
        reader = csv.reader(StringIO(text), delimiter=delimiter)
        rows: list[str] = []
        warnings: list[str] = []
        total_chars = 0
        for index, row in enumerate(reader, 1):
            if index > MAX_ROWS_PER_SHEET:
                warnings.append(f"Delimited file truncated after {MAX_ROWS_PER_SHEET} rows.")
                break
            line = "\t".join(str(cell) for cell in row[:MAX_COLS_PER_SHEET])
            rows.append(line)
            total_chars += len(line)
            if total_chars >= MAX_EXTRACTED_CHARS:
                warnings.append("Delimited text truncated at the global extraction limit.")
                break
        return _bounded("\n".join(rows)), warnings
    except csv.Error as exc:
        raise DocumentExtractionError("Delimited-text parsing failed") from exc


def _extract_json(data: bytes) -> tuple[str, list[str]]:
    text = _decode(data)
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DocumentExtractionError("Invalid JSON document") from exc
    return _bounded(json.dumps(value, ensure_ascii=False, indent=2)), []


def _extract_xml(data: bytes) -> tuple[str, list[str]]:
    try:
        root = SafeElementTree.fromstring(data)
    except Exception as exc:
        raise DocumentExtractionError("Invalid or unsafe XML document") from exc
    text = "\n".join(piece.strip() for piece in root.itertext() if piece and piece.strip())
    return _bounded(text), []


def extract_document(filename: str, data: bytes) -> tuple[str, str, list[str]]:
    extension = Path(filename).suffix.casefold()
    if extension == ".pdf":
        text, warnings = _extract_pdf(data)
        kind = "pdf"
    elif extension == ".docx":
        text, warnings = _extract_docx(data)
        kind = "docx"
    elif extension == ".pptx":
        text, warnings = _extract_pptx(data)
        kind = "pptx"
    elif extension == ".xlsx":
        text, warnings = _extract_xlsx(data)
        kind = "xlsx"
    elif extension == ".csv":
        text, warnings = _extract_csv(data)
        kind = "csv"
    elif extension == ".tsv":
        text, warnings = _extract_csv(data, delimiter="\t")
        kind = "tsv"
    elif extension == ".json":
        text, warnings = _extract_json(data)
        kind = "json"
    elif extension == ".xml":
        text, warnings = _extract_xml(data)
        kind = "xml"
    elif extension in {".jsonl", ".yaml", ".yml", ".log", ".ini", ".cfg", ".conf"}:
        text, warnings = _decode(data), []
        kind = extension.lstrip(".")
    else:
        raise DocumentExtractionError(f"Unsupported structured document type: {extension or '<none>'}")
    if not text.strip():
        raise DocumentExtractionError(f"No readable text found in {extension or 'document'}")
    return _bounded(text), kind, warnings
