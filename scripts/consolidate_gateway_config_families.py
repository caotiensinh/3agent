from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "three_agent"
ARTIFACTS = ROOT / "artifacts" / "consolidation"


def run(command: list[str], *, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=check,
    )


def failure_keys(output: str) -> set[str]:
    keys: set[str] = set()
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith(("FAILED ", "ERROR ")):
            keys.add(stripped.split(" - ", 1)[0])
    return keys


def targeted_tests() -> list[str]:
    candidates = [
        "tests/test_multimodal_attachments_v4.py",
        "tests/test_chat_memory_attachments_v22.py",
        "tests/test_chat_memory_attachments_v3.py",
    ]
    return [name for name in candidates if (ROOT / name).is_file()]


def ensure_document_visual_support() -> None:
    path = SRC / "document_extractors.py"
    text = path.read_text(encoding="utf-8")
    if "NATIVE_IMAGE_EXTENSIONS" in text and "def extract_native_visual" in text:
        return

    text = text.replace(
        "from io import BytesIO, StringIO\n",
        "from dataclasses import dataclass\nfrom io import BytesIO, StringIO\n",
        1,
    )
    text = text.replace(
        "from pypdf import PdfReader\n",
        "from pypdf import PdfReader\nfrom PIL import Image\n",
        1,
    )
    text = text.replace(
        'DOCUMENT_EXTENSIONS = PLAIN_DOCUMENT_EXTENSIONS | RICH_DOCUMENT_EXTENSIONS\n',
        'DOCUMENT_EXTENSIONS = PLAIN_DOCUMENT_EXTENSIONS | RICH_DOCUMENT_EXTENSIONS\n'
        'NATIVE_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tif", ".tiff"}\n',
        1,
    )
    old_pdf_empty = '''    if not rendered:\n        raise DocumentExtractionError(\n            "PDF contains no extractable text. Scanned/image-only PDF OCR is not configured."\n        )\n    warnings = []\n'''
    new_pdf_empty = '''    warnings = []\n    if not rendered:\n        warnings.append("PDF contains no extractable text; local visual analysis is required.")\n'''
    if old_pdf_empty not in text:
        raise RuntimeError("document_extractors PDF empty-text contract changed unexpectedly")
    text = text.replace(old_pdf_empty, new_pdf_empty, 1)
    text = text.replace(
        '    if not text.strip():\n        raise DocumentExtractionError(f"No readable text found in {extension or \'document\'}")\n',
        '    if not text.strip() and extension != ".pdf":\n        raise DocumentExtractionError(f"No readable text found in {extension or \'document\'}")\n',
        1,
    )

    visual_support = r'''

@dataclass(frozen=True)
class VisualAsset:
    name: str
    locator: str
    media_type: str
    data: bytes
    width: int
    height: int


def _normalize_visual(name: str, data: bytes, *, locator: str) -> VisualAsset:
    try:
        with Image.open(BytesIO(data)) as image:
            image.seek(0)
            normalized = image.convert("RGBA")
            width, height = normalized.size
            output = BytesIO()
            normalized.save(output, format="PNG")
    except Exception as exc:
        raise DocumentExtractionError(f"Image parsing failed: {type(exc).__name__}") from exc
    return VisualAsset(
        name=str(name or "visual")[:240],
        locator=str(locator or "visual")[:320],
        media_type="image/png",
        data=output.getvalue(),
        width=int(width),
        height=int(height),
    )


def extract_native_visual(filename: str, data: bytes) -> VisualAsset:
    extension = Path(filename).suffix.casefold()
    if extension not in NATIVE_IMAGE_EXTENSIONS:
        raise DocumentExtractionError(f"Unsupported native image type: {extension or '<none>'}")
    if not data:
        raise DocumentExtractionError("Native image is empty")
    return _normalize_visual(filename, data, locator=f"image:{Path(filename).name}")


def _ooxml_visuals(filename: str, data: bytes) -> tuple[list[VisualAsset], list[str]]:
    _guard_ooxml(data)
    extension = Path(filename).suffix.casefold()
    prefix = {".docx": "word/media/", ".pptx": "ppt/media/", ".xlsx": "xl/media/"}.get(extension)
    if not prefix:
        return [], []
    visuals: list[VisualAsset] = []
    warnings: list[str] = []
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            for info in archive.infolist():
                if info.is_dir() or not info.filename.startswith(prefix):
                    continue
                try:
                    payload = archive.read(info)
                    visuals.append(_normalize_visual(info.filename, payload, locator=info.filename))
                except (DocumentExtractionError, KeyError, OSError) as exc:
                    warnings.append(f"Embedded visual skipped: {info.filename}: {exc}")
    except (zipfile.BadZipFile, OSError) as exc:
        raise DocumentExtractionError("Invalid Office Open XML document") from exc
    return visuals, warnings


def _pdf_visuals(filename: str, data: bytes) -> tuple[list[VisualAsset], list[str]]:
    del filename
    visuals: list[VisualAsset] = []
    warnings: list[str] = []
    try:
        reader = PdfReader(BytesIO(data), strict=False)
        for page_index, page in enumerate(reader.pages[:MAX_PDF_PAGES], 1):
            try:
                page_images = list(page.images)
            except Exception as exc:
                warnings.append(f"PDF page {page_index} visual enumeration failed: {type(exc).__name__}")
                continue
            for image_index, image_file in enumerate(page_images, 1):
                payload = bytes(getattr(image_file, "data", b"") or b"")
                if not payload:
                    continue
                name = str(getattr(image_file, "name", "") or f"page-{page_index}-image-{image_index}")
                try:
                    visuals.append(
                        _normalize_visual(name, payload, locator=f"pdf:page:{page_index}")
                    )
                except DocumentExtractionError as exc:
                    warnings.append(f"PDF visual skipped: page {page_index}: {exc}")
    except Exception as exc:
        raise DocumentExtractionError(f"PDF visual extraction failed: {type(exc).__name__}") from exc
    return visuals, warnings


def extract_visual_assets(filename: str, data: bytes) -> tuple[list[VisualAsset], list[str]]:
    extension = Path(filename).suffix.casefold()
    if extension in NATIVE_IMAGE_EXTENSIONS:
        return [extract_native_visual(filename, data)], []
    if extension == ".pdf":
        return _pdf_visuals(filename, data)
    if extension in {".docx", ".pptx", ".xlsx"}:
        return _ooxml_visuals(filename, data)
    return [], []
'''
    path.write_text(text.rstrip() + visual_support + "\n", encoding="utf-8")


def consolidate_knowledge_gateway_v3() -> None:
    canonical_path = SRC / "knowledge_gateway.py"
    variant_path = SRC / "knowledge_gateway_v3.py"
    canonical = canonical_path.read_text(encoding="utf-8").rstrip()
    variant = variant_path.read_text(encoding="utf-8")

    marker = "MAX_MULTIMODAL_UPLOAD_BYTES ="
    if marker not in variant:
        raise RuntimeError("knowledge_gateway_v3 multimodal body marker missing")
    body = marker + variant.split(marker, 1)[1]
    addition = (
        "\n\n\n# Canonical multimodal attachment ingestion and bounded local visual semantics.\n"
        "from .document_extractors import (\n"
        "    DOCUMENT_EXTENSIONS,\n"
        "    NATIVE_IMAGE_EXTENSIONS,\n"
        "    DocumentExtractionError,\n"
        "    VisualAsset,\n"
        "    extract_document,\n"
        "    extract_native_visual,\n"
        "    extract_visual_assets,\n"
        ")\n"
        "from .vision import OllamaVisionClient, VisionAnalysisError\n\n"
        + body.strip()
        + "\n"
    )
    canonical_path.write_text(canonical + addition, encoding="utf-8")


def rewrite_references() -> None:
    old = "knowledge_gateway_v3"
    canonical = "knowledge_gateway"
    excluded = {(SRC / "knowledge_gateway_v3.py").resolve(), Path(__file__).resolve()}
    allowed = {".py", ".toml", ".sh", ".ps1", ".yml", ".yaml"}
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
    for name in tracked:
        if not name:
            continue
        path = (ROOT / name).resolve()
        if path in excluded:
            continue
        if path.suffix.lower() not in allowed and path.name != "pyproject.toml":
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError):
            continue
        new = text.replace(old, canonical)
        if new != text:
            path.write_text(new, encoding="utf-8")


def smoke_test() -> None:
    sys.path.insert(0, str(ROOT / "src"))
    from three_agent.document_extractors import NATIVE_IMAGE_EXTENSIONS
    from three_agent.knowledge_gateway import KnowledgeGateway, KnowledgeGatewayV2, KnowledgeGatewayV3

    assert issubclass(KnowledgeGatewayV2, KnowledgeGateway)
    assert issubclass(KnowledgeGatewayV3, KnowledgeGateway)
    assert NATIVE_IMAGE_EXTENSIONS == {
        ".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tif", ".tiff"
    }
    with tempfile.TemporaryDirectory() as td:
        gateway = KnowledgeGatewayV3(Path(td), object())
        upload = gateway.ingest_upload("note.txt", b"bounded canonical multimodal document")
        assert upload.document_count == 1
        assert upload.image_count == 0


def main() -> int:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    ensure_document_visual_support()
    tests = targeted_tests()
    (ARTIFACTS / "gateway_config_tests.txt").write_text(
        "\n".join(tests) + ("\n" if tests else ""), encoding="utf-8"
    )

    baseline = run([sys.executable, "-m", "pytest", "-q", *tests]) if tests else None
    before = baseline.stdout if baseline else ""
    (ARTIFACTS / "gateway_config_pytest_before.txt").write_text(before, encoding="utf-8")
    baseline_failures = failure_keys(before)

    consolidate_knowledge_gateway_v3()
    rewrite_references()
    (SRC / "knowledge_gateway_v3.py").unlink()

    stale = run([
        "git", "grep", "-nE", "knowledge_gateway_v3", "--",
        "src/three_agent", "tests", "pyproject.toml",
    ])
    if stale.returncode == 0 and stale.stdout.strip():
        print(stale.stdout)
        return 71

    run([sys.executable, "-m", "compileall", "-q", "src/three_agent", "tests"], check=True)
    smoke_test()

    final = run([sys.executable, "-m", "pytest", "-q", *tests]) if tests else None
    after = final.stdout if final else ""
    (ARTIFACTS / "gateway_config_pytest_after.txt").write_text(after, encoding="utf-8")
    final_failures = failure_keys(after)
    new_failures = sorted(final_failures - baseline_failures)
    removed_failures = sorted(baseline_failures - final_failures)

    payload = {
        "schema": "workspace-source-consolidation/v4",
        "families": {"knowledge_gateway": ["src/three_agent/knowledge_gateway.py"]},
        "removed": ["src/three_agent/knowledge_gateway_v3.py"],
        "baseline_returncode": baseline.returncode if baseline else 0,
        "final_returncode": final.returncode if final else 0,
        "baseline_failures": sorted(baseline_failures),
        "final_failures": sorted(final_failures),
        "new_failures": new_failures,
        "removed_failures": removed_failures,
        "remaining_variant_files": [
            str(path.relative_to(ROOT)) for path in SRC.glob("knowledge_gateway_v*.py")
        ],
    }
    (ARTIFACTS / "gateway_config_families.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    if payload["remaining_variant_files"]:
        return 72
    if new_failures:
        return 73
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
