from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape
from zoneinfo import ZoneInfo

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.shared import Cm, Pt
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

TZ = ZoneInfo("Asia/Tokyo")


LABELS = {
    "ja": {
        "report": "調査レポート",
        "status": "検証状態",
        "validated": "検証済み",
        "needs_review": "要確認",
        "summary": "概要",
        "findings": "主な確認事項",
        "analysis": "分析・考察",
        "limitations": "制約・未確認事項",
        "recommendations": "推奨アクション",
        "sources": "出典",
        "no_summary": "収集した根拠に基づき、確認できた情報を以下に整理します。",
        "no_items": "該当なし",
        "audit_note": "技術ログ、内部Evidence ID、ワークフロー履歴は本文から分離し、監査用成果物として保存しています。",
    },
    "vi": {
        "report": "Báo cáo nghiên cứu",
        "status": "Trạng thái xác minh",
        "validated": "Đã xác minh",
        "needs_review": "Cần xác nhận",
        "summary": "Tóm tắt",
        "findings": "Kết quả chính",
        "analysis": "Phân tích",
        "limitations": "Giới hạn / Nội dung chưa xác minh",
        "recommendations": "Đề xuất tiếp theo",
        "sources": "Nguồn tham khảo",
        "no_summary": "Dưới đây là các thông tin đã được tổng hợp từ những bằng chứng thu thập được.",
        "no_items": "Không có",
        "audit_note": "Log kỹ thuật, Evidence ID nội bộ và lịch sử workflow được tách khỏi báo cáo chính và lưu riêng để audit.",
    },
    "en": {
        "report": "Research Report",
        "status": "Validation status",
        "validated": "Validated",
        "needs_review": "Needs review",
        "summary": "Executive Summary",
        "findings": "Key Findings",
        "analysis": "Analysis",
        "limitations": "Limitations / Unresolved Items",
        "recommendations": "Recommended Next Steps",
        "sources": "Sources",
        "no_summary": "The findings below are organized from the evidence collected for this task.",
        "no_items": "None",
        "audit_note": "Technical logs, internal evidence IDs and workflow history are separated from this reader-facing report and preserved as audit artifacts.",
    },
}


@dataclass(frozen=True)
class HumanReportBundle:
    markdown: str
    paths: tuple[str, ...]
    warnings: tuple[str, ...] = ()


def _lang(language: str) -> str:
    value = (language or "ja").strip().lower()
    return value if value in LABELS else "ja"


def _clean(value: Any) -> str:
    return " ".join(str(value or "").split())


def _refs(item: dict[str, Any]) -> str:
    ids = item.get("source_ids")
    if not isinstance(ids, list):
        return ""
    refs = [str(x).strip() for x in ids if str(x).strip()]
    return " " + " ".join(f"[{x}]" for x in refs) if refs else ""


def build_report_data(
    task_id: str,
    title: str,
    request: str,
    handoff: dict[str, Any],
    language: str,
) -> dict[str, Any]:
    language = _lang(language)
    labels = LABELS[language]
    facts = [x for x in handoff.get("key_facts", []) if isinstance(x, dict) and _clean(x.get("claim"))]
    inferences = [x for x in handoff.get("inferences", []) if isinstance(x, dict) and _clean(x.get("claim"))]
    conflicts = [x for x in handoff.get("conflicts", []) if isinstance(x, dict)]
    unresolved = [_clean(x) for x in handoff.get("unresolved_items", []) if _clean(x)]
    actions = [_clean(x) for x in handoff.get("recommended_next_actions", []) if _clean(x)]
    sources = [x for x in handoff.get("sources", []) if isinstance(x, dict) and _clean(x.get("url"))]
    limitations: list[str] = []
    for conflict in conflicts:
        topic = _clean(conflict.get("topic"))
        description = _clean(conflict.get("description"))
        if topic and description:
            limitations.append(f"{topic}: {description}")
        elif topic or description:
            limitations.append(topic or description)
    limitations.extend(unresolved)
    blockers = [_clean(x) for x in handoff.get("blockers", []) if _clean(x)]
    if handoff.get("presentation_ready") is not True:
        limitations = blockers + limitations

    return {
        "task_id": task_id,
        "title": _clean(title) or task_id,
        "request": _clean(request),
        "language": language,
        "report_label": labels["report"],
        "status_label": labels["status"],
        "status": labels["validated"] if handoff.get("presentation_ready") is True else labels["needs_review"],
        "summary": _clean(handoff.get("conclusion")) or labels["no_summary"],
        "facts": facts,
        "inferences": inferences,
        "limitations": list(dict.fromkeys(limitations)),
        "actions": list(dict.fromkeys(actions)),
        "sources": sources,
        "labels": labels,
        "generated_at": datetime.now(TZ).isoformat(),
    }


def render_markdown(data: dict[str, Any]) -> str:
    labels = data["labels"]
    lines = [
        f"# {data['title']}",
        "",
        f"> {data['report_label']} · {data['status_label']}: **{data['status']}**",
        "",
        f"## {labels['summary']}",
        data["summary"],
        "",
        f"## {labels['findings']}",
    ]
    if data["facts"]:
        for item in data["facts"]:
            lines.append(f"- {_clean(item.get('claim'))}{_refs(item)}")
    else:
        lines.append(f"- {labels['no_items']}")

    lines += ["", f"## {labels['analysis']}"]
    if data["inferences"]:
        for item in data["inferences"]:
            lines.append(f"- {_clean(item.get('claim'))}{_refs(item)}")
    else:
        lines.append(f"- {labels['no_items']}")

    lines += ["", f"## {labels['limitations']}"]
    lines.extend(f"- {item}" for item in data["limitations"])
    if not data["limitations"]:
        lines.append(f"- {labels['no_items']}")

    lines += ["", f"## {labels['recommendations']}"]
    lines.extend(f"- {item}" for item in data["actions"])
    if not data["actions"]:
        lines.append(f"- {labels['no_items']}")

    lines += ["", f"## {labels['sources']}"]
    if data["sources"]:
        for source in data["sources"]:
            sid = _clean(source.get("source_id")) or "S?"
            name = _clean(source.get("title")) or sid
            lines.append(f"- [{sid}] {name} — {_clean(source.get('url'))}")
    else:
        lines.append(f"- {labels['no_items']}")

    lines += ["", "---", "", labels["audit_note"], "", f"Task: `{data['task_id']}`"]
    return "\n".join(lines).rstrip() + "\n"


def _set_docx_font(run, language: str, size: int | None = None, bold: bool | None = None) -> None:
    font = "Noto Sans CJK JP" if language == "ja" else "Aptos"
    run.font.name = font
    run._element.rPr.rFonts.set(qn("w:eastAsia"), font)
    if size is not None:
        run.font.size = Pt(size)
    if bold is not None:
        run.bold = bold


def _write_docx(data: dict[str, Any], path: Path) -> None:
    doc = Document()
    section = doc.sections[0]
    section.top_margin = Cm(1.8)
    section.bottom_margin = Cm(1.8)
    section.left_margin = Cm(2.0)
    section.right_margin = Cm(2.0)

    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(data["title"])
    _set_docx_font(run, data["language"], 20, True)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(f"{data['report_label']} · {data['status_label']}: {data['status']}")
    _set_docx_font(run, data["language"], 10, False)

    def heading(text: str) -> None:
        p = doc.add_paragraph()
        run = p.add_run(text)
        _set_docx_font(run, data["language"], 14, True)

    def paragraph(text: str) -> None:
        p = doc.add_paragraph()
        run = p.add_run(text)
        _set_docx_font(run, data["language"], 10, False)

    def bullets(items: list[str]) -> None:
        if not items:
            items = [data["labels"]["no_items"]]
        for text in items:
            p = doc.add_paragraph(style="List Bullet")
            run = p.add_run(text)
            _set_docx_font(run, data["language"], 10, False)

    heading(data["labels"]["summary"])
    paragraph(data["summary"])
    heading(data["labels"]["findings"])
    bullets([_clean(x.get("claim")) + _refs(x) for x in data["facts"]])
    heading(data["labels"]["analysis"])
    bullets([_clean(x.get("claim")) + _refs(x) for x in data["inferences"]])
    heading(data["labels"]["limitations"])
    bullets(data["limitations"])
    heading(data["labels"]["recommendations"])
    bullets(data["actions"])
    heading(data["labels"]["sources"])
    bullets([
        f"[{_clean(x.get('source_id')) or 'S?'}] {_clean(x.get('title')) or _clean(x.get('source_id'))} — {_clean(x.get('url'))}"
        for x in data["sources"]
    ])
    paragraph(data["labels"]["audit_note"])
    paragraph(f"Task: {data['task_id']}")
    doc.save(path)


def _pdf_font(language: str) -> str:
    if language == "ja":
        name = "HeiseiKakuGo-W5"
        try:
            pdfmetrics.getFont(name)
        except KeyError:
            pdfmetrics.registerFont(UnicodeCIDFont(name))
        return name
    regular = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
    if regular.is_file():
        name = "ThreeAgentDejaVu"
        try:
            pdfmetrics.getFont(name)
        except KeyError:
            pdfmetrics.registerFont(TTFont(name, str(regular)))
        return name
    return "Helvetica"


def _write_pdf(data: dict[str, Any], path: Path) -> None:
    font = _pdf_font(data["language"])
    styles = getSampleStyleSheet()
    title = ParagraphStyle("TA_Title", parent=styles["Title"], fontName=font, fontSize=18, leading=23, spaceAfter=8)
    meta = ParagraphStyle("TA_Meta", parent=styles["Normal"], fontName=font, fontSize=9, leading=12, textColor="#555555", spaceAfter=10)
    head = ParagraphStyle("TA_Head", parent=styles["Heading2"], fontName=font, fontSize=13, leading=17, spaceBefore=10, spaceAfter=5)
    body = ParagraphStyle("TA_Body", parent=styles["BodyText"], fontName=font, fontSize=9.5, leading=14, spaceAfter=4)
    bullet = ParagraphStyle("TA_Bullet", parent=body, leftIndent=12, firstLineIndent=-7, bulletIndent=4)
    doc = SimpleDocTemplate(str(path), pagesize=A4, rightMargin=18*mm, leftMargin=18*mm, topMargin=16*mm, bottomMargin=16*mm)
    story = [
        Paragraph(escape(data["title"]), title),
        Paragraph(escape(f"{data['report_label']} · {data['status_label']}: {data['status']}"), meta),
        Paragraph(escape(data["labels"]["summary"]), head),
        Paragraph(escape(data["summary"]), body),
    ]

    def section(label: str, items: list[str]) -> None:
        story.append(Paragraph(escape(label), head))
        values = items or [data["labels"]["no_items"]]
        for item in values:
            story.append(Paragraph("• " + escape(item), bullet))

    section(data["labels"]["findings"], [_clean(x.get("claim")) + _refs(x) for x in data["facts"]])
    section(data["labels"]["analysis"], [_clean(x.get("claim")) + _refs(x) for x in data["inferences"]])
    section(data["labels"]["limitations"], data["limitations"])
    section(data["labels"]["recommendations"], data["actions"])
    section(data["labels"]["sources"], [
        f"[{_clean(x.get('source_id')) or 'S?'}] {_clean(x.get('title')) or _clean(x.get('source_id'))} — {_clean(x.get('url'))}"
        for x in data["sources"]
    ])
    story += [Spacer(1, 8), Paragraph(escape(data["labels"]["audit_note"]), meta), Paragraph(escape(f"Task: {data['task_id']}"), meta)]
    doc.build(story)


def create_human_report(
    *,
    task_id: str,
    title: str,
    request: str,
    handoff_path: str | Path,
    artifact_root: str | Path,
    language: str,
) -> HumanReportBundle:
    path = Path(handoff_path)
    if not path.is_file():
        raise FileNotFoundError(f"Research handoff not found: {path}")
    handoff = json.loads(path.read_text(encoding="utf-8"))
    data = build_report_data(task_id, title, request, handoff, language)
    markdown = render_markdown(data)
    folder = Path(artifact_root) / "reports" / datetime.now(TZ).strftime("%Y-%m-%d")
    folder.mkdir(parents=True, exist_ok=True)
    md_path = folder / f"{task_id}_report.md"
    docx_path = folder / f"{task_id}_report.docx"
    pdf_path = folder / f"{task_id}_report.pdf"
    md_path.write_text(markdown, encoding="utf-8")
    _write_docx(data, docx_path)
    warnings: list[str] = []
    paths = [str(md_path), str(docx_path)]
    try:
        _write_pdf(data, pdf_path)
        paths.append(str(pdf_path))
    except Exception as exc:
        warnings.append(f"PDF export unavailable: {type(exc).__name__}: {exc}")
    return HumanReportBundle(markdown=markdown, paths=tuple(paths), warnings=tuple(warnings))
