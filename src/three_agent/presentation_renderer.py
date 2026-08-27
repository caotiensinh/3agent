from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.util import Inches, Pt


class PresentationRenderError(RuntimeError):
    pass


class PptxRenderer:
    def __init__(self, font_name: str = "Aptos"):
        self.font_name = font_name

    @staticmethod
    def _set_font(run, size: int, bold: bool = False, color: tuple[int, int, int] = (32, 36, 43)) -> None:
        run.font.size = Pt(size)
        run.font.bold = bold
        run.font.name = "Aptos"
        run.font.color.rgb = RGBColor(*color)

    def _add_textbox(self, slide, left, top, width, height, text: str, size: int, bold: bool = False, color=(32, 36, 43)):
        shape = slide.shapes.add_textbox(left, top, width, height)
        frame = shape.text_frame
        frame.clear()
        frame.word_wrap = True
        frame.margin_left = Inches(0.04)
        frame.margin_right = Inches(0.04)
        frame.margin_top = Inches(0.03)
        frame.margin_bottom = Inches(0.03)
        paragraph = frame.paragraphs[0]
        run = paragraph.add_run()
        run.text = text
        run.font.size = Pt(size)
        run.font.bold = bold
        run.font.name = self.font_name
        run.font.color.rgb = RGBColor(*color)
        return shape

    def _add_footer(self, slide, slide_no: int, source_ids: list[str]) -> None:
        source_text = "Sources: " + ", ".join(source_ids) if source_ids else ""
        self._add_textbox(slide, Inches(0.65), Inches(7.08), Inches(10.9), Inches(0.22), source_text, 10, color=(92, 99, 112))
        number = self._add_textbox(slide, Inches(12.1), Inches(7.03), Inches(0.6), Inches(0.25), str(slide_no), 10, color=(92, 99, 112))
        number.text_frame.paragraphs[0].alignment = PP_ALIGN.RIGHT

    def _add_notes(self, slide, notes: str, source_ids: list[str]) -> None:
        notes_frame = slide.notes_slide.notes_text_frame
        if notes_frame is None:
            return
        suffix = ""
        if source_ids:
            suffix = "\nEvidence source IDs: " + ", ".join(source_ids)
        notes_frame.text = (notes or "") + suffix

    def render(self, plan: dict[str, Any], output_path: Path) -> Path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        prs = Presentation()
        prs.slide_width = Inches(13.333)
        prs.slide_height = Inches(7.5)
        blank_layout = prs.slide_layouts[6]

        for index, item in enumerate(plan["slides"], start=1):
            slide = prs.slides.add_slide(blank_layout)
            title = str(item["title"])
            if item.get("kind") == "title" and index == 1:
                self._add_textbox(slide, Inches(0.8), Inches(1.8), Inches(11.7), Inches(1.4), title, 36, True, (18, 46, 86))
                subtitle = str(plan.get("subtitle", ""))
                if subtitle:
                    self._add_textbox(slide, Inches(0.85), Inches(3.35), Inches(11.5), Inches(0.8), subtitle, 22, False, (65, 72, 84))
                meta = f"Audience: {plan['audience']}  |  Purpose: {plan['purpose']}"
                self._add_textbox(slide, Inches(0.85), Inches(5.5), Inches(11.2), Inches(0.5), meta, 16, False, (92, 99, 112))
            else:
                self._add_textbox(slide, Inches(0.65), Inches(0.38), Inches(12.0), Inches(0.65), title, 30, True, (18, 46, 86))
                y = 1.25
                for claim in item.get("claims", []):
                    prefix = "Fact" if claim["kind"] == "verified_fact" else "Inference"
                    text = f"{prefix} {claim['claim_id']}: {claim['text']}"
                    shape = self._add_textbox(slide, Inches(0.85), Inches(y), Inches(11.55), Inches(0.72), text, 20)
                    shape.text_frame.paragraphs[0].level = 0
                    y += 0.78
                for text in item.get("context_points", []):
                    self._add_textbox(slide, Inches(0.85), Inches(y), Inches(11.55), Inches(0.65), f"• {text}", 20)
                    y += 0.7
                for text in item.get("proposal_points", []):
                    self._add_textbox(slide, Inches(0.85), Inches(y), Inches(11.55), Inches(0.65), f"Proposal / limitation: {text}", 20, True, (78, 57, 28))
                    y += 0.7
                if y > 6.75:
                    raise PresentationRenderError(f"slide {index} exceeds safe vertical content budget")
            self._add_footer(slide, index, list(item.get("source_ids", [])))
            self._add_notes(slide, str(item.get("speaker_notes", "")), list(item.get("source_ids", [])))

        prs.save(output_path)
        self.inspect(output_path, expected_titles=[slide["title"] for slide in plan["slides"]])
        return output_path

    @staticmethod
    def inspect(path: Path, expected_titles: list[str]) -> dict[str, Any]:
        prs = Presentation(path)
        if len(prs.slides) != len(expected_titles):
            raise PresentationRenderError("rendered PPTX slide count mismatch")
        observed: list[str] = []
        for slide in prs.slides:
            texts: list[str] = []
            for shape in slide.shapes:
                if getattr(shape, "has_text_frame", False):
                    value = shape.text.strip()
                    if value:
                        texts.append(value)
            observed.append(texts[0] if texts else "")
        if observed != expected_titles:
            raise PresentationRenderError(f"rendered PPTX title mismatch: {observed}")
        return {"slide_count": len(prs.slides), "titles": observed}


def convert_pptx_to_pdf(pptx_path: Path, output_dir: Path | None = None) -> Path:
    soffice = shutil.which("soffice") or shutil.which("libreoffice")
    if not soffice:
        raise PresentationRenderError("PDF output requires LibreOffice/soffice on the host")
    pptx_path = Path(pptx_path).resolve()
    output_dir = Path(output_dir or pptx_path.parent).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [soffice, "--headless", "--convert-to", "pdf", "--outdir", str(output_dir), str(pptx_path)],
        text=True,
        capture_output=True,
        check=False,
        timeout=120,
    )
    pdf_path = output_dir / f"{pptx_path.stem}.pdf"
    if result.returncode != 0 or not pdf_path.exists():
        raise PresentationRenderError(f"PDF conversion failed: {result.stderr.strip() or result.stdout.strip()}")
    return pdf_path
