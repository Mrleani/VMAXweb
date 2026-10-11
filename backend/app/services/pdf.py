"""Branded PDF audit report generation (pure-Python, no system deps)."""

from __future__ import annotations

from datetime import UTC, datetime

from fpdf import FPDF

from app.models import Finding, ScanResult, Severity

# RGB brand palette
_DARK = (11, 15, 23)
_CARD = (19, 27, 42)
_BORDER = (30, 41, 59)
_EMERALD = (16, 185, 129)
_CRIMSON = (239, 68, 68)
_AMBER = (245, 158, 11)
_CYAN = (6, 182, 212)
_SKY = (56, 189, 248)
_WHITE = (248, 250, 252)
_MUTED = (148, 163, 184)
_INK = (30, 41, 59)

_SEVERITY_COLORS: dict[Severity, tuple[int, int, int]] = {
    Severity.CRITICAL: _CRIMSON,
    Severity.WARNING: _AMBER,
    Severity.PASSED: _EMERALD,
    Severity.INFO: _SKY,
}

_REPLACEMENTS = {
    "\u2019": "'",
    "\u2018": "'",
    "\u201c": '"',
    "\u201d": '"',
    "\u2013": "-",
    "\u2014": "-",
    "\u2022": "-",
    "\u2026": "...",
    "\u2192": "->",
    "\u00a0": " ",
}


def _sanitize(text: str) -> str:
    for source, target in _REPLACEMENTS.items():
        text = text.replace(source, target)
    return text.encode("latin-1", "replace").decode("latin-1")


def _grade_color(score: int) -> tuple[int, int, int]:
    if score >= 90:
        return _EMERALD
    if score >= 70:
        return _AMBER
    return _CRIMSON


class _Report(FPDF):
    def __init__(self) -> None:
        super().__init__(orientation="P", unit="mm", format="A4")
        self.set_auto_page_break(auto=True, margin=20)
        self.set_margins(15, 15, 15)
        self.set_title("VMAXweb Security Audit Report")
        self.set_author("VMAXweb by StarNet")

    def header(self) -> None:
        if self.page_no() == 1:
            return
        self.set_fill_color(*_DARK)
        self.rect(0, 0, self.w, 14, style="F")
        self.set_xy(15, 4)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*_WHITE)
        self.cell(0, 6, "VMAXweb  -  Security Audit Report", align="L")
        self.set_x(-60)
        self.set_text_color(*_EMERALD)
        self.cell(45, 6, "by StarNet", align="R")
        self.ln(14)

    def footer(self) -> None:
        self.set_y(-15)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*_MUTED)
        self.cell(
            0,
            8,
            f"VMAXweb by StarNet  |  Page {self.page_no()}  |  Confidential",
            align="C",
        )


def _rounded_card(
    pdf: FPDF,
    x: float,
    y: float,
    w: float,
    h: float,
    *,
    fill: tuple[int, int, int],
    border: tuple[int, int, int] | None = None,
) -> None:
    pdf.set_fill_color(*fill)
    if border is not None:
        pdf.set_draw_color(*border)
        pdf.rect(x, y, w, h, style="DF", round_corners=True, corner_radius=2.5)
    else:
        pdf.rect(x, y, w, h, style="F", round_corners=True, corner_radius=2.5)


def _cover(pdf: _Report, result: ScanResult) -> None:
    pdf.add_page()
    _rounded_card(pdf, 15, 15, pdf.epw, 34, fill=_CARD, border=_BORDER)

    pdf.set_xy(22, 21)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(*_WHITE)
    pdf.cell(0, 9, "VMAXweb", align="L")

    pdf.set_xy(22, 31)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*_EMERALD)
    pdf.cell(0, 5, "Maximum Web & API Security Engine  -  by StarNet", align="L")

    pdf.set_xy(22, 37)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*_MUTED)
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    pdf.cell(0, 5, f"Generated: {generated}", align="L")

    pdf.set_xy(pdf.w - 55, 24)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*_CYAN)
    pdf.cell(33, 6, f"Engine v{result.engine_version}", align="R")


def _target_and_score(pdf: _Report, result: ScanResult) -> None:
    y = 55
    _rounded_card(pdf, 15, y, pdf.epw, 18, fill=(248, 250, 252), border=(226, 232, 240))

    pdf.set_xy(20, y + 3)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*_MUTED)
    pdf.cell(0, 4, "TARGET", align="L")
    pdf.set_xy(20, y + 8)
    pdf.set_font("Courier", "B", 12)
    pdf.set_text_color(*_INK)
    pdf.cell(0, 6, _sanitize(result.target.url), align="L")

    scanned = result.finished_at.strftime("%Y-%m-%d %H:%M UTC")
    pdf.set_xy(20, y + 13.5)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*_MUTED)
    pdf.cell(
        0,
        4,
        _sanitize(f"Scanned: {scanned}   |   Duration: {result.duration_ms} ms"),
        align="L",
    )

    # Score badge (right side)
    score_x = pdf.w - 55
    pdf.set_xy(score_x, y + 2.5)
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(*_MUTED)
    pdf.cell(40, 4, "SECURITY HEALTH", align="R")

    pdf.set_xy(score_x, y + 6.5)
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(*_grade_color(result.score))
    pdf.cell(40, 9, f"{result.score}/100", align="R")

    _stats_row(pdf, result, y + 78)


def _stats_row(pdf: _Report, result: ScanResult, y: float) -> None:
    stats = [
        ("CRITICAL", result.critical_count, _CRIMSON),
        ("WARNINGS", result.warning_count, _AMBER),
        ("PASSED", result.passed_count, _EMERALD),
        ("GRADE", result.grade, _grade_color(result.score)),
    ]
    gap = 4.0
    card_w = (pdf.epw - gap * 3) / 4

    for index, (label, value, color) in enumerate(stats):
        x = 15 + index * (card_w + gap)
        _rounded_card(pdf, x, y, card_w, 22, fill=_CARD, border=_BORDER)
        pdf.set_xy(x + 3, y + 4)
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_text_color(*_MUTED)
        pdf.cell(card_w - 6, 4, label, align="L")
        pdf.set_xy(x + 3, y + 8.5)
        pdf.set_font("Helvetica", "B", 20)
        pdf.set_text_color(*color)
        pdf.cell(card_w - 6, 10, str(value), align="L")

    pdf.set_y(y + 30)


def _findings_section(pdf: _Report, result: ScanResult) -> None:
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*_INK)
    pdf.cell(0, 8, f"Audit Findings ({len(result.findings)})", align="L")
    pdf.ln(10)

    for finding in result.findings:
        _finding_block(pdf, finding)


def _finding_block(pdf: _Report, finding: Finding) -> None:
    color = _SEVERITY_COLORS[finding.severity]
    x = 15
    width = pdf.epw

    # Estimate height then break if needed.
    if pdf.get_y() > pdf.h - 55:
        pdf.add_page()

    top = pdf.get_y()
    _rounded_card(pdf, x, top, width, 6, fill=color)

    pdf.set_xy(x + 3, top + 1)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*_WHITE)
    pdf.cell(30, 4, f" {finding.severity.value.upper()} ", align="L")

    pdf.set_x(x + 38)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(width - 41, 4, _sanitize(finding.name), align="L")

    pdf.set_xy(x, top + 8)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(*_MUTED)
    pdf.cell(width, 4, _sanitize(finding.module), align="L")

    pdf.set_xy(x, top + 12.5)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*_INK)
    pdf.cell(22, 4, "Status:", align="L")
    pdf.set_font("Courier", "", 8)
    pdf.multi_cell(width - 22, 4, _sanitize(finding.status), align="L")

    if finding.summary:
        pdf.set_x(x + 22)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*_MUTED)
        pdf.multi_cell(width - 22, 4, _sanitize(finding.summary), align="L")

    if finding.explanation:
        pdf.set_x(x)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*_CYAN)
        pdf.multi_cell(width, 5, "What is this?", align="L")
        pdf.set_x(x)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*_INK)
        pdf.multi_cell(width, 4.2, _sanitize(finding.explanation), align="L")

    if finding.fix_snippet:
        pdf.set_x(x)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*_EMERALD)
        pdf.multi_cell(width, 5, "How to fix it", align="L")

        pdf.set_font("Courier", "", 7.5)
        text = _sanitize(finding.fix_snippet)
        line_h = 3.8
        lines = pdf.multi_cell(width - 6, line_h, text, dry_run=True, output="LINES")
        box_h = line_h * max(1, len(lines)) + 4
        box_y = pdf.get_y()
        _rounded_card(pdf, x, box_y, width, box_h, fill=_DARK)
        pdf.set_xy(x + 3, box_y + 2)
        pdf.set_text_color(110, 231, 183)
        pdf.multi_cell(width - 6, line_h, text, align="L")
        pdf.set_y(box_y + box_h + 2)
    else:
        pdf.ln(2)

    pdf.ln(4)


def build_report(result: ScanResult) -> bytes:
    pdf = _Report()
    _cover(pdf, result)
    _target_and_score(pdf, result)
    _findings_section(pdf, result)
    return bytes(pdf.output())
