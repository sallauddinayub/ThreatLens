from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime
from utils import now_utc

from sqlalchemy.orm import Session

from database.models import Project, Report, Threat

REPORT_SECTIONS = [
    "Executive Summary", "System Overview", "Asset Inventory", "Data Flow Diagram",
    "Threat Model", "STRIDE Analysis", "Attack Scenarios", "Security Tests",
    "Test Results", "Evidence", "Risk Prioritization", "OWASP/CWE/MITRE Mapping",
    "Recommendations", "Threat-to-Test Traceability",
]


def _build_report_payload(db: Session, project: Project) -> dict:
    threats = db.query(Threat).filter(Threat.project_id == project.id).all()

    risk_counts: dict[str, int] = {}
    threat_rows = []
    traceability = []

    for t in threats:
        level = t.risk_assessment.risk_level.value if t.risk_assessment else "Informational"
        risk_counts[level] = risk_counts.get(level, 0) + 1

        threat_rows.append({
            "id": t.display_id,
            "title": t.title,
            "stride_category": t.stride_category.value,
            "affected_asset": t.affected_asset.name if t.affected_asset else None,
            "likelihood": t.likelihood,
            "impact": t.impact,
            "risk_score": round(t.risk_score, 3),
            "risk_level": level,
            "owasp_category": t.owasp_category,
            "cwe_id": t.cwe_id,
            "mitre_attack_technique": t.mitre_attack_technique,
            "recommended_mitigation": t.recommended_mitigation,
        })

        for scenario in t.attack_scenarios:
            for test in scenario.security_tests:
                for execution in test.executions:
                    traceability.append({
                        "asset": t.affected_asset.name if t.affected_asset else None,
                        "threat": t.display_id,
                        "stride_category": t.stride_category.value,
                        "attack_scenario": scenario.objective,
                        "security_test": test.display_id,
                        "execution_status": execution.status.value,
                        "risk_level": level,
                        "recommendation": t.recommended_mitigation,
                    })
                if not test.executions:
                    traceability.append({
                        "asset": t.affected_asset.name if t.affected_asset else None,
                        "threat": t.display_id,
                        "stride_category": t.stride_category.value,
                        "attack_scenario": scenario.objective,
                        "security_test": test.display_id,
                        "execution_status": "NOT_EXECUTED",
                        "risk_level": level,
                        "recommendation": t.recommended_mitigation,
                    })

    return {
        "generated_at": now_utc().isoformat(),
        "project": {"id": project.id, "name": project.name, "description": project.description},
        "executive_summary": {
            "total_threats": len(threats),
            "risk_distribution": risk_counts,
        },
        "system_overview": project.system_model,
        "threats": threat_rows,
        "traceability": traceability,
        "sections": REPORT_SECTIONS,
    }


def generate_json_report(db: Session, project: Project, output_dir: str) -> str:
    payload = _build_report_payload(db, project)
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, f"{project.id}_report.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
    db.add(Report(project_id=project.id, format="json", file_path=path))
    db.commit()
    return path


def generate_csv_report(db: Session, project: Project, output_dir: str) -> str:
    payload = _build_report_payload(db, project)
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, f"{project.id}_threats.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(payload["threats"][0].keys()) if payload["threats"] else [])
        if payload["threats"]:
            writer.writeheader()
            writer.writerows(payload["threats"])
    db.add(Report(project_id=project.id, format="csv", file_path=path))
    db.commit()
    return path


def generate_pdf_report(db: Session, project: Project, output_dir: str) -> str:
    """
    A multi-page, enterprise-style security assessment report. Presentation
    and structure only — every value here comes straight from
    _build_report_payload(); nothing is invented, re-scored, or re-mapped.
    Where the source data has no OWASP/CWE/MITRE mapping or no execution
    result, that is shown as-is ("-" / actual status), never fabricated.

    Uses reportlab (no external binary dependency, deterministic, offline-
    friendly) with a custom canvas subclass so the footer can show a true
    "Page X of Y" — reportlab only knows the running page count during the
    first pass, so total-page count requires buffering pages and stamping
    the footer in a second pass over the already-drawn content.
    """
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.pdfgen import canvas as canvas_mod
    from reportlab.platypus import (
        BaseDocTemplate, Flowable, Frame, KeepTogether, NextPageTemplate,
        PageBreak, PageTemplate, Paragraph, Spacer, Table, TableStyle,
    )

    payload = _build_report_payload(db, project)
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, f"{project.id}_report.pdf")

    # --- IST timestamp, matching the rest of the application (Section: keep timestamp
    # consistent with the IST standard already used everywhere else in the UI) ---
    from datetime import timedelta, timezone
    IST = timezone(timedelta(hours=5, minutes=30))
    generated_at_utc = datetime.fromisoformat(payload["generated_at"])
    generated_at_ist = generated_at_utc.replace(tzinfo=timezone.utc).astimezone(IST)
    generated_at_label = generated_at_ist.strftime("%b %d, %Y %H:%M IST")
    report_id = f"TL-{project.id[:8].upper()}"

    # --- palette: purple/indigo primary, matching the ThreatLens brand ---
    INDIGO = colors.HexColor("#4c1d95")
    PURPLE = colors.HexColor("#7c3aed")
    NAVY = colors.HexColor("#1e1b4b")
    MUTED = colors.HexColor("#64748b")
    LAVENDER_BG = colors.HexColor("#f5f3ff")
    LAVENDER_BORDER = colors.HexColor("#ddd6fe")
    CARD_BORDER = colors.HexColor("#e2e8f0")
    ROW_ALT = colors.HexColor("#faf9ff")
    RISK_COLORS = {
        "Critical": colors.HexColor("#dc2626"), "High": colors.HexColor("#ea580c"),
        "Medium": colors.HexColor("#d97706"), "Low": colors.HexColor("#2563eb"),
        "Informational": colors.HexColor("#6b7280"),
    }
    RISK_BG = {
        "Critical": colors.HexColor("#fef2f2"), "High": colors.HexColor("#fff7ed"),
        "Medium": colors.HexColor("#fffbeb"), "Low": colors.HexColor("#eff6ff"),
        "Informational": colors.HexColor("#f3f4f6"),
    }
    STATUS_COLORS = {
        "PASSED": colors.HexColor("#16a34a"), "FAILED": colors.HexColor("#dc2626"),
        "BLOCKED_BY_POLICY": colors.HexColor("#b45309"), "NOT_EXECUTED": colors.HexColor("#6b7280"),
        "ERROR": colors.HexColor("#dc2626"), "RUNNING": colors.HexColor("#2563eb"),
        "STOPPED": colors.HexColor("#6b7280"),
    }

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("CoverTitle", parent=styles["Title"], textColor=colors.white, fontSize=26, leading=30, alignment=TA_LEFT))
    styles.add(ParagraphStyle("CoverSub", parent=styles["Normal"], textColor=colors.HexColor("#ddd6fe"), fontSize=12, leading=16))
    styles.add(ParagraphStyle("CoverMeta", parent=styles["Normal"], textColor=colors.HexColor("#c4b5fd"), fontSize=9.5, leading=13))
    styles.add(ParagraphStyle("Confidential", parent=styles["Normal"], textColor=colors.white, fontSize=8.5, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle("PageTitle", parent=styles["Heading1"], textColor=NAVY, fontSize=17, spaceBefore=0, spaceAfter=4))
    styles.add(ParagraphStyle("PageSubtitle", parent=styles["Normal"], textColor=MUTED, fontSize=9.5, spaceAfter=14))
    styles.add(ParagraphStyle("SectionHeading", parent=styles["Heading2"], textColor=NAVY, fontSize=12.5, spaceBefore=14, spaceAfter=6))
    styles.add(ParagraphStyle("KpiNumber", parent=styles["Normal"], fontSize=26, fontName="Helvetica-Bold", textColor=NAVY, alignment=TA_CENTER, leading=28))
    styles.add(ParagraphStyle("KpiLabel", parent=styles["Normal"], fontSize=8.5, textColor=MUTED, alignment=TA_CENTER))
    styles.add(ParagraphStyle("Body", parent=styles["Normal"], fontSize=9.5, leading=14, textColor=colors.HexColor("#374151")))
    styles.add(ParagraphStyle("CardTitle", parent=styles["Normal"], fontSize=10.5, fontName="Helvetica-Bold", textColor=NAVY, leading=13))
    styles.add(ParagraphStyle("CardMeta", parent=styles["Normal"], fontSize=8, textColor=MUTED, leading=11))
    styles.add(ParagraphStyle("CardBody", parent=styles["Normal"], fontSize=8.5, leading=12, textColor=colors.HexColor("#374151")))
    styles.add(ParagraphStyle("CellText", parent=styles["Normal"], fontSize=8, leading=10.5))
    styles.add(ParagraphStyle("CellTextCenter", parent=styles["CellText"], alignment=TA_CENTER))
    styles.add(ParagraphStyle("HeaderCell", parent=styles["Normal"], fontSize=8, leading=10, textColor=colors.white, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle("BadgeText", parent=styles["Normal"], fontSize=7.5, fontName="Helvetica-Bold", alignment=TA_CENTER, leading=9))

    page_size = letter
    margin = 0.6 * inch
    usable_width = page_size[0] - 2 * margin

    def _esc(text) -> str:
        """Escapes &, <, > in real (possibly user-supplied) data before it's
        interpolated into a Paragraph — reportlab's Paragraph text is parsed
        as a small XML-like markup, so an unescaped '&' in a threat title,
        mitigation, or project name can corrupt rendering or raise a parse
        error. Applied to every dynamic value; our own literal markup like
        <b> tags is added after escaping, never escaped itself."""
        from xml.sax.saxutils import escape
        return escape(str(text)) if text not in (None, "") else "-"

    def _p(text, style="CellText"):
        return Paragraph(_esc(text), styles[style])

    def _header_row(labels):
        return [Paragraph(l, styles["HeaderCell"]) for l in labels]

    def _risk_badge(level: str, width=0.85 * inch) -> Table:
        color = RISK_COLORS.get(level, colors.HexColor("#6b7280"))
        bg = RISK_BG.get(level, colors.HexColor("#f3f4f6"))
        t = Table([[Paragraph(level.upper(), ParagraphStyle("b", parent=styles["BadgeText"], textColor=color))]],
                   colWidths=[width])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bg),
            ("BOX", (0, 0), (-1, -1), 0.75, color),
            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        return t

    def _status_badge(status: str, width=1.15 * inch) -> Table:
        color = STATUS_COLORS.get(status, colors.HexColor("#6b7280"))
        t = Table([[Paragraph(status.replace("_", " "), ParagraphStyle("s", parent=styles["BadgeText"], textColor=colors.white))]],
                   colWidths=[width])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), color),
            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        return t

    def _kpi_card(number, label, accent=PURPLE):
        t = Table([[Paragraph(str(number), styles["KpiNumber"])], [Paragraph(label, styles["KpiLabel"])]],
                   colWidths=[usable_width / 3 - 10])
        t.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 1, CARD_BORDER),
            ("LINEABOVE", (0, 0), (-1, 0), 3, accent),
            ("TOPPADDING", (0, 0), (-1, 0), 14), ("BOTTOMPADDING", (0, 0), (-1, 0), 2),
            ("TOPPADDING", (0, 1), (-1, 1), 2), ("BOTTOMPADDING", (0, 1), (-1, 1), 14),
        ]))
        return t

    def _asset_card(name, count, accent=PURPLE):
        t = Table([[Paragraph(str(count), ParagraphStyle("n", parent=styles["KpiNumber"], fontSize=18, leading=20))],
                    [Paragraph(name, ParagraphStyle("l", parent=styles["KpiLabel"], fontSize=8))]],
                   colWidths=[usable_width / 4 - 8])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), LAVENDER_BG),
            ("BOX", (0, 0), (-1, -1), 0.75, LAVENDER_BORDER),
            ("TOPPADDING", (0, 0), (-1, 0), 10), ("BOTTOMPADDING", (0, 1), (-1, 1), 10),
        ]))
        return t

    class _NumberedCanvas(canvas_mod.Canvas):
        """Defers footer drawing until every page exists, so 'Page X of Y' is accurate."""
        _saved_states: list = []

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._saved_page_states = []

        def showPage(self):
            self._saved_page_states.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total = len(self._saved_page_states)
            for state in self._saved_page_states:
                self.__dict__.update(state)
                self._draw_chrome(total)
                super().showPage()
            super().save()

        def _draw_chrome(self, total_pages):
            self.saveState()
            # header
            self.setFillColor(NAVY)
            self.setFont("Helvetica-Bold", 8.5)
            self.drawString(margin, page_size[1] - 0.42 * inch, "ThreatLens")
            self.setFillColor(MUTED)
            self.setFont("Helvetica", 8.5)
            self.drawString(margin + 0.62 * inch, page_size[1] - 0.42 * inch, "| Security Assessment Report")
            self.setStrokeColor(CARD_BORDER)
            self.setLineWidth(0.75)
            self.line(margin, page_size[1] - 0.5 * inch, page_size[0] - margin, page_size[1] - 0.5 * inch)
            # footer
            self.setFillColor(MUTED)
            self.setFont("Helvetica", 8)
            self.drawString(margin, 0.4 * inch, f"{project.name}  |  CONFIDENTIAL")
            self.drawRightString(page_size[0] - margin, 0.4 * inch, f"Page {self._pageNumber} of {total_pages}")
            self.restoreState()

    # ---------------------------------------------------------------- data prep --

    risk_dist = payload["executive_summary"]["risk_distribution"]
    total_threats = payload["executive_summary"]["total_threats"]
    threats_sorted = sorted(
        payload["threats"],
        key=lambda t: (["Critical", "High", "Medium", "Low", "Informational"].index(t["risk_level"])
                       if t["risk_level"] in ["Critical", "High", "Medium", "Low", "Informational"] else 5,
                       -t["risk_score"]),
    )

    asset_counts: dict[str, int] = {}
    for t in payload["threats"]:
        key = t["affected_asset"] or "Unassigned"
        asset_counts[key] = asset_counts.get(key, 0) + 1

    # ---------------------------------------------------------------- Page 1: cover --

    story = []

    cover_header = Table(
        [[Paragraph("CONFIDENTIAL &mdash; SECURITY ASSESSMENT", styles["Confidential"])]],
        colWidths=[usable_width],
    )
    cover_header.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "LEFT")]))

    cover_box = Table(
        [
            [Paragraph("ThreatLens", ParagraphStyle("logo", parent=styles["Normal"], fontSize=13, fontName="Helvetica-Bold", textColor=colors.white))],
            [Spacer(1, 10)],
            [Paragraph("Security Assessment Report", styles["CoverTitle"])],
            [Spacer(1, 6)],
            [Paragraph(_esc(project.name), styles["CoverSub"])],
            [Spacer(1, 14)],
            [Paragraph(f"Generated: {generated_at_label}", styles["CoverMeta"])],
            [Paragraph(f"Report ID: {report_id}", styles["CoverMeta"])],
        ],
        colWidths=[usable_width],
    )
    cover_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), INDIGO),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 26), ("RIGHTPADDING", (0, 0), (-1, -1), 26),
        ("TOPPADDING", (0, 0), (-1, 0), 22), ("BOTTOMPADDING", (0, -1), (-1, -1), 24),
    ]))

    story.append(cover_box)
    story.append(Spacer(1, 20))
    story.append(Paragraph("Executive Risk Overview", styles["SectionHeading"]))

    kpi_row = [
        _kpi_card(total_threats, "Total Threats", PURPLE),
        _kpi_card(risk_dist.get("High", 0) + risk_dist.get("Critical", 0), "High / Critical Risk", RISK_COLORS["High"]),
        _kpi_card(risk_dist.get("Medium", 0), "Medium Risk", RISK_COLORS["Medium"]),
    ]
    kpi_table = Table([kpi_row], colWidths=[usable_width / 3] * 3)
    kpi_table.setStyle(TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]))
    story.append(kpi_table)
    story.append(Spacer(1, 16))

    # risk distribution bar (simple horizontal proportional bar, real counts only)
    story.append(Paragraph("Risk Distribution", styles["SectionHeading"]))
    dist_order = [lvl for lvl in ["Critical", "High", "Medium", "Low", "Informational"] if risk_dist.get(lvl)]
    if dist_order and total_threats:
        bar_cells = []
        bar_widths = []
        for lvl in dist_order:
            frac = risk_dist[lvl] / total_threats
            bar_widths.append(max(frac * usable_width, 0.15 * inch))
            bar_cells.append("")
        bar = Table([bar_cells], colWidths=bar_widths, rowHeights=[0.28 * inch])
        bar.setStyle(TableStyle([("BACKGROUND", (i, 0), (i, 0), RISK_COLORS[lvl]) for i, lvl in enumerate(dist_order)]))
        story.append(bar)
        story.append(Spacer(1, 6))
        legend_cells = [[Paragraph(f"&#9679; {lvl}: {risk_dist[lvl]}", ParagraphStyle("lg", parent=styles["CardMeta"], textColor=RISK_COLORS[lvl])) for lvl in dist_order]]
        legend = Table(legend_cells, colWidths=[usable_width / len(dist_order)] * len(dist_order))
        story.append(legend)
    else:
        story.append(Paragraph("No threats have been risk-scored yet for this project.", styles["Body"]))
    story.append(Spacer(1, 16))

    # Risk posture (derived only from actual counts, no invented narrative specifics)
    story.append(Paragraph("Risk Posture", styles["SectionHeading"]))
    high_crit = risk_dist.get("Critical", 0) + risk_dist.get("High", 0)
    if total_threats == 0:
        posture_text = "No threats have been identified for this assessment yet."
    elif high_crit == 0:
        posture_text = (
            f"This assessment identified {total_threats} threat(s), none currently rated High or Critical. "
            "Findings should still be reviewed and validated through controlled testing."
        )
    else:
        posture_text = (
            f"This assessment identified {total_threats} threat(s) across the analyzed system, of which "
            f"{high_crit} are rated High or Critical risk. These findings warrant prioritized review, "
            "validation through controlled security testing, and remediation before the affected components "
            "are considered production-ready."
        )
    story.append(Paragraph(posture_text, styles["Body"]))
    story.append(Spacer(1, 14))

    story.append(Paragraph("Key Observations", styles["SectionHeading"]))
    top_3 = threats_sorted[:3]
    if top_3:
        for t in top_3:
            story.append(Paragraph(
                f"&#8226; <b>{_esc(t['id'])}</b> &mdash; {_esc(t['title'])} ({t['risk_level']} risk, score {t['risk_score']})",
                styles["Body"],
            ))
    else:
        story.append(Paragraph("No findings recorded yet.", styles["Body"]))

    story.append(NextPageTemplate("standard"))
    story.append(PageBreak())

    # ------------------------------------------------------- Page 2: assessment overview --

    story.append(Paragraph("Assessment Overview", styles["PageTitle"]))
    story.append(Paragraph("Scope, security posture, and threat distribution for this assessment.", styles["PageSubtitle"]))

    story.append(Paragraph("Assessment Scope", styles["SectionHeading"]))
    story.append(Paragraph(
        f"This assessment covers <b>{_esc(project.name)}</b>, analyzing "
        f"{len(asset_counts)} distinct asset categor{'y' if len(asset_counts) == 1 else 'ies'} and "
        f"{total_threats} identified threat(s) via STRIDE-based threat modeling.",
        styles["Body"],
    ))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Findings by Asset Category", styles["SectionHeading"]))
    if asset_counts:
        cards = [_asset_card(name, count) for name, count in sorted(asset_counts.items(), key=lambda x: -x[1])[:4]]
        while len(cards) < 4:
            cards.append(Spacer(1, 1))
        asset_row = Table([cards], colWidths=[usable_width / 4] * 4)
        asset_row.setStyle(TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]))
        story.append(asset_row)
    else:
        story.append(Paragraph("No assets recorded yet.", styles["Body"]))
    story.append(Spacer(1, 16))

    story.append(Paragraph("Top Priority Findings", styles["SectionHeading"]))
    if threats_sorted:
        col_widths = [w * usable_width for w in [0.09, 0.42, 0.13, 0.36]]
        rows = [_header_row(["ID", "Title", "Risk", "Score"])]
        for t in threats_sorted[:3]:
            rows.append([_p(t["id"]), _p(t["title"]), _risk_badge(t["risk_level"], width=0.13 * usable_width - 8), _p(t["risk_score"], "CellTextCenter")])
        tbl = Table(rows, colWidths=col_widths, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), INDIGO),
            ("GRID", (0, 0), (-1, -1), 0.5, CARD_BORDER),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(tbl)
    story.append(PageBreak())

    # ------------------------------------------------------- Page 3: threat register --

    story.append(Paragraph("Threat Model &amp; Risk Prioritization", styles["PageTitle"]))
    story.append(Paragraph("All identified threats, sorted by risk level then risk score. No mitigation text is truncated.", styles["PageSubtitle"]))

    if threats_sorted:
        for t in threats_sorted:
            card_rows = [
                [
                    Table([[Paragraph(f"{t['id']}", styles["CardTitle"]), _risk_badge(t["risk_level"], width=1.55 * inch)]],
                          colWidths=[usable_width - 1.9 * inch, 1.7 * inch],
                          style=TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("ALIGN", (1, 0), (1, 0), "RIGHT")])),
                ],
                [Paragraph(_esc(t["title"]), ParagraphStyle("tt", parent=styles["CardTitle"], fontSize=10.5, textColor=NAVY))],
                [Paragraph(
                    f"STRIDE: {t['stride_category']}  &middot;  Asset: {_esc(t['affected_asset']) if t['affected_asset'] else '-'}  &middot;  "
                    f"Likelihood: {t['likelihood']}  &middot;  Impact: {t['impact']}  &middot;  Score: {t['risk_score']}",
                    styles["CardMeta"],
                )],
                [Spacer(1, 4)],
                [Paragraph(f"<b>Recommended mitigation:</b> {_esc(t['recommended_mitigation']) if t['recommended_mitigation'] else '-'}", styles["CardBody"])],
            ]
            card = Table(card_rows, colWidths=[usable_width])
            card.setStyle(TableStyle([
                ("BOX", (0, 0), (-1, -1), 1, CARD_BORDER),
                ("LINEABOVE", (0, 0), (-1, 0), 3, RISK_COLORS.get(t["risk_level"], PURPLE)),
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 12), ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("BOTTOMPADDING", (0, -1), (-1, -1), 10),
            ]))
            story.append(KeepTogether([card, Spacer(1, 8)]))
    else:
        story.append(Paragraph("No threats recorded.", styles["Body"]))
    story.append(PageBreak())

    # ------------------------------------------------------- Page 4: framework mapping --

    story.append(Paragraph("Security Framework Mapping", styles["PageTitle"]))
    story.append(Paragraph(
        "Findings are mapped to recognized security frameworks to support standardized vulnerability "
        "classification, prioritization, and remediation planning.", styles["PageSubtitle"],
    ))
    col_widths = [w * usable_width for w in [0.08, 0.36, 0.19, 0.17, 0.20]]
    rows = [_header_row(["ID", "Title", "OWASP", "CWE", "MITRE ATT&amp;CK"])]
    for t in payload["threats"]:
        rows.append([
            _p(t["id"]), _p(t["title"]), _p(t["owasp_category"] or "-"),
            _p(t["cwe_id"] or "-"), _p(t["mitre_attack_technique"] or "-"),
        ])
    tbl = Table(rows, colWidths=col_widths, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), INDIGO),
        ("GRID", (0, 0), (-1, -1), 0.5, CARD_BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ] + [("BACKGROUND", (0, i), (-1, i), ROW_ALT) for i in range(1, len(rows)) if i % 2 == 0]))
    story.append(tbl)
    story.append(PageBreak())

    # ------------------------------------------------------- Page 5: traceability --

    story.append(Paragraph("Threat-to-Test Traceability", styles["PageTitle"]))
    story.append(Paragraph(
        "PASSED / FAILED indicate a controlled test actually executed. NOT_EXECUTED means the test has not "
        "been run yet. BLOCKED_BY_POLICY means the safety/authorization gate prevented execution.",
        styles["PageSubtitle"],
    ))
    if payload["traceability"]:
        col_widths = [w * usable_width for w in [0.09, 0.11, 0.09, 0.14, 0.12, 0.45]]
        header = _header_row(["Threat", "STRIDE", "Test", "Execution Status", "Risk", "Recommendation"])
        rows = [header]
        for row in payload["traceability"]:
            rows.append([
                _p(row["threat"]), _p(row["stride_category"]), _p(row["security_test"]),
                _status_badge(row["execution_status"], width=0.14 * usable_width - 8),
                _risk_badge(row["risk_level"], width=0.12 * usable_width - 8),
                _p(row["recommendation"] or "-"),
            ])
        tbl = Table(rows, colWidths=col_widths, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), INDIGO),
            ("GRID", (0, 0), (-1, -1), 0.5, CARD_BORDER),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ] + [("BACKGROUND", (0, i), (-1, i), ROW_ALT) for i in range(1, len(rows)) if i % 2 == 0]))
        story.append(tbl)
    else:
        story.append(Paragraph("No security tests have been generated/executed yet for this project.", styles["Body"]))
    story.append(PageBreak())

    # ------------------------------------------------------- Final page: remediation roadmap --

    story.append(Paragraph("Remediation Roadmap", styles["PageTitle"]))
    story.append(Paragraph("Findings grouped by remediation priority, derived from actual risk level and score.", styles["PageSubtitle"]))

    def _priority_group(level_names, label, tag):
        items = [t for t in threats_sorted if t["risk_level"] in level_names]
        if not items:
            return
        story.append(Paragraph(f"{tag} &mdash; {label}", ParagraphStyle(
            "prio", parent=styles["SectionHeading"], textColor=RISK_COLORS.get(level_names[0], NAVY),
        )))
        col_widths = [w * usable_width for w in [0.08, 0.34, 0.10, 0.30, 0.18]]
        rows = [_header_row(["Threat ID", "Recommended Action", "Risk", "Security Impact", "Score"])]
        for t in items:
            impact_text = f"Affects {_esc(t['affected_asset']) if t['affected_asset'] else 'unassigned asset'}; STRIDE: {t['stride_category']}"
            rows.append([
                _p(t["id"]), _p(t["recommended_mitigation"] or "-"),
                _risk_badge(t["risk_level"], width=0.10 * usable_width - 8), _p(impact_text), _p(t["risk_score"], "CellTextCenter"),
            ])
        tbl = Table(rows, colWidths=col_widths, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("GRID", (0, 0), (-1, -1), 0.5, CARD_BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(tbl)
        story.append(Spacer(1, 10))

    _priority_group(["Critical"], "Critical / Immediate", "P0")
    _priority_group(["High"], "High Priority", "P1")
    _priority_group(["Medium"], "Medium Priority", "P2")
    if not any(t["risk_level"] in ("Critical", "High", "Medium") for t in threats_sorted):
        story.append(Paragraph("No Critical, High, or Medium risk findings to prioritize.", styles["Body"]))

    story.append(Spacer(1, 12))
    story.append(Paragraph("Recommended Next Steps", styles["SectionHeading"]))
    for step in [
        "Address high-risk findings first.",
        "Validate authorization controls.",
        "Strengthen API authentication and authorization.",
        "Apply secure database access controls.",
        "Re-run security tests after remediation.",
    ]:
        story.append(Paragraph(f"&#8226; {step}", styles["Body"]))

    # ---------------------------------------------------------------- build --

    frame = Frame(margin, 0.6 * inch, usable_width, page_size[1] - 1.3 * inch, id="standard")
    cover_frame = Frame(margin, 0.6 * inch, usable_width, page_size[1] - 1.3 * inch, id="cover")
    doc = BaseDocTemplate(path, pagesize=page_size, leftMargin=margin, rightMargin=margin, topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    doc.addPageTemplates([
        PageTemplate(id="cover", frames=[cover_frame]),
        PageTemplate(id="standard", frames=[frame]),
    ])

    doc.build(story, canvasmaker=_NumberedCanvas)
    db.add(Report(project_id=project.id, format="pdf", file_path=path))
    db.commit()
    return path
