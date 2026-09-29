"""
Executive and Technical Report Generator
Renders publication-ready HTML reports with responsive print styling,
and exports structured PDF documents using ReportLab.
"""
from typing import Dict, Any, List
import os
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


class ReportGenerator:
    @staticmethod
    def generate_executive_html(data: Dict[str, Any]) -> str:
        fp = data.get("fingerprint", {})
        score_info = data.get("risk_score", {})
        findings = data.get("findings", [])
        privacy = data.get("metadata_privacy", {})
        drift = data.get("drift", {})

        score = score_info.get("overall_score", 0)
        grade = score_info.get("posture_grade", "F")

        # Color based on score
        badge_color = "#10b981" if score >= 85 else ("#f59e0b" if score >= 60 else "#ef4444")

        major_findings = [f for f in findings if f.get("severity") in ("Critical", "High")]

        findings_html = ""
        for f in major_findings:
            findings_html += f"""
            <div style="background: #ffffff; border-left: 4px solid #ef4444; padding: 12px 16px; margin-bottom: 12px; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <strong style="color: #1e293b; font-size: 15px;">{f.get('title')}</strong>
                    <span style="background: #fee2e2; color: #991b1b; padding: 2px 8px; border-radius: 9999px; font-size: 12px; font-weight: bold;">{f.get('severity')}</span>
                </div>
                <p style="color: #475569; font-size: 13px; margin: 6px 0;"><strong>Business Risk:</strong> {f.get('why_it_matters')}</p>
                <p style="color: #047857; font-size: 13px; margin: 4px 0;"><strong>Action Required:</strong> {f.get('remediation')}</p>
            </div>
            """

        if not major_findings:
            findings_html = "<p style='color: #10b981;'>No critical or high-risk vulnerabilities detected. Architecture complies with baseline policy.</p>"

        drift_badge = ""
        if drift.get("has_drift"):
            drift_badge = f"""
            <div style="background: #fef2f2; border: 1px solid #f87171; padding: 12px 16px; border-radius: 6px; margin-bottom: 20px;">
                <strong style="color: #991b1b; font-size: 14px;">⚠️ CONFIGURATION DRIFT DETECTED</strong>
                <p style="color: #7f1d1d; font-size: 13px; margin: 4px 0;">VPN configuration deviated from the authorized enterprise baseline. Review drift findings below.</p>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>IPsec Sentinel - Executive Security Report</title>
    <style>
        body {{ font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif; background: #f8fafc; color: #0f172a; margin: 0; padding: 30px; line-height: 1.5; }}
        .container {{ max-width: 900px; margin: 0 auto; background: #ffffff; padding: 40px; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }}
        .header {{ display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 2px solid #e2e8f0; padding-bottom: 20px; margin-bottom: 25px; }}
        .score-box {{ text-align: center; background: {badge_color}15; border: 2px solid {badge_color}; padding: 15px 25px; border-radius: 8px; }}
        .score-val {{ font-size: 38px; font-weight: 800; color: {badge_color}; }}
        .grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; margin-bottom: 25px; }}
        .card {{ background: #f1f5f9; padding: 14px; border-radius: 6px; }}
        .card-label {{ font-size: 11px; text-transform: uppercase; color: #64748b; font-weight: bold; letter-spacing: 0.5px; }}
        .card-val {{ font-size: 16px; font-weight: 600; color: #1e293b; margin-top: 4px; }}
        h2 {{ font-size: 18px; color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; margin-top: 30px; }}
        @media print {{ body {{ background: #fff; padding: 0; }} .container {{ box-shadow: none; padding: 20px; }} }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1 style="margin: 0; font-size: 24px; color: #1e293b;">🛡️ IPsec Sentinel — Executive Assessment</h1>
                <p style="margin: 5px 0 0 0; color: #64748b; font-size: 14px;">Target Trace: <strong>{data.get('filename')}</strong> | Analyzed: {data.get('analyzed_at')[:19]}</p>
            </div>
            <div class="score-box">
                <div class="card-label">Security Posture</div>
                <div class="score-val">{score}/100</div>
                <span style="font-weight: bold; color: {badge_color}; font-size: 14px;">Grade {grade}</span>
            </div>
        </div>

        {drift_badge}

        <h2>Executive Summary</h2>
        <p style="color: #334155; font-size: 14px;">
            This executive assessment summarizes the cryptographic resilience, protocol compliance, and side-channel exposure of the inspected IPsec VPN gateway.
            The analysis evaluates whether encryption algorithms, key exchange parameters, and operational lifetimes conform to modern NIST SP 800-77 Rev. 1 and CNSA Suite mandates.
        </p>

        <h2>VPN Digital Twin Snapshot</h2>
        <div class="grid">
            <div class="card">
                <div class="card-label">Protocol & IKE Version</div>
                <div class="card-val">{fp.get('protocol')} / {fp.get('ike_version') or 'Not Observed in Trace'}</div>
            </div>
            <div class="card">
                <div class="card-label">Encryption Suite</div>
                <div class="card-val">{fp.get('encryption') or 'Unknown'} ({fp.get('encryption_status')})</div>
            </div>
            <div class="card">
                <div class="card-label">Key Exchange (Diffie-Hellman)</div>
                <div class="card-val">{fp.get('dh_group_name') or fp.get('dh_group') or 'Unknown'}</div>
            </div>
            <div class="card">
                <div class="card-label">Perfect Forward Secrecy (PFS)</div>
                <div class="card-val">{'Enforced (Active)' if fp.get('pfs') else 'Disabled / Inactive'}</div>
            </div>
        </div>

        <h2>High Priority Findings & Recommendations</h2>
        {findings_html}

        <h2>Encrypted Traffic Privacy Rating</h2>
        <div class="card" style="margin-top: 15px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-weight: bold; font-size: 15px;">Metadata Exposure: {privacy.get('risk_level', 'Moderate')} ({privacy.get('metadata_exposure_score', 50)}/100)</span>
                <span style="font-size: 13px; color: #64748b;">Flow Duration: {privacy.get('flow_duration', 0)}s</span>
            </div>
            <p style="font-size: 13px; color: #475569; margin: 8px 0 0 0;">{privacy.get('privacy_recommendation')}</p>
        </div>

        <div style="margin-top: 40px; border-top: 1px solid #e2e8f0; padding-top: 15px; font-size: 12px; color: #94a3b8; text-align: center;">
            Generated by IPsec Sentinel Security Intelligence Engine. Confidential - For Authorized Cybersecurity Operations Only.
        </div>
    </div>
</body>
</html>"""
        return html

    @staticmethod
    def generate_technical_html(data: Dict[str, Any]) -> str:
        fp = data.get("fingerprint", {})
        score_info = data.get("risk_score", {})
        findings = data.get("findings", [])
        anomalies = data.get("anomalies", [])
        traffic = data.get("traffic_classification", {})
        stats = data.get("packet_stats", {})
        drift = data.get("drift", {})

        score = score_info.get("overall_score", 0)

        findings_rows = ""
        for f in findings:
            badge_class = "#ef4444" if f.get("severity") in ("Critical", "High") else ("#f59e0b" if f.get("severity") == "Medium" else "#3b82f6")
            findings_rows += f"""
            <tr style="border-bottom: 1px solid #e2e8f0;">
                <td style="padding: 10px; font-family: monospace; font-size: 12px;">{f.get('id')}</td>
                <td style="padding: 10px; font-weight: bold;">{f.get('title')}</td>
                <td style="padding: 10px;"><span style="color: {badge_class}; font-weight: bold;">{f.get('severity')}</span></td>
                <td style="padding: 10px; font-size: 12px;">{f.get('evidence')}</td>
                <td style="padding: 10px; font-size: 12px;">{f.get('remediation')}</td>
            </tr>
            """

        anom_rows = ""
        for a in anomalies:
            anom_rows += f"""
            <tr style="border-bottom: 1px solid #e2e8f0;">
                <td style="padding: 8px; font-weight: bold;">{a.get('anomaly_type')}</td>
                <td style="padding: 8px;"><span style="color: {'#ef4444' if a.get('severity') == 'High' else '#64748b'};">{a.get('severity')}</span></td>
                <td style="padding: 8px; font-size: 12px;">{a.get('confidence')}</td>
                <td style="padding: 8px; font-size: 12px;">{a.get('explanation')}</td>
            </tr>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>IPsec Sentinel - Comprehensive Technical Security Report</title>
    <style>
        body {{ font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, monospace, sans-serif; background: #0f172a; color: #f1f5f9; margin: 0; padding: 25px; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: #1e293b; padding: 35px; border-radius: 8px; border: 1px solid #334155; }}
        h1, h2, h3 {{ color: #38bdf8; }}
        .tech-box {{ background: #0f172a; border: 1px solid #334155; border-radius: 6px; padding: 15px; margin-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; text-align: left; }}
        th {{ background: #334155; color: #94a3b8; padding: 8px 10px; text-transform: uppercase; font-size: 11px; }}
        td {{ padding: 8px 10px; color: #cbd5e1; }}
        .badge {{ padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 11px; }}
        pre {{ background: #020617; padding: 12px; border-radius: 4px; color: #22c55e; overflow-x: auto; font-size: 12px; }}
        @media print {{ body {{ background: #fff; color: #000; }} .container {{ border: none; background: #fff; }} }}
    </style>
</head>
<body>
    <div class="container">
        <div style="display: flex; justify-content: space-between; border-bottom: 1px solid #334155; padding-bottom: 15px; margin-bottom: 25px;">
            <div>
                <h1 style="margin: 0; font-size: 22px;">🛠️ IPsec Sentinel — Deep Technical Audit</h1>
                <p style="margin: 5px 0 0 0; color: #94a3b8; font-size: 13px;">Capture: {data.get('filename')} | Timestamp: {data.get('analyzed_at')}</p>
            </div>
            <div style="text-align: right;">
                <div style="font-size: 28px; font-weight: bold; color: #38bdf8;">{score}/100</div>
                <div style="color: #94a3b8; font-size: 12px;">Security Health Index</div>
            </div>
        </div>

        <h3>1. Packet Inspection Statistics</h3>
        <div class="tech-box">
            <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px;">
                <div><span style="color: #94a3b8; font-size: 11px;">TOTAL PACKETS</span><br><strong>{stats.get('total_packets')}</strong></div>
                <div><span style="color: #94a3b8; font-size: 11px;">IPSEC / ESP / AH</span><br><strong>{stats.get('ipsec_packets')} ({stats.get('esp_packets')} ESP, {stats.get('ah_packets')} AH)</strong></div>
                <div><span style="color: #94a3b8; font-size: 11px;">IKE HANDSHAKE</span><br><strong>{stats.get('ike_packets')} pkts</strong></div>
                <div><span style="color: #94a3b8; font-size: 11px;">NAT-T (UDP 4500)</span><br><strong>{stats.get('nat_t_packets')} pkts</strong></div>
            </div>
        </div>

        <h3>2. VPN Cryptographic Fingerprint</h3>
        <table class="tech-box">
            <thead>
                <tr>
                    <th>Parameter</th>
                    <th>Value</th>
                    <th>Detection Mode</th>
                    <th>Baseline Compliance</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>Protocol & Mode</td>
                    <td><strong>{fp.get('protocol')} ({fp.get('mode') or 'Unknown'} Mode)</strong></td>
                    <td><span class="badge" style="background: #3b82f630; color: #60a5fa;">{fp.get('mode_status')}</span></td>
                    <td>RFC 4301 Standard</td>
                </tr>
                <tr>
                    <td>IKE Version</td>
                    <td><strong>{fp.get('ike_version') or 'Not Observed'}</strong></td>
                    <td><span class="badge" style="background: #3b82f630; color: #60a5fa;">{fp.get('ike_version_status')}</span></td>
                    <td>{'Compliant' if fp.get('ike_version') == 'IKEv2' else 'Deprecated (RFC 9395)'}</td>
                </tr>
                <tr>
                    <td>Encryption Cipher</td>
                    <td><strong>{fp.get('encryption') or 'Unknown'}</strong></td>
                    <td><span class="badge" style="background: #3b82f630; color: #60a5fa;">{fp.get('encryption_status')}</span></td>
                    <td>{'AEAD Approved' if 'GCM' in str(fp.get('encryption')) else 'Requires Evaluation'}</td>
                </tr>
                <tr>
                    <td>Diffie-Hellman Group</td>
                    <td><strong>{fp.get('dh_group_name') or fp.get('dh_group') or 'Unknown'}</strong></td>
                    <td><span class="badge" style="background: #3b82f630; color: #60a5fa;">{fp.get('dh_group_status')}</span></td>
                    <td>{'NIST Approved' if str(fp.get('dh_group')) in ('14','19','20','21','31') else 'Weak / Deprecated'}</td>
                </tr>
                <tr>
                    <td>Perfect Forward Secrecy</td>
                    <td><strong>{'Enabled' if fp.get('pfs') else 'Disabled / Not Observed'}</strong></td>
                    <td><span class="badge" style="background: #3b82f630; color: #60a5fa;">{fp.get('pfs_status')}</span></td>
                    <td>Mandated for Phase 2 / Child SAs</td>
                </tr>
                <tr>
                    <td>Anti-Replay Window</td>
                    <td><strong>{'Active (Monotonic)' if fp.get('replay_protection') else 'Disabled / Inactive'}</strong></td>
                    <td><span class="badge" style="background: #3b82f630; color: #60a5fa;">{fp.get('replay_protection_status')}</span></td>
                    <td>Active 32/64-bit window required</td>
                </tr>
            </tbody>
        </table>

        <h3>3. AI Flow Classification & Anomaly Detection</h3>
        <div class="tech-box">
            <p><strong>Predicted Tunnel Traffic:</strong> {traffic.get('traffic_type')} (Confidence: {int(traffic.get('confidence', 0)*100)}%)</p>
            <p style="font-size: 12px; color: #94a3b8;">Basis: {traffic.get('basis')} | {traffic.get('disclaimer')}</p>
        </div>

        <h3>4. Isolation Forest & Heuristic Anomalies</h3>
        <table class="tech-box">
            <thead>
                <tr>
                    <th>Anomaly</th>
                    <th>Severity</th>
                    <th>Confidence</th>
                    <th>Detail</th>
                </tr>
            </thead>
            <tbody>
                {anom_rows}
            </tbody>
        </table>

        <h3>5. Detailed Security Findings & Remediation</h3>
        <table class="tech-box">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Finding</th>
                    <th>Severity</th>
                    <th>Evidence</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
                {findings_rows}
            </tbody>
        </table>

        <h3>6. Verified strongSwan Remediation Patch</h3>
        <pre>{findings[0].get('remediation_patch') if findings and findings[0].get('remediation_patch') else '# Configuration complies with baseline.'}</pre>
    </div>
</body>
</html>"""
        return html

    @staticmethod
    def generate_pdf_report(data: Dict[str, Any], report_type: str = "technical") -> bytes:
        """
        Builds a binary PDF document using ReportLab.
        """
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor('#1e293b')
        )
        sub_style = ParagraphStyle(
            'SubTitle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#64748b')
        )
        h2_style = ParagraphStyle(
            'H2',
            parent=styles['Heading2'],
            fontSize=13,
            leading=16,
            textColor=colors.HexColor('#0f172a'),
            spaceBefore=14,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'Body',
            parent=styles['Normal'],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor('#334155')
        )

        elements = []

        # Title
        title_text = "IPsec Sentinel — Executive Security Report" if report_type == "executive" else "IPsec Sentinel — Technical Security Audit"
        elements.append(Paragraph(title_text, title_style))
        elements.append(Paragraph(f"Target: {data.get('filename')} | Timestamp: {data.get('analyzed_at')[:19]}", sub_style))
        elements.append(Spacer(1, 12))

        # Overall Score Box Table
        score = data.get("risk_score", {}).get("overall_score", 0)
        grade = data.get("risk_score", {}).get("posture_grade", "F")
        score_data = [
            ["Security Posture Index", "Grade", "Status"],
            [f"{score}/100", grade, "High Risk" if score < 60 else ("Medium Risk" if score < 85 else "Strong")]
        ]
        score_table = Table(score_data, colWidths=[200, 100, 200])
        score_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#f1f5f9')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1'))
        ]))
        elements.append(score_table)
        elements.append(Spacer(1, 14))

        # VPN Fingerprint Summary Table
        fp = data.get("fingerprint", {})
        elements.append(Paragraph("VPN Security Digital Twin", h2_style))
        fp_data = [
            ["Parameter", "Observed Value", "Status"],
            ["Protocol / Mode", f"{fp.get('protocol')} ({fp.get('mode') or 'Unknown'})", fp.get('mode_status', 'UNKNOWN')],
            ["IKE Version", fp.get('ike_version') or 'Not in capture', fp.get('ike_version_status', 'UNKNOWN')],
            ["Encryption Cipher", fp.get('encryption') or 'Unknown', fp.get('encryption_status', 'UNKNOWN')],
            ["Integrity / AEAD", fp.get('integrity') or 'Unknown', fp.get('integrity_status', 'UNKNOWN')],
            ["Diffie-Hellman Group", fp.get('dh_group_name') or fp.get('dh_group') or 'Unknown', fp.get('dh_group_status', 'UNKNOWN')],
            ["Perfect Forward Secrecy", "Enabled" if fp.get('pfs') else "Disabled / Inactive", fp.get('pfs_status', 'UNKNOWN')],
            ["Replay Protection", "Active" if fp.get('replay_protection') else "Inactive / Warning", fp.get('replay_protection_status', 'UNKNOWN')]
        ]
        fp_table = Table(fp_data, colWidths=[180, 220, 100])
        fp_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#334155')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')])
        ]))
        elements.append(fp_table)
        elements.append(Spacer(1, 14))

        # Security Findings
        findings = data.get("findings", [])
        elements.append(Paragraph("Security Assessment & Recommendations", h2_style))
        for f in findings:
            f_color = colors.HexColor('#dc2626') if f.get('severity') in ('Critical', 'High') else colors.HexColor('#d97706')
            p_head = Paragraph(f"<b>[{f.get('id')}] {f.get('title')}</b> — <i>{f.get('severity')}</i>", ParagraphStyle('FHead', parent=body_style, textColor=f_color, fontName='Helvetica-Bold'))
            p_desc = Paragraph(f"<b>Impact:</b> {f.get('why_it_matters')}", body_style)
            p_rem = Paragraph(f"<b>Remediation:</b> {f.get('remediation')}", body_style)
            elements.append(p_head)
            elements.append(p_desc)
            elements.append(p_rem)
            elements.append(Spacer(1, 8))

        doc.build(elements)
        return buffer.getvalue()
