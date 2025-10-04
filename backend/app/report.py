# backend/app/report.py
from fpdf import FPDF
import datetime, os

def generate_pdf_report(scan_id, target, score, details):
    filename = f"report_{scan_id}_{int(datetime.datetime.now().timestamp())}.pdf"
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Cyber Risk Scan Report", ln=True, align="C")
    pdf.ln(8)
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 8, f"Target: {target}", ln=True)
    pdf.cell(0, 8, f"Score: {score}/100", ln=True)
    pdf.ln(4)
    pdf.multi_cell(0, 8, f"Details: {details}")
    pdf.output(os.path.join("reports", filename))
    return os.path.join("reports", filename)

