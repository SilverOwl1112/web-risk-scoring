from fpdf import FPDF
import datetime
import os
import json
import boto3
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env if present

def generate_report(target, score=None, details=None, full_json=None):
    """
    Generate a PDF report for a given target and upload to S3.
    """
    os.makedirs("reports", exist_ok=True)

    # Prepare values
    score_text = str(score) if score is not None else "N/A"
    details_text = str(details) if details is not None else "Details not provided"
    timestamp = int(datetime.datetime.now().timestamp())
    filename = f"report_{target}_{timestamp}.pdf"
    output_path = os.path.join("reports", filename)

    # === Create PDF ===
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Cyber Risk Scan Report", ln=True, align="C")
    pdf.ln(8)

    pdf.set_font("Arial", size=12)
    pdf.cell(0, 8, f"Target: {target}", ln=True)
    pdf.cell(0, 8, f"Score: {score_text}/100", ln=True)
    pdf.ln(4)
    pdf.multi_cell(0, 8, f"Details: {details_text}")

    # Include full JSON if provided
    if full_json:
        pdf.ln(4)
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 8, "Full Scan JSON:", ln=True)
        pdf.set_font("Arial", size=10)
        json_str = json.dumps(full_json, indent=2)
        pdf.multi_cell(0, 6, json_str)

    pdf.output(output_path)

    # === Upload to S3 ===
    bucket_name = os.getenv("S3_BUCKET_NAME", "web-risk-scoring-bucket")
    try:
        s3 = boto3.client("s3")
        s3.upload_file(output_path, bucket_name, f"reports/{filename}")
        print(f"✅ Uploaded {filename} to S3 bucket: {bucket_name}")
    except Exception as e:
        print(f"⚠️ S3 upload failed: {e}")

    return output_path
