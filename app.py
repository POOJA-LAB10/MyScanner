from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import letter
import tempfile

@app.route("/download")
def download():
    results = request.args.getlist("result")

    # create temporary PDF file
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")

    doc = SimpleDocTemplate(temp_file.name, pagesize=letter)
    styles = getSampleStyleSheet()

    content = []

    # Title
    content.append(Paragraph("Web Vulnerability Scan Report", styles["Title"]))
    content.append(Spacer(1, 10))

    # Results
    for r in results:
        content.append(Paragraph(r, styles["Normal"]))
        content.append(Spacer(1, 8))

    doc.build(content)

    return send_file(
        temp_file.name,
        as_attachment=True,
        download_name="scan_report.pdf"
    )