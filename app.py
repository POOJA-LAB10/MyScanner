from flask import Flask, render_template, request, send_file
from scanner import scan_url
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import letter
import tempfile

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    risk = "Low"
    high_count = 0
    medium_count = 0
    low_count = 0
    pages_scanned = 0

    if request.method == "POST":
        url = request.form.get("url")
        results = scan_url(url)

        for r in results:
            if "High:" in r:
                high_count += 1
            elif "Medium:" in r:
                medium_count += 1
            elif "Low:" in r:
                low_count += 1

            if "Total pages scanned:" in r:
                pages_scanned = r.split(":")[1].strip()

        if high_count > 0:
            risk = "High"
        elif medium_count > 0 or low_count > 0:
            risk = "Medium"
        else:
            risk = "Low"

    return render_template(
        "index.html",
        results=results,
        risk=risk,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        pages_scanned=pages_scanned
    )

@app.route("/download")
def download():
    results = request.args.getlist("result")

    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    doc = SimpleDocTemplate(temp_file.name, pagesize=letter)
    styles = getSampleStyleSheet()

    content = []
    content.append(Paragraph("Web Vulnerability Scan Report", styles["Title"]))
    content.append(Spacer(1, 10))

    for r in results:
        content.append(Paragraph(r, styles["Normal"]))
        content.append(Spacer(1, 8))

    doc.build(content)

    return send_file(
        temp_file.name,
        as_attachment=True,
        download_name="scan_report.pdf"
    )

if __name__ == "__main__":
    app.run(debug=True)