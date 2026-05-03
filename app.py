from flask import Flask, render_template, request, send_file
from scanner import scan_url
import io

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

    report = "Web Vulnerability Scan Report\n\n"
    for r in results:
        report += r + "\n"

    file = io.BytesIO()
    file.write(report.encode())
    file.seek(0)

    return send_file(file, as_attachment=True, download_name="report.txt")

if __name__ == "__main__":
    app.run(debug=True)