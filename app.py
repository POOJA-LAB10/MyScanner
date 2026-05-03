from flask import Flask, render_template, request, send_file
from scanner import scan_url
import io

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    risk = "Low"   # default

    if request.method == "POST":
        url = request.form.get("url")
        results = scan_url(url)

        # 🔹 Risk calculation
        if any("High" in r for r in results):
            risk = "High"
        elif any("Low" in r for r in results):
            risk = "Medium"
        else:
            risk = "Low"

    return render_template("index.html", results=results, risk=risk)


# 🔽 DOWNLOAD REPORT ROUTE (ADD BELOW MAIN ROUTE)
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