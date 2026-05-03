from flask import Flask, render_template, request
from scanner import scan_url

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

if __name__ == "__main__":
    app.run(debug=True)