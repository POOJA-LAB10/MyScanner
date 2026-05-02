from flask import Flask, render_template, request
from scanner import scan_url

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    if request.method == "POST":
        url = request.form.get("url")
        results = scan_url(url)
    return render_template("index.html", results=results)

if __name__ == "__main__":
    app.run(debug=True)