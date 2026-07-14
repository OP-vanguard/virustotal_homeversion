"""
app.py
Flask web frontend for the IOC extraction pipeline. Single-page app: submit
a file path, hash, IP, or domain, get back a full triage report rendered
with risk verdict, static IOCs, MITRE ATT&CK mapping, and remediation steps.
"""

import os
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename

from ioc_extractor import run_analysis

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Accepts either a text target (hash/IP/domain/existing filepath) via form
    field 'target', or an uploaded file via form field 'file'. Returns the
    report dict as JSON.
    """
    uploaded_file = request.files.get("file")
    target_text = request.form.get("target", "").strip()

    try:
        if uploaded_file and uploaded_file.filename:
            filename = secure_filename(uploaded_file.filename)
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            uploaded_file.save(filepath)
            report = run_analysis(filepath)
        elif target_text:
            report = run_analysis(target_text)
        else:
            return jsonify({"error": "No file or target provided."}), 400

        return jsonify(report)

    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {e}"}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000)
