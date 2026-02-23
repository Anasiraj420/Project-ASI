import os
from flask import Flask, render_template, request
from static_analyzer.static_scan import scan_code
from dynamic_analyzer.dynamic_scan import scan_url

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    results = []

    # ---------- STATIC ANALYSIS ----------
    uploaded_files = request.files.getlist("code_files")

    for file in uploaded_files:
        if file.filename != "":
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(file_path)
            results.extend(scan_code(file_path))

    # ---------- DYNAMIC ANALYSIS ----------
    target_url = request.form.get("target_url")
    if target_url:
        results.extend(scan_url(target_url))

    return render_template('report.html', results=results)

if __name__ == '__main__':
    app.run(debug=True)
