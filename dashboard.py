from flask import Flask, render_template_string
from storage.db import get_all_findings

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Root-Cause Diagnostic Findings</title>
    <meta http-equiv="refresh" content="5"> <!-- Auto-refreshes every 5 seconds -->
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f4f4f9; }
        h1 { color: #333; }
        table { width: 100%; border-collapse: collapse; background: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th, td { padding: 10px 15px; border: 1px solid #ddd; text-align: left; }
        th { background-color: #007bff; color: white; }
        tr:nth-child(even) { background-color: #f9f9f9; }
    </style>
</head>
<body>
    <h1>Root-Cause Diagnostic Findings</h1>
    <p><em>Dashboard updates live automatically every 5 seconds.</em></p>
    <table>
        <tr><th>ID</th><th>Time</th><th>Category</th><th>Severity</th><th>Source</th><th>Message</th></tr>
        {% for f in findings %}
        <tr>
            <td>{{ f.id }}</td>
            <td>{{ f.timestamp }}</td>
            <td>{{ f.category }}</td>
            <td>{{ f.severity }}</td>
            <td>{{ f.source }}</td>
            <td>{{ f.message }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""

@app.route("/")
def index():
    findings = get_all_findings()
    return render_template_string(TEMPLATE, findings=findings)

if __name__ == "__main__":
    app.host = "0.0.0.0"
    app.port = 5000
    app.run(debug=False, use_reloader=False)