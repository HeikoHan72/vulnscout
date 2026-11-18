"""Haupteinstiegspunkt der Demo-Anwendung (absichtlich verwundbar).

Dieses Repository dient ausschließlich als Testziel für VulnScout und wird
nie produktiv betrieben. Die hier platzierten Schwachstellen sind
beabsichtigt - siehe auth.py, db.py, utils.py und network.py für weitere
Fälle.
"""

import yaml
from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.route("/calc")
def calc():
    """Code Injection (Finding): `eval` auf Benutzereingabe."""
    expression = request.args.get("expr", "0")
    return str(eval(expression))


@app.route("/run")
def run():
    """Code Injection (Finding): `exec` auf Benutzereingabe."""
    code = request.args.get("code", "")
    exec(code)
    return "ok"


@app.route("/greet")
def greet():
    """Server-Side Template Injection - SSTI (Finding): Benutzereingabe wird
    direkt als Template-String zusammengesetzt statt als Variable übergeben.
    """
    name = request.args.get("name", "")
    return render_template_string("Hallo " + name + "!")


@app.route("/config")
def load_config():
    """Unsicheres YAML-Laden (Finding): `yaml.load` ohne
    `Loader=yaml.SafeLoader` kann beliebigen Python-Code ausführen.
    """
    raw = request.args.get("raw", "{}")
    return str(yaml.load(raw, Loader=yaml.Loader))


if __name__ == "__main__":
    # Zwei Findings in einer Zeile: debug=True erlaubt Code-Ausführung über
    # den Werkzeug-Debugger, host="0.0.0.0" macht den Dienst von außen
    # erreichbar statt nur lokal.
    app.run(host="0.0.0.0", port=5000, debug=True)
