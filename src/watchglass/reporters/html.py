"""Self-contained HTML reporter."""

from __future__ import annotations

from jinja2 import BaseLoader, Environment, select_autoescape

from watchglass.models import Finding

TEMPLATE = """<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Rapport Watchglass</title><style>
body{font:16px system-ui;margin:2rem;max-width:1100px;color:#172033}
table{border-collapse:collapse;width:100%}
th,td{border-bottom:1px solid #d8dee9;padding:.65rem;text-align:left;vertical-align:top}
.critical,.high{color:#a00}.medium{color:#9a5b00}.low,.info{color:#286090}code{overflow-wrap:anywhere}
</style></head><body><h1>Rapport de sécurité Watchglass</h1>
<p>{{ findings|length }} constat(s).</p>
<p>Généré localement ; aucun fichier du projet n'a été téléversé.</p>
<table><thead><tr><th>Gravité</th><th>Règle</th><th>Emplacement</th><th>Constat</th><th>Recommandation</th></tr></thead>
<tbody>{% for item in findings %}<tr>
<td class="{{ item.severity.value }}">{{ item.severity.value|upper }}</td>
<td>{{ item.rule_id }}</td><td><code>{{ item.path }}:{{ item.line or '-' }}</code></td>
<td><strong>{{ item.title }}</strong><br><code>{{ item.evidence }}</code></td>
<td>{{ item.recommendation }}</td></tr>
{% endfor %}</tbody></table></body></html>"""


def render_html(findings: list[Finding]) -> str:
    environment = Environment(loader=BaseLoader(), autoescape=select_autoescape(default=True))
    return environment.from_string(TEMPLATE).render(findings=findings)
