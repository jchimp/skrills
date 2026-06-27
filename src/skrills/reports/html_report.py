from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import ScanResult

TEMPLATES = Path(__file__).resolve().parent.parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES)),
    autoescape=select_autoescape(["html", "xml"]),
)


def to_html(result: ScanResult) -> str:
    tpl = _env.get_template("report.html")
    return tpl.render(scan=result)
