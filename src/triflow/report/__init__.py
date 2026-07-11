"""Output reporters: console, JSON, SARIF."""

from triflow.report.console import render_console
from triflow.report.json_report import to_json
from triflow.report.sarif import to_sarif

__all__ = ["render_console", "to_json", "to_sarif"]
