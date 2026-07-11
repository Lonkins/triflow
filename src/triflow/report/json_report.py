"""JSON reporter — stable, machine-readable output."""

from __future__ import annotations

import json
from collections import Counter

from triflow import __version__
from triflow.models import ClassifiedServer, Finding, Severity


def _summary(findings: tuple[Finding, ...]) -> dict[str, object]:
    counts: Counter[str] = Counter(f.severity.value for f in findings)
    return {
        "total": len(findings),
        "by_severity": {s.value: counts.get(s.value, 0) for s in Severity},
    }


def _server_view(server: ClassifiedServer) -> dict[str, object]:
    return {
        "slug": server.slug,
        "client": server.config.client,
        "transport": server.config.transport.value,
        "capabilities": sorted(c.value for c in server.all_capabilities),
        "tools": [
            {"name": t.tool.name, "capabilities": sorted(c.value for c in t.capabilities)}
            for t in server.tools
        ],
        "introspection_error": server.introspection_error,
    }


def to_json(
    findings: tuple[Finding, ...],
    warnings: tuple[str, ...] = (),
    *,
    servers: tuple[ClassifiedServer, ...] | None = None,
    indent: int = 2,
) -> str:
    payload: dict[str, object] = {
        "triflow_version": __version__,
        "summary": _summary(findings),
        "findings": [f.model_dump(mode="json") for f in findings],
        "warnings": list(warnings),
    }
    if servers is not None:
        payload["servers"] = [_server_view(s) for s in servers]
    return json.dumps(payload, indent=indent, sort_keys=False)
