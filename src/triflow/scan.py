"""Top-level scan orchestration: discover → introspect → classify → analyze.

``scan_configs`` starts from already-discovered :class:`ServerConfig`s so the
CLI can offer both an introspecting scan and a fast config-only scan (which
relies purely on server-identity classification).
"""

from __future__ import annotations

from triflow.classify import classify_fleet
from triflow.engine import analyze
from triflow.introspect import DEFAULT_TIMEOUT_SECONDS, introspect_fleet
from triflow.llm import LLMBackend, augment_fleet
from triflow.models import IntrospectedServer, ScanReport, ServerConfig


async def scan_configs(
    configs: tuple[ServerConfig, ...] | list[ServerConfig],
    *,
    introspect: bool = True,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    llm_backend: LLMBackend | None = None,
    warnings: tuple[str, ...] = (),
) -> ScanReport:
    all_warnings = list(warnings)
    if introspect:
        introspected = await introspect_fleet(configs, timeout=timeout)
    else:
        introspected = tuple(IntrospectedServer(config=c) for c in configs)
    all_warnings.extend(
        f"{s.config.slug}: introspection failed ({s.error})" for s in introspected if not s.ok
    )

    classified = classify_fleet(introspected)
    if llm_backend is not None:
        classified, llm_warnings = augment_fleet(classified, llm_backend)
        all_warnings.extend(llm_warnings)

    findings = analyze(classified)
    return ScanReport(servers=classified, findings=findings, warnings=tuple(all_warnings))
