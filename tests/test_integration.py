"""End-to-end: real stdio servers → introspect → classify → analyze.

This is the definition-of-done scenario exercised against live subprocesses
(metadata-only), proving the trifecta is found A→B→C and no tool is invoked.
"""

from __future__ import annotations

import sys
from pathlib import Path

from triflow.models import FindingType, ServerConfig, Transport
from triflow.scan import scan_configs

SERVERS = Path(__file__).parent / "fixtures" / "servers"


def config(name: str, script: str) -> ServerConfig:
    return ServerConfig(
        name=name,
        client="test",
        config_path=Path("cfg.json"),
        transport=Transport.STDIO,
        command=sys.executable,
        args=(str(SERVERS / script),),
    )


async def test_toxic_fleet_reports_trifecta_a_to_b_to_c() -> None:
    fleet = [
        config("A", "private_data_server.py"),
        config("B", "ingress_server.py"),
        config("C", "exfil_server.py"),
    ]
    report = await scan_configs(fleet, timeout=30)
    assert report.server_count == 3
    assert all(server.introspection_error is None for server in report.servers)

    trifecta = [f for f in report.findings if f.finding_type is FindingType.LETHAL_TRIFECTA]
    assert len(trifecta) == 1
    finding = trifecta[0]
    assert finding.cross_server is True
    assert set(finding.server_slugs) == {"test:A", "test:B", "test:C"}
    refs = " ".join(p.ref for p in finding.participants)
    assert "read_file" in refs and "fetch_url" in refs and "send_email" in refs


async def test_benign_fleet_is_clean_end_to_end() -> None:
    report = await scan_configs([config("only", "ingress_server.py")], timeout=30)
    # a lone ingress server cannot compose the trifecta
    assert report.findings == ()
