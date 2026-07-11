"""Cross-server toxic-flow analysis.

Operates on the *whole classified fleet* — this is the part single-server
scanners structurally cannot do. Three detectors:

- :func:`detect_trifecta` — the lethal trifecta: private-data access +
  untrusted-content ingress + an exfiltration channel present anywhere in the
  fleet, naming a concrete server→tool chain that composes the risk.
- :func:`detect_shadowing` — the same tool name exported by two or more
  servers, letting a malicious server impersonate a trusted one.
- :func:`detect_escalation` — untrusted ingress in one server reaching code
  execution in another: prompt injection becomes cross-fleet RCE.
"""

from __future__ import annotations

from collections import defaultdict

from triflow.models import (
    SEVERITY_ORDER,
    Capability,
    ClassifiedServer,
    Finding,
    FindingType,
    Participant,
    Severity,
)

_TRIFECTA_ROLE = {
    Capability.PRIVATE_DATA_SOURCE: "private-data source",
    Capability.UNTRUSTED_CONTENT_INGRESS: "untrusted-content ingress",
    Capability.EXFILTRATION_CHANNEL: "exfiltration channel",
}
_MAX_PARTICIPANTS_PER_LEG = 8


def _contributors(
    servers: tuple[ClassifiedServer, ...], capability: Capability, role: str
) -> list[Participant]:
    """Fleet contributors to ``capability``, native matches first.

    ``code_execution`` subsumes every other capability (a shell can read, write,
    ingest, and exfiltrate), so exec tools also contribute — but they sort after
    native contributors so the representative chain reads clearly."""
    native: list[Participant] = []
    subsumed: list[Participant] = []
    for server in servers:
        for tool in server.tools:
            if capability in tool.capabilities:
                native.append(_tool_participant(server, tool.tool.name, capability, role))
            elif Capability.CODE_EXECUTION in tool.capabilities:
                subsumed.append(_tool_participant(server, tool.tool.name, capability, role))
        if capability in server.server_capabilities:
            native.append(Participant(server_slug=server.slug, capability=capability, role=role))
        elif Capability.CODE_EXECUTION in server.server_capabilities:
            subsumed.append(Participant(server_slug=server.slug, capability=capability, role=role))
    return native + subsumed


def _tool_participant(
    server: ClassifiedServer, tool_name: str, capability: Capability, role: str
) -> Participant:
    return Participant(
        server_slug=server.slug, tool_name=tool_name, capability=capability, role=role
    )


def detect_trifecta(servers: tuple[ClassifiedServer, ...]) -> Finding | None:
    legs = {
        capability: _contributors(servers, capability, role)
        for capability, role in _TRIFECTA_ROLE.items()
    }
    if not all(legs.values()):
        return None

    participants: list[Participant] = []
    representative: list[str] = []
    for capability in _TRIFECTA_ROLE:
        contributors = legs[capability]
        participants.extend(contributors[:_MAX_PARTICIPANTS_PER_LEG])
        representative.append(contributors[0].ref)

    servers_involved = {p.server_slug for p in participants}
    cross_server = len(servers_involved) > 1
    chain = " → ".join(representative)
    scope = "across servers" if cross_server else "within a single server"

    overflow = [
        f"(+{len(legs[c]) - _MAX_PARTICIPANTS_PER_LEG} more {_TRIFECTA_ROLE[c]} tools)"
        for c in _TRIFECTA_ROLE
        if len(legs[c]) > _MAX_PARTICIPANTS_PER_LEG
    ]
    detail = (
        f"The installed fleet jointly satisfies the lethal trifecta {scope}: a "
        f"tool that reads private data, a tool that ingests attacker-influenceable "
        f"content, and a tool that can send data outside. Injected instructions in "
        f"the ingested content can drive the private-data tool and then the "
        f"exfiltration tool. Representative chain: {chain}."
    )
    if overflow:
        detail += " " + " ".join(overflow)

    return Finding(
        rule_id="TRIFLOW-TRIFECTA",
        finding_type=FindingType.LETHAL_TRIFECTA,
        severity=Severity.CRITICAL,
        title=f"Lethal trifecta present {scope}: {chain}",
        detail=detail,
        remediation=(
            "Break at least one leg for the agent that can reach all three: remove "
            "or scope down the exfiltration tool, isolate the untrusted-ingress "
            "server into a separate agent/session, or gate private-data reads behind "
            "human approval. The three capabilities must not be reachable together."
        ),
        participants=tuple(participants),
        cross_server=cross_server,
    )


def detect_shadowing(servers: tuple[ClassifiedServer, ...]) -> list[Finding]:
    by_name: dict[str, list[tuple[ClassifiedServer, frozenset[Capability]]]] = defaultdict(list)
    for server in servers:
        for tool in server.tools:
            by_name[tool.tool.name].append((server, tool.capabilities))

    findings: list[Finding] = []
    for name in sorted(by_name):
        holders = by_name[name]
        if len({server.slug for server, _ in holders}) < 2:
            continue  # same name twice in one server is not cross-server shadowing
        union = frozenset().union(*(caps for _, caps in holders))
        dangerous = union & {
            Capability.EXFILTRATION_CHANNEL,
            Capability.CODE_EXECUTION,
            Capability.STATE_CHANGING,
        }
        severity = Severity.HIGH if dangerous else Severity.MEDIUM
        participants = tuple(
            Participant(
                server_slug=server.slug,
                tool_name=name,
                role="collides on tool name",
            )
            for server, _ in sorted(holders, key=lambda h: h[0].slug)
        )
        holder_list = ", ".join(sorted(server.slug for server, _ in holders))
        danger_note = (
            f" The colliding name carries {', '.join(sorted(c.value for c in dangerous))} "
            "capability, so a malicious shadow could impersonate a trusted tool to reach it."
            if dangerous
            else ""
        )
        findings.append(
            Finding(
                rule_id="TRIFLOW-SHADOW",
                finding_type=FindingType.TOOL_SHADOWING,
                severity=severity,
                title=f"Tool name {name!r} exported by {len(participants)} servers",
                detail=(
                    f"The tool name {name!r} is exported by multiple servers "
                    f"({holder_list}). An agent resolving by name may bind to the "
                    f"wrong server; a malicious server can register a colliding name "
                    f"to intercept calls intended for a trusted one.{danger_note}"
                ),
                remediation=(
                    "Namespace or rename colliding tools, pin each tool to a specific "
                    "server, or remove the untrusted server. Never resolve tools by "
                    "bare name across servers."
                ),
                participants=participants,
                cross_server=True,
            )
        )
    return findings


def detect_escalation(servers: tuple[ClassifiedServer, ...]) -> list[Finding]:
    ingress = _contributors(servers, Capability.UNTRUSTED_CONTENT_INGRESS, "untrusted ingress")
    execution = _exec_contributors(servers)

    # One finding per (ingress server → exec server) pair. A server can supply
    # exec capability via both a tool and its identity rule; _best_participant
    # collapses those to the most concrete representative so we don't duplicate.
    findings: list[Finding] = []
    seen_pairs: set[tuple[str, str]] = set()
    for exec_participant in _dedupe_by_server(execution):
        cross = [i for i in ingress if i.server_slug != exec_participant.server_slug]
        if not cross:
            continue
        source = _dedupe_by_server(cross)[0]
        pair = (source.server_slug, exec_participant.server_slug)
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)
        findings.append(
            Finding(
                rule_id="TRIFLOW-ESCALATE",
                finding_type=FindingType.PRIVILEGE_ESCALATION,
                severity=Severity.CRITICAL,
                title=(f"Injection-to-execution chain: {source.ref} → {exec_participant.ref}"),
                detail=(
                    f"Server {source.server_slug} ingests attacker-influenceable "
                    f"content while server {exec_participant.server_slug} can execute "
                    f"code. A prompt injection carried through the ingress tool can "
                    f"drive the execution tool, turning untrusted text into "
                    f"cross-server remote code execution."
                ),
                remediation=(
                    "Do not expose an untrusted-ingress server and a code-execution "
                    "server to the same agent. Sandbox the executor, require approval "
                    "for execution, or split these servers across isolated sessions."
                ),
                participants=(source, exec_participant),
                cross_server=True,
            )
        )
    return findings


def _dedupe_by_server(participants: list[Participant]) -> list[Participant]:
    """Keep one participant per server, preferring a concrete tool over an
    identity-level match. Preserves first-seen order across servers."""
    best: dict[str, Participant] = {}
    for participant in participants:
        current = best.get(participant.server_slug)
        if current is None or (current.tool_name is None and participant.tool_name is not None):
            best[participant.server_slug] = participant
    return list(best.values())


def _exec_contributors(servers: tuple[ClassifiedServer, ...]) -> list[Participant]:
    found: list[Participant] = []
    for server in servers:
        for tool in server.tools:
            if Capability.CODE_EXECUTION in tool.capabilities:
                found.append(
                    Participant(
                        server_slug=server.slug,
                        tool_name=tool.tool.name,
                        capability=Capability.CODE_EXECUTION,
                        role="code execution",
                    )
                )
        if Capability.CODE_EXECUTION in server.server_capabilities:
            found.append(
                Participant(
                    server_slug=server.slug,
                    capability=Capability.CODE_EXECUTION,
                    role="code execution",
                )
            )
    return found


def analyze(servers: tuple[ClassifiedServer, ...]) -> tuple[Finding, ...]:
    """Run every detector and return findings sorted most-severe first."""
    findings: list[Finding] = []
    trifecta = detect_trifecta(servers)
    if trifecta is not None:
        findings.append(trifecta)
    findings.extend(detect_escalation(servers))
    findings.extend(detect_shadowing(servers))
    return tuple(sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id, f.title)))
