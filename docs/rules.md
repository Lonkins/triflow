# Rule catalog

triflow has two rule layers: **classification rules** assign capabilities to
tools/servers, and **finding rules** compose those capabilities into risks.

## Finding rules

These produce the findings you see in reports (`triflow rules` lists them too).

### Lethal trifecta

- **`TRIFLOW-TRIFECTA`** · CRITICAL · `lethal_trifecta`

The fleet jointly grants private-data access, untrusted-content ingress, and an
exfiltration channel. Injected instructions in ingested content can drive the
private-data tool and then the exfiltration tool. The finding names a
representative `server → tool` chain across all three legs and flags whether it
spans multiple servers (`cross_server`).

*Remediation:* break one leg for the agent that can reach all three — remove or
scope the exfiltration tool, isolate the untrusted-ingress server into its own
session, or gate private-data reads behind approval.

### Tool shadowing

- **`TRIFLOW-SHADOW`** · HIGH / MEDIUM · `tool_shadowing`

Two or more servers export a tool with the same name. An agent resolving by
bare name can bind to the wrong server; a malicious server can register a
colliding name to intercept calls. HIGH when the colliding name carries
`exfiltration_channel`, `code_execution`, or `state_changing`; otherwise MEDIUM.

*Remediation:* namespace or pin tools to specific servers; never resolve by
bare name across servers.

### Injection-to-execution chain

- **`TRIFLOW-ESCALATE`** · CRITICAL · `privilege_escalation`

One server ingests untrusted content while another can execute code. A prompt
injection carried through the ingress tool can drive the executor — turning
untrusted text into cross-server remote code execution.

*Remediation:* do not expose an untrusted-ingress server and a code-execution
server to the same agent; sandbox the executor or split them across sessions.

### Skill rules

- **`TRIFLOW-SKILL-UNBOUNDED-SHELL`** · HIGH — a skill grants `Bash` with no
  argument scoping (`Bash`, `Bash(*)`). Scope grants like `Bash(git log:*)`.
- **`TRIFLOW-SKILL-NETWORK-AND-SECRETS`** · HIGH — a skill can both reach the
  network and touch secrets/credentials: an exfiltration path in one skill.
- **`TRIFLOW-SKILL-MISSING-SCOPING`** · MEDIUM — no `allowed-tools`, so the
  skill inherits every tool the agent has.
- **`TRIFLOW-SKILL-OVERBROAD-TOOLS`** · HIGH — a wildcard grant (`*`),
  equivalent to no scoping.

## Classification rules

Capability assignment is driven by
[`capability_rules.yaml`](https://github.com/Lonkins/triflow/blob/main/src/triflow/data/capability_rules.yaml).
Each rule has a stable ID, a rationale, and regex patterns matched (lowercased)
against one of:

- **tool name** — e.g. `read_file`, `send_email`, `run_command`
- **tool description** — e.g. "fetches a web page and returns its content"
- **schema property** — e.g. a `url` parameter on a retrieval-flavored tool
  (conjunctive: the name must also look like a fetch/load/get to avoid false
  positives)
- **server identity** — name + command + args + url, the offline fallback that
  makes config-only scanning useful (e.g. `server-filesystem`, `brave-search`,
  `gmail`, `github`)

Rule ID prefixes: `PRIV-*` (private data), `ING-*` (ingress), `EXF-*`
(exfiltration), `STATE-*` (state change), `EXEC-*` (code execution), `SRV-*`
(server-identity fallbacks).

## Writing a new classification rule

Add an entry to `capability_rules.yaml` with an `id`, `capability`,
`rationale`, and at least one pattern list. Ship it with a triggering fixture
and a non-triggering fixture (tests enforce that every rule matches something
and that all five capabilities stay covered).
