# triflow

**Cross-server MCP toxic-flow analyzer + `SKILL.md` linter.**

Most MCP security tools look at one server at a time. triflow looks at the
**whole installed fleet** and asks a different question: *do these servers, in
combination, compose into an attack?*

A filesystem server is fine. A web-fetch server is fine. An email server is
fine. Install all three under one agent and you have the **lethal trifecta** —
private-data access, untrusted-content ingress, and an exfiltration channel —
and a single poisoned web page can read your files and mail them out. No
individual server is misbehaving; the *composition* is the vulnerability.

## What triflow finds

- **Lethal trifecta** across the fleet — naming the exact `server → tool` chain
  that composes private-data + untrusted-ingress + exfiltration.
- **Tool shadowing** — the same tool name exported by two servers, letting a
  malicious server impersonate a trusted one.
- **Injection-to-execution chains** — untrusted content in one server reaching
  code execution in another (prompt injection → cross-server RCE).
- **Dangerous skills** — `SKILL.md` files granting unbounded shell, network +
  secret access together, wildcard tool grants, or no scoping at all.

## Safety first

triflow introspects servers **metadata-only**. It sends `initialize` and
`tools/list` and nothing else — it will **never invoke a tool**. That guarantee
is enforced in code and asserted by tests (see
[ADR-0001](adr/0001-metadata-only-introspection.md)). A scan is safe to run in
CI on every commit, even against a compromised fleet.

## Quick look

```console
$ triflow scan -c examples/mcp.json --no-introspect
```

```text
 CRITICAL  TRIFLOW-TRIFECTA  Lethal trifecta present across servers
 Representative chain:
   config:filesystem [private_data_source]
   → config:fetch    [untrusted_content_ingress]
   → config:gmail    [exfiltration_channel]
```

## Not a replacement for single-server scanners

triflow **complements** tools like `mcp-scan` and Snyk `agent-scan`. They
inspect individual tool descriptions for prompt-injection and rug-pulls;
triflow reasons about composition across servers and lints skill files. Run
both — see [how this complements single-server scanners](complements.md).

Start with [installation](installation.md).
