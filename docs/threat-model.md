# Threat model

## What triflow defends against

The core threat is **prompt injection weaponized by tool composition**. An
agent with the wrong combination of MCP servers can be steered by attacker
-controlled content into stealing data or executing code — without any single
server being malicious.

### The lethal trifecta

Coined by Simon Willison: an agent is exploitable when it simultaneously has

1. **access to private data**,
2. **exposure to untrusted content**, and
3. **the ability to externally communicate**.

Untrusted content (a web page, an email, a public issue) carries injected
instructions; the agent reads private data and sends it out. triflow detects
this combination *across servers*, because in a real setup the three legs
usually live in three different MCP servers nobody reviewed together.

### Cross-server privilege escalation

Untrusted ingress in one server + code execution in another = a path from
"attacker publishes a web page" to "attacker runs commands on your machine."
triflow flags these `ingress → executor` pairs even when neither server looks
dangerous alone.

### Tool shadowing

When two servers export the same tool name, name-based resolution is ambiguous.
A malicious server can deliberately shadow a trusted tool to intercept its
calls. triflow flags collisions and escalates severity when the shadowed name
carries a dangerous capability.

### Over-privileged skills

A `SKILL.md` that grants unbounded shell, or network egress alongside secret
access, hands an injected instruction everything it needs inside one skill.

## Trust boundaries and assumptions

- **Config files are trusted-ish.** triflow reads MCP client configs you
  already run. It treats their *contents* defensively (never crashes on
  malformed input) but assumes you chose to install these servers.
- **Server metadata is untrusted.** Tool names and descriptions come from
  third-party servers and may lie. triflow treats them as data (never executes
  instructions embedded in a description) and reasons about what a server
  *declares* it can do. A server that under-declares its capabilities can evade
  detection — a documented limitation.
- **triflow never invokes a tool.** Introspection sends only `initialize` and
  `tools/list`. A scan cannot itself cause side effects, even against a
  compromised fleet. This is enforced in code and asserted by transport-level
  and tripwire tests ([ADR-0001](adr/0001-metadata-only-introspection.md)).
- **Stdio servers are launched with a minimized environment** (SDK-safe vars +
  only the config-declared vars) and hard timeouts
  ([ADR-0002](adr/0002-subprocess-sandboxing.md)). triflow does not claim
  OS-level sandboxing; scan fully untrusted configs in config-only mode or a
  container.

## Out of scope

- **Single-server tool-description injection / rug-pulls** — owned by
  `mcp-scan`, Snyk `agent-scan`. See [complements](complements.md).
- **Runtime enforcement** — triflow is a static analyzer, not a call-time proxy
  or guardrail.
- **Detecting a server that lies about its capabilities** — triflow reasons
  about declared metadata; a server that hides what it does can evade the
  metadata-based classifier (though its identity may still trip a `SRV-*` rule).
