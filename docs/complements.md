# How this complements single-server scanners

triflow is **not** a replacement for tools like [`mcp-scan`][mcpscan] or
[Snyk `agent-scan`][snyk]. It answers a different question, and you should run
both.

## Two different questions

| Question | Tool |
|----------|------|
| "Is *this server's* tool description trying to inject the agent? Did it rug-pull since I pinned it?" | mcp-scan, Snyk agent-scan |
| "Do *these servers, together*, compose into the lethal trifecta or a cross-server RCE chain?" | **triflow** |

A single-server scanner reads one server in isolation: it hunts for malicious
instructions hidden in tool descriptions, unicode tricks, and changed hashes
since you last approved. That is real and valuable — and orthogonal to what
triflow does.

triflow assumes each server might be perfectly benign on its own. Its concern
is the **fleet-level composition**: three innocuous servers that, installed
together, hand an attacker a data-exfiltration path. No single-server scanner
can see that, because the risk does not exist in any single server.

## Concretely

- `filesystem` server: mcp-scan says "clean." triflow says "clean *alone*."
- `fetch` server: mcp-scan says "clean." triflow says "clean *alone*."
- `gmail` server: mcp-scan says "clean." triflow says **"CRITICAL — with
  `filesystem` and `fetch` you now have the lethal trifecta:
  filesystem → fetch → gmail."**

## Recommended pipeline

```yaml
- uses: your-single-server-scanner   # description injection, rug-pulls
- uses: Lonkins/triflow@v0.1.0        # cross-server composition + skills
```

Defense in depth: one tool watches each server's honesty, the other watches
what the servers add up to.

[mcpscan]: https://github.com/invariantlabs-ai/mcp-scan
[snyk]: https://snyk.io/
