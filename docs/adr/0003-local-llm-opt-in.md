# ADR 0003: Local-LLM classification assist — additive, opt-in, free

## Status

Accepted

## Context

Regex heuristics have bounded recall: a tool named `zap` described as
"transmits the current document to a configured recipient" is an exfiltration
channel no name pattern will catch. A language model can read descriptions
semantically. But requiring a model — or worse, a paid API — would break
triflow's promises: deterministic by default, zero cost, runs in CI.

## Decision

1. **Opt-in only.** No flag, no model. Deterministic rules are always the
   baseline and always run.
2. **Local only, BYO.** The shipped backend targets Ollama on localhost via
   stdlib `urllib` (no new dependency, no API key). Anything implementing the
   two-method `LLMBackend` protocol can replace it.
3. **Additive only.** The model may add capabilities, never remove or veto
   deterministic ones. Additions carry `LLM-ASSIST` evidence tagged with the
   backend name so reports can display provenance and users can discount them.
4. **Untrusted input discipline.** Tool descriptions are attacker-writable.
   The prompt frames them as data, output is constrained to a JSON capability
   list, parsing is strict (garbage → warning, unknown labels dropped). The
   blast radius of a fully hostile description is one mislabeled tool.
5. **Graceful degradation.** Backend unreachable, timeout, bad JSON — the
   deterministic result stands and a warning is emitted. LLM assist can never
   make a scan fail.

## Consequences

- CI never needs a model; LLM tests use a fake backend.
- Findings influenced by the model are visibly marked, keeping the
  "deterministic first" trust story intact.
- False negatives remain possible without the assist — documented limitation.
