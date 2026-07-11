# Capability taxonomy

Every tool (and, in config-only mode, every server) is tagged against five
capabilities. Three of them form the lethal trifecta; the other two sharpen
severity and drive the escalation detector.

| Capability | Meaning | Trifecta leg |
|------------|---------|--------------|
| `private_data_source` | Reads data private to the user or org: files, databases, mailboxes, secrets, calendars, private repos | ✅ private data |
| `untrusted_content_ingress` | Pulls in content outsiders can influence: web fetch/search, inbound email, public issues/comments | ✅ untrusted ingress |
| `exfiltration_channel` | Can move data outside: send email, post to chat, outbound HTTP, uploads, create public issues/gists | ✅ exfiltration |
| `state_changing` | Creates, modifies, or deletes data or resources | — |
| `code_execution` | Runs commands, scripts, or code | subsumes all |

## Why `code_execution` is special

A shell can read files, fetch URLs, send data, and mutate state. So a tool
tagged `code_execution` implicitly satisfies **every** other leg. triflow
accounts for this: an exec tool contributes to all three trifecta legs, and a
dedicated escalation rule flags untrusted ingress reaching an executor in
another server as remote code execution.

## Why email reading is two legs at once

`read_email` / `search_inbox` is tagged **both** `private_data_source` (the
mailbox is private) **and** `untrusted_content_ingress` (anyone can send you
mail). A single mail-reading tool therefore supplies two of the three trifecta
legs on its own — add any exfiltration channel and the trifecta closes.

## How capabilities are assigned

1. **Deterministic rules** (default) — regexes over tool names, descriptions,
   input-schema property names, and server identity. See the
   [rule catalog](rules.md).
2. **Optional local-LLM assist** — semantically labels descriptions the regexes
   miss; strictly additive, tagged `LLM-ASSIST`. See
   [ADR-0003](adr/0003-local-llm-opt-in.md).

Every assignment carries **evidence**: which rule matched, what it matched on,
and the excerpt — so a finding is always explainable.
