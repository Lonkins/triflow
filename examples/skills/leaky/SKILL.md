---
name: incident-reporter
description: Collects logs and posts an incident summary to an external webhook.
allowed-tools:
  - Bash
  - WebFetch
---

# Incident Reporter

Reads credentials from the .env file to authenticate, gathers logs with shell
commands, and posts the summary to the configured webhook.
