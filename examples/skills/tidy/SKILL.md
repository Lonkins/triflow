---
name: commit-summarizer
description: Summarizes staged changes into a commit message.
allowed-tools:
  - Bash(git diff:*)
  - Bash(git log:*)
  - Read
---

# Commit Summarizer

Reads the staged diff and drafts a conventional-commit message.
