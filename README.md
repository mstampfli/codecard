# codecard

A security report card for a codebase. Point it at a source tree and get a graded,
actionable audit. **Deterministic by default, works fully offline, no API keys.**

```sh
python3 codecard.py ./myproject
python3 codecard.py ./myproject --md report.md
python3 codecard.py ./myproject --ai --ai-backend ollama --ai-model qwen2.5:3b   # optional AI pass
```

## What the core scans (no AI)
- **Source patterns** - a curated ruleset per language: command/code injection, SQL
  injection, insecure deserialization (pickle / `yaml.load`), weak crypto, TLS
  verification disabled, debug-on, unbounded C buffer ops, and more.
- **Secrets** - AWS keys, GitHub/Slack tokens, private keys, and hardcoded credentials.
- **Dependencies, prioritized by real exploit intelligence** - the differentiator. OSV
  finds vulnerable dependencies (requirements.txt / package-lock.json / Cargo.lock), then
  every finding is ranked by **CISA KEV** (actively exploited in the wild) and **FIRST
  EPSS** (exploitation probability). Standard SCA tells you "a CVE exists"; codecard tells
  you *which* ones are being exploited so you fix those first. An actively-exploited
  dependency caps the grade.

Everything rolls up into an A-F grade with the exact fix per finding (terminal or `--md`).

## The optional `--ai` mode
`--ai` adds an LLM pass that, given the deterministic findings + a system prompt as
context, does two things: (1) **triages every deterministic finding** as true_positive /
false_positive / uncertain with a one-line reason from the code (the big win - kills false
positives), and (2) reports vulnerabilities the pattern scanners structurally miss (broken
authorization / IDOR, auth bypass, business-logic flaws, cross-function taint).
It is **off by default**; the tool is fully useful without it. Backends:
- **claude** (default) - the Claude Code CLI, no key.
- **ollama** - a local model, no key, fully offline (so you can audit proprietary code).
- **openai** - any OpenAI-compatible API (`--ai-url` + `OPENAI_API_KEY`).

AI findings are confidence-filtered and labeled **[AI, verify]** - LLMs hallucinate, so
they are leads to confirm, not verdicts.

## Honest scope
- **Complements, not replaces** Semgrep/CodeQL. The source ruleset is a curated starter
  set (easily extended); the headline value is the unified report + exploit-intel deps.
- **Source-focused.** Deep compiled-binary analysis is a different, much harder domain and
  is out of scope; shallow binary checks (checksec, secrets-in-strings) may come later.
- AI mode quality depends on the backend/model.

## Requirements
Python 3 (stdlib only). Network for the OSV/KEV/EPSS dependency intelligence (cached). The
`claude` CLI / Ollama / an API key are only needed for the optional `--ai` mode.

## Roadmap
- orchestrate external scanners (semgrep, gitleaks) when present, and AI-triage their output
- derive dep severity from the CVSS vector; group findings per dependency
- Metasploit / Exploit-DB signals on dependency findings (as in cve2detect)
