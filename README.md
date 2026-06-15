# codecard

A security report card for a codebase. Point it at a **whole repo or deployment** - a
monorepo, a React app, a Docker/Kubernetes setup - and get one graded, actionable audit
across source, config/IaC, secrets, and dependencies. It walks the entire tree, not a
single file. **Deterministic by default, no API keys.**

```sh
python3 codecard.py ./myproject
python3 codecard.py ./myproject --md report.md
python3 codecard.py ./myproject --ai --ai-backend ollama --ai-model qwen2.5:3b   # optional AI pass
```

## What the core scans (no AI)
- **Source** - if `semgrep` is installed it drives the source pass (the full registry
  ruleset); otherwise a built-in per-language regex ruleset runs (command/code injection,
  SQL injection, insecure deserialization, weak crypto, TLS-off, debug-on, unbounded C
  buffer ops, ...). The regex set is the fully-offline path.
- **Config / IaC** - if `trivy` is installed, Dockerfiles / Kubernetes / Terraform are
  scanned for misconfigurations (running as root, `:latest`, missing healthcheck, ...). No
  built-in equivalent; this section is empty without trivy.
- **Secrets** - a built-in detector (AWS keys, GitHub/Slack tokens, private keys,
  hardcoded credentials) always runs, and `trivy` + `trufflehog` are layered on when
  present for breadth and verified-secret confirmation. Results are de-duplicated by
  file:line.
- **Dependencies, prioritized by real exploit intelligence** - the differentiator, always
  on. When `trivy` is installed it finds vulnerable dependencies across **every ecosystem it
  parses** (pip, npm/yarn/pnpm, go, cargo, gem, composer, maven, nuget, ...), so a whole
  setup is covered; without it, a built-in OSV scan handles requirements.txt / package-lock.json
  / Cargo.lock. Either way **every CVE is then ranked by CISA KEV** (actively exploited in the
  wild) and **FIRST EPSS** (exploitation probability). Standard SCA tells you "a CVE exists";
  codecard tells you *which* ones are being exploited so you fix those first. An
  actively-exploited dependency caps the grade. (This KEV/EPSS layer is what trivy's own dep
  scan doesn't do - codecard adds it on top.)

External engines are **use-if-present**: codecard orchestrates the mature scanners when
they are on PATH and falls back to the built-in rules when they are not, then unifies and
grades everything together. The startup `engines:` line reports exactly what ran. Use
`--no-engines` to force the built-in rules only (fully offline together with `--no-deps`).

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
- **Orchestrates, doesn't reinvent.** When semgrep/trivy/trufflehog are present codecard
  uses them; the headline value is the *unified, graded report* plus the exploit-intel dep
  ranking that none of those tools do on their own. The built-in regex rules are a capable
  offline fallback, not a semgrep replacement.
- **Source + config + deps.** Deep compiled-binary analysis is a different, much harder
  domain and is out of scope; shallow binary checks (checksec, secrets-in-strings) may come
  later.
- AI mode quality depends on the backend/model.

## Requirements
Python 3 (stdlib only). Network for the OSV/KEV/EPSS dependency intelligence (cached).
Optional external engines, used automatically when on PATH:
- **semgrep** - deeper source SAST (the registry ruleset; needs network for `--config=auto`).
- **trivy** - IaC/config misconfig + secret breadth.
- **trufflehog** - verified-secret confirmation.

The `claude` CLI / Ollama / an API key are only needed for the optional `--ai` mode.

## Roadmap
- derive dep severity from the CVSS vector; group findings per dependency
- Metasploit / Exploit-DB signals on dependency findings (as in cve2detect)
- de-duplicate the few cases where semgrep and trivy flag the same Dockerfile line
