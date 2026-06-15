#!/usr/bin/env python3
"""
codecard - a security report card for a codebase.

Point it at a source tree. The deterministic core (no AI, works offline) runs:
  - a source pattern scan  (injection, deserialization, weak crypto, TLS-off, ...)
  - a secrets scan         (keys, tokens, private keys)
  - a dependency scan with EXPLOIT INTELLIGENCE: OSV finds vulnerable deps, then each
    is prioritized by CISA KEV (exploited in the wild) + FIRST EPSS (exploit probability).
Then it grades the codebase A-F with a concrete fix for every finding.

`--ai` is an OPTIONAL mode that layers logic/authz bug-finding + false-positive triage
on top, via a pluggable backend (claude CLI / local Ollama / OpenAI-compatible API).

    python3 codecard.py ./myproject
    python3 codecard.py ./myproject --md report.md
    python3 codecard.py ./myproject --ai --ai-backend ollama --ai-model qwen2.5:3b
"""

import argparse
import io
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import urllib.request

UA = {"User-Agent": "codecard/0.1"}
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "codecard")
ENGINE_BIN = os.path.join(CACHE_DIR, "bin")  # where --setup installs engines
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 2}


def ensure_engine_path():
    """Put codecard's downloaded engines on PATH so have()/subprocess find them."""
    if os.path.isdir(ENGINE_BIN) and ENGINE_BIN not in os.environ.get("PATH", "").split(os.pathsep):
        os.environ["PATH"] = ENGINE_BIN + os.pathsep + os.environ.get("PATH", "")

LANG = {".py": "python", ".js": "js", ".jsx": "js", ".ts": "js", ".tsx": "js",
        ".rb": "ruby", ".php": "php", ".go": "go", ".java": "java", ".rs": "rust",
        ".c": "c", ".cpp": "c", ".cc": "c", ".h": "c"}
SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", ".venv", "venv",
             "__pycache__", "target", ".next", "site-packages", ".tox", "coverage"}

# (id, severity, cwe, [langs] or None=any, regex, title, fix)
RULES = [
    ("py-shell", "high", "CWE-78", ["python"], r"subprocess\.\w+\([^)]*shell\s*=\s*True", "subprocess with shell=True", "pass an argument list and shell=False; never interpolate input into a shell string"),
    ("py-ossystem", "high", "CWE-78", ["python"], r"\bos\.system\s*\(", "os.system() command execution", "use subprocess with an argument list, not os.system"),
    ("py-eval", "high", "CWE-95", ["python"], r"\b(eval|exec)\s*\(", "eval/exec on dynamic input", "avoid eval/exec; parse or dispatch explicitly"),
    ("py-pickle", "high", "CWE-502", ["python"], r"\bpickle\.(loads?|Unpickler)\b", "insecure deserialization (pickle)", "never unpickle untrusted data; use json or a safe schema"),
    ("py-yaml", "high", "CWE-502", ["python"], r"yaml\.load\s*\((?![^)]*Safe)", "yaml.load without SafeLoader", "use yaml.safe_load()"),
    ("py-md5", "medium", "CWE-327", ["python"], r"hashlib\.(md5|sha1)\s*\(", "weak hash (md5/sha1)", "use SHA-256+, or bcrypt/argon2 for passwords"),
    ("py-verifyfalse", "high", "CWE-295", ["python"], r"verify\s*=\s*False", "TLS certificate verification disabled", "remove verify=False; fix the trust store instead"),
    ("py-debug", "medium", "CWE-489", ["python"], r"(debug\s*=\s*True|DEBUG\s*=\s*True)", "debug mode enabled", "disable debug in production"),
    ("py-sqlfmt", "high", "CWE-89", ["python"], r"(execute|executemany)\s*\(\s*(f[\"']|[\"'].*%|.*\+\s*\w)", "possible SQL injection (string-built query)", "use parameterized queries / bound parameters"),
    ("py-mktemp", "low", "CWE-377", ["python"], r"tempfile\.mktemp\s*\(", "insecure temp file (mktemp)", "use tempfile.mkstemp / NamedTemporaryFile"),
    ("js-eval", "high", "CWE-95", ["js"], r"\beval\s*\(", "eval() on dynamic input", "avoid eval; use JSON.parse or explicit dispatch"),
    ("js-exec", "high", "CWE-78", ["js"], r"child_process\.\w*exec\w*\s*\(", "child_process exec (command injection)", "use execFile/spawn with an argument array"),
    ("js-innerhtml", "medium", "CWE-79", ["js"], r"\.innerHTML\s*=", "innerHTML assignment (XSS)", "use textContent or a sanitizer / framework binding"),
    ("js-docwrite", "medium", "CWE-79", ["js"], r"document\.write\s*\(", "document.write (XSS)", "build DOM nodes instead of writing HTML strings"),
    ("js-rejectunauth", "high", "CWE-295", ["js"], r"rejectUnauthorized\s*:\s*false", "TLS verification disabled", "remove rejectUnauthorized:false"),
    ("js-md5", "medium", "CWE-327", ["js"], r"createHash\(\s*['\"](md5|sha1)['\"]", "weak hash (md5/sha1)", "use sha256+, or bcrypt/argon2 for passwords"),
    ("php-sqlfmt", "high", "CWE-89", ["php"], r"(mysqli_query|->query)\s*\([^)]*\$_(GET|POST|REQUEST)", "SQL injection from request input", "use prepared statements"),
    ("php-system", "high", "CWE-78", ["php"], r"\b(system|exec|shell_exec|passthru)\s*\([^)]*\$_(GET|POST|REQUEST)", "command injection from request input", "avoid shell calls on user input; use escapeshellarg + allowlists"),
    ("go-mathrand", "low", "CWE-338", ["go"], r"math/rand", "non-cryptographic randomness", "use crypto/rand for tokens/secrets"),
    ("c-strcpy", "medium", "CWE-120", ["c"], r"\b(strcpy|strcat|sprintf|gets)\s*\(", "unbounded buffer operation", "use bounded variants (strncpy/snprintf) or safer APIs"),
]

SECRET_RULES = [
    ("sec-aws", "high", r"AKIA[0-9A-Z]{16}", "AWS access key id"),
    ("sec-privkey", "high", r"-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----", "private key material"),
    ("sec-ghp", "high", r"ghp_[0-9A-Za-z]{36}", "GitHub personal access token"),
    ("sec-slack", "high", r"xox[baprs]-[0-9A-Za-z-]{10,}", "Slack token"),
    ("sec-generic", "medium", r"(?i)(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*['\"][A-Za-z0-9_\-./+]{16,}['\"]", "hardcoded credential"),
]

OSV_ECO = {"requirements.txt": "PyPI", "package-lock.json": "npm", "Cargo.lock": "crates.io"}


def get_json(url, timeout=20):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
            return json.load(r)
    except Exception:
        return None


def post_json(url, payload, timeout=30):
    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                     headers={**UA, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except Exception:
        return None


def cached_text(url, name, ttl=86400):
    os.makedirs(CACHE_DIR, exist_ok=True)
    path = os.path.join(CACHE_DIR, name)
    if os.path.exists(path) and (time.time() - os.path.getmtime(path)) < ttl:
        return open(path, encoding="utf-8", errors="ignore").read()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as r:
            data = r.read().decode("utf-8", "ignore")
        open(path, "w", encoding="utf-8").write(data)
        return data
    except Exception:
        return open(path, encoding="utf-8", errors="ignore").read() if os.path.exists(path) else ""


# ---------- source + secrets (deterministic) ----------

def collect_files(root, max_files, max_bytes=200_000):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in LANG:
                continue
            p = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(p) > max_bytes:
                    continue
                out.append((os.path.relpath(p, root), open(p, encoding="utf-8", errors="ignore").read(), LANG[ext]))
            except Exception:
                pass
            if len(out) >= max_files:
                return out
    return out


SECRET_FIX = "remove the secret, rotate it, and load from env/secret manager"


def scan_source_patterns(files):
    findings = []
    for rel, content, lang in files:
        for i, line in enumerate(content.splitlines(), 1):
            for rid, sev, cwe, langs, pat, title, fix in RULES:
                if langs and lang not in langs:
                    continue
                if re.search(pat, line):
                    findings.append({"kind": "source", "file": rel, "line": i, "severity": sev,
                                     "cwe": cwe, "title": title, "detail": line.strip()[:120],
                                     "fix": fix, "_engine": "regex"})
    return findings


def scan_secret_patterns(files):
    findings = []
    for rel, content, lang in files:
        for i, line in enumerate(content.splitlines(), 1):
            for rid, sev, pat, title in SECRET_RULES:
                if re.search(pat, line):
                    findings.append({"kind": "secret", "file": rel, "line": i, "severity": sev,
                                     "cwe": "CWE-798", "title": title, "detail": "(redacted match)",
                                     "fix": SECRET_FIX, "_engine": "regex"})
    return findings


# ---------- external engines (use-if-present, graceful fallback) ----------

SEMGREP_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
TRIVY_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "low"}


def have(tool):
    return shutil.which(tool) is not None


def _run(cmd, timeout=900):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def run_semgrep(root):
    """Source SAST via semgrep registry rules. Returns source findings, or None if semgrep absent/failed."""
    if not have("semgrep"):
        return None
    # --config=auto pulls the registry ruleset (needs network; semgrep sends anonymous metrics for it).
    # The offline path is the built-in regex ruleset (this returns None and main falls back).
    out = _run(["semgrep", "--config=auto", "--json", "--quiet", "--timeout", "30", root])
    try:
        data = json.loads(out)
    except Exception:
        return None
    findings = []
    for r in data.get("results", []):
        ex = r.get("extra", {}) or {}
        meta = ex.get("metadata", {}) or {}
        cwe_raw = meta.get("cwe", "")
        if isinstance(cwe_raw, list):
            cwe_raw = " ".join(cwe_raw)
        m = re.search(r"CWE-\d+", str(cwe_raw))
        try:
            rel = os.path.relpath(r.get("path", ""), root)
        except Exception:
            rel = r.get("path", "")
        msg = (ex.get("message", "") or "").strip().split("\n")[0]
        findings.append({"kind": "source", "file": rel, "line": r.get("start", {}).get("line"),
                         "severity": SEMGREP_SEV.get(ex.get("severity", "WARNING"), "medium"),
                         "cwe": m.group(0) if m else "", "title": (msg or r.get("check_id", ""))[:90],
                         "detail": "semgrep: " + r.get("check_id", "").split(".")[-1],
                         "fix": (meta.get("references") or ["see the semgrep rule guidance"])[0],
                         "_engine": "semgrep"})
    return findings


TRIVY_VSEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def run_trivy(root, scanners="vuln,config,secret"):
    """Cross-ecosystem dep vulns + IaC/config misconfig + secret breadth via trivy.
    Returns (vulns, config, secrets), or None if trivy is absent/failed. trivy parses every
    lockfile/manifest it supports (pip, npm/yarn/pnpm, go, cargo, gem, composer, maven, nuget, ...),
    so dependency coverage spans a whole repo, not just the three formats the built-in parser reads."""
    if not have("trivy"):
        return None
    out = _run(["trivy", "fs", "--quiet", "--format", "json", "--scanners", scanners, root])
    try:
        return _parse_trivy(json.loads(out))
    except Exception:
        return None


def run_trivy_image(image, scanners="vuln,secret"):
    """Scan a built container image's OS packages + app deps + secrets (trivy image).
    Returns (vulns, config, secrets), or None if trivy is absent/failed."""
    if not have("trivy"):
        return None
    out = _run(["trivy", "image", "--quiet", "--format", "json", "--scanners", scanners, image])
    try:
        return _parse_trivy(json.loads(out))
    except Exception:
        return None


def _parse_trivy(data):
    vulns, config, secrets = [], [], []
    for res in (data.get("Results") or []):
        tgt = res.get("Target", "")
        eco = res.get("Type") or res.get("Class") or "dep"
        for v in (res.get("Vulnerabilities") or []):
            vulns.append({"cve": v.get("VulnerabilityID", ""),
                          "severity": TRIVY_VSEV.get(v.get("Severity", ""), "unknown"),
                          "title": (v.get("Title") or v.get("Description") or "")[:90],
                          "loc": f"{eco}:{v.get('PkgName')}@{v.get('InstalledVersion')}",
                          "fixed": v.get("FixedVersion", "")})
        for mc in (res.get("Misconfigurations") or []):
            cm = mc.get("CauseMetadata", {}) or {}
            config.append({"kind": "config", "file": tgt, "line": cm.get("StartLine"),
                           "severity": TRIVY_SEV.get(mc.get("Severity", "LOW"), "low"),
                           "cwe": mc.get("ID", ""), "title": (mc.get("Title") or mc.get("ID", ""))[:90],
                           "detail": ("trivy: " + (mc.get("Message") or mc.get("Description") or ""))[:170],
                           "fix": (mc.get("Resolution") or "see the trivy misconfig guidance")[:170],
                           "_engine": "trivy"})
        for s in (res.get("Secrets") or []):
            secrets.append({"kind": "secret", "file": tgt, "line": s.get("StartLine"),
                            "severity": TRIVY_SEV.get(s.get("Severity", "HIGH"), "high"),
                            "cwe": "CWE-798", "title": (s.get("Title") or s.get("RuleID") or "secret")[:90],
                            "detail": "(redacted match) trivy: " + s.get("RuleID", ""),
                            "fix": SECRET_FIX, "_engine": "trivy"})
    return vulns, config, secrets


def enrich_deps(tvulns):
    """Prioritize trivy's cross-ecosystem dependency CVEs by CISA KEV + FIRST EPSS (the differentiator).
    KEV (exploited in the wild) forces critical and caps the grade; EPSS adds exploitation probability."""
    cves = {v["cve"] for v in tvulns if v["cve"].startswith("CVE-")}
    kev = kev_set() if cves else {}
    epss = epss_scores(cves) if cves else {}
    out = []
    for v in tvulns:
        c = v["cve"]
        in_kev = c in kev
        ep = epss.get(c)
        sev = "critical" if in_kev else v["severity"]
        intel = []
        if in_kev:
            intel.append("KEV (actively exploited)")
        if ep is not None:
            intel.append(f"EPSS {ep*100:.0f}%")
        out.append({"kind": "dependency", "file": v["loc"], "line": None, "severity": sev,
                    "cwe": c, "title": v["title"] or c,
                    "detail": "; ".join(intel) or "no exploit signal",
                    "fix": (f"upgrade to {v['fixed']}" if v.get("fixed") else "upgrade past the vulnerable version"),
                    "_kev": in_kev, "_epss": ep or 0.0})
    return out


def run_trufflehog(root):
    """Verified-secret detection via trufflehog. Returns secret findings, or None if absent."""
    if not have("trufflehog"):
        return None
    out = _run(["trufflehog", "filesystem", root, "--results=verified,unknown", "--json", "--no-update"])
    findings = []
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln.startswith("{"):
            continue
        try:
            d = json.loads(ln)
        except Exception:
            continue
        meta = (((d.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {})
        rel = meta.get("file", "")
        try:
            rel = os.path.relpath(rel, root) if rel else ""
        except Exception:
            pass
        verified = bool(d.get("Verified"))
        findings.append({"kind": "secret", "file": rel, "line": meta.get("line"),
                         "severity": "high" if verified else "medium", "cwe": "CWE-798",
                         "title": d.get("DetectorName", "secret") + (" (verified)" if verified else ""),
                         "detail": "(redacted match) trufflehog", "fix": SECRET_FIX, "_engine": "trufflehog"})
    return findings


def run_gitleaks(root):
    """Secret detection via gitleaks (broad rule pack). Returns secret findings, or None if absent."""
    if not have("gitleaks"):
        return None
    out = _run(["gitleaks", "detect", "--source", root, "--no-git", "--no-banner",
                "-f", "json", "-r", "/dev/stdout", "--exit-code", "0"])
    try:
        items = json.loads(out or "[]")
    except Exception:
        return None
    findings = []
    for it in items:
        rel = it.get("File", "")
        try:
            rel = os.path.relpath(rel, root) if rel else ""
        except Exception:
            pass
        findings.append({"kind": "secret", "file": rel, "line": it.get("StartLine"),
                         "severity": "high", "cwe": "CWE-798",
                         "title": (it.get("RuleID") or it.get("Description") or "secret")[:90],
                         "detail": "(redacted match) gitleaks", "fix": SECRET_FIX, "_engine": "gitleaks"})
    return findings


HADOLINT_SEV = {"error": "high", "warning": "medium", "info": "low", "style": "low"}


def run_hadolint(root):
    """Dockerfile linting via hadolint (shell-level issues trivy's config scan misses).
    Returns config findings, or None if hadolint is absent / no Dockerfiles found."""
    if not have("hadolint"):
        return None
    dockerfiles = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            if fn == "Dockerfile" or fn.startswith("Dockerfile.") or fn.endswith(".dockerfile"):
                dockerfiles.append(os.path.join(dirpath, fn))
    if not dockerfiles:
        return None
    out = _run(["hadolint", "--no-fail", "-f", "json"] + dockerfiles)
    try:
        items = json.loads(out or "[]")
    except Exception:
        return None
    findings = []
    for it in items:
        rel = it.get("file", "")
        try:
            rel = os.path.relpath(rel, root) if rel else ""
        except Exception:
            pass
        findings.append({"kind": "config", "file": rel, "line": it.get("line"),
                         "severity": HADOLINT_SEV.get(it.get("level", "info"), "low"),
                         "cwe": it.get("code", ""), "title": (it.get("message") or it.get("code", ""))[:90],
                         "detail": "hadolint: " + it.get("code", ""),
                         "fix": "see hadolint wiki for " + it.get("code", ""), "_engine": "hadolint"})
    return findings


def dedup_secrets(secrets):
    """Collapse secret findings from regex + trivy + trufflehog + gitleaks by (file, line), keep the strongest."""
    best = {}
    for f in secrets:
        key = (f["file"], f.get("line"))
        cur = best.get(key)
        if cur is None or SEV_RANK.get(f["severity"], 2) > SEV_RANK.get(cur["severity"], 2):
            best[key] = f
    return list(best.values())


# ---------- engine auto-install (--setup): official release binaries into ENGINE_BIN ----------

def _arch():
    return "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "amd64"


def _dl(url, timeout=240):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
        return r.read()


def _gh_tag(repo):
    return ((get_json(f"https://api.github.com/repos/{repo}/releases/latest") or {}).get("tag_name") or "")


def _write_exec(path, data):
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _extract_targz(data, basename, dest):
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        for m in tf.getmembers():
            if m.isfile() and os.path.basename(m.name) == basename:
                _write_exec(dest, tf.extractfile(m).read())
                return True
    raise RuntimeError(f"{basename} not found in archive")


def _install_hadolint(bindir):
    arch = "x86_64" if _arch() == "amd64" else "arm64"
    url = f"https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-{arch}"
    _write_exec(os.path.join(bindir, "hadolint"), _dl(url))
    return url


def _install_gitleaks(bindir):
    tag = _gh_tag("gitleaks/gitleaks"); ver = tag.lstrip("v")
    arch = "x64" if _arch() == "amd64" else "arm64"
    url = f"https://github.com/gitleaks/gitleaks/releases/download/{tag}/gitleaks_{ver}_linux_{arch}.tar.gz"
    _extract_targz(_dl(url), "gitleaks", os.path.join(bindir, "gitleaks"))
    return url


def _install_trivy(bindir):
    tag = _gh_tag("aquasecurity/trivy"); ver = tag.lstrip("v")
    arch = "64bit" if _arch() == "amd64" else "ARM64"
    url = f"https://github.com/aquasecurity/trivy/releases/download/{tag}/trivy_{ver}_Linux-{arch}.tar.gz"
    _extract_targz(_dl(url), "trivy", os.path.join(bindir, "trivy"))
    return url


def _install_trufflehog(bindir):
    tag = _gh_tag("trufflesecurity/trufflehog"); ver = tag.lstrip("v")
    arch = "amd64" if _arch() == "amd64" else "arm64"
    url = f"https://github.com/trufflesecurity/trufflehog/releases/download/{tag}/trufflehog_{ver}_linux_{arch}.tar.gz"
    _extract_targz(_dl(url), "trufflehog", os.path.join(bindir, "trufflehog"))
    return url


def _install_semgrep(bindir):
    subprocess.run([sys.executable, "-m", "pip", "install", "--user", "--quiet", "--upgrade", "semgrep"],
                   timeout=900, check=True)
    return "pip install --user semgrep"


INSTALLERS = {"trivy": _install_trivy, "semgrep": _install_semgrep, "trufflehog": _install_trufflehog,
              "gitleaks": _install_gitleaks, "hadolint": _install_hadolint}


def setup_engines():
    """Download every engine codecard uses from its official source into ENGINE_BIN (semgrep via pip)."""
    os.makedirs(ENGINE_BIN, exist_ok=True)
    ensure_engine_path()
    print(f"codecard --setup: installing engines into {ENGINE_BIN}\n")
    for name, fn in INSTALLERS.items():
        if have(name):
            print(f"  {name:<11} present  ({shutil.which(name)})")
            continue
        print(f"  {name:<11} downloading ...", flush=True)
        try:
            src = fn(ENGINE_BIN)
            ok = have(name)
            print(f"  {name:<11} {'installed' if ok else 'FAILED (not on PATH)'}  <- {src}")
        except Exception as e:
            print(f"  {name:<11} FAILED  ({e})")
    print(f"\ndone. add this to your shell to use them everywhere:  export PATH=\"{ENGINE_BIN}:$PATH\"")
    print("(codecard itself already finds them on its own.)")


# ---------- dependencies + exploit intelligence (the differentiator) ----------

def parse_manifests(root):
    deps = []  # (ecosystem, name, version)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            try:
                if fn == "requirements.txt":
                    for ln in open(p, encoding="utf-8", errors="ignore"):
                        m = re.match(r"\s*([A-Za-z0-9_.\-]+)==([0-9][\w.\-]*)", ln)
                        if m:
                            deps.append(("PyPI", m.group(1).lower(), m.group(2)))
                elif fn == "package-lock.json":
                    d = json.load(open(p, encoding="utf-8", errors="ignore"))
                    for path, meta in (d.get("packages") or {}).items():
                        if path.startswith("node_modules/") and meta.get("version"):
                            deps.append(("npm", path.split("node_modules/")[-1], meta["version"]))
                elif fn == "Cargo.lock":
                    txt = open(p, encoding="utf-8", errors="ignore").read()
                    for blk in re.findall(r"\[\[package\]\](.*?)(?=\n\[\[|\Z)", txt, re.S):
                        nm = re.search(r'name\s*=\s*"([^"]+)"', blk)
                        vr = re.search(r'version\s*=\s*"([^"]+)"', blk)
                        if nm and vr:
                            deps.append(("crates.io", nm.group(1), vr.group(1)))
            except Exception:
                pass
    # dedup
    return list({d: None for d in deps})


def kev_set():
    txt = cached_text("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "kev.json")
    try:
        data = json.loads(txt)
        return {v["cveID"]: v for v in data.get("vulnerabilities", [])}
    except Exception:
        return {}


def epss_scores(cves):
    out = {}
    cves = list(cves)
    for i in range(0, len(cves), 90):
        chunk = ",".join(cves[i:i + 90])
        d = get_json(f"https://api.first.org/data/v1/epss?cve={chunk}")
        for row in (d or {}).get("data", []):
            out[row["cve"]] = float(row["epss"])
    return out


def scan_deps_osv(root):
    """Fallback dependency scan when trivy is absent: OSV over the three lockfiles the built-in
    parser reads (requirements.txt / package-lock.json / Cargo.lock), prioritized by KEV + EPSS."""
    deps = parse_manifests(root)
    if not deps:
        return []
    queries = [{"package": {"ecosystem": e, "name": n}, "version": v} for (e, n, v) in deps]
    findings = []
    vuln_cache = {}
    # OSV querybatch (chunked)
    pending = []  # (dep, vuln_id)
    for i in range(0, len(queries), 500):
        res = post_json("https://api.osv.dev/v1/querybatch", {"queries": queries[i:i + 500]})
        for dep, r in zip(deps[i:i + 500], (res or {}).get("results", [])):
            for v in (r.get("vulns") or []):
                pending.append((dep, v["id"]))
    if not pending:
        return []
    # resolve vuln details + collect CVEs
    cves = set()
    rows = []
    for (eco, name, ver), vid in pending:
        if vid not in vuln_cache:
            vuln_cache[vid] = get_json(f"https://api.osv.dev/v1/vulns/{vid}") or {}
        v = vuln_cache[vid]
        cve = next((a for a in v.get("aliases", []) if a.startswith("CVE-")), vid)
        if cve.startswith("CVE-"):
            cves.add(cve)
        sev = (v.get("database_specific", {}) or {}).get("severity", "unknown")
        rows.append({"eco": eco, "name": name, "ver": ver, "vid": vid, "cve": cve,
                     "summary": v.get("summary", "")[:90], "severity": (sev or "unknown").lower()})
    kev = kev_set()
    epss = epss_scores(cves)
    for r in rows:
        c = r["cve"]
        in_kev = c in kev
        ep = epss.get(c)
        # exploit intel drives severity: KEV forces critical
        sev = "critical" if in_kev else (r["severity"] if r["severity"] in SEV_RANK else "unknown")
        intel = []
        if in_kev:
            intel.append("KEV (actively exploited)")
        if ep is not None:
            intel.append(f"EPSS {ep*100:.0f}%")
        findings.append({"kind": "dependency", "file": f"{r['eco']}:{r['name']}@{r['ver']}", "line": None,
                         "severity": sev, "cwe": r["cve"], "title": r["summary"] or r["vid"],
                         "detail": ("; ".join(intel) or "no exploit signal") + (f"  ({r['vid']})" if r["vid"] != c else ""),
                         "fix": "upgrade past the vulnerable version", "_kev": in_kev, "_epss": ep or 0.0})
    return findings


# ---------- optional AI mode ----------

AI_DEFAULTS = {"claude": (None, None), "ollama": ("llama3.1", "http://localhost:11434"),
               "openai": ("gpt-4o-mini", "https://api.openai.com/v1")}


AI_SYSTEM = (
    "You are a senior application security auditor reviewing automated scanner output. For each file you "
    "receive the source code and the deterministic findings the scanners already reported (each with an id). "
    "Do two things: (1) TRIAGE every reported finding as true_positive, false_positive, or uncertain, with a "
    "one-line reason grounded in the code context (this is the most valuable part: kill false positives); "
    "(2) report additional REAL vulnerabilities the pattern scanners MISSED, especially broken authorization "
    "(IDOR / missing checks), auth bypass, business-logic flaws, and cross-function taint. Be precise; never "
    "invent issues. Output ONLY JSON, no prose: "
    '{"triage":[{"id":<int>,"verdict":"true_positive|false_positive|uncertain","reason":"..."}],'
    '"missed":[{"line":<int|null>,"severity":"critical|high|medium|low","cwe":"CWE-..","title":"..",'
    '"detail":"..","fix":"..","confidence":0.0-1.0}]}'
)


def ai_generate(system, user, backend, model, url):
    if backend == "claude":
        if not shutil.which("claude"):
            return None, "claude CLI not found"
        args = ["claude", "-p", "--output-format", "text"] + (["--model", model] if model else [])
        if system:
            args += ["--append-system-prompt", system]
        try:
            r = subprocess.run(args, input=user, capture_output=True, text=True, timeout=300)
            return (r.stdout, None) if r.returncode == 0 and r.stdout.strip() else (None, r.stderr[:100] or "no output")
        except Exception as e:
            return None, str(e)
    msgs = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": user}]
    if backend == "ollama":
        d = post_json(f"{url}/api/chat", {"model": model, "messages": msgs, "stream": False}, timeout=600)
        return ((d.get("message", {}) or {}).get("content"), None) if d else (None, f"ollama unreachable at {url} / model '{model}'")
    if backend == "openai":
        key = os.environ.get("OPENAI_API_KEY") or os.environ.get("AI_API_KEY")
        if not key:
            return None, "set OPENAI_API_KEY for the openai backend"
        try:
            req = urllib.request.Request(f"{url}/chat/completions",
                data=json.dumps({"model": model, "messages": msgs}).encode(),
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"})
            with urllib.request.urlopen(req, timeout=600) as r:
                return json.load(r)["choices"][0]["message"]["content"], None
        except Exception as e:
            return None, str(e)
    return None, "unknown backend"


def ai_review(files, det_findings, backend, model, url):
    """AI mode: triage the deterministic findings (with code context) + report what scanners missed.
    Mutates det_findings (adds ai_verdict/ai_reason) and returns new AI-only findings."""
    model = model or AI_DEFAULTS[backend][0]
    url = url or AI_DEFAULTS[backend][1]
    by_file = {}
    for f in det_findings:
        if f["kind"] in ("source", "secret"):
            by_file.setdefault(f["file"], []).append(f)
    new = []
    for rel, content, lang in files:
        local = by_file.get(rel, [])
        listing = "\n".join(f"  id {i}: [{f['severity']}] {f['title']} (line {f['line']}): {f['detail']}"
                            for i, f in enumerate(local)) or "  (none reported)"
        user = f"FILE: {rel}\n\nDETERMINISTIC FINDINGS:\n{listing}\n\nSOURCE:\n```\n{content[:12000]}\n```"
        text, err = ai_generate(AI_SYSTEM, user, backend, model, url)
        if not text:
            print(f"  --ai: {rel}: skipped ({err})")
            continue
        m = re.search(r"\{.*\}", text, re.S)
        if not m:
            continue
        try:
            data = json.loads(m.group(0))
        except Exception:
            continue
        for t in data.get("triage", []):
            i = t.get("id")
            if isinstance(i, int) and 0 <= i < len(local):
                local[i]["ai_verdict"] = t.get("verdict", "")
                local[i]["ai_reason"] = (t.get("reason", "") or "")[:120]
        for it in data.get("missed", []):
            if it.get("confidence", 1) >= 0.5:
                new.append({"kind": "ai", "file": rel, "line": it.get("line"),
                            "severity": (it.get("severity") or "medium").lower(), "cwe": it.get("cwe", ""),
                            "title": it.get("title", "AI finding"),
                            "detail": (it.get("detail", "") + " [AI, verify]")[:180], "fix": it.get("fix", "")})
    return new


# ---------- grade + report ----------

def grade(findings):
    pts = sum({"critical": 25, "high": 12, "medium": 4, "low": 1}.get(f["severity"], 4) for f in findings)
    kev = any(f.get("_kev") for f in findings)
    letter = "A" if pts == 0 else "B" if pts < 6 else "C" if pts < 16 else "D" if pts < 36 else "F"
    if kev and letter in ("A", "B", "C"):
        letter = "D"  # an actively-exploited dependency caps the grade
    return pts, letter


C = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[2m", "r": "\033[0m", "b": "\033[1m"}


def report_terminal(root, findings, pts, letter):
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 2}
    findings = sorted(findings, key=lambda f: (order.get(f["severity"], 2), -f.get("_epss", 0)))
    print(f"\n{C['b']}codecard: {root}{C['r']}")
    print(f"{C['b']}grade: {letter}   ({len(findings)} findings, {pts} risk points){C['r']}\n")
    for sec, kind in (("Dependencies (exploit-prioritized)", "dependency"), ("Source", "source"),
                      ("Config / IaC", "config"), ("Secrets", "secret"),
                      ("AI (logic/authz, verify)", "ai")):
        fs = [f for f in findings if f["kind"] == kind]
        if not fs:
            continue
        print(f"{C['b']}{sec}{C['r']}")
        for f in fs:
            col = C.get(f["severity"], "")
            loc = f["file"] + (f":{f['line']}" if f["line"] else "")
            print(f"  {col}[{f['severity']:>8}]{C['r']} {f['title']}  {C['low']}{loc}{C['r']}")
            print(f"            {f['detail']}")
            if f.get("ai_verdict"):
                print(f"            {C['low']}AI triage: {f['ai_verdict']} - {f.get('ai_reason', '')}{C['r']}")
            if f.get("fix"):
                print(f"            {C['low']}fix: {f['fix']}{C['r']}")
        print()


def report_md(root, findings, pts, letter, path):
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 2}
    findings = sorted(findings, key=lambda f: (order.get(f["severity"], 2), -f.get("_epss", 0)))
    out = [f"# codecard: {root}", "", f"**Grade {letter}** - {len(findings)} findings, {pts} risk points", ""]
    for f in findings:
        loc = f["file"] + (f":{f['line']}" if f["line"] else "")
        out.append(f"- `{f['severity']}` **{f['title']}** ({f['cwe']}) - `{loc}`  \n  {f['detail']}  \n  fix: {f.get('fix','')}")
    open(path, "w").write("\n".join(out) + "\n")
    print(f"wrote {path}")


def main():
    ap = argparse.ArgumentParser(description="security report card for a codebase")
    ap.add_argument("path", nargs="?", help="source tree to scan (a whole repo / deployment)")
    ap.add_argument("--image", metavar="TAG", help="also scan a built container image's OS + app packages (trivy image)")
    ap.add_argument("--setup", action="store_true", help="download the external engines into the cache, then exit")
    ap.add_argument("--max-files", type=int, default=400)
    ap.add_argument("--md", metavar="FILE")
    ap.add_argument("--no-deps", action="store_true", help="skip the dependency/exploit-intel scan")
    ap.add_argument("--no-engines", action="store_true",
                    help="skip external engines (semgrep/trivy/trufflehog/gitleaks/hadolint); built-in rules only")
    ap.add_argument("--ai", action="store_true", help="OPTIONAL: add an LLM pass for logic/authz bugs")
    ap.add_argument("--ai-backend", choices=["claude", "ollama", "openai"], default="claude")
    ap.add_argument("--ai-model")
    ap.add_argument("--ai-url")
    args = ap.parse_args()

    ensure_engine_path()
    if args.setup:
        setup_engines()
        return
    if not args.path and not args.image:
        ap.error("give a PATH to scan, or --image TAG, or --setup")
    if args.path and not os.path.isdir(args.path):
        sys.exit(f"error: {args.path} is not a directory")

    engines = []          # human-readable list of what actually ran
    findings = []
    secrets = []
    dep_vulns = []        # trivy vulns (fs + image), enriched once with KEV/EPSS
    files = []
    use_engines = not args.no_engines

    if args.path:
        files = collect_files(args.path, args.max_files)
        print(f"scanning {len(files)} source files in {args.path} ...", file=sys.stderr)

        # One trivy fs pass feeds three sections: dep vulns (broad ecosystem coverage), config/IaC, secrets.
        scanners = ("config,secret" if args.no_deps else "vuln,config,secret")
        trivy_res = run_trivy(args.path, scanners) if use_engines else None

        # SOURCE: prefer semgrep (registry rules); fall back to the built-in regex ruleset.
        src = run_semgrep(args.path) if use_engines else None
        if src is not None:
            engines.append(f"semgrep ({len(src)} source)")
            findings += src
        else:
            findings += scan_source_patterns(files)
            if args.no_engines:
                engines.append("regex source rules")
            elif have("semgrep"):
                engines.append("regex source rules (semgrep present but returned nothing; needs network for --config=auto)")
            else:
                engines.append("regex source rules (semgrep not installed; run --setup)")

        # CONFIG/IaC: trivy + hadolint (Dockerfile depth).   SECRETS: regex + trivy + trufflehog + gitleaks.
        secrets += scan_secret_patterns(files)
        if trivy_res is not None:
            tvuln, tcfg, tsec = trivy_res
            engines.append(f"trivy ({len(tvuln)} dep, {len(tcfg)} config, {len(tsec)} secret)")
            findings += tcfg
            secrets += tsec
            dep_vulns += tvuln
        if use_engines:
            for runner, kind in ((run_hadolint, "config"), (run_trufflehog, "secret"), (run_gitleaks, "secret")):
                res = runner(args.path)
                if res is not None:
                    engines.append(f"{runner.__name__[4:]} ({len(res)} {kind})")
                    (findings if kind == "config" else secrets).extend(res)

    # CONTAINER IMAGE: OS packages + app deps + layer secrets.
    if args.image:
        ti = run_trivy_image(args.image, "secret" if args.no_deps else "vuln,secret")
        if ti is None:
            print("--image needs trivy; run `codecard --setup`", file=sys.stderr)
        else:
            ivuln, _icfg, isec = ti
            engines.append(f"trivy image {args.image} ({len(ivuln)} vuln, {len(isec)} secret)")
            secrets += isec
            dep_vulns += ivuln

    findings += dedup_secrets(secrets)
    print("engines: " + ("; ".join(engines) or "built-in rules only"), file=sys.stderr)

    # DEPENDENCIES: trivy's cross-ecosystem vulns (fs + image) when trivy is present (whole-setup
    # coverage), else OSV over the built-in lockfiles. Either way, prioritized by KEV + EPSS.
    if not args.no_deps:
        if have("trivy"):
            print("prioritizing dependency CVEs by KEV + EPSS ...", file=sys.stderr)
            findings += enrich_deps(dep_vulns)
        elif args.path:
            print("checking dependencies against OSV + KEV + EPSS ...", file=sys.stderr)
            findings += scan_deps_osv(args.path)

    if args.ai:
        print(f"--ai: triaging findings + logic/authz pass with {args.ai_backend} ...", file=sys.stderr)
        findings += ai_review(files, findings, args.ai_backend, args.ai_model, args.ai_url)

    target = args.path or args.image
    pts, letter = grade(findings)
    report_terminal(target, findings, pts, letter)
    if args.md:
        report_md(target, findings, pts, letter, args.md)


if __name__ == "__main__":
    main()
