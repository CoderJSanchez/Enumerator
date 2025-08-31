#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import subprocess
from datetime import datetime
from pathlib import Path
import sys
import re
import shlex
import string
import time
import random

import requests
from urllib.parse import urlencode, unquote, urlparse, parse_qs, urljoin

# Try optional dependency for form parsing
try:
    from bs4 import BeautifulSoup  # type: ignore
    HAVE_BS4 = True
except Exception:
    HAVE_BS4 = False

# Silence SSL warnings for lab targets
requests.packages.urllib3.disable_warnings()

# =========================
# Terminal styling + banner
# =========================
def _supports_color() -> bool:
    return sys.stdout.isatty()

class C:
    def __init__(self, enabled: bool):
        if enabled:
            self.G = "\033[32m"  # green
            self.R = "\033[31m"  # red
            self.Y = "\033[33m"  # yellow
            self.B = "\033[34m"  # blue
            self.D = "\033[0m"   # reset
            self.BD = "\033[1m"  # bold
        else:
            self.G = self.R = self.Y = self.B = self.D = self.BD = ""

def print_banner(c: C):
    ascii_logo = r"""
                                              
               E N U M E R A T O R
    """
    print(f"{c.BD}{c.B}{ascii_logo}{c.D}")
    print(f"{c.G}Created by Julio C. Sanchez Jr{c.D}\n")

def print_title(title: str, c: C):
    print(f"{c.BD}====={title}====={c.D}")

def print_ok(msg: str, c: C):
    print(f"{c.G}[+]{c.D} {msg}")

def print_warn(msg: str, c: C):
    print(f"{c.Y}[!]{c.D} {msg}")

def print_bad(msg: str, c: C):
    print(f"{c.R}[-]{c.D} {msg}")

# =========================
# Run directory helper
# =========================
def make_run_directory(base: str) -> Path:
    root = Path(base)
    root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
    run_dir = root / f"intel_{stamp}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir

# =========================
# Target + command validation
# =========================
def _looks_like_target(s: str) -> bool:
    # IPv4 or hostname-ish
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", s):
        return True
    if re.fullmatch(r"[A-Za-z0-9.-]{1,253}", s):
        return True
    return False

def _validate_nmap_template(tmpl: str) -> None:
    if any(x in tmpl for x in [";", "|", "&", ">", "<", "$(", "`"]):
        raise ValueError("Nmap template contains forbidden shell metacharacters.")
    if "{target}" not in tmpl:
        raise ValueError('Nmap template must contain "{target}".')
    toks = shlex.split(tmpl)
    if not toks:
        raise ValueError("Empty nmap template.")
    first = toks[0]
    if first == "sudo":
        if len(toks) < 2 or toks[1] != "nmap":
            raise ValueError("After 'sudo', the command must be 'nmap'.")
    else:
        if first != "nmap":
            raise ValueError("Template must invoke 'nmap'.")

# =========================
# Nmap runner
# =========================
def run_nmap(target: str, nmap_cmd_template: str, out_dir: Path, c: C) -> tuple[Path, str]:
    _validate_nmap_template(nmap_cmd_template)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_path = out_dir / f"nmap_{target}_{stamp}.txt"

    nmap_cmd = nmap_cmd_template.format(target=target)
    print_ok(f"Running Nmap: {nmap_cmd}", c)
    print()

    argv = shlex.split(nmap_cmd)
    with scan_path.open("w", encoding="utf-8", errors="ignore") as f:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in proc.stdout:
            print(line, end="")
            f.write(line)
        proc.wait()

    if proc.returncode != 0:
        print_warn("Nmap exited with a non-zero status. Check the scan file for details.", c)
    print_ok(f"Scan saved to: {scan_path}", c)
    return scan_path, nmap_cmd

# =========================
# Keyword intake + sanitization
# =========================
_MAX_KEYWORDS = 20
_MAX_KEYWORD_LEN = 80
_ALLOWED_CHARS = set(string.ascii_letters + string.digits + " .:/_-+")

def _sanitize_keyword(s: str) -> str:
    s = s.strip()
    s = "".join(ch for ch in s if ch in _ALLOWED_CHARS)
    return s[:_MAX_KEYWORD_LEN]

def get_keywords(c: C) -> list[str]:
    print("\n[?] Enter keywords from Nmap scan to research (comma separated):")
    print("    e.g., RaspAP, lighttpd 1.4.53, Apache Tomcat, mysql")
    raw = input("> ")
    if not raw:
        return []
    cleaned = []
    for k in raw.split(","):
        k2 = _sanitize_keyword(k)
        if k2:
            cleaned.append(k2)
    uniq = list(dict.fromkeys(cleaned))[:_MAX_KEYWORDS]
    if not uniq:
        print_bad("No valid keywords after sanitization.", c)
    return uniq

# =========================
# searchsploit
# =========================
_MAX_SPLIT_LINES = 500

def run_searchsploit(keyword: str) -> list[str]:
    try:
        result = subprocess.run(["searchsploit", keyword],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=45)
        output = result.stdout
        if not output:
            return []
        lines = [ln.rstrip() for ln in output.splitlines() if ln.strip()]
        if len(lines) > _MAX_SPLIT_LINES:
            lines = lines[:_MAX_SPLIT_LINES] + [f"... (truncated to {_MAX_SPLIT_LINES} lines)"]
        return lines
    except subprocess.TimeoutExpired:
        return ["[!] searchsploit timed out."]
    except FileNotFoundError:
        return ["[!] searchsploit not found. Install ExploitDB (apt install exploitdb)."]

# =========================
# Generic-keyword pre-warning/refine
# =========================
def preflight_refine_keyword(keyword: str, threshold: int, interactive: bool, c: C) -> tuple[str, list[str] | None]:
    lines = run_searchsploit(keyword)
    count = len(lines)
    if interactive and count >= threshold:
        print_warn(f"The keyword '{keyword}' looks broad ({count} lines).", c)
        print("    Press Enter to continue, or type a more specific variant (e.g., 'Apache 2.4', 'mysql 5.7').")
        new_kw = input("> ").strip()
        if new_kw:
            new_kw = _sanitize_keyword(new_kw)
            if new_kw:
                return new_kw, None
    return keyword, lines

# =========================
# Defaults (inline) + SecLists file discovery (with aliases)
# =========================
DEFAULT_INLINE_CREDS = {
    "raspap": [("admin", "secret", "Inline default (RaspAP)"),
               ("admin", "admin", "Inline default (RaspAP)")],
    "tomcat": [("tomcat", "tomcat", "Inline default (Tomcat manager)"),
               ("admin", "admin", "Inline default")],
    "mysql":  [("root", "", "Inline default (no password, older installs)")],
    "postgres": [("postgres", "postgres", "Inline default")],
}

SERVICE_ALIASES = {
    "apache tomcat": "tomcat",
    "mariadb": "mysql",
    "mysql server": "mysql",
    "postgresql": "postgres",
    "rasp ap": "raspap",
    "raspap": "raspap",
    "tomcat": "tomcat",
}

def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().lower())

def _canonical_hits_for_keyword(keyword: str) -> set[str]:
    k = _norm(keyword)
    hits = set()
    for alias, canon in SERVICE_ALIASES.items():
        if re.search(r"\b" + re.escape(alias) + r"\b", k):
            hits.add(canon)
    for canon in DEFAULT_INLINE_CREDS.keys():
        if re.search(r"\b" + re.escape(canon) + r"\b", k):
            hits.add(canon)
    if not hits:
        token = re.split(r"[^a-z0-9]+", k)[0] if k else ""
        if token in DEFAULT_INLINE_CREDS:
            hits.add(token)
    return hits

_MAX_FILES_PER_DIR = 20000

def get_inline_default_creds(keyword: str) -> list[tuple[str, str, str]]:
    hits = _canonical_hits_for_keyword(keyword)
    out: list[tuple[str, str, str]] = []
    seen = set()
    for h in hits:
        for tup in DEFAULT_INLINE_CREDS.get(h, []):
            if tup not in seen:
                seen.add(tup)
                out.append(tup)
    return out

def find_seclists_files_for_keyword(keyword: str, creds_dirs: list[Path]) -> list[str]:
    hits = {h.lower() for h in _canonical_hits_for_keyword(keyword)}
    if not hits or not creds_dirs:
        return []
    matches: list[str] = []
    for base in creds_dirs:
        if not base.exists() or not base.is_dir():
            continue
        count = 0
        for p in base.rglob("*"):
            if p.is_file():
                count += 1
                name = p.name.lower()
                if any(h in name for h in hits):
                    matches.append(str(p))
                if count >= _MAX_FILES_PER_DIR:
                    break
    # de-dup
    return list(dict.fromkeys(matches))

# =========================
# Creds dirs resolution
# =========================
DEFAULT_SEC_PATH = Path("/usr/share/seclists/Passwords/Default-Credentials")
DEFAULT_CHEATSHEET_PATH = Path("/opt/DefaultCreds-cheat-sheet")

def resolve_creds_dirs(args, c: C) -> list[Path]:
    chosen: list[Path] = []
    if args.creds_dirs:
        for p in args.creds_dirs:
            pp = Path(p)
            if pp.exists():
                chosen.append(pp)
            else:
                print_warn(f"Creds path not found: {pp}", c)
        if chosen:
            return chosen
        print_warn("No valid directories from --creds-dirs. Trying defaults...", c)

    for pp in (DEFAULT_SEC_PATH, DEFAULT_CHEATSHEET_PATH):
        if pp.exists():
            chosen.append(pp)
    if chosen:
        print_ok(f"Using autodetected creds dirs: {', '.join(str(p) for p in chosen)}", c)
        return chosen

    print_warn(f"Default creds dirs not found at:\n    - {DEFAULT_SEC_PATH}\n    - {DEFAULT_CHEATSHEET_PATH}", c)
    if args.no_creds_prompt or not sys.stdin.isatty():
        print_warn("Continuing without creds directories (inline defaults only).", c)
        return []

    while True:
        print("\n[?] Enter one or more directories for default creds (comma-separated), or press Enter to skip.")
        user_in = input("> ").strip()
        if not user_in:
            print_warn("Skipping local lists. Inline defaults only.", c)
            return []
        parts = [Path(p.strip()) for p in user_in.split(",") if p.strip()]
        valid = [p for p in parts if p.exists()]
        invalid = [p for p in parts if not p.exists()]
        if invalid:
            for p in invalid:
                print_bad(f"Path not found: {p}", c)
            continue
        print_ok(f"Using creds dirs: {', '.join(str(p) for p in valid)}", c)
        return valid

# =========================
# Web search (DuckDuckGo) with clean links, retries, pacing
# =========================
def _ddg_clean_url(url: str) -> str:
    if url.startswith("//duckduckgo.com/l/?"):
        parsed = urlparse("https:" + url)
        qs = parse_qs(parsed.query)
        if "uddg" in qs:
            return unquote(qs["uddg"][0])
    return url

def _polite_sleep(base: float, jitter: float) -> None:
    lo = max(0.0, base - jitter)
    hi = base + jitter
    time.sleep(random.uniform(lo, hi))

def web_search_duckduckgo(query: str, num: int = 3, timeout: int = 12, retries: int = 3,
                          sleep_base: float = 0.6, sleep_jitter: float = 0.4) -> list[tuple[str, str]]:
    headers = {"User-Agent": "Mozilla/5.0"}
    params = {"q": query}
    url = "https://duckduckgo.com/html/?" + urlencode(params)

    last_err = None
    for _ in range(max(1, retries)):
        try:
            r = requests.get(url, headers=headers, timeout=timeout)
            r.raise_for_status()
            html = r.text

            results = []
            for m in re.finditer(
                r'<a[^>]*class="[^"]*result__a[^"]*"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
                html, re.IGNORECASE | re.DOTALL
            ):
                link = _ddg_clean_url(m.group(1))
                raw_title = m.group(2)
                title = re.sub("<[^>]+>", "", raw_title)
                title = re.sub(r"\s+", " ", title).strip()
                if title and link:
                    results.append((title, link))
                if len(results) >= num:
                    break

            if results:
                return results

            # Light fallback selector (optional – not strictly needed now)
            _polite_sleep(sleep_base, sleep_jitter)
            continue

        except Exception as e:
            last_err = e
            _polite_sleep(sleep_base, sleep_jitter)
            continue

    if last_err is not None:
        return [(f"Web search error (DuckDuckGo): {type(last_err).__name__}", str(last_err) or "")]
    else:
        return [("No results (DuckDuckGo)", "")]

def run_web_searches_for_keyword(keyword: str, timeout: int, retries: int, sleep_base: float, sleep_jitter: float) -> dict[str, list[tuple[str, str]]]:
    queries = {
        "exploits": f"{keyword} exploits",
        "default_creds": f"{keyword} default credentials",
        "github": f"{keyword} exploit github",
    }
    out: dict[str, list[tuple[str, str]]] = {}
    for bucket, q in queries.items():
        out[bucket] = web_search_duckduckgo(q, num=3, timeout=timeout, retries=retries,
                                            sleep_base=sleep_base, sleep_jitter=sleep_jitter)
        _polite_sleep(sleep_base, sleep_jitter)
    return out

# =========================
# HTTP helpers (Basic Auth brute templates + Form parsing)
# =========================
def build_basic_auth_ffuf_cmd(root_url: str, users_path: str = "users.txt",
                              passwords_path: str = "passwords.txt",
                              combos_b64_path: str = "basic_auth_combos.b64",
                              hide_codes: str = "401"):
    parsed = urlparse(root_url)
    scheme_host_port = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path if parsed.path else "/"
    gen = (
        f'while read u; do while read p; do echo -n "$u:$p" | base64; done < {passwords_path}; '
        f'done < {users_path} > {combos_b64_path}'
    )
    ff = (
        "ffuf -w {b64} -u {base}{path} "
        '-H "Authorization: Basic FUZZ" '
        "-fc {hide}".format(b64=combos_b64_path, base=scheme_host_port, path=path, hide=hide_codes)
    )
    return gen, ff

def build_basic_auth_wfuzz_cmd(root_url: str, combos_b64_path: str = "basic_auth_combos.b64",
                               hide_codes: str = "401"):
    parsed = urlparse(root_url)
    url = root_url if parsed.path else (root_url + "/")
    wf = (
        'wfuzz -c -z file,{b64} -H "Authorization: Basic FUZZ" '
        '--hc {hide} "{url}"'.format(b64=combos_b64_path, hide=hide_codes, url=url)
    )
    return wf

def _guess_username_field(inputs: list[tuple[str, str]]) -> str | None:
    candidates = []
    for name, typ in inputs:
        namel = (name or "").lower()
        typl = (typ or "").lower()
        if "user" in namel or "login" in namel or "email" in namel:
            candidates.append(name)
        elif typl in ("text", "email"):
            candidates.append(name)
    return candidates[0] if candidates else (inputs[0][0] if inputs else None)

def _build_hydra_template_for_form(page_url: str, action: str, method: str,
                                   inputs: list[tuple[str, str, str]]) -> tuple[str, str]:
    abs_path = urljoin(page_url, action) if action else page_url
    parsed = urlparse(abs_path)
    scheme_host_port = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path if parsed.path else "/"

    # Split inputs
    user_field = None
    pass_field = None
    hidden_pairs = []
    text_inputs = []
    for name, typ, val in inputs:
        t = (typ or "").lower()
        n = name or ""
        if t == "password" and not pass_field:
            pass_field = n
        elif t in ("text", "email", ""):
            text_inputs.append((n, t))
        elif t == "hidden" and name:
            hidden_pairs.append((name, val))
        elif n and ("user" in n.lower() or "login" in n.lower()):
            text_inputs.append((n, t))

    if not pass_field:
        pass_field = "password"
    if not user_field:
        user_field = _guess_username_field(text_inputs) or "username"

    # Build POST body with placeholders
    kv = []
    kv.append(f"{user_field}=^USER^")
    kv.append(f"{pass_field}=^PASS^")
    for k, v in hidden_pairs:
        kv.append(f"{k}={v}")
    post_body = "&".join(kv)

    hydra_fmt = f'{path}:{post_body}:F=invalid'
    hydra_cmd = f'hydra -L users.txt -P passwords.txt {parsed.netloc} http-post-form "{hydra_fmt}"'

    curl_body = post_body.replace("^USER^", "test").replace("^PASS^", "test")
    curl_cmd = (
        f'curl -i -s -k -X POST "{scheme_host_port}{path}" '
        f'-H "Content-Type: application/x-www-form-urlencoded" '
        f'-d "{curl_body}"'
    )

    return hydra_cmd, curl_cmd

def parse_post_forms(page_url: str, html: str) -> list[dict]:
    out = []
    if not HAVE_BS4:
        return out
    soup = BeautifulSoup(html, "html.parser")
    for form in soup.find_all("form"):
        method = (form.get("method") or "").lower()
        if method != "post":
            continue
        action = form.get("action") or ""
        inputs = []
        for inp in form.find_all("input"):
            name = inp.get("name") or ""
            typ = (inp.get("type") or "").lower()
            val = inp.get("value") or ""
            inputs.append((name, typ, val))
        hydra_cmd, curl_cmd = _build_hydra_template_for_form(page_url, action, method, inputs)
        out.append({
            "action": action,
            "method": method,
            "inputs": inputs,
            "hydra_cmd": hydra_cmd,
            "curl_cmd": curl_cmd
        })
    return out

# =========================
# HTTP scraper (headers + title + version hints + Basic Auth + form parsing)
# =========================
HTTP_VERSION_PATTERNS = [
    r'\bversion\s*[:=]\s*([0-9]+(?:\.[0-9]+){1,3})\b',
    r'\bv\s*[:=]?\s*([0-9]+(?:\.[0-9]+){1,3})\b',
    r'\b([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)\b',
]

COMMON_EXTRA_PATHS = ["/", "/login", "/admin", "/robots.txt", "/sitemap.xml"]

def parse_http_targets_from_nmap(nmap_file: Path, target_host: str) -> list[dict]:
    text = nmap_file.read_text(encoding="utf-8", errors="ignore")
    targets = []
    http_line_re = re.compile(r'^\s*(\d+)/tcp\s+open\s+([^\s]+)', re.IGNORECASE | re.MULTILINE)
    for m in http_line_re.finditer(text):
        port = int(m.group(1))
        service = m.group(2).lower()
        if "http" not in service and "https" not in service:
            continue
        scheme = "https" if ("ssl/http" in service or "https" in service) else "http"
        url = f"{scheme}://{target_host}:{port}/"
        targets.append({"port": port, "scheme": scheme, "url": url, "service": service})
    seen = set()
    uniq = []
    for t in targets:
        key = (t["port"], t["scheme"])
        if key not in seen:
            seen.add(key)
            uniq.append(t)
    return uniq

def _find_versions(s: str) -> list[str]:
    hits = []
    for pat in HTTP_VERSION_PATTERNS:
        for m in re.finditer(pat, s, flags=re.IGNORECASE):
            ver = m.group(1)
            if ver and ver not in hits:
                hits.append(ver)
    return hits

def scrape_http_target(url: str, timeout: int = 8) -> dict:
    info = {"status": None, "title": None, "headers": {}, "version_hits": [],
            "generator": None, "error": None, "auth_scheme": None, "auth_realm": None,
            "forms": [], "extra_paths": []}
    try:
        r = requests.get(url, timeout=timeout, verify=False, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
        info["status"] = r.status_code
        interesting = {}
        for h in ("Server", "X-Powered-By", "WWW-Authenticate", "Set-Cookie"):
            if h in r.headers:
                interesting[h] = r.headers.get(h)
        info["headers"] = interesting

        # Auth scheme / realm (e.g., 'Basic realm="RaspAP"')
        wa = interesting.get("WWW-Authenticate", "") or ""
        m_basic = re.search(r'(?i)\bBasic\b(?:\s+realm="?([^"]*)"?|)', wa)
        if m_basic:
            info["auth_scheme"] = "Basic"
            if m_basic.group(1):
                info["auth_realm"] = m_basic.group(1).strip()

        body = r.text or ""
        mt = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
        if mt:
            title = re.sub("<[^>]+>", "", mt.group(1)).strip()
            info["title"] = re.sub(r"\s+", " ", title)
        mg = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', body, re.IGNORECASE)
        if mg:
            info["generator"] = mg.group(1).strip()

        haystack = body + " " + " ".join(f"{k}:{v}" for k, v in interesting.items())
        info["version_hits"] = _find_versions(haystack)

        # Form parsing (POST) for Hydra templates
        if HAVE_BS4:
            forms = parse_post_forms(url, body)
            info["forms"] = forms

        # Probe a few extra paths quickly
        extras = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for p in COMMON_EXTRA_PATHS:
            try:
                rr = requests.get(base + p, timeout=timeout, verify=False, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
                ttl = None
                mtt = re.search(r'<title[^>]*>(.*?)</title>', rr.text or "", re.IGNORECASE | re.DOTALL)
                if mtt:
                    ttl = re.sub("<[^>]+>", "", mtt.group(1)).strip()
                    ttl = re.sub(r"\s+", " ", ttl)
                extras.append({"path": p, "status": rr.status_code, "title": ttl})
            except Exception:
                extras.append({"path": p, "status": None, "title": None})
        info["extra_paths"] = extras

        return info
    except Exception as e:
        info["error"] = f"{type(e).__name__}: {e}"
        return info

# =========================
# CeWL runner (optional)
# =========================
def have_cewl() -> bool:
    try:
        subprocess.run(["cewl", "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        return True
    except Exception:
        return False

def run_cewl(url: str, out_dir: Path, depth: int, minlen: int) -> tuple[Path | None, str]:
    parsed = urlparse(url)
    host = parsed.netloc.replace(":", "_") or "site"
    word_dir = out_dir / "wordlists"
    word_dir.mkdir(parents=True, exist_ok=True)
    out_path = word_dir / f"{host}.txt"
    cewl_cmd = f'cewl -d {depth} -m {minlen} -e -w "{out_path}" "{parsed.scheme}://{parsed.netloc}/"'
    try:
        subprocess.run(["cewl", "-d", str(depth), "-m", str(minlen), "-e",
                        "-w", str(out_path), f"{parsed.scheme}://{parsed.netloc}/"],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=300)
        return out_path, cewl_cmd
    except Exception:
        return None, cewl_cmd

def lowercase_unique_wordlist(in_path: Path, out_path: Path) -> None:
    try:
        with in_path.open("r", encoding="utf-8", errors="ignore") as f:
            words = [w.strip().lower() for w in f if w.strip()]
        uniq = sorted(set(words))
        with out_path.open("w", encoding="utf-8") as f:
            for w in uniq:
                f.write(w + "\n")
    except Exception:
        pass

# =========================
# Report writer
# =========================
def write_report(target, nmap_file: Path, findings, inline_creds_map, seclist_files_map,
                 creds_dirs, out_dir, web_map=None, http_map=None,
                 nmap_cmd_used: str | None = None, search_cmd_map: dict[str, str] | None = None,
                 cewl_entries: list[dict] | None = None) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = out_dir / f"report_{target}_{stamp}.md"
    with report_path.open("w", encoding="utf-8") as f:
        f.write(f"# Enumerator Report\n\n")
        f.write(f"- **Target:** `{target}`\n")
        f.write(f"- **Nmap output:** `{nmap_file}`\n")
        f.write(f"- **Generated:** {datetime.now().isoformat(timespec='seconds')}\n")
        f.write(f"- **Run directory:** `{out_dir}`\n")
        if creds_dirs:
            f.write(f"- **Creds dirs used:** {', '.join(str(p) for p in creds_dirs)}\n")
        else:
            f.write(f"- **Creds dirs used:** _None (inline defaults only)_\n")
        f.write("\n---\n\n")

        # Commands used / templates
        f.write("## Commands\n\n")
        if nmap_cmd_used:
            f.write("**Nmap**\n\n")
            f.write("```bash\n" + nmap_cmd_used + "\n```\n\n")
        if search_cmd_map:
            f.write("**searchsploit**\n\n")
            for kw, cmd in search_cmd_map.items():
                f.write(f"- `{kw}`\n\n```bash\n{cmd}\n```\n\n")
        if cewl_entries:
            f.write("**CeWL (site-specific wordlists)**\n\n")
            for entry in cewl_entries:
                f.write(f"- `{entry['url']}` → `{entry['out_base']}`\n\n")
                f.write("```bash\n" + entry["cewl_cmd"] + "\n```\n\n")
                f.write("_Lowercase + unique (awk):_\n\n")
                f.write(f"```bash\nawk '{{print tolower($0)}}' {entry['out_base']} | sort -u > {entry['out_lc']}\n```\n\n")
                f.write("_Or using tr:_\n\n")
                f.write(f"```bash\ntr '[:upper:]' '[:lower:]' < {entry['out_base']} | sort -u > {entry['out_lc']}\n```\n\n")
        f.write("---\n\n")

        # HTTP summary (including Basic Auth & forms)
        if http_map:
            f.write("## HTTP scrape summary\n\n")
            for entry in http_map:
                f.write(f"### {entry['url']}\n\n")
                if entry.get("error"):
                    f.write(f"- Error: {entry['error']}\n\n")
                    continue
                f.write(f"- Status: {entry.get('status')}\n")
                if entry.get("title"):
                    f.write(f"- Title: {entry['title']}\n")
                if entry.get("generator"):
                    f.write(f"- Generator: {entry['generator']}\n")
                if entry.get("headers"):
                    f.write("- Headers:\n")
                    for k, v in entry["headers"].items():
                        f.write(f"  - {k}: {v}\n")
                if entry.get("version_hits"):
                    f.write(f"- Version hints: {', '.join(entry['version_hits'])}\n")

                # Extra paths snapshot
                if entry.get("extra_paths"):
                    f.write("- Quick path checks:\n")
                    for ex in entry["extra_paths"]:
                        st = ex["status"]
                        ttl = f' | title: {ex["title"]}' if ex.get("title") else ""
                        f.write(f"  - {ex['path']}: {st}{ttl}\n")

                # Basic Auth templates
                if entry.get("auth_scheme") == "Basic":
                    realm = entry.get("auth_realm")
                    if realm:
                        f.write(f"- Auth: Basic (realm: `{realm}`)\n")
                    else:
                        f.write(f"- Auth: Basic\n")
                    gen, ff = build_basic_auth_ffuf_cmd(entry["url"])
                    wf = build_basic_auth_wfuzz_cmd(entry["url"])
                    f.write("\n**Sample brute-force commands (Basic Auth)**\n\n")
                    f.write("_Generate base64(user:pass) combos (from users.txt and passwords.txt):_\n\n")
                    f.write("```bash\n" + gen + "\n```\n\n")
                    f.write("_ffuf with Authorization header fuzzing (hide 401 responses):_\n\n")
                    f.write("```bash\n" + ff + "\n```\n\n")
                    f.write("_wfuzz with Authorization header fuzzing (hide 401 responses):_\n\n")
                    f.write("```bash\n" + wf + "\n```\n\n")

                # POST forms → Hydra + curl
                if entry.get("forms"):
                    f.write("**Detected POST forms**\n\n")
                    for i, frm in enumerate(entry["forms"], 1):
                        f.write(f"- Form {i}: action `{frm['action']}`\n")
                        f.write("  - Inputs:\n")
                        for (name, typ, val) in frm["inputs"]:
                            showv = val if val and len(val) <= 40 else (val[:40]+"..." if val else "")
                            f.write(f"    - {name} (type={typ})" + (f" value={showv}" if showv else "") + "\n")
                        f.write("\n_Hydra template (edit failure indicator `F=` to match site response):_\n\n")
                        f.write("```bash\n" + frm["hydra_cmd"] + "\n```\n\n")
                        f.write("_curl test (discover failure/success strings):_\n\n")
                        f.write("```bash\n" + frm["curl_cmd"] + "\n```\n\n")

                f.write("\n")

        # Per-keyword sections
        for kw in findings.keys():
            f.write(f"## {kw}\n\n")
            lines = findings[kw]
            if lines:
                f.write("### searchsploit\n```\n")
                for ln in lines:
                    f.write(ln + "\n")
                f.write("```\n\n")
            else:
                f.write("_No searchsploit results._\n\n")

            inline_creds = inline_creds_map.get(kw, [])
            if inline_creds:
                f.write("### Possible default credentials (inline)\n")
                for u, p, note in inline_creds:
                    f.write(f"- `{u}:{p}` — {note}\n")
                f.write("\n")

            files_to_review = seclist_files_map.get(kw, [])
            if files_to_review:
                f.write("### Default-credential files to review\n")
                for path in files_to_review:
                    f.write(f"- `{path}`\n")
                f.write("\n")

            if web_map and web_map.get(kw):
                f.write("### Web search\n")
                for key, title in [("exploits","Exploits"),("default_creds","Default credentials"),("github","Exploit GitHub")]:
                    rows = web_map[kw].get(key, [])
                    f.write(f"**{title}**\n\n")
                    if not rows:
                        f.write("- _No results_\n\n")
                    else:
                        for row_title, row_url in rows:
                            if row_title.startswith("Web search error"):
                                f.write(f"- {row_title}\n")
                                if row_url: f.write(f"  - {row_url}\n")
                                continue
                            if row_title and row_url:
                                f.write(f"- [{row_title}]({row_url})\n")
                            elif row_title:
                                f.write(f"- {row_title}\n")
                            elif row_url:
                                f.write(f"- {row_url}\n")
                        f.write("\n")
    return report_path

# =========================
# Main
# =========================
def main():
    examples = r"""
Examples:
  # Quick scan + research (defaults); enter keywords when prompted
  python3 enumerator.py 10.10.10.5

  # Custom nmap (no ping, all ports), then research
  python3 enumerator.py 192.168.56.101 \
    --nmap "sudo nmap -sC -sV -Pn -p- {target} -vv --open"

  # Provide SecLists Default-Credentials path to list relevant files
  python3 enumerator.py app.lab.local \
    --creds-dirs /usr/share/seclists/Passwords/Default-Credentials

  # Be gentle with web searches (reduce throttling)
  python3 enumerator.py 10.10.10.5 \
    --web-retries 5 --web-sleep 1.2 --web-jitter 0.8

  # Skip web or HTTP scrape if offline or not needed
  python3 enumerator.py 10.10.10.5 --no-web
  python3 enumerator.py 10.10.10.5 --no-http-scrape

  # Run CeWL to build a site-specific wordlist (then auto-make lowercase+unique)
  python3 enumerator.py 10.10.10.5 --cewl --cewl-depth 2 --cewl-minlen 5
"""
    parser = argparse.ArgumentParser(
        description=(
            "Run Nmap, then help you research footholds from its results.\n"
            "- Saves everything into a per-run intel folder.\n"
            "- For each keyword you enter (e.g., service names/versions), it:\n"
            "  * runs searchsploit,\n"
            "  * shows inline default creds,\n"
            "  * lists SecLists Default-Credentials filenames matching your keyword,\n"
            "  * performs web searches (exploits, default creds, GitHub PoCs),\n"
            "  * optionally scrapes HTTP(S) services (title/headers/version),\n"
            "  * detects Basic Auth -> ffuf/wfuzz templates,\n"
            "  * detects POST forms -> Hydra + curl templates,\n"
            "  * optionally runs CeWL to build wordlists."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=examples
    )

    parser.add_argument("target",
                        help="Target to scan (IPv4 or hostname), e.g., 10.10.10.5 or app.internal.lab")

    parser.add_argument("--nmap",
                        default="sudo nmap -sV -sC -T4 -p- {target} -vv --open",
                        help=(
                            "Nmap command template. Must include {target}. "
			    "The full command including the quotes is: python3 enumerator.py 127.0.0.1 'nmap -sV {target}'"
                            "Safety: validated and executed without a shell.\n"
                            "Default: 'sudo nmap -sV -sC -T4 -p- {target} -vv --open'"
                        ))

    parser.add_argument("--out-base", default="intel",
                        help="Base directory for per-run intel folders (default: intel)")

    parser.add_argument("--creds-dirs", nargs="*",
                        help=("One or more directories with default-credential lists "
                              "(e.g., SecLists/Passwords/Default-Credentials). "
                              "We list filenames that contain your keyword."))

    parser.add_argument("--no-creds-prompt", action="store_true",
                        help="If default creds dirs are missing, do NOT prompt for a path (inline defaults only).")

    # Web search controls
    parser.add_argument("--no-web", action="store_true",
                        help="Disable DuckDuckGo web searches (useful offline or with strict proxies).")
    parser.add_argument("--web-timeout", type=int, default=12,
                        help="HTTP timeout per web request (seconds). Default: 12")
    parser.add_argument("--web-retries", type=int, default=3,
                        help="Retry attempts per query bucket (exploits/default creds/GitHub). Default: 3")
    parser.add_argument("--web-sleep", type=float, default=0.6,
                        help="Base delay between web requests (seconds). Default: 0.6")
    parser.add_argument("--web-jitter", type=float, default=0.4,
                        help="Random jitter added/subtracted from --web-sleep. Default: 0.4")

    # HTTP scraper controls
    parser.add_argument("--no-http-scrape", action="store_true",
                        help=("Skip scraping discovered HTTP/HTTPS services. "
                              "By default we GET /, capture status/title/meta-generator/headers, "
                              "and grep for version-like strings. Also tries /login, /admin, /robots.txt, /sitemap.xml"))
    parser.add_argument("--http-timeout", type=int, default=8,
                        help="Timeout per HTTP target (seconds). Default: 8")

    # Keyword guidance
    parser.add_argument("--prewarn-threshold", type=int, default=10,
                        help=("Warn/refine if initial searchsploit lines >= this (e.g., 'Apache' might be noisy). "
                              "Press Enter to keep, or type a refined keyword. Default: 10"))
    parser.add_argument("--no-refine-prompt", action="store_true",
                        help="Do not prompt to refine generic keywords even if they look noisy.")

    # CeWL (optional)
    parser.add_argument("--cewl", action="store_true",
                        help="Run CeWL against each HTTP root URL to build a site-specific wordlist.")
    parser.add_argument("--cewl-depth", type=int, default=2,
                        help="CeWL crawl depth (default: 2)")
    parser.add_argument("--cewl-minlen", type=int, default=5,
                        help="CeWL minimum word length (default: 5)")

    # Display
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI colors (useful on minimal terminals).")

    args = parser.parse_args()
    c = C(enabled=_supports_color() and not args.no_color)
    print_banner(c)

    # Validate target (warn; proceed)
    if not _looks_like_target(args.target):
        print_warn(f"Target '{args.target}' looks unusual (not IPv4/hostname). Proceeding anyway.", c)

    # Create per-run intel directory
    run_dir = make_run_directory(args.out_base)
    print_ok(f"Run directory: {run_dir}", c)

    # Nmap
    nmap_file, nmap_cmd_used = run_nmap(args.target, args.nmap, run_dir, c)

    # Creds dirs
    creds_dirs = resolve_creds_dirs(args, c)

    # Optional HTTP scrape
    http_findings = []
    cewl_entries: list[dict] = []
    if not args.no_http_scrape:
        http_targets = parse_http_targets_from_nmap(nmap_file, args.target)
        if http_targets:
            print_title("HTTP targets from Nmap", c)
            for t in http_targets:
                print(f"   - {t['url']} ({t['service']})")
            print_title("Scraping HTTP targets", c)
            for t in http_targets:
                info = scrape_http_target(t["url"], timeout=args.http_timeout)
                entry = {"url": t["url"], **info}
                http_findings.append(entry)
                if info.get("error"):
                    print_bad(f"{t['url']} -> ERROR: {info['error']}", c)
                    continue
                line = f"{t['url']} -> {info.get('status')}"
                if info.get("title"):
                    line += f" | title: {info['title']}"
                if info.get("generator"):
                    line += f" | generator: {info['generator']}"
                if info.get("version_hits"):
                    line += f" | versions: {', '.join(info['version_hits'])}"
                print("   - " + line)

                if info.get("auth_scheme") == "Basic":
                    realm = info.get("auth_realm")
                    realm_note = f' (realm="{realm}")' if realm else ""
                    print_ok(f"Detected HTTP Basic Auth{realm_note}: ffuf/wfuzz templates will be in the report.", c)
                    print("   - Prepare users.txt and passwords.txt (see report).")

                if info.get("forms"):
                    print_ok(f"Detected {len(info['forms'])} POST form(s) on {t['url']}: Hydra/curl templates in report.", c)
                    if not HAVE_BS4:
                        print_warn("bs4 not installed; form parsing limited. Install with: sudo apt install python3-bs4", c)

                # Optional CeWL
                if args.cewl:
                    if have_cewl():
                        wl, cewl_cmd = run_cewl(t["url"], run_dir, args.cewl_depth, args.cewl_minlen)
                        if wl and wl.exists():
                            out_lc = wl.with_name(wl.stem + "_lc.txt")
                            lowercase_unique_wordlist(wl, out_lc)
                            cewl_entries.append({
                                "url": t["url"],
                                "out_base": str(wl),
                                "out_lc": str(out_lc),
                                "cewl_cmd": cewl_cmd
                            })
                            print_ok(f"CeWL wordlist written: {wl.name} (lowercased+unique: {out_lc.name})", c)
                        else:
                            print_warn("CeWL run did not produce a wordlist (see report for command).", c)
                            cewl_entries.append({
                                "url": t["url"],
                                "out_base": "(no file produced)",
                                "out_lc": "(run shell one-liners after you have a file)",
                                "cewl_cmd": cewl_cmd
                            })
                    else:
                        print_warn("CeWL not found. Install it (e.g., apt install cewl) or rerun without --cewl.", c)
        else:
            print_warn("No HTTP/HTTPS services detected in Nmap output.", c)
    else:
        print_warn("HTTP scraping disabled (--no-http-scrape).", c)

    # Keywords
    keywords = get_keywords(c)
    search_cmd_map: dict[str, str] = {}
    if not keywords:
        print_warn("No keywords provided. Writing report with current data only.", c)
        report = write_report(args.target, nmap_file, {}, {}, {}, run_dir,
                              web_map={}, http_map=http_findings,
                              nmap_cmd_used=nmap_cmd_used, search_cmd_map=search_cmd_map,
                              cewl_entries=cewl_entries)
        print_ok(f"Report saved to: {report}", c)
        print_ok(f"All artifacts for this run live in: {run_dir}", c)
        sys.exit(0)

    # Per-keyword work
    findings, inline_creds_map, seclist_files_map, web_map = {}, {}, {}, {}

    for kw in keywords:
        print()
        print_title(kw, c)

        interactive = sys.stdin.isatty() and (not args.no_refine_prompt)
        final_kw, pre_lines = preflight_refine_keyword(kw, args.prewarn_threshold, interactive, c)
        if final_kw != kw:
            print_ok(f"Using refined keyword: {final_kw}", c)

        # searchsploit (reuse preflight lines if not refined)
        if pre_lines is not None and final_kw == kw:
            exploits = pre_lines
        else:
            exploits = run_searchsploit(final_kw)
        findings[final_kw] = exploits
        search_cmd_map[final_kw] = f'searchsploit "{final_kw}"'

        # >>> NEW: Always print something to console <<<
        if exploits:
            print_ok("searchsploit results:", c)
            for ln in exploits:
                print("   " + ln)
        else:
            print_warn("No searchsploit results", c)
        # ----------------------------------------------

        # inline defaults
        inline_hits = get_inline_default_creds(final_kw)
        inline_creds_map[final_kw] = inline_hits
        if inline_hits:
            print_ok("Default creds (inline candidates):", c)
            for u, p, note in inline_hits:
                print(f"   {u}:{p} - {note}")
        else:
            print_warn("No inline defaults for this keyword", c)

        # SecLists files to review
        files_to_review = find_seclists_files_for_keyword(final_kw, creds_dirs)
        seclist_files_map[final_kw] = files_to_review
        if files_to_review:
            print_ok("Files to review (default credentials lists):", c)
            for path in files_to_review[:8]:
                print(f"   {path}")
            if len(files_to_review) > 8:
                print(f"   ... {len(files_to_review)-8} more")
        else:
            print_warn("No matching SecLists filenames found (or no creds dirs configured)", c)

        # web search (DuckDuckGo)
        if args.no_web:
            web_res = {}
        else:
            web_res = run_web_searches_for_keyword(
                final_kw, timeout=args.web_timeout, retries=args.web_retries,
                sleep_base=args.web_sleep, sleep_jitter=args.web_jitter
            )
        web_map[final_kw] = web_res

        # Console print for web buckets
        def _print_web_bucket(bucket, rows):
            labels = {"exploits": "Web search: exploits",
                      "default_creds": "Web search: default credentials",
                      "github": "Web search: exploit github"}
            print_ok(labels[bucket], c)
            if not rows:
                print("   (no results)")
                return
            for title, url in rows:
                if title.startswith("Web search error"):
                    print(f"   - {title}" + (f" -> {url}" if url else ""))
                    print("   (Tip: check network/HTTP proxy, or run with --no-web.)")
                    continue
                show = title or "(no title)"
                print(f"   - {show}" + (f" -> {url}" if url else ""))

        for bucket in ("exploits", "default_creds", "github"):
            _print_web_bucket(bucket, web_res.get(bucket, []))

    # Report into this run's folder
    report = write_report(args.target, nmap_file, findings, inline_creds_map, seclist_files_map,
                          creds_dirs, run_dir, web_map=web_map, http_map=http_findings,
                          nmap_cmd_used=nmap_cmd_used, search_cmd_map=search_cmd_map,
                          cewl_entries=cewl_entries)
    print()
    print_ok(f"Report saved to: {report}", c)
    print_ok(f"All artifacts for this run live in: {run_dir}", c)


if __name__ == "__main__":
    main()
