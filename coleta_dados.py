#!/usr/bin/env python3
import subprocess
import re
import requests
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

# ================= CONFIG =================

domain = input("Dominio: ").strip()

BASE_DIR = Path(f"coleta_{domain}")
BASE_DIR.mkdir(exist_ok=True)

URLS_FILE = BASE_DIR / "urls.txt"

GF_PATTERNS = ["xss", "sqli", "ssrf", "redirect", "ssti"]

SENSITIVE_REGEX = r"\.(php|html|xml|zip|gz|env|log|bak|sql|txt|conf|ini|yml|yaml|db|pem|key|crt|sh|py|jsp|asp|aspx)$"

JS_DIR = BASE_DIR / "js"
JS_DIR.mkdir(exist_ok=True)

JS_FILE = BASE_DIR / "js_urls.txt"
RESULT_FILE = BASE_DIR / "js_sensiveis.txt"

HEADERS = {
    "User-Agent": "Mozilla/5.0 recon"
}

SENSITIVE_PATTERNS = {
    "api_key": r'api[_-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}',
    "token": r'token["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-\.]{16,}',
    "jwt": r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
    "aws_key": r'AKIA[0-9A-Z]{16}',
    "secret": r'secret["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-\/+=]{16,}',
    "authorization": r'Bearer\s+[A-Za-z0-9_\-\.]{16,}',
    "password": r'password["\']?\s*[:=]\s*["\'][^"\']{6,}', # vai trazer muito lixo, mas é bom manter
    "senha": r'senha["\']?\s*[:=]\s*["\'][^"\']{6,}' # vai trazer muito lixo, mas é bom manter
}

# ================= UTIL =================

def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout.splitlines()
    except:
        return []

# ================= URL COLLECTION =================

def collect_urls():
    print("[+] gau")
    gau = run_cmd(["gau", domain])

    print("[+] waybackurls")
    wayback = subprocess.run(
        ["waybackurls"],
        input=domain,
        text=True,
        capture_output=True
    ).stdout.splitlines()

    print("[+] katana")
    katana = run_cmd([
        "katana",
        "-u", domain,
        "-d", "5",
        "-ps", "waybackarchive,commoncrawl,alienvault",
        "-kf",
        "-jc",
        "-ef", "woff,css,png,svg,jpg,woff2,jpeg,gif"
    ])

    urls = set(gau + wayback + katana)

    with open(URLS_FILE, "w") as f:
        for u in sorted(urls):
            f.write(u + "\n")

    print(f"[+] URLs coletadas: {len(urls)}")

# ================= GF =================

def run_gf():
    gf_dir = BASE_DIR / "gf"
    gf_dir.mkdir(exist_ok=True)

    for pattern in GF_PATTERNS:
        print(f"[+] GF {pattern}")

        output = gf_dir / f"gf_{pattern}.txt"

        with open(output, "w") as out:
            subprocess.run(
                f"cat {URLS_FILE} | gf {pattern}",
                shell=True,
                stdout=out
            )

# ================= SENSITIVE FILES =================

def extract_sensitive():
    print("[+] filtrando arquivos para analisar")

    output = BASE_DIR / "urls_analisar.txt"
    regex = re.compile(SENSITIVE_REGEX, re.IGNORECASE)

    with open(URLS_FILE) as f, open(output, "w") as out:
        for line in f:
            if regex.search(line):
                out.write(line)

# ================= JS COLLECTION =================

def collect_js():
    print("[+] coletando JS")

    js_urls = set()

    with open(URLS_FILE) as f:
        for line in f:
            if ".js" in line.lower():
                js_urls.add(line.strip())

    with open(JS_FILE, "w") as f:
        for u in js_urls:
            f.write(u + "\n")

    print(f"[+] JS encontrados: {len(js_urls)}")

# ================= JS ANALYSIS =================

def is_valid_js(resp, content):
    ct = resp.headers.get("Content-Type", "")
    if "javascript" in ct:
        return True
    if content.strip().startswith(("var ", "let ", "const ", "function", "!function", "(function")):
        return True
    return False

def analyze_js(content, url):
    with open(RESULT_FILE, "a", encoding="utf-8") as out:
        for name, regex in SENSITIVE_PATTERNS.items():
            for match in re.finditer(regex, content, re.IGNORECASE):
                value = match.group(0)

                print(f"[!!!] {name} -> {url}")

                out.write(
                    f"[{name}] {url}\n{value}\n"
                    + "-"*60 + "\n"
                )

def process_js(url):
    try:
        resp = requests.get(url, headers=HEADERS, timeout=10, verify=False)

        if resp.status_code != 200:
            return

        content = resp.text

        if not is_valid_js(resp, content):
            return

        analyze_js(content, url)

    except:
        pass

def analyze_all_js():
    print("[+] analisando JS")

    with open(JS_FILE) as f:
        urls = [x.strip() for x in f]

    with ThreadPoolExecutor(max_workers=20) as executor:
        executor.map(process_js, urls)

# ================= MAIN =================

def main():
    collect_urls()
    run_gf()
    extract_sensitive()
    collect_js()
    analyze_all_js()

    print("\n[✓] finalizado")

if __name__ == "__main__":
    main()
