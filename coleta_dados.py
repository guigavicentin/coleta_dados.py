```python
#!/usr/bin/env python3
import subprocess
import re
import requests
from pathlib import Path

# ================= CONFIG =================

domain = input("Dominio: ").strip()

BASE_DIR = Path(f"coleta_{domain}")
BASE_DIR.mkdir(exist_ok=True)

JS_DIR = BASE_DIR / "js"
JS_DIR.mkdir(exist_ok=True)

URLS_FILE = BASE_DIR / "urls.txt"
RESULT_FILE = BASE_DIR / "js_sensiveis.txt"

# regex sensível
SENSITIVE_PATTERNS = {
    "api_key": r'api[_-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-]{8,}',
    "token": r'token["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-\.]{8,}',
    "jwt": r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
    "authorization": r'Authorization["\']?\s*[:=]\s*["\']Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*',
    "aws": r'AKIA[0-9A-Z]{16}',
    "google_api": r'AIza[0-9A-Za-z\-_]{35}',
    "secret": r'secret["\']?\s*[:=]\s*["\'][^"\']{8,}',
    "password": r'password["\']?\s*[:=]\s*["\'][^"\']{6,}'
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
    print("[+] coletando urls")

    gau = run_cmd(["gau", domain])

    wayback = subprocess.run(
        ["waybackurls"],
        input=domain,
        text=True,
        capture_output=True
    ).stdout.splitlines()

    katana = run_cmd([
        "katana",
        "-u", domain,
        "-d", "5",
        "-jc"
    ])

    urls = set(gau + wayback + katana)

    with open(URLS_FILE, "w") as f:
        for u in sorted(urls):
            f.write(u + "\n")

    print(f"[+] total urls: {len(urls)}")

    return urls

# ================= JS FILTER =================

def extract_js(urls):
    print("[+] filtrando js")

    js_urls = set()

    for url in urls:
        if ".js" in url.lower():
            js_urls.add(url.split("?")[0])

    print(f"[+] js encontrados: {len(js_urls)}")

    return js_urls

# ================= ANALYZE =================

def analyze_js(content, url):

    results = []

    with open(RESULT_FILE, "a", encoding="utf-8") as out:

        for name, regex in SENSITIVE_PATTERNS.items():
            for match in re.finditer(regex, content, re.IGNORECASE):

                value = match.group(0)

                print("\n[!!! SENSITIVE FOUND]")
                print("type :", name)
                print("url  :", url)
                print("match:", value[:200])

                out.write(
                    f"[{name}] {url}\n{value}\n"
                    + "-"*60 + "\n"
                )

                results.append((name, url, value))

    return results

# ================= VERIFY JS =================

def verify_and_download(js_urls):
    print("[+] verificando js acessiveis")

    findings = []

    for url in js_urls:
        try:
            r = requests.get(url, timeout=10)

            if r.status_code != 200:
                continue

            content_type = r.headers.get("Content-Type", "")

            if "javascript" not in content_type.lower() and not url.endswith(".js"):
                continue

            filename = JS_DIR / url.split("/")[-1]

            with open(filename, "w", encoding="utf-8", errors="ignore") as f:
                f.write(r.text)

            print(f"[JS] {url}")

            found = analyze_js(r.text, url)
            findings.extend(found)

        except:
            continue

    return findings

# ================= MAIN =================

def main():

    urls = collect_urls()

    js_urls = extract_js(urls)

    findings = verify_and_download(js_urls)

    print("\n===================================")
    print("TOTAL JS:", len(js_urls))
    print("SENSITIVE:", len(findings))
    print("SALVO EM:", RESULT_FILE)
    print("===================================")


if __name__ == "__main__":
    main()
```
