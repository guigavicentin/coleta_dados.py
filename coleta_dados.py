#!/usr/bin/env python3
import subprocess
import re
from pathlib import Path

# ================= CONFIG =================

domain = input("Dominio: ").strip()

BASE_DIR = Path(f"coleta_{domain}")
BASE_DIR.mkdir(exist_ok=True)

URLS_FILE = BASE_DIR / "urls.txt"

GF_PATTERNS = ["xss", "sqli", "ssrf", "redirect", "ssti"]

SENSITIVE_REGEX = r"\.(php|html|xml|zip|gz|env|log|bak|sql|txt|conf|ini|yml|yaml|db|pem|key|crt|sh|py|jsp|asp|aspx)$"

NUCLEI_DIR = "/root/nuclei-templates/http/vulnerabilities/generic/"

# ================= UTIL =================

def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout.splitlines()
    except Exception as e:
        print(f"[!] erro: {e}")
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
        "-ef", "woff,css,png,svg,jpg,woff2,jpeg,gif,svg"
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

    gf_files = {}

    for pattern in GF_PATTERNS:
        print(f"[+] GF {pattern}")

        output = gf_dir / f"gf_{pattern}.txt"

        with open(output, "w") as out:
            subprocess.run(
                f"cat {URLS_FILE} | gf {pattern}",
                shell=True,
                stdout=out
            )

        gf_files[pattern] = output

    return gf_files

# ================= SENSITIVE FILES =================

def extract_sensitive():
    print("[+] filtrando sensíveis")

    output = BASE_DIR / "urls_sensiveis.txt"
    regex = re.compile(SENSITIVE_REGEX, re.IGNORECASE)

    with open(URLS_FILE) as f, open(output, "w") as out:
        for line in f:
            if regex.search(line):
                out.write(line)

# ================= NUCLEI =================

def run_nuclei(gf_files):
    nuclei_dir = BASE_DIR / "nuclei"
    nuclei_dir.mkdir(exist_ok=True)

    for pattern, file in gf_files.items():

        if pattern not in ["xss", "sqli", "redirect"]:
            continue

        print(f"[+] nuclei {pattern}")

        output = nuclei_dir / f"nuclei_{pattern}.txt"

        subprocess.run([
            "nuclei",
            "-l", str(file),
            "-t", NUCLEI_DIR,
            "-o", str(output),
            "-silent"
        ])

# ================= MAIN =================

def main():
    collect_urls()
    gf_files = run_gf()
    extract_sensitive()
    run_nuclei(gf_files)

    print("\n[✓] finalizado")

if __name__ == "__main__":
    main()
