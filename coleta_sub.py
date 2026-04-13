#!/usr/bin/env python3
import argparse
import subprocess
import re
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

# Template paths
NUCLEI_TAKEOVER = "/root/nuclei-templates/http/takeovers/"
NUCLEI_NETWORK = "/root/nuclei-templates/network/"
NUCLEI_HTTP = "/root/nuclei-templates/http/"
NUCLEI_GITS = "/home/guilherme/kali/nuclei-templates-gits/"

THREADS = 50

fingerprints = [
    "NoSuchBucket",
    "There isn't a GitHub Pages site here",
    "No such app",
    "Fastly error: unknown domain",
    "Repository not found",
    "project not found"
]

def run(cmd):
    print(f"[CMD] {cmd}")
    subprocess.run(cmd, shell=True)

def banner(step):
    print("\n" + "="*60)
    print(f"[+] ETAPA: {step}")
    print("="*60)

# =========================
# NOVO: SUBJACK
# =========================
def run_subjack(input_file, output_all, output_vuln):
    print(f"[SUBJACK] Rodando em {input_file}")

    try:
        subprocess.run(
            f"subjack -w {input_file} -t 100 -timeout 30 -ssl -v -o {output_all}",
            shell=True
        )

        with open(output_all) as f, open(output_vuln, "w") as out:
            for line in f:
                if "Vulnerable" in line or "vulnerable" in line:
                    out.write(line)

    except Exception as e:
        print(f"[ERRO SUBJACK] {e}")

# =========================
# NOVO: MASSDNS
# =========================
def run_massdns(input_file, output_file):
    print(f"[MASSDNS] Rodando em {input_file}")

    try:
        subprocess.run(
            f"massdns -r /home/guilherme/kali/minha_ferramenta/resolvers.txt -t A -o S {input_file} > {output_file}",
            shell=True
        )
    except Exception as e:
        print(f"[ERRO MASSDNS] {e}")

# =========================

def run_subzy(input_file, output):
    print(f"[SUBZY] Rodando em {input_file}")
    try:
        r = subprocess.check_output(
            f"subzy run --targets {input_file} --hide_fails",
            shell=True
        ).decode(errors="ignore")

        with open(output, "w") as f:
            for line in r.splitlines():
                if line.strip():
                    f.write(line.strip() + "\n")

    except subprocess.CalledProcessError:
        pass

def takeover_worker(url):
    try:
        r = subprocess.check_output(
            f"curl -s -k --max-time 8 -L {url}",
            shell=True
        ).decode(errors="ignore")

        for fp in fingerprints:
            if fp.lower() in r.lower():
                return url
    except:
        pass

    return None

def threaded_takeover(alive_file, output_file):
    urls = []
    with open(alive_file) as f:
        for line in f:
            if line.strip():
                urls.append(line.split()[0])

    results = []
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        for r in executor.map(takeover_worker, urls):
            if r:
                print(f"[TAKEOVER] {r}")
                results.append(r)

    with open(output_file, "w") as f:
        for r in sorted(set(results)):
            f.write(r + "\n")

def extract_ips(input_file, output_file):
    ips = set()
    with open(input_file) as f:
        for line in f:
            match = re.findall(r"\[(\d+\.\d+\.\d+\.\d+)\]", line)
            if match:
                ips.add(match[-1])

    with open(output_file, "w") as f:
        for ip in sorted(ips):
            f.write(ip + "\n")

def merge_takeovers(files, output):
    merged = set()

    for file in files:
        if Path(file).exists():
            with open(file) as f:
                for line in f:
                    if line.strip():
                        merged.add(line.strip())

    with open(output, "w") as f:
        for line in sorted(merged):
            f.write(line + "\n")

def process_domain(domain, args):
    base = Path(domain)
    base.mkdir(exist_ok=True)

    subs = base / "subdomains.txt"
    alive = base / "alive.txt"
    ips = base / "ips.txt"
    takeover_thread = base / "takeover_threaded.txt"
    takeover_nuclei = base / "takeover_nuclei.txt"
    takeover_final = base / "takeover_final.txt"
    subzy_output = base / "subzy_takeovers.txt"
    nmap = base / "nmap.txt"

    # NOVOS
    subjack_all = base / "subjack_all.txt"
    subjack_vuln = base / "subjack_vuln.txt"
    massdns_output = base / "massdns.txt"

    template_dirs = [NUCLEI_TAKEOVER, NUCLEI_GITS]

    if not args.no_network:
        template_dirs.append(NUCLEI_NETWORK)
    if not args.no_http:
        template_dirs.append(NUCLEI_HTTP)

    banner("Coleta Subdomínios")
    run(f"subfinder -d {domain} --all -silent > {base}/subfinder.txt")
    run(f"amass enum -passive -norecursive -d {domain} -o {base}/amass.txt")
    run(f"shodanx subdomain -d {domain} -o {base}/shodanx.txt")
    run(f"chaos -d {domain} -silent > {base}/chaos.txt")
    run(f"assetfinder --subs-only {domain} > {base}/assetfinder.txt")

    run(f"cat {base}/subfinder.txt {base}/amass.txt {base}/shodanx.txt {base}/chaos.txt {base}/assetfinder.txt | grep -v '*' | sort -u > {subs}")

    # =========================
    banner("MassDNS Scan")
    run_massdns(subs, massdns_output)

    banner("Subjack Scan")
    run_subjack(subs, subjack_all, subjack_vuln)
    # =========================

    banner("Subzy Takeover Scan")
    run_subzy(subs, subzy_output)

    banner("Hosts ativos - HTTPX")
    run(f"httpx -silent -ip -title -sc -l {subs} -o {alive}")

    banner("Takeover Threaded")
    threaded_takeover(alive, takeover_thread)

    all_takeovers = [takeover_thread, subzy_output, subjack_vuln]

    for template_dir in template_dirs:
        template_name = template_dir.strip("/").split("/")[-1]
        template_file = base / f"nuclei_{template_name}.txt"

        severity = ""
        if args.severity:
            severity = f"-severity {args.severity}"

        banner(f"Nuclei Scan: {template_name}")
        run(f"nuclei -l {alive} -t {template_dir} {severity} -o {template_file}")

        all_takeovers.append(template_file)

    banner("Merge Takeover")
    merge_takeovers(all_takeovers, takeover_final)

    if args.no_nmap:
        return

    banner("Extraindo IPs")
    extract_ips(alive, ips)

    banner("Nmap Scan")
    run(f"nmap -p- -T4 -sV -Pn -sS -iL {ips} -oN {nmap}")

def main():
    parser = argparse.ArgumentParser(description="Recon + Domain Takeover + Nmap automation")
    parser.add_argument("domain", nargs="?", help="Domínio alvo")
    parser.add_argument("-l", "--list", help="Lista de domínios")
    parser.add_argument("--only-takeover", action="store_true")
    parser.add_argument("--no-nmap", action="store_true")
    parser.add_argument("--no-network", action="store_true")
    parser.add_argument("--no-http", action="store_true")
    parser.add_argument("--severity", help="Filtro severity nuclei")

    args = parser.parse_args()
    domains = []

    if args.domain:
        domains.append(args.domain)

    if args.list:
        with open(args.list) as f:
            domains.extend([d.strip() for d in f if d.strip()])

    if not domains:
        parser.print_help()
        sys.exit()

    for d in domains:
        print(f"\n######## PROCESSANDO {d} ########")
        process_domain(d, args)

if __name__ == "__main__":
    main()
