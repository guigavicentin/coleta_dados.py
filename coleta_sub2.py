#!/usr/bin/env python3
"""
takeover.py — Recon de subdomínios + Domain Takeover + Port Scan

Fluxo:
  1. Enumeração de subdomínios  (subfinder, assetfinder, crt.sh, github-subdomains, chaos)
  2. Resolução DNS em massa     (dnsx)
  3. Bruteforce de subdomínios  (puredns, opcional)
  4. Hosts vivos                (httpx com portas extras)
  5. WAF detection              (wafw00f)
  6. Screenshot                 (gowitness)
  7. Takeover detection         (subzy, subjack, fingerprints manuais, nuclei)
  8. Nmap port scan             (opcional)
  9. Relatório HTML consolidado

Ferramentas SEM token obrigatório:
  subfinder, assetfinder, crt.sh (HTTP), dnsx, puredns,
  httpx, wafw00f, gowitness, subzy, subjack, nuclei, nmap

Ferramentas COM token OPCIONAL (rendem mais com token):
  subfinder  → ~/.config/subfinder/provider-config.yaml
  chaos      → variável de ambiente CHAOS_KEY
  github-subdomains → variável de ambiente GITHUB_TOKEN
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────────────────────────────────────
# Configuração de paths — todos via argumentos ou variáveis de ambiente
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_NUCLEI_TEMPLATES  = os.environ.get("NUCLEI_TEMPLATES",  "/root/nuclei-templates")
DEFAULT_RESOLVERS_FILE    = os.environ.get("RESOLVERS_FILE",    "/usr/share/wordlists/resolvers.txt")
DEFAULT_SUBDOMAINS_WORDLIST = os.environ.get("SUBDOMAINS_WORDLIST", "/usr/share/wordlists/subdomains.txt")

THREADS = 50
HTTPX_PORTS = "80,443,8080,8443,8888,4443,3000,5000"

# ─────────────────────────────────────────────────────────────────────────────
# Fingerprints de takeover — baseado em can-i-take-over-xyz (seleção)
# ─────────────────────────────────────────────────────────────────────────────

TAKEOVER_FINGERPRINTS: list[tuple[str, str]] = [
    ("AWS S3",           "NoSuchBucket"),
    ("AWS S3",           "The specified bucket does not exist"),
    ("GitHub Pages",     "There isn't a GitHub Pages site here"),
    ("GitHub Pages",     "For root URLs (like http://example.com/) you must provide an index.html file"),
    ("Heroku",           "No such app"),
    ("Heroku",           "herokucdn.com/error-pages/no-such-app"),
    ("Fastly",           "Fastly error: unknown domain"),
    ("Shopify",          "Sorry, this shop is currently unavailable"),
    ("Tumblr",           "Whatever you were looking for doesn't currently exist at this address"),
    ("WordPress",        "Do you want to register"),
    ("Pantheon",         "The gods are wise"),
    ("Zendesk",          "Help Center Closed"),
    ("Desk.com",         "Sorry, We Couldn't Find That Page"),
    ("Tictail",          "Building a store takes a few seconds"),
    ("Bitbucket",        "Repository not found"),
    ("Ghost",            "The thing you were looking for is no longer here"),
    ("Surge.sh",         "project not found"),
    ("Unbounce",         "The requested URL was not found on this server"),
    ("Statuspage",       "Better luck next time"),
    ("Azure",            "404 Web Site not found"),
    ("Azure",            "This web app is stopped"),
    ("Cargo",            "If you're moving your domain away from Cargo"),
    ("Feedpress",        "The feed has not been found"),
    ("Readme.io",        "Project doesnt exist"),
    ("Helpjuice",        "We could not find what you're looking for"),
    ("HelpScout",        "No settings were found for this company"),
    ("Intercom",         "This page is reserved for artistic dogs"),
    ("Kajabi",           "The page you were looking for doesn't exist"),
    ("Launchrock",       "It looks like you may have taken a wrong turn somewhere"),
    ("Pingdom",          "This public report page has not been activated"),
    ("Proposify",        "If you need immediate assistance"),
    ("Simplebooklet",    "We can't find this book"),
    ("Strikingly",       "But if you're looking to build your own website"),
    ("Uberflip",         "Non-hub domain, The URL you've accessed does not provide"),
    ("Uptimerobot",      "page not found"),
    ("Vend",             "Looks like you've traveled too far into cyberspace"),
    ("Webflow",          "The page you are looking for doesn't exist or has been moved"),
    ("Wishpond",         "https://www.wishpond.com/404"),
    ("Wufoo",            "Hmm, we can't find this page"),
]

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

def setup_logging(log_file: Path) -> logging.Logger:
    logger = logging.getLogger("takeover")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    log_file.parent.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger


def banner(step: str, logger: logging.Logger) -> None:
    logger.info("=" * 60)
    logger.info("ETAPA: %s", step)
    logger.info("=" * 60)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def run_cmd(
    cmd: list[str],
    logger: logging.Logger,
    stdin: str | None = None,
    timeout: int = 300,
    env: dict | None = None,
) -> list[str]:
    """Executa comando sem shell=True. Retorna linhas de stdout."""
    if not tool_available(cmd[0]):
        logger.warning("Ferramenta não encontrada: %s — pulando.", cmd[0])
        return []
    try:
        result = subprocess.run(
            cmd,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, **(env or {})},
        )
        if result.stderr:
            logger.debug("[stderr] %s: %s", cmd[0], result.stderr.strip()[:300])
        return [l for l in result.stdout.splitlines() if l.strip()]
    except subprocess.TimeoutExpired:
        logger.warning("Timeout: %s", " ".join(cmd))
        return []
    except Exception as exc:
        logger.error("Erro em %s: %s", cmd[0], exc)
        return []


def write_lines(path: Path, lines: list[str], logger: logging.Logger) -> bool:
    """Escreve arquivo apenas se houver conteúdo. Retorna True se escreveu."""
    clean = sorted(set(l.strip() for l in lines if l.strip()))
    if not clean:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(clean) + "\n", encoding="utf-8")
    logger.debug("Salvo: %s (%d linhas)", path, len(clean))
    return True


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 1: Enumeração de subdomínios
# ─────────────────────────────────────────────────────────────────────────────

def enumerate_subdomains(
    domain: str,
    base: Path,
    args: argparse.Namespace,
    logger: logging.Logger,
) -> list[str]:
    banner("Enumeração de Subdomínios", logger)
    all_subs: set[str] = set()

    # subfinder
    if tool_available("subfinder"):
        logger.info("[subfinder] coletando…")
        lines = run_cmd(["subfinder", "-d", domain, "--all", "-silent"], logger, timeout=300)
        all_subs.update(lines)
        logger.info("[subfinder] %d subdomínios", len(lines))
    else:
        logger.warning("subfinder não encontrado.")

    # assetfinder
    if tool_available("assetfinder"):
        logger.info("[assetfinder] coletando…")
        lines = run_cmd(["assetfinder", "--subs-only", domain], logger, timeout=120)
        all_subs.update(lines)
        logger.info("[assetfinder] %d subdomínios", len(lines))
    else:
        logger.warning("assetfinder não encontrado.")

    # crt.sh — API pública, sem token
    logger.info("[crt.sh] consultando…")
    crt_subs = _crt_sh(domain, logger)
    all_subs.update(crt_subs)
    logger.info("[crt.sh] %d subdomínios", len(crt_subs))

    # chaos — só se tiver token
    chaos_key = os.environ.get("CHAOS_KEY", "").strip()
    if chaos_key and tool_available("chaos"):
        logger.info("[chaos] coletando…")
        lines = run_cmd(
            ["chaos", "-d", domain, "-silent"],
            logger,
            env={"CHAOS_KEY": chaos_key},
            timeout=120,
        )
        all_subs.update(lines)
        logger.info("[chaos] %d subdomínios", len(lines))
    elif not chaos_key:
        logger.info("[chaos] CHAOS_KEY não definida — pulando.")

    # github-subdomains — só se tiver token
    github_token = os.environ.get("GITHUB_TOKEN", "").strip()
    if github_token and tool_available("github-subdomains"):
        logger.info("[github-subdomains] coletando…")
        lines = run_cmd(
            ["github-subdomains", "-d", domain, "-t", github_token, "-o", "/dev/stdout"],
            logger, timeout=180,
        )
        all_subs.update(lines)
        logger.info("[github-subdomains] %d subdomínios", len(lines))
    elif not github_token:
        logger.info("[github-subdomains] GITHUB_TOKEN não definida — pulando.")

    # Filtra apenas subdomínios do domínio alvo
    clean = [s for s in all_subs if domain in s and "*" not in s]
    logger.info("Total de subdomínios únicos: %d", len(clean))
    write_lines(base / "subdomains_raw.txt", clean, logger)
    return clean


def _crt_sh(domain: str, logger: logging.Logger) -> list[str]:
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=30,
            headers={"User-Agent": "Mozilla/5.0 takeover-recon"},
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        subs: set[str] = set()
        for entry in data:
            name = entry.get("name_value", "")
            for line in name.splitlines():
                line = line.strip().lstrip("*.")
                if domain in line:
                    subs.add(line)
        return sorted(subs)
    except Exception as exc:
        logger.debug("crt.sh erro: %s", exc)
        return []


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 2: Resolução DNS com dnsx
# ─────────────────────────────────────────────────────────────────────────────

def resolve_dns(
    subs: list[str],
    base: Path,
    resolvers_file: str,
    logger: logging.Logger,
) -> list[str]:
    banner("Resolução DNS (dnsx)", logger)

    input_file = base / "_dnsx_input.txt"
    write_lines(input_file, subs, logger)

    if not tool_available("dnsx"):
        logger.warning("dnsx não encontrado — usando lista bruta.")
        return subs

    cmd = ["dnsx", "-l", str(input_file), "-silent", "-a", "-resp"]
    if Path(resolvers_file).exists():
        cmd += ["-r", resolvers_file]

    lines = run_cmd(cmd, logger, timeout=300)
    # dnsx retorna "subdomain [IP]" — extrai só o subdomínio
    resolved = [l.split()[0] for l in lines if l.strip()]

    logger.info("Subdomínios resolvidos: %d", len(resolved))
    write_lines(base / "subdomains_resolved.txt", resolved, logger)
    return resolved


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 3: Bruteforce com puredns (opcional)
# ─────────────────────────────────────────────────────────────────────────────

def bruteforce_subs(
    domain: str,
    base: Path,
    wordlist: str,
    resolvers_file: str,
    logger: logging.Logger,
) -> list[str]:
    banner("Bruteforce de Subdomínios (puredns)", logger)

    if not tool_available("puredns"):
        logger.info("puredns não encontrado — pulando bruteforce.")
        return []

    if not Path(wordlist).exists():
        logger.warning("Wordlist não encontrada: %s — pulando bruteforce.", wordlist)
        return []

    cmd = ["puredns", "bruteforce", wordlist, domain, "-q"]
    if Path(resolvers_file).exists():
        cmd += ["-r", resolvers_file]

    lines = run_cmd(cmd, logger, timeout=600)
    logger.info("puredns encontrou: %d subdomínios", len(lines))
    write_lines(base / "subdomains_bruteforce.txt", lines, logger)
    return lines


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 4: Hosts vivos com httpx
# ─────────────────────────────────────────────────────────────────────────────

def probe_alive(
    subs: list[str],
    base: Path,
    logger: logging.Logger,
) -> tuple[list[str], list[str]]:
    """
    Retorna (urls_completas, dominios_limpos).
    Sonda portas extras além de 80/443.
    """
    banner("Hosts Vivos (httpx)", logger)

    if not tool_available("httpx"):
        logger.warning("httpx não encontrado.")
        return [], []

    input_file = base / "_httpx_input.txt"
    write_lines(input_file, subs, logger)

    result = subprocess.run(
        [
            "httpx",
            "-l", str(input_file),
            "-silent",
            "-ports", HTTPX_PORTS,
            "-mc", "200,201,204,301,302,307,308,403",
            "-threads", "50",
            "-timeout", "10",
            "-title",
            "-sc",
            "-ip",
            "-json",
        ],
        capture_output=True, text=True, timeout=600,
    )

    alive_urls:    list[str] = []
    alive_domains: list[str] = []
    httpx_data:    list[dict] = []

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            url = obj.get("url", "")
            if url:
                alive_urls.append(url)
                domain_clean = re.sub(r'^https?://', '', url).split('/')[0].split(':')[0]
                alive_domains.append(domain_clean)
                httpx_data.append(obj)
        except json.JSONDecodeError:
            # fallback: linha é só a URL
            alive_urls.append(line)
            domain_clean = re.sub(r'^https?://', '', line).split('/')[0].split(':')[0]
            alive_domains.append(domain_clean)

    write_lines(base / "alive.txt", alive_urls, logger)
    write_lines(base / "alive_domains.txt", alive_domains, logger)

    # Salva JSON completo para o relatório HTML
    if httpx_data:
        (base / "httpx_data.jsonl").write_text(
            "\n".join(json.dumps(d) for d in httpx_data) + "\n", encoding="utf-8"
        )

    logger.info("Hosts vivos: %d", len(alive_urls))
    return alive_urls, list(set(alive_domains))


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 5: WAF Detection
# ─────────────────────────────────────────────────────────────────────────────

def detect_waf(alive_urls: list[str], base: Path, logger: logging.Logger) -> dict[str, str]:
    banner("WAF Detection (wafw00f)", logger)
    waf_map: dict[str, str] = {}

    if not tool_available("wafw00f"):
        logger.info("wafw00f não encontrado — pulando WAF detection.")
        return waf_map

    waf_lines: list[str] = []
    # Limita para não demorar demais
    for url in alive_urls[:100]:
        try:
            result = subprocess.run(
                ["wafw00f", url, "-a", "-f", "json"],
                capture_output=True, text=True, timeout=20,
            )
            for line in result.stdout.splitlines():
                try:
                    obj = json.loads(line)
                    waf = obj.get("detected", [])
                    if waf:
                        waf_name = waf[0].get("firewall", "Unknown")
                        waf_map[url] = waf_name
                        waf_lines.append(f"{url}  →  {waf_name}")
                        logger.info("[WAF] %s → %s", url, waf_name)
                except json.JSONDecodeError:
                    pass
        except Exception as exc:
            logger.debug("wafw00f erro em %s: %s", url, exc)

    if waf_lines:
        write_lines(base / "waf_detected.txt", waf_lines, logger)
        logger.info("WAFs detectados: %d hosts", len(waf_map))
    else:
        logger.info("Nenhum WAF detectado.")

    return waf_map


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 6: Screenshots com gowitness
# ─────────────────────────────────────────────────────────────────────────────

def take_screenshots(alive_urls: list[str], base: Path, logger: logging.Logger) -> bool:
    banner("Screenshots (gowitness)", logger)

    if not tool_available("gowitness"):
        logger.info("gowitness não encontrado — pulando screenshots.")
        logger.info("Instale: go install github.com/sensepost/gowitness@latest")
        return False

    if not alive_urls:
        return False

    input_file = base / "_gowitness_input.txt"
    write_lines(input_file, alive_urls, logger)
    screenshots_dir = base / "screenshots"
    screenshots_dir.mkdir(exist_ok=True)

    try:
        subprocess.run(
            [
                "gowitness", "file",
                "-f", str(input_file),
                "--screenshot-path", str(screenshots_dir),
                "--disable-db",
                "--timeout", "10",
                "--threads", "5",
            ],
            capture_output=True, text=True, timeout=600,
        )
        count = len(list(screenshots_dir.glob("*.png")))
        logger.info("Screenshots capturados: %d → %s", count, screenshots_dir)
        return count > 0
    except Exception as exc:
        logger.error("gowitness erro: %s", exc)
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 7: Takeover Detection
# ─────────────────────────────────────────────────────────────────────────────

def _takeover_fingerprint_worker(url: str) -> Optional[tuple[str, str]]:
    """Checa fingerprints de takeover via curl. Retorna (url, serviço) ou None."""
    try:
        result = subprocess.run(
            ["curl", "-sk", "--max-time", "8", "-L", url],
            capture_output=True, text=True, timeout=12,
        )
        body = result.stdout
        for service, fp in TAKEOVER_FINGERPRINTS:
            if fp.lower() in body.lower():
                return url, service
    except Exception:
        pass
    return None


def run_takeover_fingerprints(
    alive_urls: list[str],
    base: Path,
    logger: logging.Logger,
) -> list[tuple[str, str]]:
    logger.info("Fingerprint takeover em %d URLs…", len(alive_urls))
    hits: list[tuple[str, str]] = []

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(_takeover_fingerprint_worker, url): url for url in alive_urls}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    url, service = result
                    logger.warning("[TAKEOVER fingerprint] %s → %s", url, service)
                    hits.append(result)
            except Exception as exc:
                logger.debug("Thread erro: %s", exc)

    return hits


def run_subzy(domains: list[str], base: Path, logger: logging.Logger) -> list[str]:
    if not tool_available("subzy"):
        logger.info("subzy não encontrado — pulando.")
        return []

    input_file = base / "_subzy_input.txt"
    write_lines(input_file, domains, logger)

    lines = run_cmd(
        ["subzy", "run", "--targets", str(input_file), "--hide_fails", "--verify"],
        logger, timeout=300,
    )
    hits = [l for l in lines if "VULNERABLE" in l.upper()]
    if hits:
        write_lines(base / "subzy_vulnerable.txt", hits, logger)
        logger.warning("[subzy] %d vulneráveis encontrados", len(hits))
    else:
        logger.info("[subzy] nenhum takeover encontrado.")
    return hits


def run_subjack(domains: list[str], base: Path, logger: logging.Logger) -> list[str]:
    if not tool_available("subjack"):
        logger.info("subjack não encontrado — pulando.")
        return []

    input_file  = base / "_subjack_input.txt"
    output_file = base / "subjack_results.txt"
    write_lines(input_file, domains, logger)

    run_cmd(
        ["subjack", "-w", str(input_file), "-t", "100",
         "-timeout", "30", "-ssl", "-v", "-o", str(output_file)],
        logger, timeout=300,
    )

    if not output_file.exists():
        return []
    vuln = [l for l in read_lines(output_file)
            if "vulnerable" in l.lower()]
    if vuln:
        logger.warning("[subjack] %d vulneráveis encontrados", len(vuln))
    return vuln


def _nuclei_run_dir(
    label: str,
    template_dir: Path,
    alive_file: Path,
    output_file: Path,
    severity_flag: list[str],
    logger: logging.Logger,
    timeout: int = 600,
) -> list[str]:
    """
    Executa nuclei em um único diretório de templates.
    Retorna as linhas de achados. Não cria arquivo se vazio.
    """
    if not template_dir.exists():
        logger.warning("[nuclei/%s] diretório não encontrado: %s", label, template_dir)
        return []

    banner(f"Nuclei [{label}]  →  {template_dir}", logger)
    run_cmd(
        ["nuclei",
         "-l", str(alive_file),
         "-t", str(template_dir),
         "-silent",
         "-o", str(output_file),
         "-timeout", "10"]
        + severity_flag,
        logger,
        timeout=timeout,
    )

    hits = read_lines(output_file)
    if hits:
        logger.warning("[nuclei/%s] %d achados → %s", label, len(hits), output_file)
    else:
        logger.info("[nuclei/%s] nenhum achado.", label)
        if output_file.exists():
            output_file.unlink()   # não deixa arquivo vazio
    return hits


def run_all_nuclei(
    alive_file: Path,
    base: Path,
    args: argparse.Namespace,
    logger: logging.Logger,
) -> list[str]:
    """
    Executa nuclei em TODOS os diretórios de templates configurados,
    cada um com seu próprio arquivo de saída.

    Diretórios rodados (em ordem):
      1. <nuclei_templates>/http/takeovers   — sempre
      2. <nuclei_templates>/network          — a menos que --no-network
      3. <nuclei_templates>/http             — a menos que --no-http
      4. Cada path em --nuclei-extra         — sempre (ex: templates de gits)

    Retorna lista de achados de takeover (apenas do diretório de takeovers
    e dos extras) para alimentar o merge final.
    """
    if not tool_available("nuclei"):
        logger.info("nuclei não encontrado — pulando todos os scans nuclei.")
        return []
    if not alive_file.exists():
        return []

    severity_flag = ["-severity", args.severity] if getattr(args, "severity", None) else []
    takeover_hits: list[str] = []

    # ── 1. Templates de takeover do repositório principal ────────────────────
    main_templates = Path(args.nuclei_templates or DEFAULT_NUCLEI_TEMPLATES)
    takeover_dir   = main_templates / "http" / "takeovers"
    hits = _nuclei_run_dir(
        label        = "takeovers",
        template_dir = takeover_dir,
        alive_file   = alive_file,
        output_file  = base / "nuclei_takeovers.txt",
        severity_flag= severity_flag,
        logger       = logger,
    )
    takeover_hits.extend(hits)

    # ── 2. Network templates (opcional) ──────────────────────────────────────
    if not getattr(args, "no_network", False):
        _nuclei_run_dir(
            label        = "network",
            template_dir = main_templates / "network",
            alive_file   = alive_file,
            output_file  = base / "nuclei_network.txt",
            severity_flag= severity_flag,
            logger       = logger,
            timeout      = 900,
        )

    # ── 3. HTTP templates (opcional) ─────────────────────────────────────────
    if not getattr(args, "no_http", False):
        _nuclei_run_dir(
            label        = "http",
            template_dir = main_templates / "http",
            alive_file   = alive_file,
            output_file  = base / "nuclei_http.txt",
            severity_flag= severity_flag,
            logger       = logger,
            timeout      = 1800,
        )

    # ── 4. Diretórios extras (--nuclei-extra), ex: templates de gits ─────────
    for extra_path in getattr(args, "nuclei_extra", []) or []:
        extra_dir = Path(extra_path)
        if not extra_dir.exists():
            logger.warning("[nuclei/extra] path não encontrado: %s", extra_dir)
            continue

        # Nome do output baseado no nome do diretório (sanitizado)
        label       = re.sub(r'[^\w\-]', '_', extra_dir.name) or "extra"
        output_file = base / f"nuclei_{label}.txt"

        # Evita sobrescrever se já existe label igual
        counter = 1
        while output_file.exists():
            output_file = base / f"nuclei_{label}_{counter}.txt"
            counter += 1

        hits = _nuclei_run_dir(
            label        = f"extra/{extra_dir.name}",
            template_dir = extra_dir,
            alive_file   = alive_file,
            output_file  = output_file,
            severity_flag= severity_flag,
            logger       = logger,
            timeout      = 900,
        )
        takeover_hits.extend(hits)

    return takeover_hits


def detect_takeovers(
    alive_urls: list[str],
    alive_domains: list[str],
    base: Path,
    args: argparse.Namespace,
    logger: logging.Logger,
) -> list[dict]:
    banner("Takeover Detection", logger)
    all_findings: list[dict] = []

    # Fingerprints manuais
    fp_hits = run_takeover_fingerprints(alive_urls, base, logger)
    for url, service in fp_hits:
        all_findings.append({"url": url, "source": "fingerprint", "detail": service})

    # subzy
    subzy_hits = run_subzy(alive_domains, base, logger)
    for hit in subzy_hits:
        all_findings.append({"url": hit, "source": "subzy", "detail": ""})

    # subjack
    subjack_hits = run_subjack(alive_domains, base, logger)
    for hit in subjack_hits:
        all_findings.append({"url": hit, "source": "subjack", "detail": ""})

    # nuclei — todos os diretórios configurados
    alive_file   = base / "alive.txt"
    nuclei_hits  = run_all_nuclei(alive_file, base, args, logger)
    for hit in nuclei_hits:
        all_findings.append({"url": hit, "source": "nuclei", "detail": ""})

    # Deduplica por URL
    seen: set[str] = set()
    deduped: list[dict] = []
    for f in all_findings:
        if f["url"] not in seen:
            seen.add(f["url"])
            deduped.append(f)

    if deduped:
        lines = [f"[{f['source']}] {f['url']}  {f['detail']}".strip() for f in deduped]
        write_lines(base / "takeovers_confirmed.txt", lines, logger)
        logger.warning("=" * 50)
        logger.warning("TAKEOVERS ENCONTRADOS: %d", len(deduped))
        for f in deduped:
            logger.warning("  [%s] %s %s", f["source"], f["url"], f["detail"])
        logger.warning("=" * 50)
    else:
        logger.info("Nenhum takeover confirmado.")

    return deduped


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 8: Nmap
# ─────────────────────────────────────────────────────────────────────────────

def extract_ips(httpx_jsonl: Path, logger: logging.Logger) -> list[str]:
    ips: set[str] = set()
    if not httpx_jsonl.exists():
        return []
    for line in httpx_jsonl.read_text(encoding="utf-8").splitlines():
        try:
            obj = json.loads(line)
            ip = obj.get("host", "") or obj.get("ip", "")
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                ips.add(ip)
        except Exception:
            pass
    return sorted(ips)


def run_nmap(base: Path, logger: logging.Logger, timeout: int = 3600) -> None:
    banner("Nmap Port Scan", logger)

    ips = extract_ips(base / "httpx_data.jsonl", logger)
    if not ips:
        # Fallback: tenta extrair IPs do alive.txt via resolução
        logger.info("IPs não encontrados no JSON do httpx — pulando nmap.")
        return

    if not tool_available("nmap"):
        logger.warning("nmap não encontrado.")
        return

    ip_file  = base / "ips.txt"
    nmap_out = base / "nmap.txt"
    write_lines(ip_file, ips, logger)
    logger.info("Rodando nmap em %d IPs…", len(ips))

    run_cmd(
        ["nmap", "-p-", "-T4", "-sV", "-Pn", "--open",
         "-iL", str(ip_file), "-oN", str(nmap_out)],
        logger,
        timeout=timeout,
    )

    if nmap_out.exists() and nmap_out.stat().st_size > 0:
        logger.info("Nmap finalizado → %s", nmap_out)
    else:
        logger.info("Nmap não retornou resultados.")


# ─────────────────────────────────────────────────────────────────────────────
# Etapa 9: Relatório HTML
# ─────────────────────────────────────────────────────────────────────────────

def generate_html_report(
    domain: str,
    base: Path,
    stats: dict,
    takeovers: list[dict],
    waf_map: dict[str, str],
    logger: logging.Logger,
) -> None:
    banner("Relatório HTML", logger)

    alive_urls = read_lines(base / "alive.txt")
    screenshots_dir = base / "screenshots"

    # Monta linhas da tabela de hosts
    host_rows = ""
    for url in alive_urls[:500]:
        waf = waf_map.get(url, "—")
        screenshot_file = screenshots_dir / f"{re.sub(r'[^\w]', '_', url)}.png"
        screenshot_html = (
            f'<a href="screenshots/{screenshot_file.name}" target="_blank">'
            f'<img src="screenshots/{screenshot_file.name}" width="120"></a>'
            if screenshot_file.exists() else "—"
        )
        host_rows += (
            f"<tr><td><a href='{url}' target='_blank'>{url}</a></td>"
            f"<td>{waf}</td><td>{screenshot_html}</td></tr>\n"
        )

    # Monta linhas de takeover
    takeover_rows = ""
    for f in takeovers:
        takeover_rows += (
            f"<tr class='vuln'><td>{f['url']}</td>"
            f"<td>{f['source']}</td><td>{f['detail']}</td></tr>\n"
        )
    if not takeover_rows:
        takeover_rows = "<tr><td colspan='3'>Nenhum takeover encontrado.</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<title>Recon — {domain}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
    --danger: #f85149; --warn: #d29922; --ok: #3fb950;
    --font: 'Courier New', monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--font); padding: 2rem; }}
  h1 {{ color: var(--accent); margin-bottom: .5rem; font-size: 1.6rem; }}
  h2 {{ color: var(--muted); font-size: 1rem; border-bottom: 1px solid var(--border);
        padding-bottom: .4rem; margin: 2rem 0 .8rem; }}
  .meta {{ color: var(--muted); font-size: .85rem; margin-bottom: 2rem; }}
  .stats {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px;
           padding: .8rem 1.2rem; min-width: 140px; }}
  .stat .n {{ font-size: 2rem; color: var(--accent); font-weight: bold; }}
  .stat .l {{ font-size: .75rem; color: var(--muted); }}
  table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
  th {{ background: var(--surface); color: var(--muted); text-align: left;
        padding: .5rem .8rem; border-bottom: 1px solid var(--border); }}
  td {{ padding: .45rem .8rem; border-bottom: 1px solid var(--border); word-break: break-all; }}
  tr:hover td {{ background: var(--surface); }}
  tr.vuln td {{ color: var(--danger); }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  img {{ border-radius: 4px; border: 1px solid var(--border); }}
</style>
</head>
<body>
<h1>&#x1F50D; Recon — {domain}</h1>
<p class="meta">Gerado em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

<div class="stats">
  <div class="stat"><div class="n">{stats.get('subdomains', 0)}</div><div class="l">Subdomínios</div></div>
  <div class="stat"><div class="n">{stats.get('resolved', 0)}</div><div class="l">Resolvidos</div></div>
  <div class="stat"><div class="n">{stats.get('alive', 0)}</div><div class="l">Vivos</div></div>
  <div class="stat"><div class="n" style="color:{'var(--danger)' if takeovers else 'var(--ok)'}">
    {len(takeovers)}</div><div class="l">Takeovers</div></div>
  <div class="stat"><div class="n">{stats.get('wafs', 0)}</div><div class="l">WAFs detectados</div></div>
</div>

<h2>&#x26A0; Takeovers Encontrados</h2>
<table>
  <tr><th>URL</th><th>Fonte</th><th>Serviço</th></tr>
  {takeover_rows}
</table>

<h2>&#x1F310; Hosts Vivos ({len(alive_urls)})</h2>
<table>
  <tr><th>URL</th><th>WAF</th><th>Screenshot</th></tr>
  {host_rows}
</table>

</body>
</html>"""

    report_file = base / "report.html"
    report_file.write_text(html, encoding="utf-8")
    logger.info("Relatório HTML → %s", report_file)


# ─────────────────────────────────────────────────────────────────────────────
# Orquestração por domínio
# ─────────────────────────────────────────────────────────────────────────────

def process_domain(domain: str, args: argparse.Namespace, logger: logging.Logger) -> None:
    base = Path(domain)
    base.mkdir(exist_ok=True)
    stats: dict[str, int] = {}

    # 1. Enumeração
    subs = enumerate_subdomains(domain, base, args, logger)
    stats["subdomains"] = len(subs)

    # 2. Bruteforce (opcional)
    if not args.no_bruteforce:
        bf_subs = bruteforce_subs(
            domain, base,
            args.wordlist or DEFAULT_SUBDOMAINS_WORDLIST,
            args.resolvers or DEFAULT_RESOLVERS_FILE,
            logger,
        )
        subs = sorted(set(subs + bf_subs))

    # 3. Resolução DNS
    resolved = resolve_dns(subs, base, args.resolvers or DEFAULT_RESOLVERS_FILE, logger)
    stats["resolved"] = len(resolved)

    # 4. Hosts vivos
    alive_urls, alive_domains = probe_alive(resolved, base, logger)
    stats["alive"] = len(alive_urls)

    if not alive_urls:
        logger.warning("Nenhum host vivo encontrado para %s — abortando.", domain)
        return

    # 5. WAF
    waf_map: dict[str, str] = {}
    if not args.no_waf:
        waf_map = detect_waf(alive_urls, base, logger)
        stats["wafs"] = len(waf_map)
    else:
        stats["wafs"] = 0

    # 6. Screenshots
    if not args.no_screenshots:
        take_screenshots(alive_urls, base, logger)

    # 7. Takeover
    takeovers = detect_takeovers(
        alive_urls, alive_domains, base, args, logger,
    )
    stats["takeovers"] = len(takeovers)

    # 8. Nmap
    if not args.no_nmap:
        run_nmap(base, logger, timeout=args.nmap_timeout)

    # 9. Relatório HTML
    generate_html_report(domain, base, stats, takeovers, waf_map, logger)

    # Sumário no terminal
    logger.info("=" * 60)
    logger.info("SUMÁRIO — %s", domain)
    logger.info("  Subdomínios enumerados : %d", stats.get("subdomains", 0))
    logger.info("  Subdomínios resolvidos : %d", stats.get("resolved", 0))
    logger.info("  Hosts vivos            : %d", stats.get("alive", 0))
    logger.info("  Takeovers encontrados  : %d", stats.get("takeovers", 0))
    logger.info("  WAFs detectados        : %d", stats.get("wafs", 0))
    logger.info("  Saída                  : %s", base)
    logger.info("=" * 60)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Recon de subdomínios + Domain Takeover + Port Scan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Variáveis de ambiente opcionais:
  CHAOS_KEY            Token do Chaos (projectdiscovery.io)
  GITHUB_TOKEN         GitHub Personal Access Token
  NUCLEI_TEMPLATES     Path dos templates nuclei  (padrão: /root/nuclei-templates)
  RESOLVERS_FILE       Path do arquivo de resolvers DNS
  SUBDOMAINS_WORDLIST  Wordlist para bruteforce puredns
""",
    )
    p.add_argument("domain",          nargs="?",           help="Domínio alvo")
    p.add_argument("-l", "--list",                         help="Arquivo com lista de domínios")
    p.add_argument("--nuclei-templates", default=None,
                   help=f"Path do repositório principal de templates nuclei (padrão: {DEFAULT_NUCLEI_TEMPLATES})")
    p.add_argument("--nuclei-extra",     action="append", metavar="PATH", default=[],
                   help="Diretório extra de templates nuclei — pode ser usado várias vezes. "
                        "Ex: --nuclei-extra ~/nuclei-templates-gits --nuclei-extra ~/meus-templates")
    p.add_argument("--resolvers",     default=None,        help="Path do arquivo resolvers.txt")
    p.add_argument("--wordlist",      default=None,        help="Wordlist para puredns bruteforce")
    p.add_argument("--severity",      default=None,        help="Filtro de severity no nuclei (ex: critical,high)")
    p.add_argument("--nmap-timeout",  type=int, default=3600, help="Timeout do nmap em segundos (padrão: 3600)")
    p.add_argument("--no-nmap",       action="store_true", help="Pula nmap")
    p.add_argument("--no-network",    action="store_true", help="Pula nuclei/network")
    p.add_argument("--no-http",       action="store_true", help="Pula nuclei/http")
    p.add_argument("--no-waf",        action="store_true", help="Pula WAF detection")
    p.add_argument("--no-screenshots",action="store_true", help="Pula gowitness")
    p.add_argument("--no-bruteforce", action="store_true", help="Pula puredns bruteforce")
    return p.parse_args()


def main() -> None:
    args    = parse_args()
    domains: list[str] = []

    if args.domain:
        domains.append(args.domain)
    if args.list:
        with open(args.list) as f:
            domains.extend(d.strip() for d in f if d.strip())

    if not domains:
        parse_args().print_help()
        sys.exit(1)

    for domain in domains:
        log_file = Path(domain) / "takeover.log"
        logger   = setup_logging(log_file)
        logger.info("######## PROCESSANDO %s ########", domain)
        process_domain(domain, args, logger)


if __name__ == "__main__":
    main()
